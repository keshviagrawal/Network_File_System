#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <ctype.h>
#include <sys/time.h>
#include <time.h>
#include <dirent.h>
#include <pthread.h>

#include "../include/protocol.h"
#include "../include/constants.h"
#include "../include/error_codes.h"

int connect_to_server(char *ip, int port);
int send_message(int sockfd, Message *msg);
int receive_message(int sockfd, Message *msg);
void log_event(const char *filename, const char *component, const char *event);
void log_event_detailed(const char *filename, const char *component, 
                       const char *operation, const char *username,
                       const char *ip, int port, const char *details,
                       int display_terminal);
int create_server_socket(int port);

// Globals to let SS notify NM after commit
static char nm_ip_global[32] = "127.0.0.1";
static int nm_port_global = 0;
static char ss_name[64] = "SS0";
static int ss_id_global = -1;  // Assigned SS ID from NM, -1 until registered

static int ss_create_file(const char *fname, const char *owner) {
    // Ensure data directory exists
    struct stat st = {0};
    if (stat("data", &st) == -1) {
        mkdir("data", 0755);
    }
    char path[512];
    snprintf(path, sizeof(path), "data/%s", fname);
    // Check if exists
    if (stat(path, &st) == 0) {
        return ERR_BAD_REQUEST; // already exists
    }
    FILE *f = fopen(path, "w");
    if (!f) return ERR_INTERNAL;
    fclose(f);
    // write a minimal meta sidecar with ACL defaults
    char mpath[512];
    snprintf(mpath, sizeof(mpath), "data/%s.meta", fname);
    FILE *m = fopen(mpath, "w");
    if (m) {
        char tbuf[32]; time_t now = time(NULL); struct tm *tm_info = localtime(&now);
        strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", tm_info);
        // readers/writers initialized to owner
        fprintf(m, "owner=%s\nreaders=%s\nwriters=%s\nwords=0\nchars=0\nlast_modified=%s\n", owner, owner, owner, tbuf);
        fclose(m);
    }
    return SUCCESS;
}

typedef struct {
    char filename[64];
    int sentence_idx;
    int locked;
    char locked_by[32];
    char req_id[64];
} SentenceLock;

#define MAX_LOCKS 1024
static SentenceLock locks[MAX_LOCKS];
static pthread_mutex_t locks_mutex = PTHREAD_MUTEX_INITIALIZER;

static SentenceLock* find_lock_slot_nolock(const char *fname, int sentence_idx) {
    // NOTE: caller must hold locks_mutex when calling this
    for (int i=0;i<MAX_LOCKS;i++) {
        if (locks[i].locked && strcmp(locks[i].filename, fname)==0 && locks[i].sentence_idx==sentence_idx) return &locks[i];
    }
    for (int i=0;i<MAX_LOCKS;i++) {
        if (!locks[i].locked) return &locks[i];
    }
    return NULL;
}

static int load_file(const char *fname, char **out_buf) {
    char path[512]; snprintf(path, sizeof(path), "data/%s", fname);
    FILE *f = fopen(path, "r"); if (!f) return ERR_FILE_NOT_FOUND;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return ERR_INTERNAL; }
    char *buf = (char*)malloc((size_t)sz + 1); if (!buf) { fclose(f); return ERR_INTERNAL; }
    size_t n = fread(buf, 1, (size_t)sz, f); fclose(f);
    buf[n] = '\0'; *out_buf = buf; return SUCCESS;
}

static void ensure_parent_dirs(const char *path) {
    // Create parent directories for the given path (mkdir -p behavior)
    char tmp[512]; strncpy(tmp, path, sizeof(tmp)-1); tmp[sizeof(tmp)-1]='\0';
    // find last '/'
    char *last = strrchr(tmp, '/'); if (!last) return; *last = '\0';
    // iterate and mkdir each level
    char *p = tmp;
    if (*p == '\0') return;
    while ((p = strchr(p, '/')) != NULL) { *p = '\0'; mkdir(tmp, 0755); *p = '/'; p++; }
    mkdir(tmp, 0755);
}

static void save_undo(const char *fname, const char *data) {
    char upath[512]; snprintf(upath, sizeof(upath), "data/.undo_%s", fname);
    ensure_parent_dirs(upath);
    FILE *u = fopen(upath, "w"); if (!u) return; fwrite(data, 1, strlen(data), u); fclose(u);
}

static int save_file(const char *fname, const char *data) {
    char path[512]; snprintf(path, sizeof(path), "data/%s", fname);
    FILE *f = fopen(path, "w"); if (!f) return ERR_INTERNAL;
    fwrite(data, 1, strlen(data), f); fclose(f); return SUCCESS;
}

// Forward declaration used by replication handler
static void update_meta_counts(const char *fname);

// Replication sink: receive stream and write file fully
static int handle_repl_write(int sock, Message *first) {
    // Ensure parent folder exists
    char dpath[512]; snprintf(dpath, sizeof(dpath), "data/%s", first->filename);
    char tmp[512]; strncpy(tmp, dpath, sizeof(tmp)-1); tmp[sizeof(tmp)-1]='\0';
    char *slash = strrchr(tmp, '/'); if (slash) { *slash='\0'; struct stat st; if (stat(tmp,&st)!=0) mkdir(tmp,0755); }
    // Collect stream
    size_t cap=8192,len=0; char *buf=(char*)malloc(cap); if(!buf) return ERR_INTERNAL; buf[0]='\0';
    while (1) {
        Message rp; int n=receive_message(sock,&rp); if(n<=0){ free(buf); return ERR_INTERNAL; }
        if (rp.op_code==OP_STREAM || strcmp(rp.command, OP_STREAM_S)==0) {
            size_t blen=strlen(rp.payload); if(len+blen+1>cap){ cap=(len+blen+1)*2; char *nb=(char*)realloc(buf,cap); if(!nb){free(buf);return ERR_INTERNAL;} buf=nb; }
            memcpy(buf+len, rp.payload, blen); len+=blen; buf[len]='\0';
        } else if (rp.op_code==OP_STREAM_END || strcmp(rp.command, OP_STREAM_END_S)==0) {
            int rc=save_file(first->filename, buf);
            if (rc==SUCCESS) {
                update_meta_counts(first->filename);
            }
            free(buf);
            return rc;
        } else {
            free(buf); return ERR_INTERNAL;
        }
    }
}

static void compute_counts(const char *fname, int *words, int *chars) {
    *words = 0; *chars = 0;
    char path[512]; snprintf(path, sizeof(path), "data/%s", fname);
    FILE *f = fopen(path, "r"); if (!f) return;
    int in_word = 0; int c;
    while ((c = fgetc(f)) != EOF) {
        (*chars)++;
        if (!isspace(c)) {
            if (!in_word) { (*words)++; in_word = 1; }
        } else {
            in_word = 0;
        }
    }
    fclose(f);
}

static int read_version(const char *fname) {
    char mpath[512]; snprintf(mpath, sizeof(mpath), "data/%s.meta", fname);
    FILE *m = fopen(mpath, "r");
    if (!m) return 0;
    int version = 0;
    char line[256];
    while (fgets(line, sizeof(line), m)) {
        if (strncmp(line, "version=", 8) == 0) {
            version = atoi(line+8);
            break;
        }
    }
    fclose(m);
    return version;
}

static void update_meta_counts(const char *fname) {
    char mpath[512]; snprintf(mpath, sizeof(mpath), "data/%s.meta", fname);
    // read existing fields to preserve ACL lists and version
    char owner[64] = ""; char readers[256] = ""; char writers[256] = "";
    int version = 0;
    FILE *m = fopen(mpath, "r");
    if (m) {
        char line[256];
        while (fgets(line, sizeof(line), m)) {
            if (strncmp(line, "owner=", 6) == 0) {
                strncpy(owner, line+6, sizeof(owner)-1);
                size_t L = strlen(owner); if (L>0 && (owner[L-1]=='\n' || owner[L-1]=='\r')) owner[L-1]='\0';
            } else if (strncmp(line, "readers=", 8) == 0) {
                strncpy(readers, line+8, sizeof(readers)-1);
                size_t L = strlen(readers); if (L>0 && (readers[L-1]=='\n' || readers[L-1]=='\r')) readers[L-1]='\0';
            } else if (strncmp(line, "writers=", 8) == 0) {
                strncpy(writers, line+8, sizeof(writers)-1);
                size_t L = strlen(writers); if (L>0 && (writers[L-1]=='\n' || writers[L-1]=='\r')) writers[L-1]='\0';
            } else if (strncmp(line, "version=", 8) == 0) {
                version = atoi(line+8);
            }
        }
        fclose(m);
    }
    // Increment version on each update
    version++;
    
    int w=0, c=0; compute_counts(fname, &w, &c);
    // compute last_modified timestamp string
    char tbuf[32]; time_t now = time(NULL); struct tm *tm_info = localtime(&now);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", tm_info);
    m = fopen(mpath, "w");
    if (m) {
        fprintf(m, "owner=%s\nreaders=%s\nwriters=%s\nwords=%d\nchars=%d\nversion=%d\nlast_modified=%s\n", 
                owner, readers, writers, w, c, version, tbuf);
        fclose(m);
    }
}

// naive sentence split by .,!,? keeping delimiters
static int split_sentences(char *text, char **starts, int max) {
    int count=0; char *p=text; char *s=text;
    while (*p && count<max) {
        if (*p=='.' || *p=='!' || *p=='?') {
            char *next = p+1; // include delimiter
            while (*next==' ') next++;
            starts[count++] = s;
            *next = *next; // no-op, markers via indexes
            s = next;
        }
        p++;
    }
    if (*s && count<max) starts[count++] = s;
    return count;
}

// Helpers for sentence-level editing
// Count total sentences in text (0-indexed)
static int count_sentences(const char *text) {
    if (!text || text[0] == '\0') return 0;
    int count = 0; int in_sentence = 0;
    for (size_t i = 0; text[i]; i++) {
        if (text[i] == '.' || text[i] == '!' || text[i] == '?') {
            if (in_sentence) { count++; in_sentence = 0; }
            while (text[i+1] == ' ') i++;
        } else if (text[i] != ' ' && text[i] != '\n' && text[i] != '\r' && text[i] != '\t') {
            in_sentence = 1;
        }
    }
    // Count last sentence if no trailing delimiter
    if (in_sentence) count++;
    return count;
}

// Check if text ends with a sentence delimiter
static int has_trailing_delimiter(const char *text) {
    if (!text || text[0] == '\0') return 0;
    size_t len = strlen(text);
    // Skip trailing whitespace
    while (len > 0 && (text[len-1] == ' ' || text[len-1] == '\n' || text[len-1] == '\r' || text[len-1] == '\t')) {
        len--;
    }
    if (len == 0) return 0;
    char last = text[len-1];
    return (last == '.' || last == '!' || last == '?');
}


static void find_sentence_bounds(const char *text, int target_idx, int *start_out, int *end_out) {
    // target_idx is 0-based
    int count = 0; int s = 0; int i = 0; int start = -1, end = -1;
    size_t N = strlen(text);
    while (i < (int)N) {
        if (text[i]=='.' || text[i]=='!' || text[i]=='?') {
            if (count == target_idx) { start = s; end = i+1; break; }
            // advance to next sentence start
            count++; i++; while (i<(int)N && text[i]==' ') i++; s = i; continue;
        }
        i++;
    }
    if (start < 0) {
        if (count == target_idx) { start = s; end = (int)N; }
        else if (count+1 == target_idx) { start = (int)N; end = (int)N; }
    }
    if (start < 0) { start = (int)N; end = (int)N; }
    *start_out = start; *end_out = end;
}

static char *str_ndup(const char *src, size_t len) {
    char *p = (char*)malloc(len+1); if (!p) return NULL; memcpy(p, src, len); p[len]='\0'; return p;
}

// Count words in a sentence (strips trailing delimiter first)
static int count_words_in_sentence(const char *sentence_in) {
    size_t L = strlen(sentence_in);
    while (L>0 && (sentence_in[L-1]==' ' || sentence_in[L-1]=='\n' || sentence_in[L-1]=='\r' || sentence_in[L-1]=='\t')) L--;
    if (L>0 && (sentence_in[L-1]=='.' || sentence_in[L-1]=='!' || sentence_in[L-1]=='?')) L--;
    while (L>0 && sentence_in[L-1]==' ') L--;
    if (L == 0) return 0;
    char *base = str_ndup(sentence_in, L); if (!base) return 0;
    int count = 0;
    char *save=NULL; char *tok = strtok_r(base, " ", &save);
    while (tok) { count++; tok = strtok_r(NULL, " ", &save); }
    free(base);
    return count;
}

static char *edit_sentence_build(const char *sentence_in, int word_index, const char *content, int *error_out) {
    // Normalize input: strip trailing whitespace and capture any trailing delimiter
    *error_out = 0;
    size_t L = strlen(sentence_in);
    while (L>0 && (sentence_in[L-1]==' ' || sentence_in[L-1]=='\n' || sentence_in[L-1]=='\r' || sentence_in[L-1]=='\t')) L--;
    char delim = 0; if (L>0 && (sentence_in[L-1]=='.' || sentence_in[L-1]=='!' || sentence_in[L-1]=='?')) { delim = sentence_in[L-1]; L--; }
    while (L>0 && sentence_in[L-1]==' ') L--;
    char *base = str_ndup(sentence_in, L);
    if (!base) return NULL;
    
    // Count words to validate index
    int word_count = 0;
    char *temp = strdup(base); if (!temp) { free(base); return NULL; }
    char *save2=NULL; char *tok2 = strtok_r(temp, " ", &save2);
    while (tok2) { word_count++; tok2 = strtok_r(NULL, " ", &save2); }
    free(temp);
    
    // Validate word_index:
    // - Negative index: ERROR
    // - Index > word_count: ERROR (cannot insert beyond end)
    // - Index == word_count: OK (insert at end)
    // - Index 0 to word_count-1: OK (insert after that word)
    if (word_index < 0 || word_index > word_count) {
        *error_out = 1;
        free(base);
        return NULL;
    }
    
    // Special-case: prepend when word_index == 0
    if (word_index == 0) {
        size_t content_len = strlen(content);
        if (content_len == 0) {
            // no-op
            char *noop = str_ndup(sentence_in, L);
            if (delim) { size_t cap = L + 2; char *tmp = (char*)realloc(noop, cap); if (tmp) { noop = tmp; size_t ol=strlen(noop); noop[ol]=delim; noop[ol+1]='\0'; } }
            free(base);
            return noop;
        }
        size_t cap = content_len + (L>0?1:0) + L + 2;
        char *out = (char*)malloc(cap);
        if (!out) { free(base); return NULL; }
        out[0] = '\0';
        strcat(out, content);
        if (L > 0) strcat(out, " ");
        strncat(out, sentence_in, L);
        if (delim) { size_t ol = strlen(out); out[ol] = delim; out[ol+1] = '\0'; }
        free(base);
        return out;
    }

    // Tokenize by single spaces (existing text)
    char *save=NULL; char *tok = strtok_r(base, " ", &save);
    // Prepare output buffer
    size_t cap = L + strlen(content) + 64; char *out = (char*)malloc(cap); if (!out) { free(base); return NULL; }
    out[0]='\0';
    int idx = 0; int first = 1;
    
    // Special case: insert at beginning when word_index == 0
    if (word_index == 0) {
        size_t need = strlen(out) + strlen(content) + 1 + 1; if (need > cap) { cap = need + 64; char *tmp=(char*)realloc(out, cap); if (!tmp) { free(out); free(base); return NULL; } out = tmp; }
        strcat(out, content);
        if (tok) strcat(out, " ");
    }
    while (tok) {
        // Add current token
        size_t need = strlen(out) + strlen(tok) + 2; if (need > cap) { cap = need + 64; char *tmp=(char*)realloc(out, cap); if (!tmp) { free(out); free(base); return NULL; } out = tmp; }
        if (!first && out[strlen(out)-1] != ' ') strcat(out, " ");
        strcat(out, tok);
        idx++; // idx now equals the 1-based position of the word we just added
        // After the word at position 'word_index', insert content (insertion semantics)
        if (idx == word_index) {
            need = strlen(out) + 1 + strlen(content) + 1; if (need > cap) { cap = need + 64; char *tmp=(char*)realloc(out, cap); if (!tmp) { free(out); free(base); return NULL; } out = tmp; }
            strcat(out, " "); strcat(out, content);
        }
        first = 0; tok = strtok_r(NULL, " ", &save);
    }
    
    // Note: No need to check "word_index > idx" case anymore because
    // we validate word_index <= word_count upfront, so it's always valid
    
    if (delim) {
        size_t need = strlen(out) + 2; if (need > cap) { cap = need + 16; char *tmp=(char*)realloc(out, cap); if (!tmp) { free(out); free(base); return NULL; } out = tmp; }
        size_t ol = strlen(out); out[ol] = delim; out[ol+1] = '\0';
    }
    free(base); return out;
}

static void handle_write_request(int s, Message *req) {
    struct timeval tv_start, tv_end; gettimeofday(&tv_start, NULL);
    int sentence_idx = atoi(req->payload);
    
    // Validate sentence index before acquiring lock
    char *text=NULL; if (load_file(req->filename, &text)!=SUCCESS) { text=strdup(""); }
    if (!text) { 
        Message er; memset(&er,0,sizeof(er)); er.op_code=OP_WRITE_DENY; strcpy(er.command, OP_WRITE_DENY_S); 
        er.status_code=ERR_INTERNAL; strcpy(er.payload, "ERROR: Out of memory"); 
        send_message(s,&er); return; 
    }
    
    int total_sentences = count_sentences(text);
    int has_delim = has_trailing_delimiter(text);
    
    // Validation rules:
    // - Can write to existing sentences (0 to total_sentences-1)
    // - Can write to sentence 0 if file is empty
    // - Can ONLY write to sentence total_sentences if last sentence has delimiter
    //   (i.e., cannot append new sentence if last sentence incomplete)
    int max_allowed = total_sentences - 1;
    if (total_sentences == 0 || has_delim) {
        max_allowed = total_sentences; // Allow creating new sentence
    }
    
    if (sentence_idx < 0 || sentence_idx > max_allowed) {
        free(text);
        Message er; memset(&er,0,sizeof(er)); er.op_code=OP_WRITE_DENY; strcpy(er.command, OP_WRITE_DENY_S); 
        er.status_code=ERR_INVALID_INDEX; strcpy(er.payload, "ERROR: Sentence index out of range."); 
        send_message(s,&er); return;
    }
    
    // Acquire sentence lock with proper concurrency control
    pthread_mutex_lock(&locks_mutex);
    SentenceLock *slot = find_lock_slot_nolock(req->filename, sentence_idx);
    Message resp; memset(&resp, 0, sizeof(resp));
    resp.op_code = OP_WRITE_REQUEST; strcpy(resp.command, OP_WRITE_REQUEST_S);
    if (!slot) {
        pthread_mutex_unlock(&locks_mutex);
        free(text); resp.status_code = ERR_INTERNAL; strcpy(resp.payload, "No lock slots"); send_message(s, &resp); return; }
    // log attempt to acquire lock
    {
        char lbuf[256]; snprintf(lbuf, sizeof(lbuf), "LOCK_ATTEMPT file=%s idx=%d user=%s", req->filename, sentence_idx, req->username);
        log_event_detailed("logs/ss.log", "SS", "LOCK", req->username, "", 0, lbuf, 1);
    }
    if (slot->locked && strcmp(slot->locked_by, req->username)!=0) {
        pthread_mutex_unlock(&locks_mutex);
        free(text);
        resp.status_code = ERR_LOCKED; strcpy(resp.payload, "Locked by another user"); send_message(s, &resp); return;
    }
    // Acquire/record lock (permit re-entrant by same user)
    strncpy(slot->filename, req->filename, sizeof(slot->filename)-1);
    slot->sentence_idx = sentence_idx; slot->locked = 1; strncpy(slot->locked_by, req->username, sizeof(slot->locked_by)-1);
    // Store request id for correlation
    if (req->req_id[0]) strncpy(slot->req_id, req->req_id, sizeof(slot->req_id)-1);
    pthread_mutex_unlock(&locks_mutex);
    resp.status_code = SUCCESS; strcpy(resp.payload, "LOCKED"); send_message(s, &resp);
    char logbuf[128]; snprintf(logbuf, sizeof(logbuf), "LOCK_ACQUIRED file=%s idx=%d by=%s", req->filename, sentence_idx, req->username);
    log_event_detailed("logs/ss.log", "SS", "LOCK_ACQUIRED", req->username, "", 0, logbuf, 1);
    // Receive edits on same connection: sentence-level editing in-memory
    // Create undo backup only if there is an existing non-empty version
    if (text[0] != '\0') { save_undo(req->filename, text); }
    while (1) {
        Message edit; int n = receive_message(s, &edit); if (n<=0) break;
        if (edit.op_code == OP_WRITE_END || strcmp(edit.command, OP_WRITE_END_S)==0) {
            // STOP received from client signalling end of edits
            log_event_detailed("logs/ss.log", "SS", "STOP_RECEIVED", req->username, "", 0, "STOP (end of edits) received", 1);
            break;
        }
        if (edit.op_code == OP_WRITE_EDIT || strcmp(edit.command, OP_WRITE_EDIT_S)==0) {
            size_t len = strnlen(edit.payload, sizeof(edit.payload));
            while (len>0 && (edit.payload[len-1]=='\n' || edit.payload[len-1]=='\r')) { edit.payload[--len]='\0'; }
            if (len>0) {
                int widx = 0; char content[1800]={0};
                if (sscanf(edit.payload, "%d %[^\n]", &widx, content) < 1) {
                    // Missing word index, send an error back
                    Message err_msg; memset(&err_msg,0,sizeof(err_msg));
                    err_msg.op_code=OP_WRITE_DENY; strcpy(err_msg.command, OP_WRITE_DENY_S);
                    err_msg.status_code=ERR_BAD_REQUEST;
                    strcpy(err_msg.payload, "ERROR: Provide word index before content. Example: '3 your text'");
                    send_message(s, &err_msg);
                    continue;
                }
                // Find current sentence bounds each time (reflecting prior edits)
                int s_pos=0, e_pos=0; find_sentence_bounds(text, sentence_idx, &s_pos, &e_pos);
                // Extract current sentence substring
                char *sent = str_ndup(text + s_pos, (size_t)(e_pos - s_pos)); if (!sent) continue;
                // Build new sentence with validation
                const char *cont = (content[0] ? content : "");
                int error = 0;
                char *edited = edit_sentence_build(sent, widx, cont, &error);
        if (!edited || error) { 
                    free(sent); 
                    if (error) {
                        // Send error message for invalid word index
                        Message err_msg; memset(&err_msg,0,sizeof(err_msg)); 
                        err_msg.op_code=OP_WRITE_DENY; strcpy(err_msg.command, OP_WRITE_DENY_S); 
                        err_msg.status_code=ERR_INVALID_INDEX; 
                        strcpy(err_msg.payload, "ERROR: Word index out of range.");
                        send_message(s, &err_msg);
                        free(text);
            pthread_mutex_lock(&locks_mutex);
            slot->locked = 0;
            pthread_mutex_unlock(&locks_mutex);
                        return;
                    }
                    continue; 
                }
                // Reconstruct new text
                size_t before_len = (size_t)s_pos; size_t after_len = strlen(text) - (size_t)e_pos;
                size_t new_len = before_len + strlen(edited) + after_len;
                char *new_text = (char*)malloc(new_len + 1);
                if (new_text) {
                    memcpy(new_text, text, before_len);
                    memcpy(new_text + before_len, edited, strlen(edited));
                    memcpy(new_text + before_len + strlen(edited), text + e_pos, after_len);
                    new_text[new_len] = '\0';
                    free(text); text = new_text;
                    // Log edit details (sanitized / truncated)
                    char eds[256]; snprintf(eds, sizeof(eds), "EDIT file=%s idx=%d user=%s word_idx=%d len=%zu", req->filename, sentence_idx, req->username, widx, strlen(content));
                    log_event_detailed("logs/ss.log", "SS", "EDIT", req->username, "", 0, eds, 1);
                }
                // Defer persistence until ETIRW: do not write intermediary edits to disk.
                // This ensures concurrent READ/STREAM see original content until commit.
                free(sent); free(edited);
            }
        }
    }
    // Rebase commit onto latest file contents to avoid clobbering other sentences
    // Extract final edited sentence from our working text
    int final_s=0, final_e=0; find_sentence_bounds(text, sentence_idx, &final_s, &final_e);
    char *final_sentence = str_ndup(text + final_s, (size_t)(final_e - final_s));
    free(text);

    char *latest=NULL; if (load_file(req->filename, &latest)!=SUCCESS) latest=strdup("");
    if (!latest) latest = strdup("");
    int ls=0, le=0; find_sentence_bounds(latest, sentence_idx, &ls, &le);
    size_t before_len2 = (size_t)ls; size_t after_len2 = strlen(latest) - (size_t)le;
    size_t new_len2 = before_len2 + (final_sentence?strlen(final_sentence):0) + after_len2;
    char *rebased = (char*)malloc(new_len2 + 1);
    if (rebased) {
        memcpy(rebased, latest, before_len2);
        if (final_sentence) memcpy(rebased + before_len2, final_sentence, strlen(final_sentence));
        memcpy(rebased + before_len2 + (final_sentence?strlen(final_sentence):0), latest + le, after_len2);
        rebased[new_len2] = '\0';
        save_file(req->filename, rebased);
        free(rebased);
    } else {
        // Fallback: save latest untouched to avoid data loss
        save_file(req->filename, latest);
    }
    free(latest);
    if (final_sentence) free(final_sentence);
    // refresh meta counts after write
    update_meta_counts(req->filename);
    
    // Read updated counts and version for logging
    int words=0, chars=0; 
    compute_counts(req->filename, &words, &chars);
    int version = read_version(req->filename);
    
    // Log ETIRW (end-to-intermediate->real write) and COMMIT/UNLOCK explicitly
    char etirwbuf[128]; 
    snprintf(etirwbuf, sizeof(etirwbuf), "ETIRW owner=%s", req->username);
    log_event_detailed("logs/ss.log", "SS", "ETIRW", req->username, "", 0, etirwbuf, 1);
    
    char commitbuf[256];
    snprintf(commitbuf, sizeof(commitbuf), "COMMIT file=%s ver=%d bytes=%d words=%d chars=%d code=OK", 
             req->filename, version, chars, words, chars);
    log_event_detailed("logs/ss.log", "SS", "COMMIT", req->username, "", 0, commitbuf, 1);
    
    char unlockbuf[128]; 
    snprintf(unlockbuf, sizeof(unlockbuf), "UNLOCK file=%s sentence=%d owner=%s", 
             req->filename, sentence_idx, req->username);
    log_event_detailed("logs/ss.log", "SS", "UNLOCK", req->username, "", 0, unlockbuf, 1);
    pthread_mutex_lock(&locks_mutex);
    slot->locked = 0;
    pthread_mutex_unlock(&locks_mutex);
    Message ack; memset(&ack,0,sizeof(ack)); ack.op_code=OP_WRITE_ACK; strcpy(ack.command, OP_WRITE_ACK_S); ack.status_code=SUCCESS; strcpy(ack.payload, "WRITE OK");
    // Indicate STOP sent and then send ACK
    log_event_detailed("logs/ss.log", "SS", "STOP_SENT", req->username, "", 0, "STOP/END acknowledgement sent to client", 1);
    send_message(s, &ack);
    gettimeofday(&tv_end, NULL);
    double elapsed = (tv_end.tv_sec - tv_start.tv_sec) + (tv_end.tv_usec - tv_start.tv_usec)/1000000.0;
    char donebuf[128]; snprintf(donebuf, sizeof(donebuf), "[WRITE] %s took %.2fs", req->filename, elapsed);
    log_event("logs/ss.log", "SS", donebuf);

    // Prepare a WRITE_NOTIFY message to inform NM of commit details (ACK path)
    {
        int words = 0, chars = 0; 
        compute_counts(req->filename, &words, &chars);
        int ver = read_version(req->filename);
        char payload[512];
        // include req_id if present to correlate
        const char *rid = slot->req_id[0] ? slot->req_id : req->req_id;
        snprintf(payload, sizeof(payload), "req_id=%s,file=%s,ss_id=%d,ver=%d,words=%d,chars=%d,elapsed=%.3f", 
                 rid ? rid : "", req->filename, ss_id_global, ver, words, chars, elapsed);
        Message notify; memset(&notify,0,sizeof(notify)); notify.op_code = OP_WRITE_NOTIFY; strcpy(notify.command, OP_WRITE_NOTIFY_S);
        strncpy(notify.filename, req->filename, sizeof(notify.filename)-1);
        strncpy(notify.username, ss_name, sizeof(notify.username)-1);
        strncpy(notify.payload, payload, sizeof(notify.payload)-1);
        if (rid && rid[0]) strncpy(notify.req_id, rid, sizeof(notify.req_id)-1);
        // Send to NM (best-effort)
        if (nm_port_global > 0) {
            int nmsock = connect_to_server(nm_ip_global, nm_port_global);
            if (nmsock >= 0) {
                send_message(nmsock, &notify);
                // Optionally read a response (not required)
                Message r; receive_message(nmsock, &r);
                close(nmsock);
                char lmsg[256]; snprintf(lmsg, sizeof(lmsg), "WRITE_NOTIFY sent to NM for %s req_id=%s", req->filename, rid ? rid : "");
                log_event("logs/ss.log", "SS", lmsg);
            } else {
                log_event("logs/ss.log", "SS", "WRITE_NOTIFY failed to connect to NM");
            }
        }
    }
}
static int ss_handle_read(const char *fname, int s, const char *username, const char *client_ip, int client_port) {
    char path[512];
    snprintf(path, sizeof(path), "data/%s", fname);
    FILE *f = fopen(path, "r");
    if (!f) {
        Message err; memset(&err, 0, sizeof(err));
        strcpy(err.command, OP_READ_S);
        err.op_code = OP_READ;
        strncpy(err.filename, fname, sizeof(err.filename)-1);
        err.status_code = ERR_FILE_NOT_FOUND;
        strcpy(err.payload, "File not found");
        send_message(s, &err);
        char log_buf[128];
        snprintf(log_buf, sizeof(log_buf), "file=%s result=NOT_FOUND", fname);
        log_event_detailed("logs/ss.log", "SS", "READ", username, client_ip, client_port, log_buf, 1);
        return ERR_FILE_NOT_FOUND;
    }

    // Stream the file in chunks so large files are supported
    size_t total = 0;
    char buf[1500];
    while (1) {
        size_t n = fread(buf, 1, sizeof(buf)-1, f);
        if (n == 0) break;
        buf[n] = '\0';
        Message part; memset(&part, 0, sizeof(part));
        part.op_code = OP_STREAM; strcpy(part.command, OP_STREAM_S);
        part.status_code = SUCCESS;
        strncpy(part.filename, fname, sizeof(part.filename)-1);
        strncpy(part.payload, buf, sizeof(part.payload)-1);
        if (send_message(s, &part) <= 0) { fclose(f); return ERR_INTERNAL; }
        total += n;
    }
    fclose(f);
    Message end; memset(&end, 0, sizeof(end));
    end.op_code = OP_STREAM_END; strcpy(end.command, OP_STREAM_END_S);
    end.status_code = SUCCESS;
    strncpy(end.filename, fname, sizeof(end.filename)-1);
    send_message(s, &end);

    char log_buf[128];
    snprintf(log_buf, sizeof(log_buf), "file=%s bytes=%zu result=OK", fname, total);
    log_event_detailed("logs/ss.log", "SS", "READ", username, client_ip, client_port, log_buf, 1);
    return SUCCESS;
}

static int ss_handle_stream(const char *fname, int s, const char *username, const char *client_ip, int client_port) {
    char path[512];
    snprintf(path, sizeof(path), "data/%s", fname);
    FILE *f = fopen(path, "r");
    if (!f) {
        Message resp; memset(&resp, 0, sizeof(resp));
        strcpy(resp.command, OP_STREAM_S);
        resp.op_code = OP_STREAM;
        resp.status_code = ERR_FILE_NOT_FOUND;
        strcpy(resp.payload, "File not found");
        send_message(s, &resp);
        
        char log_buf[128];
        snprintf(log_buf, sizeof(log_buf), "file=%s result=NOT_FOUND", fname);
        log_event_detailed("logs/ss.log", "SS", "STREAM", username, client_ip, client_port, log_buf, 1);
        return ERR_FILE_NOT_FOUND;
    }
    
    char filebuf[4096]; 
    size_t n = fread(filebuf, 1, sizeof(filebuf)-1, f); 
    fclose(f);
    filebuf[n] = '\0';
    
    char *saveptr = NULL; 
    char *tok = strtok_r(filebuf, " \t\n", &saveptr);
    int word_count = 0;
    while (tok) {
        Message part; memset(&part, 0, sizeof(part));
        strcpy(part.command, OP_STREAM_S);
        part.op_code = OP_STREAM;
        part.status_code = SUCCESS;
        strncpy(part.payload, tok, sizeof(part.payload)-1);
        if (send_message(s, &part) <= 0) break;
        usleep(100000);
        word_count++;
        tok = strtok_r(NULL, " \t\n", &saveptr);
    }
    
    Message end; memset(&end, 0, sizeof(end));
    strcpy(end.command, OP_STREAM_END_S);
    end.op_code = OP_STREAM_END;
    end.status_code = SUCCESS;
    send_message(s, &end);
    
    char log_buf[128];
    snprintf(log_buf, sizeof(log_buf), "file=%s words=%d result=OK", fname, word_count);
    log_event_detailed("logs/ss.log", "SS", "STREAM", username, client_ip, client_port, log_buf, 1);
    return SUCCESS;
}

// Helper: find any available port dynamically
static int find_free_port() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = 0;  // system assigns a free port
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    socklen_t len = sizeof(addr);
    if (getsockname(sock, (struct sockaddr*)&addr, &len) == -1) {
        close(sock);
        return -1;
    }
    int port = ntohs(addr.sin_port);
    close(sock);
    return port;
}

typedef struct {
    int sock;
    struct sockaddr_in addr;
} client_ctx_t;

static void *handle_client_thread(void *arg) {
    client_ctx_t *ctx = (client_ctx_t*)arg;
    int s = ctx->sock; 
    struct sockaddr_in addr = ctx->addr; 
    free(ctx);
    
    Message req; memset(&req, 0, sizeof(req));
    if (receive_message(s, &req) <= 0) { 
        close(s); 
        return NULL; 
    }
    
    // Extract client info
    char client_ip[32];
    inet_ntop(AF_INET, &addr.sin_addr, client_ip, sizeof(client_ip));
    int client_port = ntohs(addr.sin_port);
    
    // Single log entry per request
    char log_buf[256];
    snprintf(log_buf, sizeof(log_buf), "op=%s file=%s", req.command, req.filename);
    log_event_detailed("logs/ss.log", "SS", "REQ", req.username, client_ip, client_port, log_buf, 1);

    if (strcmp(req.command, OP_CREATE) == 0) {
        int rc = ss_create_file(req.filename, req.username);
        req.status_code = rc;
        if (rc == SUCCESS) {
            strcpy(req.payload, "SS CREATE OK");
        } else if (rc == ERR_BAD_REQUEST) {
            strcpy(req.payload, "File already exists");
        } else if (rc == ERR_INTERNAL) {
            strcpy(req.payload, "IO error while creating file");
        } else {
            strcpy(req.payload, "SS CREATE ERR");
        }
        send_message(s, &req);
        
        char log_buf[128];
        snprintf(log_buf, sizeof(log_buf), "file=%s result=%s", 
                 req.filename, rc == SUCCESS ? "OK" : "FAILED");
        log_event_detailed("logs/ss.log", "SS", "CREATE", req.username, client_ip, client_port, log_buf, 1);
    } else if (strcmp(req.command, OP_READ_S) == 0 || req.op_code == OP_READ) {
        ss_handle_read(req.filename, s, req.username, client_ip, client_port);
    } else if (strcmp(req.command, OP_STREAM_S) == 0 || req.op_code == OP_STREAM) {
        ss_handle_stream(req.filename, s, req.username, client_ip, client_port);
    } else if (strcmp(req.command, OP_WRITE_REQUEST_S) == 0 || req.op_code == OP_WRITE_REQUEST) {
        handle_write_request(s, &req);
    } else if (strcmp(req.command, OP_UNDO_S) == 0 || req.op_code == OP_UNDO) {
        char main_path[512], undo_path[512];
        snprintf(main_path, sizeof(main_path), "data/%s", req.filename);
        snprintf(undo_path, sizeof(undo_path), "data/.undo_%s", req.filename);
        
        Message resp; memset(&resp, 0, sizeof(resp));
        strcpy(resp.command, OP_UNDO_S); 
        resp.op_code = OP_UNDO;
        
        if (access(undo_path, F_OK) != 0) {
            resp.status_code = ERR_BAD_REQUEST; 
            strcpy(resp.payload, "UNDO ERR: No previous version");
            send_message(s, &resp);
            
            char log_buf[128]; 
            snprintf(log_buf, sizeof(log_buf), "file=%s result=NO_BACKUP", req.filename);
            log_event_detailed("logs/ss.log", "SS", "UNDO", req.username, client_ip, client_port, log_buf, 1);
        } else {
            FILE *undo = fopen(undo_path, "r");
            FILE *mainf = fopen(main_path, "w");
            
            if (undo && mainf) {
                char buf[1024]; size_t n;
                while ((n = fread(buf, 1, sizeof(buf), undo)) > 0) fwrite(buf, 1, n, mainf);
                fclose(undo); fclose(mainf);
                remove(undo_path);
                update_meta_counts(req.filename);
                resp.status_code = SUCCESS; 
                strcpy(resp.payload, "UNDO OK");
                
                char log_buf[128]; 
                snprintf(log_buf, sizeof(log_buf), "file=%s result=OK", req.filename);
                log_event_detailed("logs/ss.log", "SS", "UNDO", req.username, client_ip, client_port, log_buf, 1);
            } else {
                if (undo) fclose(undo); 
                if (mainf) fclose(mainf);
                resp.status_code = ERR_BAD_REQUEST; 
                strcpy(resp.payload, "UNDO ERR: No previous version");
                
                char log_buf[128]; 
                snprintf(log_buf, sizeof(log_buf), "file=%s result=FILE_ERROR", req.filename);
                log_event_detailed("logs/ss.log", "SS", "UNDO", req.username, client_ip, client_port, log_buf, 1);
            }
            send_message(s, &resp);
        }
    } else if (strcmp(req.command, OP_DELETE_S) == 0 || req.op_code == OP_DELETE) {
        char main_path[512], meta_path[512], undo_path[512];
        snprintf(main_path, sizeof(main_path), "data/%s", req.filename);
        snprintf(meta_path, sizeof(meta_path), "data/%s.meta", req.filename);
        snprintf(undo_path, sizeof(undo_path), "data/.undo_%s", req.filename);
        
        int ok1 = (remove(main_path) == 0);
        int ok2 = (remove(meta_path) == 0);
        remove(undo_path);
        
        Message resp; memset(&resp, 0, sizeof(resp));
        strcpy(resp.command, OP_DELETE_S); 
        resp.op_code = OP_DELETE;
        
        if (ok1 || ok2) {
            resp.status_code = SUCCESS; 
            strcpy(resp.payload, "DELETE OK");
            
            char log_buf[128]; 
            snprintf(log_buf, sizeof(log_buf), "file=%s result=OK", req.filename);
            log_event_detailed("logs/ss.log", "SS", "DELETE", req.username, client_ip, client_port, log_buf, 1);
        } else {
            resp.status_code = ERR_FILE_NOT_FOUND; 
            strcpy(resp.payload, "DELETE ERR: File not found");
            
            char log_buf[128]; 
            snprintf(log_buf, sizeof(log_buf), "file=%s result=FAILED reason=not_found", req.filename);
            log_event_detailed("logs/ss.log", "SS", "DELETE", req.username, client_ip, client_port, log_buf, 1);
        }
        send_message(s, &resp);
    } else if (strcmp(req.command, OP_CHECKPOINT_S) == 0) {
        // payload = tag
        if (!req.payload[0]) { req.status_code=ERR_BAD_REQUEST; strcpy(req.payload,"Tag required"); send_message(s,&req); }
        else {
            char src[512]; snprintf(src,sizeof(src),"data/%s", req.filename);
            FILE *f = fopen(src,"r"); if(!f){ req.status_code=ERR_FILE_NOT_FOUND; strcpy(req.payload,"File not found"); send_message(s,&req); }
            else {
                char cpdir[512]; snprintf(cpdir,sizeof(cpdir),"data/.cp_%s", req.filename);
                mkdir(cpdir,0755);
                char dst[512]; snprintf(dst,sizeof(dst),"%s/%s", cpdir, req.payload);
                FILE *d=fopen(dst,"w"); if(!d){ fclose(f); req.status_code=ERR_INTERNAL; strcpy(req.payload,"Checkpoint create failed"); send_message(s,&req); }
                else { char buf[1024]; size_t n; while((n=fread(buf,1,sizeof(buf),f))>0) fwrite(buf,1,n,d); fclose(f); fclose(d); req.status_code=SUCCESS; strcpy(req.payload,"CHECKPOINT OK"); send_message(s,&req); }
            }
        }
    } else if (strcmp(req.command, OP_VIEWCHECKPOINT_S) == 0) {
        if (!req.payload[0]) { req.status_code=ERR_BAD_REQUEST; strcpy(req.payload,"Tag required"); send_message(s,&req); }
        else {
            char path[512]; snprintf(path,sizeof(path),"data/.cp_%s/%s", req.filename, req.payload);
            FILE *f=fopen(path,"r"); if(!f){ req.status_code=ERR_FILE_NOT_FOUND; strcpy(req.payload,"Checkpoint not found"); send_message(s,&req); }
            else { char out[1024]; size_t n=fread(out,1,sizeof(out)-1,f); out[n]='\0'; fclose(f); req.status_code=SUCCESS; strncpy(req.payload,out,sizeof(req.payload)-1); send_message(s,&req); }
        }
    } else if (strcmp(req.command, OP_REVERT_S) == 0) {
        if (!req.payload[0]) { req.status_code=ERR_BAD_REQUEST; strcpy(req.payload,"Tag required"); send_message(s,&req); }
        else {
            char cp[512]; snprintf(cp,sizeof(cp),"data/.cp_%s/%s", req.filename, req.payload);
            FILE *f=fopen(cp,"r"); if(!f){ req.status_code=ERR_FILE_NOT_FOUND; strcpy(req.payload,"Checkpoint not found"); send_message(s,&req); }
            else {
                char dst[512]; snprintf(dst,sizeof(dst),"data/%s", req.filename);
                FILE *d=fopen(dst,"w"); if(!d){ fclose(f); req.status_code=ERR_INTERNAL; strcpy(req.payload,"Revert failed"); send_message(s,&req); }
                else { char buf[1024]; size_t n; while((n=fread(buf,1,sizeof(buf),f))>0) fwrite(buf,1,n,d); fclose(f); fclose(d); update_meta_counts(req.filename); req.status_code=SUCCESS; strcpy(req.payload,"REVERT OK"); send_message(s,&req); }
            }
        }
    } else if (strcmp(req.command, OP_LISTCHECKPOINTS_S) == 0) {
        char dir[512]; snprintf(dir,sizeof(dir),"data/.cp_%s", req.filename);
        DIR *d=opendir(dir); if(!d){ req.status_code=SUCCESS; strcpy(req.payload,""); send_message(s,&req); }
        else { req.payload[0]='\0'; struct dirent *de; size_t off=0; while((de=readdir(d))){ if(de->d_name[0]=='.') continue; off += snprintf(req.payload+off,sizeof(req.payload)-off,"%s\n", de->d_name); if(off>=sizeof(req.payload)) break; } closedir(d); req.status_code=SUCCESS; send_message(s,&req); }
    } else if (strcmp(req.command, OP_REPL_WRITE_S) == 0) {
        handle_repl_write(s, &req);
    } else if (strcmp(req.command, OP_PING_S) == 0) {
        req.status_code = SUCCESS; strcpy(req.payload, "PONG"); send_message(s,&req);
    } else {
        req.status_code = ERR_BAD_REQUEST;
        strcpy(req.payload, "Unknown SS op");
        send_message(s, &req);
    }
    close(s);
    return NULL;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    // CLI: ./bin/ss <NM_IP> <NM_PORT> <CLIENT_PORT> [ADVERTISE_IP]
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <NM_IP> <NM_PORT> <CLIENT_PORT> [ADVERTISE_IP]\n", argv[0]);
        fprintf(stderr, "Example: %s 127.0.0.1 5050 10001 192.168.1.50\n", argv[0]);
        return 1;
    }
    const char *nm_ip = argv[1];
    int nm_port = atoi(argv[2]);
    int client_port = atoi(argv[3]);
    const char *adv_ip = (argc >= 5 ? argv[4] : "");
    if (nm_port <= 0 || nm_port > 65535 || client_port <= 0 || client_port > 65535) {
        fprintf(stderr, "Invalid port(s).\n");
        return 1;
    }
    
    printf("Storage Server starting...\n");
    printf("→ NM connection: %s:%d\n", nm_ip, nm_port);
    printf("→ Client/SS port: %d\n", client_port);
    
    // Ensure data directory exists
    struct stat st = {0};
    if (stat("data", &st) == -1) {
        mkdir("data", 0755);
    }
    
    // Scan existing files before registering
    char file_list[2048] = "";
    DIR *d = opendir("data");
    if (d) {
        struct dirent *de;
        int first = 1;
        while ((de = readdir(d)) != NULL) {
            // Skip hidden files and .meta files
            if (de->d_name[0] != '.' && strstr(de->d_name, ".meta") == NULL) {
                if (!first) strcat(file_list, ",");
                strncat(file_list, de->d_name, sizeof(file_list) - strlen(file_list) - 1);
                first = 0;
            }
        }
        closedir(d);
    }
    
    printf("Connecting to Name Server at %s:%d...\n", nm_ip, nm_port);
    // Store NM connection info for later notifications
    strncpy(nm_ip_global, nm_ip, sizeof(nm_ip_global)-1);
    nm_port_global = nm_port;

    int nmsock = connect_to_server((char*)nm_ip, nm_port);
    if (nmsock < 0) {
        fprintf(stderr, "Failed to connect to Name Server at %s:%d\n", nm_ip, nm_port);
        exit(1);
    }

    Message msg;
    memset(&msg, 0, sizeof(msg));
    strcpy(msg.command, OP_REGISTER_SS);
    // Use a temporary name for registration; will be updated based on ss_id from NM
    strncpy(msg.username, "SS_TEMP", sizeof(msg.username)-1);
    // Advertise the client_port; include advertise IP if provided, otherwise let NM infer from peer address.
    if (adv_ip && adv_ip[0] != '\0') {
        snprintf(msg.payload, sizeof(msg.payload),
                 "ip=%s,nm_port=%d,client_port=%d,files=%s",
                 adv_ip, nm_port, client_port, file_list);
    } else {
        snprintf(msg.payload, sizeof(msg.payload),
                 "nm_port=%d,client_port=%d,files=%s",
                 nm_port, client_port, file_list);
    }
    send_message(nmsock, &msg);
    receive_message(nmsock, &msg);
    
    if (msg.status_code == SUCCESS) {
        // Parse ss_id from response payload like "Registered SS (ss_id=0)"
        int assigned_ss_id = 0;
        char *ss_id_str = strstr(msg.payload, "ss_id=");
        if (ss_id_str) {
            assigned_ss_id = atoi(ss_id_str + 6);
        }
        // Update SS name and global ID based on assigned ss_id
        ss_id_global = assigned_ss_id;
        snprintf(ss_name, sizeof(ss_name), "SS%d", assigned_ss_id);
        printf("✓ Registration successful: %s (assigned name: %s)\n", msg.payload, ss_name);
    } else {
        printf("✗ Registration failed: %s\n", msg.payload);
        close(nmsock);
        exit(1);
    }
    
    log_event("logs/ss.log", "SS", "Registered successfully with NM");
    close(nmsock);

    printf("Starting server on port %d...\n", client_port);
    // Act as a server for NM commands (simple single-request loop on client_port)
    int srv = create_server_socket(client_port);
    while (1) {
        struct sockaddr_in addr; socklen_t alen = sizeof(addr);
        int s = accept(srv, (struct sockaddr*)&addr, &alen);
        if (s < 0) continue;
        client_ctx_t *ctx = (client_ctx_t*)malloc(sizeof(client_ctx_t));
        if (!ctx) { close(s); continue; }
        ctx->sock = s; ctx->addr = addr;
        pthread_t tid; pthread_create(&tid, NULL, handle_client_thread, ctx);
        pthread_detach(tid);
    }

    return 0;
}
