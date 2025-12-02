// Minimal in-memory registry for Part 2: CREATE/VIEW/INFO
#define _XOPEN_SOURCE
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>

#include "../include/protocol.h"
#include "../include/error_codes.h"
#include "../include/constants.h"
#include "../include/uthash.h"

// External helpers from nm_main.c used for recovery and health
int nm_server_is_alive(int ss_id);
void replicate_file_async(const char *filename);
int nm_get_ss_ip_port(int ss_id, char *ip, size_t iplen, int *port_out);
int nm_get_ss_name(int ss_id, char *name, size_t namelen);
void nm_update_ss_name(int ss_id, const char *new_name);

// Logger function declarations
void log_event(const char *filename, const char *component, const char *event);
void log_event_detailed(const char *filename, const char *component, 
                       const char *operation, const char *username,
                       const char *ip, int port, const char *details,
                       int display_terminal);

#define MAX_FILES 1024
#define MAX_SRV 64
#define MAX_CLIENTS 256
#define CACHE_SIZE 100

typedef struct {
	char filename[MAX_FILENAME_LEN];
	char owner[MAX_USERNAME_LEN];
	int ss_id; // index into storage servers list
	int replica_ss_id; // secondary replica server id (-1 if none)
	int words;
	int chars;
	time_t created;
	time_t modified;
	time_t last_access;
    int version;
	char last_access_by[MAX_USERNAME_LEN];
} FileEntry;

typedef struct {
	char name[64]; // e.g., "SS1"
	char ip[32];
	int client_port; // future use
	int alive; // 1 if last contact succeeded
	time_t last_seen; // timestamp of last successful interaction
} StorageServer;

static FileEntry files[MAX_FILES];
static int file_count = 0;

static StorageServer servers[MAX_SRV];
static int server_count = 0;
static int rr_index = 0;

// Access request tracking
#define MAX_ACCESS_REQUESTS 1024
typedef struct { char filename[MAX_FILENAME_LEN]; char requester[MAX_USERNAME_LEN]; char type; /* 'R' or 'W' */ int active; } AccessRequest;
static AccessRequest access_requests[MAX_ACCESS_REQUESTS];

// Forward prototypes for functions referenced in access request helpers
// (defined later in this file). Added to avoid implicit declaration errors.
static int find_file(const char *fname);
static void load_acl(const char *fname, char *owner, size_t olen, char *readers, size_t rlen, char *writers, size_t wlen);
int nm_check_read(const char *fname, const char *user);
int nm_check_write(const char *fname, const char *user);
int nm_addaccess(const char *fname, const char *requestor, const char *mode, const char *target_user);
static int find_next_alive_ss(int start_ss, int exclude1, int exclude2);
int nm_server_is_alive(int ss_id);

static int find_request(const char *fname, const char *user, char type) {
	for (int i=0;i<MAX_ACCESS_REQUESTS;i++) if (access_requests[i].active && access_requests[i].type==type && strcmp(access_requests[i].filename,fname)==0 && strcmp(access_requests[i].requester,user)==0) return i; return -1;
}

int nm_request_access(const char *fname, const char *user, char type) {
	if (type!='R' && type!='W') return ERR_BAD_REQUEST;
	// Reject if file does not exist in registry
	if (find_file(fname) < 0) return ERR_FILE_NOT_FOUND;
	// cannot request if already has that access
	if ((type=='R' && nm_check_read(fname,user)==SUCCESS) || (type=='W' && nm_check_write(fname,user)==SUCCESS)) return ERR_BAD_REQUEST;
	if (find_request(fname,user,type)>=0) return SUCCESS; // idempotent
	for (int i=0;i<MAX_ACCESS_REQUESTS;i++) if (!access_requests[i].active) {
		access_requests[i].active=1; strncpy(access_requests[i].filename,fname,sizeof(access_requests[i].filename)-1); strncpy(access_requests[i].requester,user,sizeof(access_requests[i].requester)-1); access_requests[i].type=type; return SUCCESS;
	}
	return ERR_INTERNAL;
}

int nm_list_requests(const char *owner, char *out, size_t outlen) {
	size_t off=0; out[0]='\0';
	for (int i=0;i<MAX_ACCESS_REQUESTS;i++) if (access_requests[i].active) {
	// Prefer registry owner; fall back to ACL owner if registry missing
	int idx = find_file(access_requests[i].filename); if (idx<0) continue;
	const char *reg_owner = files[idx].owner;
	char acl_owner[64]="", rs[8]="", ws[8]="";
	load_acl(access_requests[i].filename, acl_owner, sizeof(acl_owner), rs, sizeof(rs), ws, sizeof(ws));
	const char *effective_owner = (acl_owner[0] ? acl_owner : reg_owner);
	if (strcmp(effective_owner, owner)!=0) continue;
		off += snprintf(out+off, outlen-off, "%s %c %s\n", access_requests[i].filename, access_requests[i].type, access_requests[i].requester);
		if (off>=outlen) break;
	}
	return SUCCESS;
}

int nm_approve_request(const char *owner, const char *fname, const char *requester, char type) {
	int idx = find_file(fname); if (idx<0) return ERR_FILE_NOT_FOUND;
	char fowner[64], rs[512], ws[512]; fowner[0]=rs[0]=ws[0]='\0';
	load_acl(fname, fowner, sizeof(fowner), rs, sizeof(rs), ws, sizeof(ws));
	if (strcmp(fowner, owner)!=0) return ERR_PERMISSION_DENIED;
	int ridx = find_request(fname, requester, type); if (ridx<0) return ERR_BAD_REQUEST;
	// grant
	if (type=='R') nm_addaccess(fname, owner, "R", requester); else nm_addaccess(fname, owner, "W", requester);
	access_requests[ridx].active=0; return SUCCESS;
}

int nm_deny_request(const char *owner, const char *fname, const char *requester, char type) {
	int idx = find_file(fname); if (idx<0) return ERR_FILE_NOT_FOUND;
	char fowner[64], rs[8], ws[8]; fowner[0]=rs[0]=ws[0]='\0';
	load_acl(fname, fowner, sizeof(fowner), rs, sizeof(rs), ws, sizeof(ws));
	if (strcmp(fowner, owner)!=0) return ERR_PERMISSION_DENIED;
	int ridx = find_request(fname, requester, type); if (ridx<0) return ERR_BAD_REQUEST;
	access_requests[ridx].active=0; return SUCCESS;
}

typedef struct { char username[32]; char ip[32]; int port; } ClientInfo;
static ClientInfo clients[MAX_CLIENTS];
static int client_count = 0;

// Function to remove a client from the tracking list
void nm_remove_client(const char *user) {
    int idx = -1;
    for (int i = 0; i < client_count; i++) {
        if (strcmp(clients[i].username, user) == 0) {
            idx = i;
            break;
        }
    }
    
    if (idx >= 0) {
        // Shift remaining clients down to fill the gap
        for (int i = idx; i < client_count - 1; i++) {
            clients[i] = clients[i + 1];
        }
        client_count--;
    }
}

// Hash map for O(1) file lookup
typedef struct {
	char filename[MAX_FILENAME_LEN];
	int file_index;
	UT_hash_handle hh;
} FileHashEntry;

// Ensure parent directories exist for a path (mkdir -p style)
static void ensure_dirs_for_path(const char *path) {
	char tmp[512]; strncpy(tmp, path, sizeof(tmp)-1); tmp[sizeof(tmp)-1]='\0';
	char *p = tmp;
	// skip leading components until first slash
	while (*p && *p=='/') p++;
	for (char *q = p; *q; q++) {
		if (*q == '/') {
			*q = '\0'; mkdir(tmp, 0755); *q = '/';
		}
	}
	// make final dir if path ends with '/'
	size_t L=strlen(tmp); if (L>0 && tmp[L-1]=='/') mkdir(tmp,0755);
}

static FileHashEntry *file_hash = NULL;

// LRU Cache for recent file searches
typedef struct CacheNode {
	char filename[MAX_FILENAME_LEN];
	int file_index;
	time_t last_access;
	struct CacheNode *prev;
	struct CacheNode *next;
} CacheNode;

static CacheNode *cache_head = NULL;
static CacheNode *cache_tail = NULL;
static int cache_count = 0;

// Cache statistics
static unsigned long cache_hits = 0;
static unsigned long cache_misses = 0;

// Forward declarations
static int find_file(const char *fname);
static void hash_add_file(const char *fname, int index);
static void hash_remove_file(const char *fname);
static void hash_update_indices(int deleted_index);
static void cache_invalidate(const char *fname);

// Helper: recursively scan data/ and load any .meta files into registry
static void nm_scan_data_dir(const char *root, const char *relprefix) {
	char dirpath[512];
	if (relprefix && *relprefix) snprintf(dirpath, sizeof(dirpath), "%s/%s", root, relprefix);
	else snprintf(dirpath, sizeof(dirpath), "%s", root);

	DIR *d = opendir(dirpath);
	if (!d) return;

	struct dirent *de;
	while ((de = readdir(d)) != NULL) {
		const char *name = de->d_name;
		if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
		// Skip hidden and our internal dot-prefixed directories like .cp_/ .undo_
		if (name[0] == '.') continue;

		char child_rel[512];
		if (relprefix && *relprefix) snprintf(child_rel, sizeof(child_rel), "%s/%s", relprefix, name);
		else snprintf(child_rel, sizeof(child_rel), "%s", name);

		// Build full path to stat
		char fullpath[512]; snprintf(fullpath, sizeof(fullpath), "%s/%s", root, child_rel);
		struct stat st; if (stat(fullpath, &st) != 0) continue;
		if (S_ISDIR(st.st_mode)) {
			// Recurse
			nm_scan_data_dir(root, child_rel);
			continue;
		}

		// Handle .meta files
		int nlen = (int)strlen(child_rel);
		if (nlen > 5 && strcmp(child_rel + nlen - 5, ".meta") == 0) {
			char filename[256];
			strncpy(filename, child_rel, nlen - 5);
			filename[nlen - 5] = '\0';
			if (find_file(filename) >= 0) continue; // already registered

			// Read metadata to populate registry
			FILE *mf = fopen(fullpath, "r");
			if (!mf) continue;
			char owner[64] = "unknown";
			char last_access_str[64] = "";
			int words = 0, chars = 0;
			char line[256];
			while (fgets(line, sizeof(line), mf)) {
				if (strncmp(line, "owner=", 6) == 0) {
					strncpy(owner, line + 6, sizeof(owner) - 1);
					size_t L = strlen(owner);
					if (L > 0 && (owner[L-1] == '\n' || owner[L-1] == '\r')) owner[L-1] = '\0';
				} else if (strncmp(line, "words=", 6) == 0) {
					words = atoi(line + 6);
				} else if (strncmp(line, "chars=", 6) == 0) {
					chars = atoi(line + 6);
				} else if (strncmp(line, "last_access=", 12) == 0) {
					strncpy(last_access_str, line + 12, sizeof(last_access_str) - 1);
					size_t L = strlen(last_access_str);
					if (L > 0 && (last_access_str[L-1] == '\n' || last_access_str[L-1] == '\r')) last_access_str[L-1] = '\0';
				}
			}
			fclose(mf);

			// Get timestamps from the data file if present
			char fpath[512]; snprintf(fpath, sizeof(fpath), "%s/%s", root, filename);
			time_t created = 0, modified = 0, last_access = 0;
			struct stat fst;
			if (stat(fpath, &fst) == 0) { 
				created = fst.st_ctime; 
				modified = fst.st_mtime; 
			}
			else { 
				time(&created); 
				modified = created; 
			}
			
			// Parse last_access from metadata if available
			if (last_access_str[0]) {
				struct tm tm_acc = {0};
				if (strptime(last_access_str, "%Y-%m-%d %H:%M:%S", &tm_acc)) {
					last_access = mktime(&tm_acc);
				} else {
					last_access = modified; // fallback
				}
			} else {
				last_access = modified; // fallback if not in metadata
			}

			if (file_count < MAX_FILES) {
				FileEntry *e = &files[file_count];
				memset(e, 0, sizeof(*e));
				strncpy(e->filename, filename, sizeof(e->filename) - 1);
				strncpy(e->owner, owner, sizeof(e->owner) - 1);
				e->ss_id = 0; // default; will be used for resolves
				e->words = words;
				e->chars = chars;
				e->created = created;
				e->modified = modified;
				e->last_access = last_access;
				strncpy(e->last_access_by, owner, sizeof(e->last_access_by)-1);
				hash_add_file(filename, file_count);
				file_count++;
			}
		}
	}
	closedir(d);
}

// Load existing files from data/ directory on startup (now recursive)
void nm_load_persisted_files() {
	int before = file_count;
	nm_scan_data_dir("data", "");
	int loaded = file_count - before;
	printf("Loaded %d persisted files from data/ directory\n", loaded);
}

// Check if username is currently taken by an active client
int nm_is_username_active(const char *user) {
    for (int i = 0; i < client_count; i++) {
        if (strcmp(clients[i].username, user) == 0) {
            return 1; // Username is active
        }
    }
    return 0; // Username not active
}

int nm_track_client(const char *user, const char *ip, int port) {
    // First check if client already exists
    int existing_idx = -1;
    for (int i = 0; i < client_count; i++) {
        if (strcmp(clients[i].username, user) == 0) {
            existing_idx = i;
            break;
        }
    }
    
    // Remove existing entry for this user if any
    if (existing_idx >= 0) {
        // Shift remaining entries left to fill the gap
        for (int i = existing_idx; i < client_count - 1; i++) {
            clients[i] = clients[i + 1];
        }
        client_count--;
    }
    
    // Add as new client
    if (client_count < MAX_CLIENTS) {
        strncpy(clients[client_count].username, user, sizeof(clients[client_count].username)-1);
        if (ip) strncpy(clients[client_count].ip, ip, sizeof(clients[client_count].ip)-1);
        clients[client_count].port = port;
        client_count++;
        return 1; // Always treat as new connection
    }
    return 0;
}

int nm_list_users(char *out, size_t outlen) {
    time_t now;
    time(&now);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Create temporary sorted array of client indices
    int sorted_idx[MAX_CLIENTS];
    for (int i = 0; i < client_count; i++) {
        sorted_idx[i] = i;
    }
    
    // Sort by username to maintain consistent order
    for (int i = 0; i < client_count - 1; i++) {
        for (int j = 0; j < client_count - i - 1; j++) {
            if (strcmp(clients[sorted_idx[j]].username, 
                      clients[sorted_idx[j+1]].username) > 0) {
                int temp = sorted_idx[j];
                sorted_idx[j] = sorted_idx[j+1];
                sorted_idx[j+1] = temp;
            }
        }
    }
    
    size_t off = 0;
    off += snprintf(out+off, outlen-off, "Active users as of %s:\n", timestamp);
    for (int i = 0; i < client_count; i++) {
        int idx = sorted_idx[i];
        off += snprintf(out+off, outlen-off, "--> %s@%s:%d\n", 
                       clients[idx].username, 
                       clients[idx].ip[0] ? clients[idx].ip : "unknown",
                       clients[idx].port);
        if (off >= outlen) break;
    }
    
    // Log the LIST operation
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "LIST command showed %d active users", client_count);
    log_event("logs/nm.log", "NM", log_msg);
    
    return SUCCESS;
}

// ACL helpers: load/update readers/writers from .meta
static void load_acl(const char *fname, char *owner, size_t olen, char *readers, size_t rlen, char *writers, size_t wlen) {
	char mpath[512]; snprintf(mpath, sizeof(mpath), "data/%s.meta", fname);
	FILE *m=fopen(mpath, "r"); if (!m) { owner[0]=readers[0]=writers[0]='\0'; return; }
	char line[256]; while (fgets(line, sizeof(line), m)) {
		if (strncmp(line, "owner=",6)==0) { strncpy(owner, line+6, olen-1); }
		else if (strncmp(line, "readers=",8)==0) { strncpy(readers, line+8, rlen-1); }
		else if (strncmp(line, "writers=",8)==0) { strncpy(writers, line+8, wlen-1); }
	}
	fclose(m);
	// trim newlines
	char *arr[3]={owner,readers,writers}; for (int i=0;i<3;i++){ size_t L=strlen(arr[i]); if(L>0&&(arr[i][L-1]=='\n'||arr[i][L-1]=='\r')) arr[i][L-1]='\0'; }
}

static int write_acl(const char *fname, const char *owner, const char *readers, const char *writers) {
	char mpath[512]; snprintf(mpath, sizeof(mpath), "data/%s.meta", fname);
	// Load counts and last_modified to preserve
	int words=0, chars=0; char lastmod[64]=""; FILE *m=fopen(mpath, "r");
	if (m) { char line[256]; while (fgets(line,sizeof(line),m)) {
		if (strncmp(line, "words=",6)==0) words = atoi(line+6);
		else if (strncmp(line, "chars=",6)==0) chars = atoi(line+6);
		else if (strncmp(line, "last_modified=",14)==0) { strncpy(lastmod, line+14, sizeof(lastmod)-1); size_t L=strlen(lastmod); if(L>0&&(lastmod[L-1]=='\n'||lastmod[L-1]=='\r')) lastmod[L-1]='\0'; }
	} fclose(m);}    
	m=fopen(mpath, "w"); if (!m) return ERR_INTERNAL;
	fprintf(m, "owner=%s\nreaders=%s\nwriters=%s\nwords=%d\nchars=%d\nlast_modified=%s\n", owner, readers, writers, words, chars, lastmod);
	fclose(m); return SUCCESS;
}

static int in_list(const char *csv, const char *user) {
	char tmp[512]; strncpy(tmp, csv, sizeof(tmp)-1); tmp[sizeof(tmp)-1]='\0';
	char *save=NULL; char *tok=strtok_r(tmp, ",", &save);
	while (tok) { while (*tok==' ') tok++; size_t L=strlen(tok); while(L>0 && (tok[L-1]==' ')) tok[--L]='\0'; if (strcmp(tok,user)==0) return 1; tok=strtok_r(NULL, ",", &save);} return 0;
}

// (find_file prototype declared earlier near access request forward decls)

int nm_addaccess(const char *fname, const char *requestor, const char *mode, const char *target_user) {
	int idx = find_file(fname); 
	if (idx<0) {
		char log_buf[256];
		snprintf(log_buf, sizeof(log_buf), "FAILED file=%s requestor=%s target=%s mode=%s reason=FILE_NOT_FOUND", 
		         fname, requestor, target_user, mode);
		log_event_detailed("logs/nm.log", "NM", "ADDACCESS", requestor, "", 0, log_buf, 1);
		return ERR_FILE_NOT_FOUND;
	}
	
	char owner[64], readers[512], writers[512]; owner[0]=readers[0]=writers[0]='\0';
	load_acl(fname, owner, sizeof(owner), readers, sizeof(readers), writers, sizeof(writers));
	
	if (strcmp(owner, requestor)!=0) {
		char log_buf[256];
		snprintf(log_buf, sizeof(log_buf), "FAILED file=%s requestor=%s target=%s mode=%s owner=%s reason=NOT_OWNER", 
		         fname, requestor, target_user, mode, owner);
		log_event_detailed("logs/nm.log", "NM", "ADDACCESS", requestor, "", 0, log_buf, 1);
		return ERR_PERMISSION_DENIED;
	}
	
	// Append target to readers and maybe writers if not present
	if (!in_list(readers, target_user)) { 
		if (*readers) strncat(readers, ",", sizeof(readers)-strlen(readers)-1); 
		strncat(readers, target_user, sizeof(readers)-strlen(readers)-1); 
	}
	if (mode[0]=='W') {
		if (!in_list(writers, target_user)) { 
			if (*writers) strncat(writers, ",", sizeof(writers)-strlen(writers)-1); 
			strncat(writers, target_user, sizeof(writers)-strlen(writers)-1); 
		}
	}
	
	int result = write_acl(fname, owner, readers, writers);
	if (result == SUCCESS) {
		char log_buf[256];
		snprintf(log_buf, sizeof(log_buf), "SUCCESS file=%s requestor=%s target=%s mode=%s permission=%s", 
		         fname, requestor, target_user, mode, mode[0]=='W' ? "READ+WRITE" : "READ");
		log_event_detailed("logs/nm.log", "NM", "ADDACCESS", requestor, "", 0, log_buf, 1);
	} else {
		char log_buf[256];
		snprintf(log_buf, sizeof(log_buf), "FAILED file=%s requestor=%s target=%s mode=%s reason=WRITE_ACL_ERROR", 
		         fname, requestor, target_user, mode);
		log_event_detailed("logs/nm.log", "NM", "ADDACCESS", requestor, "", 0, log_buf, 1);
	}
	
	return result;
}

int nm_remaccess(const char *fname, const char *requestor, const char *target_user) {
	int idx = find_file(fname); 
	if (idx<0) {
		char log_buf[256];
		snprintf(log_buf, sizeof(log_buf), "FAILED file=%s requestor=%s target=%s reason=FILE_NOT_FOUND", 
		         fname, requestor, target_user);
		log_event_detailed("logs/nm.log", "NM", "REMACCESS", requestor, "", 0, log_buf, 1);
		return ERR_FILE_NOT_FOUND;
	}
	
	char owner[64], readers[512], writers[512]; owner[0]=readers[0]=writers[0]='\0';
	load_acl(fname, owner, sizeof(owner), readers, sizeof(readers), writers, sizeof(writers));
	
	if (strcmp(owner, requestor)!=0) {
		char log_buf[256];
		snprintf(log_buf, sizeof(log_buf), "FAILED file=%s requestor=%s target=%s owner=%s reason=NOT_OWNER", 
		         fname, requestor, target_user, owner);
		log_event_detailed("logs/nm.log", "NM", "REMACCESS", requestor, "", 0, log_buf, 1);
		return ERR_PERMISSION_DENIED;
	}
	
	// rebuild lists without target
	char newr[512]="", neww[512]=""; char *save=NULL; char *tok=NULL; char tmp[512];
	strncpy(tmp, readers, sizeof(tmp)-1); tok=strtok_r(tmp, ",", &save);
	while (tok) { while(*tok==' ') tok++; size_t L=strlen(tok); while(L>0 && tok[L-1]==' ') tok[--L]='\0'; if (strcmp(tok,target_user)!=0){ if(*newr) strcat(newr, ","); strcat(newr, tok);} tok=strtok_r(NULL, ",", &save);}    
	strncpy(tmp, writers, sizeof(tmp)-1); save=NULL; tok=strtok_r(tmp, ",", &save);
	while (tok) { while(*tok==' ') tok++; size_t L=strlen(tok); while(L>0 && tok[L-1]==' ') tok[--L]='\0'; if (strcmp(tok,target_user)!=0){ if(*neww) strcat(neww, ","); strcat(neww, tok);} tok=strtok_r(NULL, ",", &save);}    
	
	int result = write_acl(fname, owner, newr, neww);
	if (result == SUCCESS) {
		char log_buf[256];
		snprintf(log_buf, sizeof(log_buf), "SUCCESS file=%s requestor=%s target=%s removed_permissions=ALL", 
		         fname, requestor, target_user);
		log_event_detailed("logs/nm.log", "NM", "REMACCESS", requestor, "", 0, log_buf, 1);
	} else {
		char log_buf[256];
		snprintf(log_buf, sizeof(log_buf), "FAILED file=%s requestor=%s target=%s reason=WRITE_ACL_ERROR", 
		         fname, requestor, target_user);
		log_event_detailed("logs/nm.log", "NM", "REMACCESS", requestor, "", 0, log_buf, 1);
	}
	
	return result;
}

// Access enforcement helpers
int nm_check_read(const char *fname, const char *user) {
	int idx = find_file(fname); 
	if (idx<0) {
		char log_buf[256];
		snprintf(log_buf, sizeof(log_buf), "ACCESS_DENIED file=%s user=%s reason=FILE_NOT_FOUND", fname, user);
		log_event_detailed("logs/nm.log", "NM", "CHECK_READ", user, "", 0, log_buf, 1);
		return ERR_FILE_NOT_FOUND;
	}
	
	char owner[64], readers[512], writers[512]; owner[0]=readers[0]=writers[0]='\0';
	load_acl(fname, owner, sizeof(owner), readers, sizeof(readers), writers, sizeof(writers));
	
	if (strcmp(owner,user)==0) {
		char log_buf[256];
		snprintf(log_buf, sizeof(log_buf), "ACCESS_GRANTED file=%s user=%s role=OWNER permission=READ", fname, user);
		log_event_detailed("logs/nm.log", "NM", "CHECK_READ", user, "", 0, log_buf, 1);
		return SUCCESS;
	}
	
	// Writers also have read access (as per TA: -W flag gives both read and write)
	if (in_list(readers, user)) {
		char log_buf[256];
		snprintf(log_buf, sizeof(log_buf), "ACCESS_GRANTED file=%s user=%s role=READER permission=READ", fname, user);
		log_event_detailed("logs/nm.log", "NM", "CHECK_READ", user, "", 0, log_buf, 1);
		return SUCCESS;
	}
	
	if (in_list(writers, user)) {
		char log_buf[256];
		snprintf(log_buf, sizeof(log_buf), "ACCESS_GRANTED file=%s user=%s role=WRITER permission=READ", fname, user);
		log_event_detailed("logs/nm.log", "NM", "CHECK_READ", user, "", 0, log_buf, 1);
		return SUCCESS;
	}
	
	char log_buf[256];
	snprintf(log_buf, sizeof(log_buf), "ACCESS_DENIED file=%s user=%s owner=%s reason=NO_READ_PERMISSION", fname, user, owner);
	log_event_detailed("logs/nm.log", "NM", "CHECK_READ", user, "", 0, log_buf, 1);
	return ERR_PERMISSION_DENIED;
}
int nm_check_write(const char *fname, const char *user) {
	int idx = find_file(fname); 
	if (idx<0) {
		char log_buf[256];
		snprintf(log_buf, sizeof(log_buf), "ACCESS_DENIED file=%s user=%s reason=FILE_NOT_FOUND", fname, user);
		log_event_detailed("logs/nm.log", "NM", "CHECK_WRITE", user, "", 0, log_buf, 1);
		return ERR_FILE_NOT_FOUND;
	}
	
	char owner[64], readers[512], writers[512]; owner[0]=readers[0]=writers[0]='\0';
	load_acl(fname, owner, sizeof(owner), readers, sizeof(readers), writers, sizeof(writers));
	
	if (strcmp(owner,user)==0) {
		char log_buf[256];
		snprintf(log_buf, sizeof(log_buf), "ACCESS_GRANTED file=%s user=%s role=OWNER permission=WRITE", fname, user);
		log_event_detailed("logs/nm.log", "NM", "CHECK_WRITE", user, "", 0, log_buf, 1);
		return SUCCESS;
	}
	
	if (in_list(writers, user)) {
		char log_buf[256];
		snprintf(log_buf, sizeof(log_buf), "ACCESS_GRANTED file=%s user=%s role=WRITER permission=WRITE", fname, user);
		log_event_detailed("logs/nm.log", "NM", "CHECK_WRITE", user, "", 0, log_buf, 1);
		return SUCCESS;
	}
	
	char log_buf[256];
	snprintf(log_buf, sizeof(log_buf), "ACCESS_DENIED file=%s user=%s owner=%s reason=NO_WRITE_PERMISSION", fname, user, owner);
	log_event_detailed("logs/nm.log", "NM", "CHECK_WRITE", user, "", 0, log_buf, 1);
	return ERR_PERMISSION_DENIED;
}

int nm_is_owner(const char *fname, const char *user) {
	// Treat non-existent files as not found, not access denied
	int idx = find_file(fname);
	if (idx < 0) return ERR_FILE_NOT_FOUND;
	char owner[64], readers[8], writers[8]; owner[0]='\0';
	load_acl(fname, owner, sizeof(owner), readers, sizeof(readers), writers, sizeof(writers));
	return (strcmp(owner, user)==0) ? SUCCESS : ERR_PERMISSION_DENIED;
}

int nm_delete_entry(const char *fname) {
	int idx = find_file(fname); if (idx<0) return ERR_FILE_NOT_FOUND;
	
	// Remove from hash map
	hash_remove_file(fname);
	
	// Invalidate cache
	cache_invalidate(fname);
	
	// compact array
	for (int i=idx+1;i<file_count;i++) files[i-1]=files[i];
	file_count--;
	
	// Update hash map indices for shifted files
	hash_update_indices(idx);
	
	return SUCCESS;
}

// Try reading counts/owner from sidecar meta file to enrich VIEW -l
static void load_meta_for(const char *fname, int *words_out, int *chars_out, char *owner_out, size_t owner_len) {
	char mpath[512];
	snprintf(mpath, sizeof(mpath), "data/%s.meta", fname);
	FILE *f = fopen(mpath, "r");
	if (!f) return; // fallback to registry values
	char line[256];
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "owner=", 6) == 0 && owner_out && owner_len > 0) {
			strncpy(owner_out, line+6, owner_len-1);
			// trim newline
			size_t L = strlen(owner_out); if (L>0 && (owner_out[L-1]=='\n' || owner_out[L-1]=='\r')) owner_out[L-1]='\0';
		} else if (strncmp(line, "words=", 6) == 0 && words_out) {
			*words_out = atoi(line+6);
		} else if (strncmp(line, "chars=", 6) == 0 && chars_out) {
			*chars_out = atoi(line+6);
		}
	}
	fclose(f);
}

// API exported to nm_main.c
int nm_register_ss(const char *name, const char *ip, int client_port) {
	// If an SS with the same advertised IP and client_port exists, treat as reconnect
	for (int i = 0; i < server_count; i++) {
		if (strcmp(servers[i].ip, ip) == 0 && servers[i].client_port == client_port) {
			// Update name (optional), mark alive, refresh last_seen
			if (name && *name) {
				strncpy(servers[i].name, name, sizeof(servers[i].name)-1);
				servers[i].name[sizeof(servers[i].name)-1] = '\0';
			}
			servers[i].alive = 1;
			time(&servers[i].last_seen);
			return i; // stable ss_id reused
		}
	}
	// New SS registration
	if (server_count >= MAX_SRV) return -1;
	strncpy(servers[server_count].name, name ? name : "", sizeof(servers[server_count].name)-1);
	servers[server_count].name[sizeof(servers[server_count].name)-1] = '\0';
	strncpy(servers[server_count].ip, ip ? ip : "", sizeof(servers[server_count].ip)-1);
	servers[server_count].ip[sizeof(servers[server_count].ip)-1] = '\0';
	servers[server_count].client_port = client_port;
	servers[server_count].alive = 1; time(&servers[server_count].last_seen);
	return server_count++;
}

int nm_choose_ss() {
	if (server_count == 0) return -1;
	
	// Try to find an alive SS starting from round-robin position
	int start = rr_index % server_count;
	for (int offset = 0; offset < server_count; offset++) {
		int candidate = (start + offset) % server_count;
		if (nm_server_is_alive(candidate)) {
			rr_index = (candidate + 1) % server_count;
			return candidate;
		}
	}
	
	// No alive SS found, return round-robin anyway (will fail later)
	int chosen = rr_index % server_count;
	rr_index = (rr_index + 1) % server_count;
	return chosen;
}

// ============================================================================
// EFFICIENT SEARCH: Hash Map + LRU Cache Implementation
// ============================================================================

// Add entry to hash map
static void hash_add_file(const char *fname, int index) {
	FileHashEntry *entry = (FileHashEntry*)malloc(sizeof(FileHashEntry));
	if (!entry) return;
	strncpy(entry->filename, fname, MAX_FILENAME_LEN-1);
	entry->filename[MAX_FILENAME_LEN-1] = '\0';
	entry->file_index = index;
	HASH_ADD_STR(file_hash, filename, entry);
}

// Remove entry from hash map
static void hash_remove_file(const char *fname) {
	FileHashEntry *entry;
	HASH_FIND_STR(file_hash, fname, entry);
	if (entry) {
		HASH_DEL(file_hash, entry);
		free(entry);
	}
}

// Update hash map when file index changes (e.g., after deletion)
static void hash_update_indices(int deleted_index) {
	FileHashEntry *entry, *tmp;
	HASH_ITER(hh, file_hash, entry, tmp) {
		if (entry->file_index > deleted_index) {
			entry->file_index--;
		}
	}
}

// Move cache node to front (most recently used)
static void cache_move_to_front(CacheNode *node) {
	if (node == cache_head) return; // already at front
	
	// Remove from current position
	if (node->prev) node->prev->next = node->next;
	if (node->next) node->next->prev = node->prev;
	if (node == cache_tail) cache_tail = node->prev;
	
	// Insert at front
	node->prev = NULL;
	node->next = cache_head;
	if (cache_head) cache_head->prev = node;
	cache_head = node;
	if (!cache_tail) cache_tail = node;
}

// Remove LRU node (from tail)
static void cache_remove_lru() {
	if (!cache_tail) return;
	CacheNode *old_tail = cache_tail;
	cache_tail = old_tail->prev;
	if (cache_tail) cache_tail->next = NULL;
	else cache_head = NULL;
	free(old_tail);
	cache_count--;
}

// Add to cache
static void cache_insert(const char *fname, int index) {
	// Check if already in cache
	CacheNode *node = cache_head;
	while (node) {
		if (strcmp(node->filename, fname) == 0) {
			node->file_index = index;
			node->last_access = time(NULL);
			cache_move_to_front(node);
			return;
		}
		node = node->next;
	}
	
	// Not in cache, create new node
	CacheNode *new_node = (CacheNode*)malloc(sizeof(CacheNode));
	if (!new_node) return;
	strncpy(new_node->filename, fname, MAX_FILENAME_LEN-1);
	new_node->filename[MAX_FILENAME_LEN-1] = '\0';
	new_node->file_index = index;
	new_node->last_access = time(NULL);
	new_node->prev = NULL;
	new_node->next = cache_head;
	
	if (cache_head) cache_head->prev = new_node;
	cache_head = new_node;
	if (!cache_tail) cache_tail = new_node;
	cache_count++;
	
	// Evict LRU if cache full
	if (cache_count > CACHE_SIZE) {
		cache_remove_lru();
	}
}

// Invalidate cache entry
static void cache_invalidate(const char *fname) {
	CacheNode *node = cache_head;
	while (node) {
		if (strcmp(node->filename, fname) == 0) {
			if (node->prev) node->prev->next = node->next;
			if (node->next) node->next->prev = node->prev;
			if (node == cache_head) cache_head = node->next;
			if (node == cache_tail) cache_tail = node->prev;
			free(node);
			cache_count--;
			return;
		}
		node = node->next;
	}
}

void nm_cache_invalidate(const char *fname, const char *reason) {
	cache_invalidate(fname);
	char log_buf[128]; 
	snprintf(log_buf, sizeof(log_buf), "file=%s reason=%s", fname, reason ? reason : "unknown");
	log_event_detailed("logs/nm.log", "NM", "CACHE_INV", "", "", 0, log_buf, 1);
}

// Update metadata after a write commit: words/chars/last_modified/version bump
int nm_update_after_write(const char *fname, const char *user, int words, int chars, int new_version) {
	int idx = find_file(fname);
	if (idx < 0) return ERR_FILE_NOT_FOUND;
	FileEntry *e = &files[idx];
	e->words = words;
	e->chars = chars;
	e->version = new_version > 0 ? new_version : (e->version + 1);
	time(&e->modified);
	// Don't update last_access on write - only on read/stream/info
	// e->last_access should only be updated by nm_mark_access()
	return SUCCESS;
}

// Mark file access (read/stream/info) updating last_access and user
int nm_mark_access(const char *fname, const char *user) {
	int idx = find_file(fname); if (idx < 0) return ERR_FILE_NOT_FOUND;
	FileEntry *e = &files[idx]; 
	time(&e->last_access); 
	if (user && *user) strncpy(e->last_access_by, user, sizeof(e->last_access_by)-1);
	
	// Save last_access to metadata for persistence
	char mpath[512]; snprintf(mpath, sizeof(mpath), "data/%s.meta", fname);
	char owner[64]="", readers[512]="", writers[512]="", lastmod[64]="";
	int words=0, chars=0;
	FILE *m = fopen(mpath, "r");
	if (m) {
		char line[256];
		while (fgets(line, sizeof(line), m)) {
			if (strncmp(line, "owner=", 6) == 0) { strncpy(owner, line+6, sizeof(owner)-1); }
			else if (strncmp(line, "readers=", 8) == 0) { strncpy(readers, line+8, sizeof(readers)-1); }
			else if (strncmp(line, "writers=", 8) == 0) { strncpy(writers, line+8, sizeof(writers)-1); }
			else if (strncmp(line, "words=", 6) == 0) { words = atoi(line+6); }
			else if (strncmp(line, "chars=", 6) == 0) { chars = atoi(line+6); }
			else if (strncmp(line, "last_modified=", 14) == 0) { strncpy(lastmod, line+14, sizeof(lastmod)-1); }
		}
		fclose(m);
	}
	// Trim newlines
	char *arr[4]={owner,readers,writers,lastmod};
	for (int i=0;i<4;i++){ size_t L=strlen(arr[i]); if(L>0&&(arr[i][L-1]=='\n'||arr[i][L-1]=='\r')) arr[i][L-1]='\0'; }
	
	// Write back with updated last_access
	char access_time[64];
	struct tm *tm_info = localtime(&e->last_access);
	strftime(access_time, sizeof(access_time), "%Y-%m-%d %H:%M:%S", tm_info);
	
	m = fopen(mpath, "w");
	if (m) {
		fprintf(m, "owner=%s\nreaders=%s\nwriters=%s\nwords=%d\nchars=%d\nlast_modified=%s\nlast_access=%s\n",
			owner, readers, writers, words, chars, lastmod, access_time);
		fclose(m);
	}
	
	return SUCCESS;
}

// O(1) hash-based file lookup with LRU cache
static int find_file(const char *fname) {
	// Check cache first - O(1) for recent files
	CacheNode *node = cache_head;
	while (node) {
		if (strcmp(node->filename, fname) == 0) {
			cache_hits++;
			node->last_access = time(NULL);
			cache_move_to_front(node);
			return node->file_index;
		}
		node = node->next;
	}
	
	// Cache miss - lookup in hash map - O(1) average
	cache_misses++;
	FileHashEntry *entry;
	HASH_FIND_STR(file_hash, fname, entry);
	if (entry) {
		// Add to cache for future lookups
		cache_insert(fname, entry->file_index);
		return entry->file_index;
	}
	
	return -1;
}

// Get cache statistics
void nm_get_cache_stats(unsigned long *hits, unsigned long *misses, int *size) {
	if (hits) *hits = cache_hits;
	if (misses) *misses = cache_misses;
	if (size) *size = cache_count;
}

// Public wrapper for file lookup (returns file index)
int nm_find_file_index(const char *fname) {
	return find_file(fname);
}

// Update the storage server ID for an existing file
void nm_update_file_ss(int file_index, int ss_id) {
	if (file_index < 0 || file_index >= file_count) return;
	files[file_index].ss_id = ss_id;
	// Also update replica if needed
	files[file_index].replica_ss_id = find_next_alive_ss(ss_id, ss_id, -1);
}

// ============================================================================

int nm_create_file(const char *fname, const char *user, int ss_id, char *errbuf, size_t errlen) {
	if (!fname || !*fname || strlen(fname) >= MAX_FILENAME_LEN) {
		snprintf(errbuf, errlen, "invalid filename");
		return ERR_BAD_REQUEST;
	}
	if (find_file(fname) >= 0) {
		snprintf(errbuf, errlen, "file exists");
		return ERR_BAD_REQUEST;
	}
	if (ss_id < 0 || ss_id >= server_count) {
		snprintf(errbuf, errlen, "no storage server available");
		return ERR_INTERNAL;
	}
	FileEntry *e = &files[file_count++];
	memset(e, 0, sizeof(*e));
	strncpy(e->filename, fname, sizeof(e->filename)-1);
	strncpy(e->owner, user, sizeof(e->owner)-1);
	e->ss_id = ss_id;
	// Assign a replica server in circular order (next alive SS after primary)
	e->replica_ss_id = find_next_alive_ss(ss_id, ss_id, -1);
	e->words = 0;
	e->chars = 0;
    e->version = 1;
	time(&e->created);
	e->modified = e->created;
	e->last_access = e->created;
	strncpy(e->last_access_by, user, sizeof(e->last_access_by)-1);
	
	// Add to hash map for O(1) lookup
	hash_add_file(fname, file_count - 1);
	
	return SUCCESS;
}

// Move file on disk (data/) along with .meta and .undo_, then update registry name
int nm_move_file(const char *fname, const char *folder, char *errbuf, size_t errlen) {
	if (!fname || !folder || !*fname || !*folder) { snprintf(errbuf, errlen, "bad args"); return ERR_BAD_REQUEST; }
	int idx = find_file(fname); if (idx < 0) { snprintf(errbuf, errlen, "not found"); return ERR_FILE_NOT_FOUND; }
	char newname[512]; snprintf(newname, sizeof(newname), "%s/%s", folder, fname);
	if (find_file(newname) >= 0) { snprintf(errbuf, errlen, "target exists"); return ERR_BAD_REQUEST; }

	// Ensure destination folder exists
	char folderPath[512]; snprintf(folderPath, sizeof(folderPath), "data/%s", folder);
	struct stat st; if (stat(folderPath, &st) != 0 || !S_ISDIR(st.st_mode)) {
		snprintf(errbuf, errlen, "folder missing");
		return ERR_BAD_REQUEST;
	}

	// Perform renames on data, meta, and undo files
	char src[512], dst[512];
	snprintf(src, sizeof(src), "data/%s", fname);
	snprintf(dst, sizeof(dst), "data/%s", newname);
	if (rename(src, dst) != 0) {
		snprintf(errbuf, errlen, "rename failed");
		return ERR_INTERNAL;
	}
	char srcMeta[512], dstMeta[512];
	snprintf(srcMeta, sizeof(srcMeta), "data/%s.meta", fname);
	snprintf(dstMeta, sizeof(dstMeta), "data/%s.meta", newname);
	ensure_dirs_for_path(dstMeta);
	rename(srcMeta, dstMeta); // best-effort

	// Move undo path: pattern is data/.undo_<filename>
	char srcUndo[512], dstUndo[512];
	snprintf(srcUndo, sizeof(srcUndo), "data/.undo_%s", fname);
	snprintf(dstUndo, sizeof(dstUndo), "data/.undo_%s", newname);
	ensure_dirs_for_path(dstUndo);
	rename(srcUndo, dstUndo); // best-effort

	// Move checkpoints directory: from data/.cp_<old> to data/.cp_<new>
	char srcCp[512], dstCp[512];
	snprintf(srcCp, sizeof(srcCp), "data/.cp_%s", fname);
	snprintf(dstCp, sizeof(dstCp), "data/.cp_%s", newname);
	ensure_dirs_for_path(dstCp);
	rename(srcCp, dstCp); // best-effort

	// Update registry entry filename and index maps
	hash_remove_file(fname);
	strncpy(files[idx].filename, newname, sizeof(files[idx].filename)-1);
	files[idx].filename[sizeof(files[idx].filename)-1] = '\0';
	hash_add_file(newname, idx);
	cache_invalidate(fname);
	// Update any pending access requests referencing old name
	for (int i=0;i<MAX_ACCESS_REQUESTS;i++) if (access_requests[i].active && strcmp(access_requests[i].filename, fname)==0) {
		strncpy(access_requests[i].filename, newname, sizeof(access_requests[i].filename)-1);
		access_requests[i].filename[sizeof(access_requests[i].filename)-1]='\0';
	}
	return SUCCESS;
}

// List files in a folder (basenames) filtered by ACL
int nm_list_folder(const char *folder, const char *user, char *out, size_t outlen) {
	if (!folder || !*folder) return ERR_BAD_REQUEST;
	size_t off=0; out[0]='\0'; size_t fl = strlen(folder);
	for (int i=0;i<file_count;i++) {
		const char *fname = files[i].filename;
		if (strncmp(fname, folder, fl)==0 && fname[fl]=='/') {
			if (nm_check_read(fname, user)!=SUCCESS) continue;
			const char *base = fname + fl + 1;
			off += snprintf(out+off, outlen-off, "%s\n", base);
			if (off >= outlen) break;
		}
	}
	return SUCCESS;
}

// Expose server count for NM loops
int nm_get_server_count() { return server_count; }

// Replication helpers
int nm_get_replica_ss_id(const char *filename) {
	int idx = find_file(filename); if (idx < 0) return -1;
	return files[idx].replica_ss_id;
}

int nm_get_primary_ss_id(const char *filename) {
	int idx = find_file(filename); if (idx < 0) return -1;
	return files[idx].ss_id;
}

int nm_get_owner_name(const char *filename, char *out, size_t outlen) {
	int idx = find_file(filename); if (idx < 0) return ERR_FILE_NOT_FOUND;
	strncpy(out, files[idx].owner, outlen-1); out[outlen-1] = '\0';
	return SUCCESS;
}

// List files by role for recovery: role 'P' (primary at ss_id) or 'R' (replica at ss_id)
int nm_list_files_by_role(int ss_id, char role, char *out, size_t outlen) {
	size_t off = 0; out[0] = '\0';
	for (int i=0;i<file_count;i++) {
		int match = (role=='P') ? (files[i].ss_id==ss_id) : (files[i].replica_ss_id==ss_id);
		if (match) {
			size_t need = strlen(files[i].filename) + 1;
			if (off + need + 1 >= outlen) break;
			off += snprintf(out+off, outlen-off, "%s\n", files[i].filename);
		}
	}
	return SUCCESS;
}

// Placeholder recovery sync: mark server alive and update last_seen; future work can diff primaries/replicas
int nm_sync_recovered_ss(int ss_id) {
	if (ss_id<0 || ss_id>=server_count) return ERR_BAD_REQUEST;
	servers[ss_id].alive = 1; time(&servers[ss_id].last_seen);
	
	int count_as_primary = 0, count_as_replica = 0;
	int synced_as_primary = 0, synced_as_replica = 0;
	
	// Case 1: Files where this server is PRIMARY - sync FROM replica if available
	for (int i=0;i<file_count;i++) {
		if (files[i].ss_id == ss_id) {
			count_as_primary++;
			int replica = files[i].replica_ss_id;
			if (replica >= 0 && nm_server_is_alive(replica)) {
				// Recovered primary should fetch data from its replica
				// Note: This would need a COPY_FROM_REPLICA operation
				// For now, trigger replication which will sync metadata
				printf("  → Syncing '%s' to recovered primary SS%d from replica SS%d\n", 
					   files[i].filename, ss_id, replica);
				synced_as_primary++;
				// TODO: Implement actual file copy from replica to primary
				// For now, the file should still exist on recovered SS
			}
		}
	}
	
	// Case 2: Files where this server is REPLICA - sync FROM primary if available
	for (int i=0;i<file_count;i++) {
		if (files[i].replica_ss_id == ss_id) {
			count_as_replica++;
			int primary = files[i].ss_id;
			if (!nm_server_is_alive(primary)) continue; // primary not available
			// Trigger replication for this file to refresh recovered replica
				printf("  → Syncing '%s' to recovered replica SS%d from primary SS%d\n", 
				   files[i].filename, ss_id, primary);
			replicate_file_async(files[i].filename);
			synced_as_replica++;
		}
	}
	
	printf("  → SS%d recovery complete: %d files as primary, %d files as replica\n", 
		   ss_id, count_as_primary, count_as_replica);	return SUCCESS;
}

// Build a simple listing into payload text. flags: bit0 = -a, bit1 = -l, bit2 = -s (show SS)
int nm_view(int flags, const char *user, char *out, size_t outlen) {
	// For Part 2, no ACL, just owner considered for default view.
	int include_all = (flags & 1);
	int long_fmt = (flags & 2);
	int show_ss = (flags & 4);
	size_t off = 0;
	if (long_fmt) {
		// Table header
		if (show_ss) {
			off += snprintf(out+off, outlen-off, "-------------------------------------------------------------------------------------\n");
			off += snprintf(out+off, outlen-off, "|  %-20s| %-5s| %-5s| %-18s| %-7s| %-20s|\n",
				"Filename", "Words", "Chars", "Last Access Time", "Owner", "Storage");
			off += snprintf(out+off, outlen-off, "|----------------------|-------|-------|------------------|-------|----------------------|\n");
		} else {
			off += snprintf(out+off, outlen-off, "-------------------------------------------------------------------------\n");
			off += snprintf(out+off, outlen-off, "|  %-20s| %-5s| %-5s| %-18s| %-7s|\n",
				"Filename", "Words", "Chars", "Last Access Time", "Owner");
			off += snprintf(out+off, outlen-off, "|----------------------|-------|-------|------------------|-------|\n");
		}
	}
	for (int i = 0; i < file_count; ++i) {
		FileEntry *e = &files[i];
		int visible = include_all || (nm_check_read(e->filename, user) == SUCCESS);
		if (!visible) continue;
		char timebuf[32];
		struct tm *tm_info = localtime(&e->last_access);
		// For display, match spec minute precision
		strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M", tm_info);
		if (long_fmt) {
			int w = e->words, c = e->chars; char owner_buf[64]; owner_buf[0]='\0';
			load_meta_for(e->filename, &w, &c, owner_buf, sizeof(owner_buf));
			const char *owner_disp = (owner_buf[0] ? owner_buf : e->owner);
			
			// Truncate filename if too long, preserving other columns
			char display_filename[22];
			if (strlen(e->filename) > 20) {
				// Truncate with ellipsis
				strncpy(display_filename, e->filename, 17);
				display_filename[17] = '.';
				display_filename[18] = '.';
				display_filename[19] = '.';
				display_filename[20] = '\0';
			} else {
				strncpy(display_filename, e->filename, sizeof(display_filename) - 1);
				display_filename[sizeof(display_filename) - 1] = '\0';
			}
			
			if (show_ss) {
				// Show SS information
				char ss_brief[32];
				if (e->replica_ss_id >= 0) {
					const char *p_stat = nm_server_is_alive(e->ss_id) ? "✓" : "✗";
					const char *r_stat = nm_server_is_alive(e->replica_ss_id) ? "✓" : "✗";
					snprintf(ss_brief, sizeof(ss_brief), "P:%d%s R:%d%s", 
						e->ss_id, p_stat, e->replica_ss_id, r_stat);
				} else {
					const char *p_stat = nm_server_is_alive(e->ss_id) ? "✓" : "✗";
					snprintf(ss_brief, sizeof(ss_brief), "P:%d%s", e->ss_id, p_stat);
				}
				off += snprintf(out+off, outlen-off, "|  %-20s| %5d| %5d| %-18s| %-7.7s| %-20.20s|\n",
					display_filename, w, c, timebuf, owner_disp, ss_brief);
			} else {
				// show only timestamp in table per spec; detailed user access shown in INFO
				off += snprintf(out+off, outlen-off, "|  %-20s| %5d| %5d| %-18s| %-7.7s|\n",
					display_filename, w, c, timebuf, owner_disp);
			}
		} else {
			off += snprintf(out+off, outlen-off, "%s\n", e->filename);
		}
		if (off >= outlen) break;
	}
	// If -a is set, also include files present on disk (data/*.meta) that are not yet in registry
	if (include_all) {
		DIR *d = opendir("data");
		if (d) {
			struct dirent *de;
			while ((de = readdir(d)) != NULL) {
				const char *name = de->d_name;
				int nlen = (int)strlen(name);
				if (nlen > 5 && strcmp(name + nlen - 5, ".meta") == 0) {
					char base[256]; strncpy(base, name, nlen - 5); base[nlen - 5] = '\0';
					// check if already listed from registry
					int exists = 0; for (int i=0;i<file_count;i++) { if (strcmp(files[i].filename, base)==0) { exists=1; break; } }
					if (exists) continue;
					// gather meta owner/words/chars
					int w=0,c=0; char owner_buf[64]; owner_buf[0]='\0';
					load_meta_for(base, &w, &c, owner_buf, sizeof(owner_buf));
					// compute last access time using file mtime if available
					char timebuf[32]; time_t mt=0; struct stat st; char fpath[512]; snprintf(fpath,sizeof(fpath),"data/%s", base);
					if (stat(fpath, &st)==0) { mt = st.st_mtime; } else { time(&mt); }
					struct tm *tm_info = localtime(&mt); strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M", tm_info);
					if (long_fmt) {
						// Truncate filename if longer than 20 characters
						char display_filename[24];
						if (strlen(base) > 20) {
							strncpy(display_filename, base, 17);
							display_filename[17] = '\0';
							strcat(display_filename, "...");
						} else {
							strcpy(display_filename, base);
						}
						off += snprintf(out+off, outlen-off, "|  %-20s| %5d| %5d| %-18s| %-7.7s|\n", display_filename, w, c, timebuf, owner_buf[0]?owner_buf:"-");
					} else {
						off += snprintf(out+off, outlen-off, "%s\n", base);
					}
					if (off >= outlen) break;
				}
			}
			closedir(d);
		}
	}
	if (long_fmt) {
		if (show_ss) {
			off += snprintf(out+off, outlen-off, "---------------------------------------------------------------------------------------------------\n");
		} else {
			off += snprintf(out+off, outlen-off, "-----------------------------------------------------------------------\n");
		}
	}
	return SUCCESS;
}

int nm_info(const char *fname, char *out, size_t outlen) {
	int idx = find_file(fname);
	if (idx < 0) return ERR_FILE_NOT_FOUND;
	FileEntry *e = &files[idx];
	// mark this info retrieval as access by owner for now (caller supplies username separately in nm_main)
	// nm_main passes the user; for accuracy we won't overwrite here. If last_access_by empty, keep owner.
	char cbuf[32], abuf[32];
	struct tm *tm_info;
	tm_info = localtime(&e->created); strftime(cbuf, sizeof(cbuf), "%Y-%m-%d %H:%M:%S", tm_info);
	tm_info = localtime(&e->last_access); strftime(abuf, sizeof(abuf), "%Y-%m-%d %H:%M:%S", tm_info);
	// Read live metadata from sidecar to reflect latest WRITE updates
	int words = e->words, chars = e->chars; char owner_buf[64]; owner_buf[0] = '\0';
	load_meta_for(fname, &words, &chars, owner_buf, sizeof(owner_buf));
	const char *owner_disp = owner_buf[0] ? owner_buf : e->owner;
	// Try to get last_modified from meta too
	char mpath[512]; snprintf(mpath, sizeof(mpath), "data/%s.meta", fname);
	char lastmod[32] = ""; FILE *mf = fopen(mpath, "r");
	if (mf) {
		char line[256];
		while (fgets(line, sizeof(line), mf)) {
			if (strncmp(line, "last_modified=", 14) == 0) {
				strncpy(lastmod, line+14, sizeof(lastmod)-1);
				size_t L=strlen(lastmod); if (L>0 && (lastmod[L-1]=='\n'||lastmod[L-1]=='\r')) lastmod[L-1]='\0';
				break;
			}
		}
		fclose(mf);
	}
	if (lastmod[0] == '\0') {
		// fallback: use created as modified if not available
		strncpy(lastmod, cbuf, sizeof(lastmod)-1);
	}
	// Compute file size in bytes
	char fpath[512]; snprintf(fpath, sizeof(fpath), "data/%s", fname);
	long fsize = 0; struct stat st; if (stat(fpath, &st) == 0) fsize = (long)st.st_size;
	// Build Access summary from ACL
	char acl_owner[64] = "", readers[512] = "", writers[512] = "";
	load_acl(fname, acl_owner, sizeof(acl_owner), readers, sizeof(readers), writers, sizeof(writers));
	// Prepare access list string
	char access[512]; access[0] = '\0';
	// Owner always RW
	snprintf(access, sizeof(access), "%s (RW)", owner_disp);
	// Iterate readers CSV and append labels, merging RW where applicable
	char tmp[512]; strncpy(tmp, readers, sizeof(tmp)-1); tmp[sizeof(tmp)-1]='\0';
	char *save=NULL; char *tok=strtok_r(tmp, ",", &save);
	while (tok) {
		while (*tok==' ') tok++; size_t L=strlen(tok); while (L>0 && tok[L-1]==' ') tok[--L]='\0';
		if (tok[0] && strcmp(tok, owner_disp) != 0) {
			int is_rw = in_list(writers, tok);
			size_t need = strlen(access) + 2 + strlen(tok) + 5 + 1; // comma, space, name, (RW)/(R), nul
			if (need < sizeof(access)) {
				strcat(access, ", "); strcat(access, tok); strcat(access, is_rw?" (RW)":" (R)");
			}
		}
		tok = strtok_r(NULL, ",", &save);
	}
	// Include any writer not listed in readers (grant RW)
	strncpy(tmp, writers, sizeof(tmp)-1); tmp[sizeof(tmp)-1]='\0'; save=NULL; tok=strtok_r(tmp, ",", &save);
	while (tok) {
		while (*tok==' ') tok++; size_t L=strlen(tok); while (L>0 && tok[L-1]==' ') tok[--L]='\0';
		if (tok[0] && strcmp(tok, owner_disp) != 0 && !in_list(readers, tok)) {
			size_t need = strlen(access) + 2 + strlen(tok) + 5 + 1;
			if (need < sizeof(access)) { strcat(access, ", "); strcat(access, tok); strcat(access, " (RW)"); }
		}
		tok = strtok_r(NULL, ",", &save);
	}
	
	// Get SS and replica information with status
	char ss_info[256];
	int primary_ss = e->ss_id;
	int replica_ss = e->replica_ss_id;
	char primary_ip[32] = "N/A", replica_ip[32] = "N/A";
	int primary_port = 0, replica_port = 0;
	
	// Get primary SS details
	if (primary_ss >= 0 && primary_ss < server_count) {
		nm_get_ss_ip_port(primary_ss, primary_ip, sizeof(primary_ip), &primary_port);
		const char *primary_status = nm_server_is_alive(primary_ss) ? "ALIVE" : "DEAD";
		
		if (replica_ss >= 0 && replica_ss < server_count) {
			nm_get_ss_ip_port(replica_ss, replica_ip, sizeof(replica_ip), &replica_port);
			const char *replica_status = nm_server_is_alive(replica_ss) ? "ALIVE" : "DEAD";
			snprintf(ss_info, sizeof(ss_info), 
				"Primary SS%d (%s:%d) [%s], Replica SS%d (%s:%d) [%s]",
				primary_ss, primary_ip, primary_port, primary_status,
				replica_ss, replica_ip, replica_port, replica_status);
		} else {
			snprintf(ss_info, sizeof(ss_info), 
				"Primary SS%d (%s:%d) [%s], Replica: None",
				primary_ss, primary_ip, primary_port, primary_status);
		}
	} else {
		snprintf(ss_info, sizeof(ss_info), "Primary: Unknown, Replica: Unknown");
	}
	
	snprintf(out, outlen,
		"File: %s\nOwner: %s\nCreated: %s\nLast Modified: %s\nSize: %ld bytes\nWords: %d\nChars: %d\nAccess: %s\nStorage: %s\nLast Accessed: %s by %s\n",
		e->filename, owner_disp, cbuf, lastmod, fsize, words, chars, access, ss_info, abuf, (e->last_access_by[0]?e->last_access_by:owner_disp));
	return SUCCESS;
}

// Precheck: valid and not exists
int nm_can_create(const char *fname, char *errbuf, size_t errlen) {
	if (!fname || !*fname || strlen(fname) >= MAX_FILENAME_LEN) {
		snprintf(errbuf, errlen, "invalid filename");
		return ERR_BAD_REQUEST;
	}
	if (find_file(fname) >= 0) {
		snprintf(errbuf, errlen, "file exists");
		return ERR_BAD_REQUEST;
	}
	return SUCCESS;
}

int nm_get_ss_ip_port(int ss_id, char *ip, size_t iplen, int *port_out) {
	if (ss_id < 0 || ss_id >= server_count) return -1;
	strncpy(ip, servers[ss_id].ip, iplen-1);
	ip[iplen-1] = '\0';
	// Return the actual registered client port for this Storage Server
	if (port_out) *port_out = servers[ss_id].client_port;
	return 0;
}

int nm_get_ss_name(int ss_id, char *name, size_t namelen) {
	if (ss_id < 0 || ss_id >= server_count) return -1;
	strncpy(name, servers[ss_id].name, namelen-1);
	name[namelen-1] = '\0';
	return 0;
}

void nm_update_ss_name(int ss_id, const char *new_name) {
	if (ss_id < 0 || ss_id >= server_count || !new_name) return;
	strncpy(servers[ss_id].name, new_name, sizeof(servers[ss_id].name)-1);
	servers[ss_id].name[sizeof(servers[ss_id].name)-1] = '\0';
}

// Helper: Find next alive SS in circular order, excluding specified SSs
static int find_next_alive_ss(int start_ss, int exclude1, int exclude2) {
	if (server_count <= 1) return -1;
	
	// Try circular search starting from (start_ss + 1)
	for (int offset = 1; offset < server_count; offset++) {
		int candidate = (start_ss + offset) % server_count;
		if (candidate != exclude1 && candidate != exclude2 && nm_server_is_alive(candidate)) {
			return candidate;
		}
	}
	return -1; // No alive SS found
}

void nm_mark_ss_dead(int ss_id) { 
	if (ss_id < 0 || ss_id >= server_count) return;
	servers[ss_id].alive = 0;
	
	// Handle files where this SS was the primary - promote replica to primary
	for (int i = 0; i < file_count; i++) {
		if (files[i].ss_id == ss_id) {
			// Promote replica to primary if available
			if (files[i].replica_ss_id >= 0 && nm_server_is_alive(files[i].replica_ss_id)) {
				int old_replica = files[i].replica_ss_id;
				files[i].ss_id = old_replica;  // Promote replica to primary
				
				// Assign new replica using circular order from new primary
				int new_replica = find_next_alive_ss(files[i].ss_id, ss_id, files[i].ss_id);
				files[i].replica_ss_id = new_replica;
				
				printf("  → Primary failed for '%s': SS%d (dead) -> SS%d promoted, new replica: SS%d\n", 
					   files[i].filename, ss_id, files[i].ss_id, new_replica);
			} else {
				// No replica available - file has no backup
				printf("  → WARNING: File '%s' has no replica (primary SS%d is dead)\n", 
					   files[i].filename, ss_id);
				files[i].replica_ss_id = -1;
			}
		}
		// Also reassign replicas for files that had this SS as replica
		else if (files[i].replica_ss_id == ss_id) {
			// Find new replica in circular order from primary
			int new_replica = find_next_alive_ss(files[i].ss_id, ss_id, files[i].ss_id);
			files[i].replica_ss_id = new_replica;
			
			printf("  → Replica reassigned for '%s': SS%d (dead) -> SS%d\n", 
				   files[i].filename, ss_id, new_replica);
		}
	}
}
void nm_mark_ss_alive(int ss_id) { if (ss_id>=0 && ss_id<server_count) { servers[ss_id].alive=1; time(&servers[ss_id].last_seen);} }
int nm_server_is_alive(int ss_id) { return (ss_id>=0 && ss_id<server_count) ? servers[ss_id].alive : 0; }

int nm_resolve_for_read(char *filename, char *username, char *ss_ip_out, int *ss_port_out) {
	int idx = find_file(filename);
	if (idx < 0) return ERR_FILE_NOT_FOUND;
	int primary = files[idx].ss_id; int replica = files[idx].replica_ss_id;
	int chosen = primary;
	if (!nm_server_is_alive(primary) && nm_server_is_alive(replica)) chosen = replica;
	if (nm_get_ss_ip_port(chosen, ss_ip_out, 32, ss_port_out) != 0) return ERR_INTERNAL;
	nm_mark_access(filename, username);
	return SUCCESS;
}

int nm_resolve_for_write(char *filename, char *username, char *ss_ip_out, int *ss_port_out) {
	int idx = find_file(filename); if (idx < 0) return ERR_FILE_NOT_FOUND;
	int primary = files[idx].ss_id; int replica = files[idx].replica_ss_id;
	int chosen = primary;
	// Writes stick to primary unless dead and replica alive (degraded mode)
	if (!nm_server_is_alive(primary) && nm_server_is_alive(replica)) chosen = replica;
	if (nm_get_ss_ip_port(chosen, ss_ip_out, 32, ss_port_out) != 0) return ERR_INTERNAL;
	nm_mark_access(filename, username);
	return SUCCESS;
}

// Return storage server id for a given file, or -1 if not found
int nm_get_ss_id(const char *filename) {
	int idx = find_file(filename);
	if (idx < 0) return -1;
	return files[idx].ss_id;
}

