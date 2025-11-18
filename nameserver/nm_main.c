#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <pthread.h>
#include <signal.h>

#include "../include/protocol.h"
#include "../include/constants.h"
#include "../include/error_codes.h"

#define MAX_CLIENTS 256  // Maximum number of clients we can track

// Using utils as compiled objects via Makefile
int create_server_socket(int port);
int receive_message(int sockfd, Message *msg);
int send_message(int sockfd, Message *msg);
void log_event(const char *filename, const char *component, const char *event);
void log_event_detailed(const char *filename, const char *component, 
                       const char *operation, const char *username,
                       const char *ip, int port, const char *details,
                       int display_terminal);

// From nm_registry.c
void nm_load_persisted_files();
void nm_get_cache_stats(unsigned long *hits, unsigned long *misses, int *size);
int nm_register_ss(const char *name, const char *ip, int client_port);
int nm_choose_ss();
void nm_remove_client(const char *user);
int nm_create_file(const char *fname, const char *user, int ss_id, char *errbuf, size_t errlen);
int nm_view(int flags, const char *user, char *out, size_t outlen);
int nm_info(const char *fname, char *out, size_t outlen);
int nm_can_create(const char *fname, char *errbuf, size_t errlen);
int nm_get_ss_ip_port(int ss_id, char *ip, size_t iplen, int *port_out);
int nm_resolve_for_read(char *filename, char *username, char *ss_ip_out, int *ss_port_out);
int nm_resolve_for_write(char *filename, char *username, char *ss_ip_out, int *ss_port_out);
int nm_resolve_for_undo(char *filename, char *username, char *ss_ip_out, int *ss_port_out);
int nm_track_client(const char *user, const char *ip, int port);  // Returns 1 if new client, 0 if existing
int nm_list_users(char *out, size_t outlen);
int nm_check_read(const char *fname, const char *user);
int nm_check_write(const char *fname, const char *user);
int nm_addaccess(const char *fname, const char *requestor, const char *mode, const char *target_user);
int nm_remaccess(const char *fname, const char *requestor, const char *target_user);
int nm_delete_entry(const char *fname);
int nm_is_owner(const char *fname, const char *user);
int nm_check_read(const char *fname, const char *user);
int nm_get_ss_id(const char *filename);
int nm_move_file(const char *fname, const char *folder, char *errbuf, size_t errlen);
int nm_request_access(const char *fname, const char *user, char type);
int nm_list_requests(const char *owner, char *out, size_t outlen);
int nm_approve_request(const char *owner, const char *fname, const char *requester, char type);
int nm_deny_request(const char *owner, const char *fname, const char *requester, char type);
// Health helpers from registry
void nm_mark_ss_dead(int ss_id);
void nm_mark_ss_alive(int ss_id);
int nm_server_is_alive(int ss_id);
int nm_get_server_count();
int nm_get_ss_name(int ss_id, char *name, size_t namelen);
void nm_update_ss_name(int ss_id, const char *new_name);
#ifndef MAX_SS
#define MAX_SS 64
#endif

// Forward declarations for pending request helpers (defined later)
static void add_pending_req(const char *req_id, const char *client_ip, int client_port, const char *username, const char *filename, int ss_id);
static int find_pending_idx_by_req(const char *req_id);
static void remove_pending_idx(int idx);

// Registry helpers implemented in nm_registry.c
void nm_cache_invalidate(const char *fname, const char *reason);
int nm_update_after_write(const char *fname, const char *user, int words, int chars, int new_version);
int nm_mark_access(const char *fname, const char *user);

int connect_to_server(char *ip, int port);
void replicate_file_async(const char *filename);

// Forward declarations for health helpers
// Non-fatal connect helper (returns -1 on failure)
static int try_connect_nofatal(const char *ip, int port);

// Helper to get client IP from socket
static void get_client_info(int sock, char *ip_out, int *port_out) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    if (getpeername(sock, (struct sockaddr*)&addr, &addr_len) == 0) {
        inet_ntop(AF_INET, &addr.sin_addr, ip_out, 32);
        *port_out = ntohs(addr.sin_port);
    } else {
        strcpy(ip_out, "unknown");
        *port_out = 0;
    }
}

static void handle_register_ss(int sock, Message *msg, struct sockaddr_in *addr) {
    char ip[32];
    inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
    // Parse payload of the form: "ip=<ip>,nm_port=<n>,client_port=<p>,files=<csv>"
    int client_port = 0;
    char payload_ip[32] = "";
    char files_csv[2048] = "";
    
    if (msg->payload[0]) {
        // Make a copy to tokenize safely
        char tmp[sizeof(msg->payload)];
        strncpy(tmp, msg->payload, sizeof(tmp)-1);
        tmp[sizeof(tmp)-1] = '\0';
        char *save = NULL; char *tok = strtok_r(tmp, ",", &save);
        while (tok) {
            while (*tok == ' ') tok++;
            if (strncmp(tok, "client_port=", 12) == 0) {
                client_port = atoi(tok + 12);
            } else if (strncmp(tok, "ip=", 3) == 0) {
                strncpy(payload_ip, tok + 3, sizeof(payload_ip)-1);
                payload_ip[sizeof(payload_ip)-1] = '\0';
            } else if (strncmp(tok, "files=", 6) == 0) {
                strncpy(files_csv, tok + 6, sizeof(files_csv)-1);
                files_csv[sizeof(files_csv)-1] = '\0';
            }
            tok = strtok_r(NULL, ",", &save);
        }
    }
    
    // Prefer payload IP if provided (useful when behind NAT); else use peer IP
    const char *reg_ip = (payload_ip[0] ? payload_ip : ip);
    int ss_id = nm_register_ss(msg->username, reg_ip, client_port);
    
    // Update SS name to proper format (SS0, SS1, etc.)
    char proper_name[64];
    snprintf(proper_name, sizeof(proper_name), "SS%d", ss_id);
    nm_update_ss_name(ss_id, proper_name);
    
    // Process file list from SS and register files with this ss_id
    int files_registered = 0;
    if (files_csv[0]) {
        char *file_tok = strtok(files_csv, ";");
        while (file_tok) {
            // Skip empty entries
            while (*file_tok == ' ') file_tok++;
            if (*file_tok && strcmp(file_tok, "NONE") != 0) {
                // Register this file with the SS
                // Use nm_create_file to add it to registry
                char owner[64] = "system";  // Files from SS are system-owned by default
                char err[128];
                int create_result = nm_create_file(file_tok, owner, ss_id, err, sizeof(err));
                if (create_result == SUCCESS) {
                    files_registered++;
                    // Don't print individual files to avoid accessing them unnecessarily
                }
            }
            file_tok = strtok(NULL, ";");
        }
    }
    
    snprintf(msg->payload, sizeof(msg->payload), 
             "Registered SS (ss_id=%d, %d files)", ss_id, files_registered);
    msg->status_code = SUCCESS;
    send_message(sock, msg);
    
    char log_buf[256];
    snprintf(log_buf, sizeof(log_buf), "SS%d registered with %d files", 
             ss_id, files_registered);
    log_event("logs/nm.log", "NM", log_buf);
}

// Pending requests tracked by NM to correlate SS notifications back to clients
#define MAX_PENDING 512
typedef struct {
    char req_id[64];
    struct timeval start;
    char client_ip[32];
    int client_port;
    char username[64];
    char filename[256];
    int ss_id;
} PendingReq;
static PendingReq pending_reqs[MAX_PENDING];
static int pending_count = 0;

static void add_pending_req(const char *req_id, const char *client_ip, int client_port, const char *username, const char *filename, int ss_id) {
    if (pending_count >= MAX_PENDING) return;
    PendingReq *p = &pending_reqs[pending_count++];
    strncpy(p->req_id, req_id, sizeof(p->req_id)-1);
    gettimeofday(&p->start, NULL);
    strncpy(p->client_ip, client_ip, sizeof(p->client_ip)-1);
    p->client_port = client_port;
    strncpy(p->username, username, sizeof(p->username)-1);
    strncpy(p->filename, filename, sizeof(p->filename)-1);
    p->ss_id = ss_id;
}

static int find_pending_idx_by_req(const char *req_id) {
    for (int i = 0; i < pending_count; ++i) {
        if (strcmp(pending_reqs[i].req_id, req_id) == 0) return i;
    }
    return -1;
}

static void remove_pending_idx(int idx) {
    if (idx < 0 || idx >= pending_count) return;
    for (int i = idx; i < pending_count - 1; ++i) pending_reqs[i] = pending_reqs[i+1];
    pending_count--;
}

// Function to track client sockets for disconnect detection


static void handle_client_req(int sock, Message *msg) {
    // Get client IP and port for logging
    char client_ip[32];
    int client_port = 0;
    get_client_info(sock, client_ip, &client_port);
    // generate a request id for tracing
    struct timeval tvtmp; gettimeofday(&tvtmp, NULL);
    snprintf(msg->req_id, sizeof(msg->req_id), "%lx%lx", (unsigned long)tvtmp.tv_sec, (unsigned long)tvtmp.tv_usec);
    // Single log entry per request with operation details
    char reqlog[512]; 
    snprintf(reqlog, sizeof(reqlog), "id=%s op=%s file=%s", 
             msg->req_id, msg->command, msg->filename);
    log_event_detailed("logs/nm.log", "NM", "REQ", msg->username, client_ip, client_port, reqlog, 1);
    
    if (strcmp(msg->command, OP_CREATE) == 0) {
        char err[128];
        int rc = nm_can_create(msg->filename, err, sizeof(err));
        if (rc != SUCCESS) {
            msg->status_code = rc;
            snprintf(msg->payload, sizeof(msg->payload), "CREATE ERR: %s", err);
            send_message(sock, msg);
            return;
        }
        
        // Try to create on an available SS, with fallback to other SSs
        int ss_id = -1;
        int ssock = -1;
        Message fwd;
        int max_attempts = nm_get_server_count();
        
        for (int attempt = 0; attempt < max_attempts; attempt++) {
            ss_id = nm_choose_ss();
            char ip[32]; int port = 0;
            
            if (nm_get_ss_ip_port(ss_id, ip, sizeof(ip), &port) != 0) {
                continue; // Try next SS
            }
            
            // Try to connect to this SS
            ssock = connect_to_server(ip, port);
            if (ssock < 0) {
                // SS unavailable, try next one
                continue;
            }
            
            // Send CREATE request
            memset(&fwd, 0, sizeof(fwd));
            strcpy(fwd.command, OP_CREATE);
            strncpy(fwd.filename, msg->filename, sizeof(fwd.filename)-1);
            strncpy(fwd.username, msg->username, sizeof(fwd.username)-1);
            
            if (send_message(ssock, &fwd) <= 0 || receive_message(ssock, &fwd) <= 0) {
                close(ssock);
                ssock = -1;
                continue; // Try next SS
            }
            
            // Successfully communicated with SS
            break;
        }
        
        // Check if we successfully found an SS
        if (ssock < 0 || ss_id < 0) {
            msg->status_code = ERR_INTERNAL;
            strcpy(msg->payload, "CREATE ERR: no storage server available");
            send_message(sock, msg);
            return;
        }
        
        close(ssock);
        
        if (fwd.status_code == SUCCESS) {
            int rc2 = nm_create_file(msg->filename, msg->username, ss_id, err, sizeof(err));
            if (rc2 == SUCCESS) {
                msg->status_code = SUCCESS;
                // Get replica assignment to include in response
                int replica_id = nm_get_replica_ss_id(msg->filename);
                if (replica_id >= 0) {
                    snprintf(msg->payload, sizeof(msg->payload), 
                             "CREATE OK on SS %d (replica: SS %d)", ss_id, replica_id);
                } else {
                    snprintf(msg->payload, sizeof(msg->payload), 
                             "CREATE OK on SS %d (no replica)", ss_id);
                }
                // Trigger initial replication for empty file to ensure replica sidecar/meta exists
                replicate_file_async(msg->filename);
            } else {
                msg->status_code = rc2;
                snprintf(msg->payload, sizeof(msg->payload), "CREATE ERR: %s", err);
            }
        } else {
            msg->status_code = fwd.status_code;
            snprintf(msg->payload, sizeof(msg->payload), "CREATE ERR at SS: %s", fwd.payload);
        }
        send_message(sock, msg);
        
        // Single result log
        char log_buf[256];
        snprintf(log_buf, sizeof(log_buf), "file=%s ss=%d result=%s", 
                 msg->filename, ss_id, msg->status_code == SUCCESS ? "OK" : "FAILED");
        log_event_detailed("logs/nm.log", "NM", "CREATE", msg->username, client_ip, client_port, log_buf, 1);
    } else if (strcmp(msg->command, OP_VIEW) == 0) {
        int flags = 0;
        for (const char *p = msg->payload; *p; ++p) {
            if (*p == 'a') flags |= 1;
            if (*p == 'l') flags |= 2;
            if (*p == 's') flags |= 4;  // show SS information
        }
        int rc = nm_view(flags, msg->username, msg->payload, sizeof(msg->payload));
        msg->status_code = rc;
        send_message(sock, msg);
        
        char log_buf[128];
        snprintf(log_buf, sizeof(log_buf), "flags=0x%x result=%s", flags, rc == SUCCESS ? "OK" : "FAILED");
        log_event_detailed("logs/nm.log", "NM", "VIEW", msg->username, client_ip, client_port, log_buf, 1);
        
    } else if (strcmp(msg->command, OP_INFO) == 0) {
    // Mark access prior to generating info (updates last_access timestamp and user)
    nm_mark_access(msg->filename, msg->username);
    int rc = nm_info(msg->filename, msg->payload, sizeof(msg->payload));
        msg->status_code = rc;
        send_message(sock, msg);
        
        char log_buf[128];
        snprintf(log_buf, sizeof(log_buf), "file=%s result=%s", msg->filename, rc == SUCCESS ? "OK" : "FAILED");
        log_event_detailed("logs/nm.log", "NM", "INFO", msg->username, client_ip, client_port, log_buf, 1);
    } else if (strcmp(msg->command, OP_RESOLVE_READ_S) == 0 || msg->op_code == OP_RESOLVE_READ) {
        char ip[32]; int port = 0;
        int rc = nm_check_read(msg->filename, msg->username);
        if (rc == SUCCESS) rc = nm_resolve_for_read(msg->filename, msg->username, ip, &port);
        msg->status_code = rc;
        
        if (rc == SUCCESS) {
            snprintf(msg->payload, sizeof(msg->payload), "%s:%d", ip, port);
        } else if (rc == ERR_FILE_NOT_FOUND) {
            strcpy(msg->payload, "File not found");
        } else if (rc == ERR_PERMISSION_DENIED) {
            strcpy(msg->payload, "Access denied");
        } else {
            strcpy(msg->payload, "Resolve error");
        }
        send_message(sock, msg);
        
        char log_buf[128];
        snprintf(log_buf, sizeof(log_buf), "file=%s result=%s", msg->filename, rc == SUCCESS ? "OK" : "FAILED");
        log_event_detailed("logs/nm.log", "NM", "RESOLVE_READ", msg->username, client_ip, client_port, log_buf, 1);
        
    } else if (strcmp(msg->command, OP_RESOLVE_STREAM_S) == 0 || msg->op_code == OP_RESOLVE_STREAM) {
        char ip[32]; int port = 0;
        int rc = nm_check_read(msg->filename, msg->username);
        if (rc == SUCCESS) rc = nm_resolve_for_read(msg->filename, msg->username, ip, &port);
        msg->status_code = rc;
        
        if (rc == SUCCESS) {
            snprintf(msg->payload, sizeof(msg->payload), "%s:%d", ip, port);
        } else if (rc == ERR_FILE_NOT_FOUND) {
            strcpy(msg->payload, "File not found");
        } else if (rc == ERR_PERMISSION_DENIED) {
            strcpy(msg->payload, "Access denied");
        } else {
            strcpy(msg->payload, "Resolve error");
        }
        send_message(sock, msg);
        
        char log_buf[128];
        snprintf(log_buf, sizeof(log_buf), "file=%s result=%s", msg->filename, rc == SUCCESS ? "OK" : "FAILED");
        log_event_detailed("logs/nm.log", "NM", "RESOLVE_STREAM", msg->username, client_ip, client_port, log_buf, 1);
    } else if (strcmp(msg->command, OP_WRITE_REQUEST_S) == 0 || msg->op_code == OP_WRITE_REQUEST) {
        char ip[32]; int port = 0;
        int rc = nm_check_write(msg->filename, msg->username);
        
        struct timeval lookup_start, lookup_end;
        gettimeofday(&lookup_start, NULL);
        if (rc == SUCCESS) rc = nm_resolve_for_write(msg->filename, msg->username, ip, &port);
        gettimeofday(&lookup_end, NULL);
        double lookup_ms = (lookup_end.tv_sec - lookup_start.tv_sec) * 1000.0 + 
                           (lookup_end.tv_usec - lookup_start.tv_usec) / 1000.0;
        
        msg->status_code = rc;
        if (rc == SUCCESS) {
            snprintf(msg->payload, sizeof(msg->payload), "%s:%d", ip, port);
            int ssid = nm_get_ss_id(msg->filename);
            
            char log_buf[256];
            snprintf(log_buf, sizeof(log_buf), "file=%s ss=%d time=%.3fms", msg->filename, ssid, lookup_ms);
            log_event_detailed("logs/nm.log", "NM", "LOOKUP", msg->username, client_ip, client_port, log_buf, 1);
            
            snprintf(log_buf, sizeof(log_buf), "id=%s ss=%d op=WRITE", msg->req_id, ssid);
            log_event_detailed("logs/nm.log", "NM", "FORWARD", msg->username, client_ip, client_port, log_buf, 1);
            
            add_pending_req(msg->req_id, client_ip, client_port, msg->username, msg->filename, ssid);
        } else if (rc == ERR_FILE_NOT_FOUND) {
            strcpy(msg->payload, "File not found");
            char log_buf[128]; 
            snprintf(log_buf, sizeof(log_buf), "file=%s result=NOT_FOUND", msg->filename);
            log_event_detailed("logs/nm.log", "NM", "LOOKUP", msg->username, client_ip, client_port, log_buf, 1);
        } else if (rc == ERR_PERMISSION_DENIED) {
            strcpy(msg->payload, "Access denied");
            char log_buf[128]; 
            snprintf(log_buf, sizeof(log_buf), "file=%s result=DENIED", msg->filename);
            log_event_detailed("logs/nm.log", "NM", "LOOKUP", msg->username, client_ip, client_port, log_buf, 1);
        } else {
            strcpy(msg->payload, "Write resolve error");
            char log_buf[128]; 
            snprintf(log_buf, sizeof(log_buf), "file=%s result=ERROR", msg->filename);
            log_event_detailed("logs/nm.log", "NM", "LOOKUP", msg->username, client_ip, client_port, log_buf, 1);
        }
        send_message(sock, msg);
    } else if (strcmp(msg->command, OP_WRITE_NOTIFY_S) == 0 || msg->op_code == OP_WRITE_NOTIFY) {
        char reqid[64] = ""; char fname[256] = ""; int ssid = -1; int ver = 0; int words = 0; int chars = 0;
        char *p = msg->payload; char tok[256];
        while (p && *p) {
            char *comma = strchr(p, ','); size_t len = comma ? (size_t)(comma - p) : strlen(p);
            if (len < sizeof(tok)) { strncpy(tok, p, len); tok[len] = '\0'; }
            else { tok[0]='\0'; }
            if (strncmp(tok, "req_id=", 7) == 0) strncpy(reqid, tok+7, sizeof(reqid)-1);
            else if (strncmp(tok, "file=", 5) == 0) strncpy(fname, tok+5, sizeof(fname)-1);
            else if (strncmp(tok, "ss_id=", 6) == 0) ssid = atoi(tok+6);
            else if (strncmp(tok, "ver=", 4) == 0) ver = atoi(tok+4);
            else if (strncmp(tok, "words=", 6) == 0) words = atoi(tok+6);
            else if (strncmp(tok, "chars=", 6) == 0) chars = atoi(tok+6);
            if (!comma) break; p = comma + 1;
        }
        
        int idx = -1;
        if (reqid[0]) idx = find_pending_idx_by_req(reqid);
        
        // Single ACK log
        char log_buf[256];
        snprintf(log_buf, sizeof(log_buf), "id=%s ss=%d ver=%d words=%d chars=%d", 
                 reqid[0]?reqid:msg->req_id, ssid, ver, words, chars);
        log_event_detailed("logs/nm.log", "NM", "ACK", msg->username, client_ip, client_port, log_buf, 1);
        
        if (fname[0]) {
            nm_cache_invalidate(fname, "WRITE_COMMIT");
            nm_update_after_write(fname, msg->username, words, chars, ver);
            // Replicate updated contents to replica (if any)
            replicate_file_async(fname);
        }
        
        // RESP: compute latency and emit response log
        if (idx >= 0) {
            struct timeval now; gettimeofday(&now, NULL);
            double latency = (now.tv_sec - pending_reqs[idx].start.tv_sec) + 
                           (now.tv_usec - pending_reqs[idx].start.tv_usec)/1000000.0;
            snprintf(log_buf, sizeof(log_buf), "id=%s latency=%.3fs ver=%d",
                    pending_reqs[idx].req_id, latency, ver);
            log_event_detailed("logs/nm.log", "NM", "RESP", pending_reqs[idx].username, 
                             pending_reqs[idx].client_ip, pending_reqs[idx].client_port, log_buf, 1);
            remove_pending_idx(idx);
        }
        msg->status_code = SUCCESS; strcpy(msg->payload, "NOTED"); send_message(sock, msg);
    } else if (strcmp(msg->command, OP_UNDO_S) == 0 || msg->op_code == OP_UNDO) {
        char ip[32]; int port = 0;
        // UNDO requires write permission as per TA clarification
        int rc = nm_resolve_for_write(msg->filename, msg->username, ip, &port);
        if (rc != SUCCESS) {
            msg->status_code = rc;
            if (rc == ERR_FILE_NOT_FOUND) strcpy(msg->payload, "File not found");
            else if (rc == ERR_PERMISSION_DENIED) strcpy(msg->payload, "Access denied");
            else strcpy(msg->payload, "Resolve error");
            send_message(sock, msg);
            return;
        }
        
        int ssock = connect_to_server(ip, port);
        Message fwd; memset(&fwd, 0, sizeof(fwd));
        strcpy(fwd.command, OP_UNDO_S); 
        strncpy(fwd.filename, msg->filename, sizeof(fwd.filename)-1);
        strncpy(fwd.username, msg->username, sizeof(fwd.username)-1);
        if (ssock < 0 || send_message(ssock, &fwd) <= 0 || receive_message(ssock, &fwd) <= 0) {
            if (ssock >= 0) close(ssock);
            msg->status_code = ERR_INTERNAL; strcpy(msg->payload, "UNDO ERR: SS unavailable");
            send_message(sock, msg);
            return;
        }
        close(ssock);
        
        msg->status_code = fwd.status_code;
        strncpy(msg->payload, fwd.payload, sizeof(msg->payload)-1);
        send_message(sock, msg);
        
        // If UNDO was successful, replicate the reverted state to replica
        if (fwd.status_code == SUCCESS) {
            replicate_file_async(msg->filename);
        }
        
        char log_buf[128];
        snprintf(log_buf, sizeof(log_buf), "file=%s result=%s", msg->filename, 
                 fwd.status_code == SUCCESS ? "OK" : "FAILED");
        log_event_detailed("logs/nm.log", "NM", "UNDO", msg->username, client_ip, client_port, log_buf, 1);
    } else if (strcmp(msg->command, "LOGOUT") == 0 || msg->op_code == OP_LOGOUT) {
        nm_remove_client(msg->username);
        msg->status_code = SUCCESS;
        strcpy(msg->payload, "Logged out");
        send_message(sock, msg);
        
        char log_buf[128];
        snprintf(log_buf, sizeof(log_buf), "user=%s", msg->username);
        log_event_detailed("logs/nm.log", "NM", "LOGOUT", msg->username, client_ip, client_port, log_buf, 1);
        
    } else if (strcmp(msg->command, OP_LIST_S) == 0 || msg->op_code == OP_LIST) {
        msg->status_code = nm_list_users(msg->payload, sizeof(msg->payload));
        send_message(sock, msg);
        
        char log_buf[128];
        snprintf(log_buf, sizeof(log_buf), "result=%s", msg->status_code == SUCCESS ? "OK" : "FAILED");
        log_event_detailed("logs/nm.log", "NM", "LIST", msg->username, client_ip, client_port, log_buf, 1);
        
    } else if (strcmp(msg->command, OP_ADDACCESS_S) == 0 || msg->op_code == OP_ADDACCESS) {
        char mode[2] = {0}; char target[64] = {0};
        sscanf(msg->payload, "%1[^|]|%63s", mode, target);
        int rc = nm_addaccess(msg->filename, msg->username, mode, target);
        msg->status_code = rc;
        if (rc==SUCCESS) strcpy(msg->payload, "OK"); 
        else strcpy(msg->payload, (rc==ERR_PERMISSION_DENIED)?"Access denied":"Error");
        send_message(sock, msg);
        
        char log_buf[128];
        snprintf(log_buf, sizeof(log_buf), "file=%s mode=%s target=%s result=%s", 
                 msg->filename, strcmp(mode, "R") == 0 ? "R" : "W", target, rc == SUCCESS ? "OK" : "FAILED");
        log_event_detailed("logs/nm.log", "NM", "ADDACCESS", msg->username, client_ip, client_port, log_buf, 1);
        
    } else if (strcmp(msg->command, OP_REMACCESS_S) == 0 || msg->op_code == OP_REMACCESS) {
        char target_user[64];
        strncpy(target_user, msg->payload, sizeof(target_user) - 1);
        target_user[sizeof(target_user) - 1] = '\0';
        int rc = nm_remaccess(msg->filename, msg->username, msg->payload);
        msg->status_code = rc;
        if (rc==SUCCESS) strcpy(msg->payload, "OK"); 
        else strcpy(msg->payload, (rc==ERR_PERMISSION_DENIED)?"Access denied":"Error");
        send_message(sock, msg);
        
        char log_buf[128];
        snprintf(log_buf, sizeof(log_buf), "file=%s target=%s result=%s", 
                 msg->filename, target_user, rc == SUCCESS ? "OK" : "FAILED");
        log_event_detailed("logs/nm.log", "NM", "REMACCESS", msg->username, client_ip, client_port, log_buf, 1);
    } else if (strcmp(msg->command, OP_DELETE_S) == 0 || msg->op_code == OP_DELETE) {
        char ip[32]; int port=0;
        int rc = nm_is_owner(msg->filename, msg->username);
        if (rc != SUCCESS) {
            msg->status_code = rc;
            if (rc == ERR_FILE_NOT_FOUND) strcpy(msg->payload, "File not found.");
            else strcpy(msg->payload, "Access denied.");
            send_message(sock, msg);
            
            char log_buf[128];
            snprintf(log_buf, sizeof(log_buf), "file=%s result=FAILED reason=%s", 
                     msg->filename, rc == ERR_FILE_NOT_FOUND ? "not_found" : "access_denied");
            log_event_detailed("logs/nm.log", "NM", "DELETE", msg->username, client_ip, client_port, log_buf, 1);
            return;
        }
        
        rc = nm_resolve_for_read(msg->filename, msg->username, ip, &port);
        if (rc != SUCCESS) { 
            msg->status_code=rc; strcpy(msg->payload, "Resolve error"); 
            send_message(sock, msg);
            
            char log_buf[128];
            snprintf(log_buf, sizeof(log_buf), "file=%s result=FAILED reason=resolve_error", msg->filename);
            log_event_detailed("logs/nm.log", "NM", "DELETE", msg->username, client_ip, client_port, log_buf, 1);
            return; 
        }
        
        int ssock = connect_to_server(ip, port); 
        Message fwd; memset(&fwd,0,sizeof(fwd)); 
        strcpy(fwd.command, OP_DELETE_S); 
        strncpy(fwd.filename, msg->filename, sizeof(fwd.filename)-1);
        strncpy(fwd.username, msg->username, sizeof(fwd.username)-1);
        if (ssock < 0 || send_message(ssock, &fwd) <= 0 || receive_message(ssock, &fwd) <= 0) {
            if (ssock >= 0) close(ssock);
            msg->status_code = ERR_INTERNAL; strcpy(msg->payload, "DELETE ERR: SS unavailable");
            send_message(sock, msg);
            
            char log_buf[128];
            snprintf(log_buf, sizeof(log_buf), "file=%s result=FAILED reason=SS_unavailable", msg->filename);
            log_event_detailed("logs/nm.log", "NM", "DELETE", msg->username, client_ip, client_port, log_buf, 1);
            return;
        }
        close(ssock);
        
        if (fwd.status_code == SUCCESS) { 
            // Delete from replica if exists
            int replica_id = nm_get_replica_ss_id(msg->filename);
            if (replica_id >= 0 && nm_server_is_alive(replica_id)) {
                char rep_ip[32]; int rep_port = 0;
                if (nm_get_ss_ip_port(replica_id, rep_ip, sizeof(rep_ip), &rep_port) == 0) {
                    int rep_sock = try_connect_nofatal(rep_ip, rep_port);
                    if (rep_sock >= 0) {
                        Message rep_del; memset(&rep_del, 0, sizeof(rep_del));
                        strcpy(rep_del.command, OP_DELETE_S);
                        strncpy(rep_del.filename, msg->filename, sizeof(rep_del.filename)-1);
                        strncpy(rep_del.username, msg->username, sizeof(rep_del.username)-1);
                        send_message(rep_sock, &rep_del);
                        receive_message(rep_sock, &rep_del); // ignore result
                        close(rep_sock);
                    }
                }
            }
            
            nm_delete_entry(msg->filename); 
            msg->status_code=SUCCESS; 
            strcpy(msg->payload, "DELETE OK"); 
        } else { 
            msg->status_code=fwd.status_code; 
            strncpy(msg->payload, fwd.payload, sizeof(msg->payload)-1); 
        }
        send_message(sock, msg);
        
        char log_buf[128];
        snprintf(log_buf, sizeof(log_buf), "file=%s result=%s", 
                 msg->filename, fwd.status_code == SUCCESS ? "OK" : "FAILED");
        log_event_detailed("logs/nm.log", "NM", "DELETE", msg->username, client_ip, client_port, log_buf, 1);
        
    } else if (strcmp(msg->command, OP_EXEC_S) == 0 || msg->op_code == OP_EXEC) {
        if (nm_check_read(msg->filename, msg->username) != SUCCESS) {
            msg->status_code = ERR_PERMISSION_DENIED; 
            strcpy(msg->payload, "Error: Access denied."); 
            send_message(sock, msg);
            
            char log_buf[128];
            snprintf(log_buf, sizeof(log_buf), "file=%s result=FAILED reason=access_denied", msg->filename);
            log_event_detailed("logs/nm.log", "NM", "EXEC", msg->username, client_ip, client_port, log_buf, 1);
            return;
        }
        
        char ip[32]; int port=0; 
        int rc = nm_resolve_for_read(msg->filename, msg->username, ip, &port);
        if (rc != SUCCESS) { 
            msg->status_code=rc; strcpy(msg->payload, "Resolve error"); 
            send_message(sock, msg);
            
            char log_buf[128];
            snprintf(log_buf, sizeof(log_buf), "file=%s result=FAILED reason=resolve_error", msg->filename);
            log_event_detailed("logs/nm.log", "NM", "EXEC", msg->username, client_ip, client_port, log_buf, 1);
            return; 
        }
        
    int ssock = connect_to_server(ip, port);
        Message rq; memset(&rq,0,sizeof(rq)); 
        rq.op_code=OP_READ; strcpy(rq.command, OP_READ_S); 
        strncpy(rq.filename, msg->filename, sizeof(rq.filename)-1);
        strncpy(rq.username, msg->username, sizeof(rq.username)-1);
    if (ssock < 0 || send_message(ssock, &rq) <= 0) { if (ssock>=0) close(ssock); msg->status_code=ERR_INTERNAL; strcpy(msg->payload, "Error: SS unavailable."); send_message(sock, msg); return; }
    Message rr; if (receive_message(ssock, &rr)<=0 || rr.status_code!=SUCCESS) { close(ssock); msg->status_code=ERR_INTERNAL; strcpy(msg->payload, "Error: Could not fetch file."); send_message(sock, msg); return; }
        close(ssock);
        // Write content to a temp script file
        char tmpl[] = "/tmp/langos_exec_XXXXXX"; int fd = mkstemp(tmpl);
        if (fd < 0) { msg->status_code=ERR_INTERNAL; strcpy(msg->payload, "Error: Temp file failed."); send_message(sock, msg); return; }
        FILE *tf = fdopen(fd, "w"); if (!tf) { close(fd); msg->status_code=ERR_INTERNAL; strcpy(msg->payload, "Error: Temp open failed."); send_message(sock, msg); return; }
        fputs(rr.payload, tf); fclose(tf);
        // Execute via shell and stream stdout
        char cmd[1024]; snprintf(cmd, sizeof(cmd), "/bin/sh %s", tmpl);
        FILE *out = popen(cmd, "r");
        if (!out) { unlink(tmpl); msg->status_code=ERR_INTERNAL; strcpy(msg->payload, "Error: Could not execute commands."); send_message(sock, msg); return; }
        char line[512];
        while (fgets(line, sizeof(line), out)) {
            // stream each line back
            Message outm; memset(&outm,0,sizeof(outm)); outm.status_code=SUCCESS; strncpy(outm.payload, line, sizeof(outm.payload)-1);
            // trim trailing newlines for display parity
            size_t L=strlen(outm.payload); while(L>0&&(outm.payload[L-1]=='\n'||outm.payload[L-1]=='\r')) outm.payload[--L]='\0';
            send_message(sock, &outm);
        }
        pclose(out); unlink(tmpl);
        Message end; memset(&end,0,sizeof(end)); 
        strcpy(end.payload, "STOP"); end.status_code=SUCCESS; 
        send_message(sock, &end);
        
        char log_buf[128]; 
        snprintf(log_buf, sizeof(log_buf), "file=%s result=OK", msg->filename);
        log_event_detailed("logs/nm.log", "NM", "EXEC", msg->username, client_ip, client_port, log_buf, 1);
    } else if (strcmp(msg->command, OP_CREATEFOLDER_S) == 0) {
        // payload unused; filename holds folder path (allow nested like a/b/c)
        if (!msg->filename[0]) { msg->status_code=ERR_BAD_REQUEST; strcpy(msg->payload, "Folder name required"); send_message(sock,msg); return; }
        char path[512]; snprintf(path, sizeof(path), "data/%s", msg->filename);
        int rc = mkdir(path, 0755);
        if (rc==0) { msg->status_code=SUCCESS; strcpy(msg->payload, "FOLDER OK"); }
        else { msg->status_code=ERR_BAD_REQUEST; strcpy(msg->payload, "Folder exists or invalid"); }
        send_message(sock, msg);
        char log_buf[128]; snprintf(log_buf,sizeof(log_buf), "folder=%s result=%s", msg->filename, msg->status_code==SUCCESS?"OK":"FAILED");
        log_event_detailed("logs/nm.log","NM","CREATEFOLDER", msg->username, client_ip, client_port, log_buf,1);
    } else if (strcmp(msg->command, OP_MOVE_S) == 0) {
        // payload holds target folder; filename holds file name (relative)
        if (!msg->filename[0] || !msg->payload[0]) { msg->status_code=ERR_BAD_REQUEST; strcpy(msg->payload, "Args missing"); send_message(sock,msg); return; }
        // Check ownership or write access
        int ow = nm_check_write(msg->filename, msg->username); if (ow!=SUCCESS) { msg->status_code=ow; strcpy(msg->payload, "Access denied"); send_message(sock,msg); return; }
        char errbuf[128];
        int rc = nm_move_file(msg->filename, msg->payload, errbuf, sizeof(errbuf));
        msg->status_code = rc;
        if (rc==SUCCESS) strcpy(msg->payload, "MOVE OK"); else snprintf(msg->payload,sizeof(msg->payload), "Move failed: %s", errbuf);
        send_message(sock,msg);
        char log_buf[160]; snprintf(log_buf,sizeof(log_buf),"file=%s folder=%s result=%s", msg->filename, msg->payload, msg->status_code==SUCCESS?"OK":"FAILED");
        log_event_detailed("logs/nm.log","NM","MOVE", msg->username, client_ip, client_port, log_buf,1);
    } else if (strcmp(msg->command, OP_VIEWFOLDER_S) == 0) {
        char folder[256]; strncpy(folder, msg->filename, sizeof(folder)-1); folder[sizeof(folder)-1]='\0';
        if (!folder[0]) { msg->status_code=ERR_BAD_REQUEST; strcpy(msg->payload, "Folder required"); send_message(sock,msg); return; }
        char path[512]; snprintf(path,sizeof(path),"data/%s", folder);
        struct stat st; if (stat(path,&st)!=0 || !S_ISDIR(st.st_mode)) { msg->status_code=ERR_FILE_NOT_FOUND; strcpy(msg->payload, "Folder not found"); send_message(sock,msg); return; }
        int lrc = nm_list_folder(folder, msg->username, msg->payload, sizeof(msg->payload));
        msg->status_code = (lrc==SUCCESS?SUCCESS:lrc);
        if (lrc!=SUCCESS) strcpy(msg->payload,"List failed");
        send_message(sock,msg);
        char log_buf[128]; snprintf(log_buf,sizeof(log_buf),"folder=%s listed rc=%d", folder, lrc);
        log_event_detailed("logs/nm.log","NM","VIEWFOLDER", msg->username, client_ip, client_port, log_buf,1);
    } else if (strcmp(msg->command, OP_CHECKPOINT_S) == 0) {
        // write permission required
        int perm = nm_check_write(msg->filename, msg->username);
        if (perm != SUCCESS) { msg->status_code=perm; strcpy(msg->payload, "Access denied"); send_message(sock,msg); return; }
        char ip[32]; int port=0; int rc = nm_resolve_for_write(msg->filename, msg->username, ip, &port);
        if (rc != SUCCESS) { msg->status_code=rc; strcpy(msg->payload, "Resolve error"); send_message(sock,msg); return; }
        int ssock = connect_to_server(ip, port);
        Message f; memset(&f,0,sizeof(f)); strcpy(f.command, OP_CHECKPOINT_S);
        strncpy(f.username, msg->username, sizeof(f.username)-1);
        strncpy(f.filename, msg->filename, sizeof(f.filename)-1);
        strncpy(f.payload, msg->payload, sizeof(f.payload)-1); // tag
        if (ssock < 0 || send_message(ssock, &f) <= 0 || receive_message(ssock, &f) <= 0) {
            if (ssock >= 0) close(ssock);
            msg->status_code = ERR_INTERNAL; strcpy(msg->payload, "Checkpoint failed: SS unavailable");
            send_message(sock, msg); return;
        }
        close(ssock);
        msg->status_code = f.status_code; strncpy(msg->payload, f.payload, sizeof(msg->payload)-1); 
        
        // If checkpoint was successful, replicate to replica
        if (f.status_code == SUCCESS) {
            int replica_id = nm_get_replica_ss_id(msg->filename);
            if (replica_id >= 0 && nm_server_is_alive(replica_id)) {
                char rep_ip[32]; int rep_port = 0;
                if (nm_get_ss_ip_port(replica_id, rep_ip, sizeof(rep_ip), &rep_port) == 0) {
                    int rep_sock = try_connect_nofatal(rep_ip, rep_port);
                    if (rep_sock >= 0) {
                        Message rep_cp; memset(&rep_cp, 0, sizeof(rep_cp));
                        strcpy(rep_cp.command, OP_CHECKPOINT_S);
                        strncpy(rep_cp.username, msg->username, sizeof(rep_cp.username)-1);
                        strncpy(rep_cp.filename, msg->filename, sizeof(rep_cp.filename)-1);
                        strncpy(rep_cp.payload, msg->payload, sizeof(rep_cp.payload)-1);
                        send_message(rep_sock, &rep_cp);
                        receive_message(rep_sock, &rep_cp); // ignore result
                        close(rep_sock);
                    }
                }
            }
        }
        
        send_message(sock,msg);
        char log_buf[128]; snprintf(log_buf,sizeof(log_buf),"file=%s tag=%s rc=%d", msg->filename, msg->payload, msg->status_code); log_event_detailed("logs/nm.log","NM","CHECKPOINT", msg->username, client_ip, client_port, log_buf,1);
    } else if (strcmp(msg->command, OP_VIEWCHECKPOINT_S) == 0) {
        // read permission required
        int perm = nm_check_read(msg->filename, msg->username);
        if (perm != SUCCESS) { msg->status_code=perm; strcpy(msg->payload, "Access denied"); send_message(sock,msg); return; }
        char ip[32]; int port=0; int rc = nm_resolve_for_read(msg->filename, msg->username, ip, &port);
        if (rc != SUCCESS) { msg->status_code=rc; strcpy(msg->payload, "Resolve error"); send_message(sock,msg); return; }
        int ssock = connect_to_server(ip, port);
        Message f; memset(&f,0,sizeof(f)); strcpy(f.command, OP_VIEWCHECKPOINT_S);
        strncpy(f.username, msg->username, sizeof(f.username)-1);
        strncpy(f.filename, msg->filename, sizeof(f.filename)-1);
        strncpy(f.payload, msg->payload, sizeof(f.payload)-1); // tag
        if (ssock < 0 || send_message(ssock, &f) <= 0 || receive_message(ssock, &f) <= 0) {
            if (ssock >= 0) close(ssock);
            msg->status_code = ERR_INTERNAL; strcpy(msg->payload, "View checkpoint failed: SS unavailable");
            send_message(sock, msg); return;
        }
        close(ssock);
        msg->status_code = f.status_code; strncpy(msg->payload, f.payload, sizeof(msg->payload)-1); send_message(sock,msg);
        char log_buf[128]; snprintf(log_buf,sizeof(log_buf),"file=%s tag=%s rc=%d", msg->filename, msg->payload, msg->status_code); log_event_detailed("logs/nm.log","NM","VIEWCHECKPOINT", msg->username, client_ip, client_port, log_buf,1);
    } else if (strcmp(msg->command, OP_REVERT_S) == 0) {
        // write permission required
        int perm = nm_check_write(msg->filename, msg->username);
        if (perm != SUCCESS) { msg->status_code=perm; strcpy(msg->payload, "Access denied"); send_message(sock,msg); return; }
        char ip[32]; int port=0; int rc = nm_resolve_for_write(msg->filename, msg->username, ip, &port);
        if (rc != SUCCESS) { msg->status_code=rc; strcpy(msg->payload, "Resolve error"); send_message(sock,msg); return; }
        int ssock = connect_to_server(ip, port);
        Message f; memset(&f,0,sizeof(f)); strcpy(f.command, OP_REVERT_S);
        strncpy(f.username, msg->username, sizeof(f.username)-1);
        strncpy(f.filename, msg->filename, sizeof(f.filename)-1);
        strncpy(f.payload, msg->payload, sizeof(f.payload)-1); // tag
        if (ssock < 0 || send_message(ssock, &f) <= 0 || receive_message(ssock, &f) <= 0) {
            if (ssock >= 0) close(ssock);
            msg->status_code = ERR_INTERNAL; strcpy(msg->payload, "Revert failed: SS unavailable");
            send_message(sock, msg); return;
        }
        close(ssock);
        msg->status_code = f.status_code; strncpy(msg->payload, f.payload, sizeof(msg->payload)-1); 
        
        // If revert was successful, replicate the reverted state to replica
        if (f.status_code == SUCCESS) {
            replicate_file_async(msg->filename);
        }
        
        send_message(sock,msg);
        char log_buf[128]; snprintf(log_buf,sizeof(log_buf),"file=%s tag=%s rc=%d", msg->filename, msg->payload, msg->status_code); log_event_detailed("logs/nm.log","NM","REVERT", msg->username, client_ip, client_port, log_buf,1);
    } else if (strcmp(msg->command, OP_LISTCHECKPOINTS_S) == 0) {
        // read permission required to list
        int perm = nm_check_read(msg->filename, msg->username);
        if (perm != SUCCESS) { msg->status_code=perm; strcpy(msg->payload, "Access denied"); send_message(sock,msg); return; }
        char ip[32]; int port=0; int rc = nm_resolve_for_read(msg->filename, msg->username, ip, &port);
        if (rc != SUCCESS) { msg->status_code=rc; strcpy(msg->payload, "Resolve error"); send_message(sock,msg); return; }
        int ssock = connect_to_server(ip, port);
        Message f; memset(&f,0,sizeof(f)); strcpy(f.command, OP_LISTCHECKPOINTS_S);
        strncpy(f.username, msg->username, sizeof(f.username)-1);
        strncpy(f.filename, msg->filename, sizeof(f.filename)-1);
        if (ssock < 0 || send_message(ssock, &f) <= 0 || receive_message(ssock, &f) <= 0) {
            if (ssock >= 0) close(ssock);
            msg->status_code = ERR_INTERNAL; strcpy(msg->payload, "List checkpoints failed: SS unavailable");
            send_message(sock, msg); return;
        }
        close(ssock);
        msg->status_code = f.status_code; strncpy(msg->payload, f.payload, sizeof(msg->payload)-1); send_message(sock,msg);
        char log_buf[128]; snprintf(log_buf,sizeof(log_buf),"file=%s rc=%d", msg->filename, msg->status_code); log_event_detailed("logs/nm.log","NM","LISTCHECKPOINTS", msg->username, client_ip, client_port, log_buf,1);
    } else if (strcmp(msg->command, OP_REQUESTACCESS_S) == 0) {
        // payload: R|W
        char mode = (msg->payload[0]?msg->payload[0]:'R');
        // Must refer to an existing file; requester can request even without read access
        int idx = nm_is_owner(msg->filename, msg->username);
        if (idx==SUCCESS) { msg->status_code=ERR_BAD_REQUEST; strcpy(msg->payload,"Owner already has access"); send_message(sock,msg); return; }
        int rc = nm_request_access(msg->filename, msg->username, mode);
        msg->status_code = rc; strcpy(msg->payload, rc==SUCCESS?"REQUEST OK":"REQUEST ERR"); send_message(sock,msg);
        
        char log_buf[128];
        snprintf(log_buf, sizeof(log_buf), "file=%s mode=%c result=%s", msg->filename, mode, rc == SUCCESS ? "OK" : "FAILED");
        log_event_detailed("logs/nm.log", "NM", "REQUESTACCESS", msg->username, client_ip, client_port, log_buf, 1);
        
    } else if (strcmp(msg->command, OP_VIEWREQUESTS_S) == 0) {
        // Owner-only: list all requests for files owned by this user
        int rc = nm_list_requests(msg->username, msg->payload, sizeof(msg->payload));
        msg->status_code = rc; if (rc!=SUCCESS) strcpy(msg->payload, "ERR"); send_message(sock,msg);
        
        char log_buf[128];
        snprintf(log_buf, sizeof(log_buf), "result=%s", rc == SUCCESS ? "OK" : "FAILED");
        log_event_detailed("logs/nm.log", "NM", "VIEWREQUESTS", msg->username, client_ip, client_port, log_buf, 1);
        
    } else if (strcmp(msg->command, OP_APPROVEREQUEST_S) == 0 || strcmp(msg->command, OP_DENYREQUEST_S) == 0) {
        // payload: <R|W>|<requester>
        char mode='R'; char target[64]={0}; sscanf(msg->payload, "%c|%63s", &mode, target);
        int rc;
        const char *operation = (strcmp(msg->command, OP_APPROVEREQUEST_S)==0) ? "APPROVEREQUEST" : "DENYREQUEST";
        if (strcmp(msg->command, OP_APPROVEREQUEST_S)==0) rc = nm_approve_request(msg->username, msg->filename, target, mode);
        else rc = nm_deny_request(msg->username, msg->filename, target, mode);
        msg->status_code = rc; strcpy(msg->payload, rc==SUCCESS?"OK":"ERR"); send_message(sock,msg);
        
        char log_buf[128];
        snprintf(log_buf, sizeof(log_buf), "file=%s requester=%s mode=%c result=%s", 
                 msg->filename, target, mode, rc == SUCCESS ? "OK" : "FAILED");
        log_event_detailed("logs/nm.log", "NM", operation, msg->username, client_ip, client_port, log_buf, 1);
        
    } else {
        msg->status_code = ERR_BAD_REQUEST;
        strcpy(msg->payload, "Unknown command");
        send_message(sock, msg);
    }
}

// Non-fatal connect helper (returns -1 on failure)
static int try_connect_nofatal(const char *ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_in serv_addr; memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET; serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) { close(sock); return -1; }
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) { close(sock); return -1; }
    return sock;
}

// Fetch file from primary/serving SS and stream to replica (non-fatal)
void replicate_file_async(const char *filename) {
    int replica_id = nm_get_replica_ss_id(filename);
    if (replica_id < 0) return;
    char src_ip[32] = "", dst_ip[32] = ""; int src_port=0, dst_port=0;
    char tmp_user[8] = ""; // not used here
    if (nm_resolve_for_read((char*)filename, tmp_user, src_ip, &src_port) != SUCCESS) return;
    if (nm_get_ss_ip_port(replica_id, dst_ip, sizeof(dst_ip), &dst_port) != 0) return;
    int s_sock = try_connect_nofatal(src_ip, src_port); if (s_sock < 0) { log_event_detailed("logs/nm.log","NM","REPL_SKIP","",src_ip,src_port,"source connect failed",1); return; }
    Message rq; memset(&rq,0,sizeof(rq)); rq.op_code = OP_READ; strcpy(rq.command, OP_READ_S);
    strncpy(rq.filename, filename, sizeof(rq.filename)-1);
    if (send_message(s_sock, &rq) <= 0) { close(s_sock); return; }
    int d_sock = try_connect_nofatal(dst_ip, dst_port); if (d_sock < 0) { log_event_detailed("logs/nm.log","NM","REPL_SKIP","",dst_ip,dst_port,"dest connect failed",1); close(s_sock); return; }
    Message wr; memset(&wr,0,sizeof(wr)); strcpy(wr.command, OP_REPL_WRITE_S);
    strncpy(wr.filename, filename, sizeof(wr.filename)-1);
    if (send_message(d_sock, &wr) <= 0) { close(s_sock); close(d_sock); return; }
    while (1) {
        Message rp; int n = receive_message(s_sock, &rp);
        if (n <= 0) break;
        if (rp.op_code == OP_STREAM || strcmp(rp.command, OP_STREAM_S) == 0) {
            Message out; memset(&out,0,sizeof(out)); strcpy(out.command, OP_STREAM_S);
            strncpy(out.filename, filename, sizeof(out.filename)-1);
            strncpy(out.payload, rp.payload, sizeof(out.payload)-1);
            if (send_message(d_sock, &out) <= 0) break;
        } else if (rp.op_code == OP_STREAM_END || strcmp(rp.command, OP_STREAM_END_S) == 0) {
            Message out; memset(&out,0,sizeof(out)); strcpy(out.command, OP_STREAM_END_S);
            strncpy(out.filename, filename, sizeof(out.filename)-1);
            send_message(d_sock, &out);
            break;
        } else { break; }
    }
    close(s_sock); close(d_sock);
}

static fd_set active_fds;
static int max_fd = 0;
static void add_client_socket(int sock, const char *username) {
    FD_SET(sock, &active_fds);
    if (sock > max_fd) max_fd = sock;
}

static void *ping_thread(void *arg) {
    (void)arg;
    static int was_alive[MAX_SS] = {0};
    while (1) {
        for (int i=0;i<MAX_SS;i++) {
            char ip[32]; int port=0; if(nm_get_ss_ip_port(i,ip,sizeof(ip),&port)!=0) continue;
            char ss_name[64] = ""; nm_get_ss_name(i, ss_name, sizeof(ss_name));
            int s = try_connect_nofatal(ip,port);
            if(s<0){ 
                if (was_alive[i]) { 
                    char buf[128]; 
                    snprintf(buf,sizeof(buf),"ss=%d ip=%s port=%d -> DEAD",i,ip,port); 
                    log_event_detailed("logs/nm.log","NM","HEALTH",ss_name[0] ? ss_name : "",ip,port,buf,1);
                } 
                nm_mark_ss_dead(i); was_alive[i]=0; continue; 
            }
            Message pm; memset(&pm,0,sizeof(pm)); strcpy(pm.command, OP_PING_S); 
            strncpy(pm.username, "NM", sizeof(pm.username)-1);  // Set username to "NM" for PING
            send_message(s,&pm);
            if(receive_message(s,&pm)>0 && pm.status_code==SUCCESS) {
                nm_mark_ss_alive(i);
                if (!was_alive[i]) { 
                    char buf[128]; 
                    snprintf(buf,sizeof(buf),"ss=%d ip=%s port=%d -> ALIVE",i,ip,port); 
                    log_event_detailed("logs/nm.log","NM","HEALTH",ss_name[0] ? ss_name : "",ip,port,buf,1); 
                    nm_sync_recovered_ss(i); 
                }
                was_alive[i]=1;
            } else { nm_mark_ss_dead(i); was_alive[i]=0; }
            close(s);
        }
        sleep(5);
    }
    return NULL;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    int nm_port = NM_PORT;
    if (argc >= 2) {
        nm_port = atoi(argv[1]);
        if (nm_port <= 0 || nm_port > 65535) {
            fprintf(stderr, "Usage: %s <port>\n", argv[0]);
            return 1;
        }
    }
    
    // Initialize fd set for tracking client connections
    FD_ZERO(&active_fds);
    
    printf("Name Server starting on port %d...\n", nm_port);

    // Don't load files from disk - NM should learn about files from SS registrations
    // nm_load_persisted_files();  // REMOVED: NM should get file list from SS

    int server_fd = create_server_socket(nm_port);
    log_event("logs/nm.log", "NM", "Server started");

    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    char client_ip[32];
    int client_port = 0;

    pthread_t pt; pthread_create(&pt,NULL,ping_thread,NULL); pthread_detach(pt);

    while (1) {
        int sock = accept(server_fd, (struct sockaddr*)&addr, &addrlen);
        if (sock < 0) {
            perror("accept failed");
            continue;
        }
        get_client_info(sock, client_ip, &client_port);
        Message msg;
        memset(&msg, 0, sizeof(msg));
        if (receive_message(sock, &msg) <= 0) {
            // If receive fails and we have a username from a previous message,
            // assume client disconnected and remove them
            if (msg.username[0] != '\0') {
                nm_remove_client(msg.username);
                char log_msg[256];
                snprintf(log_msg, sizeof(log_msg), "Client disconnected: %s@%s:%d",
                        msg.username, client_ip, client_port);
                log_event_detailed("logs/nm.log", "NM", "DISCONNECT", msg.username,
                                 client_ip, client_port, log_msg, 1);
            }
            close(sock);
            continue;
        }
        
        // Get client info for any connection
        char client_ip[32];
        int client_port = 0;
        get_client_info(sock, client_ip, &client_port);
        
        if (strcmp(msg.command, OP_REGISTER_SS) == 0 || strcmp(msg.command, "REGISTER_SS") == 0) {
            handle_register_ss(sock, &msg, &addr);
        } else if (strcmp(msg.command, "AUTH") == 0 || strcmp(msg.command, "CONNECT") == 0) {
            // Handle initial client authentication/connection
            
            // First remove any existing entry for this user (in case of reconnect)
            nm_remove_client(msg.username);
            
            // Handle initial client authentication/connection
            // First remove any previous entry for this user
            nm_remove_client(msg.username);
            
            // Track the initial connection
            nm_track_client(msg.username, client_ip, client_port);
            
            char connect_msg[256];
            snprintf(connect_msg, sizeof(connect_msg), "New client connected: %s@%s:%d",
                    msg.username, client_ip, client_port);
            log_event_detailed("logs/nm.log", "NM", "CONNECTION", msg.username,
                             client_ip, client_port, connect_msg, 1);
            
            msg.status_code = SUCCESS;
            strcpy(msg.payload, "Connected");
            send_message(sock, &msg);
        } else {
            handle_client_req(sock, &msg);
        }
        close(sock);
    }

    close(server_fd);
    return 0;
}
