#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/select.h>

#include "../include/protocol.h"
#include "../include/constants.h"
#include "../include/error_codes.h"

int connect_to_server(char *ip, int port);
int send_message(int sockfd, Message *msg);
int receive_message(int sockfd, Message *msg);
void log_event(const char *filename, const char *component, const char *event);

static char username[32];
static char nm_ip[64] = "127.0.0.1";
static int nm_port_cfg = NM_PORT;

static void send_logout() {
    Message logout_msg;
    memset(&logout_msg, 0, sizeof(logout_msg));
    strcpy(logout_msg.command, "LOGOUT");
    strncpy(logout_msg.username, username, sizeof(logout_msg.username)-1);
    int nm_sock = connect_to_server(nm_ip, nm_port_cfg);
    if (nm_sock >= 0) {
        send_message(nm_sock, &logout_msg);
        close(nm_sock);
    }
}

static void handle_signal(int sig) {
    if (sig == SIGINT) {
        printf("\nLogging out...\n");
        send_logout();
        exit(0);
    }
}

static void set_username_default() {
    const char *envs[] = { "DFS_USER", "LANGOS_USER", "NM_USER", "USERNAME", "USER", NULL };
    const char *u = NULL;
    for (int i=0; envs[i]; i++) { u = getenv(envs[i]); if (u && *u) break; }
    if (!u) u = "user1";
    strncpy(username, u, sizeof(username)-1); username[sizeof(username)-1] = '\0';
}



static int send_req(Message *msg) {
    int sock = connect_to_server(nm_ip, nm_port_cfg);
    if (sock < 0) return -1;
    int rc = send_message(sock, msg);
    if (rc <= 0) { close(sock); return rc; }
    rc = receive_message(sock, msg);
    close(sock);
    return rc;
}

static void do_create(const char *fname) {
    Message m; memset(&m, 0, sizeof(m));
    strcpy(m.command, OP_CREATE);
    strncpy(m.filename, fname, sizeof(m.filename)-1);
    strncpy(m.username, username, sizeof(m.username)-1);
    send_req(&m);
    printf("%s\n", m.payload);
    log_event("logs/client.log", "CLIENT", "CREATE sent");
}

static void do_view(const char *flags) {
    Message m; memset(&m, 0, sizeof(m));
    strcpy(m.command, OP_VIEW);
    strncpy(m.username, username, sizeof(m.username)-1);
    if (flags) strncpy(m.payload, flags, sizeof(m.payload)-1);
    send_req(&m);
    printf("%s", m.payload);
    log_event("logs/client.log", "CLIENT", "VIEW sent");
}

static void do_info(const char *fname) {
    Message m; memset(&m, 0, sizeof(m));
    strcpy(m.command, OP_INFO);
    strncpy(m.username, username, sizeof(m.username)-1);
    strncpy(m.filename, fname, sizeof(m.filename)-1);
    send_req(&m);
    if (m.status_code == SUCCESS) printf("%s", m.payload);
    else printf("ERROR %d: %s\n", m.status_code, m.payload);
    log_event("logs/client.log", "CLIENT", "INFO sent");
}

static void usage(const char *p) {
    printf("Usage:\n  %s [-u USER] CREATE <filename>\n  %s [-u USER] VIEW [-a][-l]\n  %s [-u USER] INFO <filename>\n  %s [-u USER] READ <filename>\n  %s [-u USER] STREAM <filename>\n  %s [-u USER] WRITE <filename> <sentence_idx>\n  %s [-u USER] UNDO <filename>\n  %s [-u USER] LIST\n  %s [-u USER] ADDACCESS -R|-W <filename> <username>\n  %s [-u USER] REMACCESS <filename> <username>\n  %s [-u USER] DELETE <filename>\n  %s [-u USER] EXEC <filename>\n  %s [-u USER] CREATEFOLDER <folder>\n  %s [-u USER] MOVE <filename> <folder>\n  %s [-u USER] VIEWFOLDER <folder>\n  %s [-u USER] CHECKPOINT <filename> <tag>\n  %s [-u USER] VIEWCHECKPOINT <filename> <tag>\n  %s [-u USER] REVERT <filename> <tag>\n  %s [-u USER] LISTCHECKPOINTS <filename>\n  %s [-u USER] REQUESTACCESS -R|-W <filename>\n  %s [-u USER] VIEWREQUESTS\n  %s [-u USER] APPROVEREQUEST <filename> -R|-W <username>\n  %s [-u USER] DENYREQUEST <filename> -R|-W <username>\n", p, p, p, p, p, p, p, p, p, p, p, p, p, p, p, p, p, p, p, p, p, p, p);
}

// Forward declarations for command handlers
static void handle_command(int argc, char **argv, int argi);

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    // Optional: ./bin/client [NM_IP NM_PORT]
    if (argc >= 3) {
        strncpy(nm_ip, argv[1], sizeof(nm_ip)-1);
        nm_ip[sizeof(nm_ip)-1] = '\0';
        nm_port_cfg = atoi(argv[2]);
        if (nm_port_cfg <= 0 || nm_port_cfg > 65535) {
            fprintf(stderr, "Invalid NM port: %s\n", argv[2]);
            return 1;
        }
    }
    // Always prompt for username
    printf("Enter username: ");
    fflush(stdout);
    if (fgets(username, sizeof(username), stdin) == NULL) {
        fprintf(stderr, "Failed to read username.\n");
        exit(1);
    }
    username[strcspn(username, "\n")] = 0;  // remove newline
    if (strlen(username) == 0) {
        fprintf(stderr, "Username cannot be empty.\n");
        exit(1);
    }

    // Set up signal handler for Ctrl+C
    signal(SIGINT, handle_signal);

    // Send initial authentication to NM
    Message auth_msg; memset(&auth_msg, 0, sizeof(auth_msg));
    strcpy(auth_msg.command, "AUTH");
    strncpy(auth_msg.username, username, sizeof(auth_msg.username)-1);
    int nm_sock = connect_to_server(nm_ip, nm_port_cfg);
    if (nm_sock < 0) {
        fprintf(stderr, "Failed to connect to Name Server at %s:%d\n", nm_ip, nm_port_cfg);
        exit(1);
    }
    if (send_message(nm_sock, &auth_msg) <= 0) {
        fprintf(stderr, "Failed to send authentication\n");
        close(nm_sock);
        exit(1);
    }
    if (receive_message(nm_sock, &auth_msg) <= 0) {
        fprintf(stderr, "Failed to receive authentication response\n");
        close(nm_sock);
        exit(1);
    }
    close(nm_sock);
    if (auth_msg.status_code != SUCCESS) {
        fprintf(stderr, "Authentication failed: %s\n", auth_msg.payload);
        exit(1);
    }

    // Enter interactive shell mode
    printf("Logged in as: %s\n", username);
    printf("Type 'help' for commands, 'exit' to quit.\n");
    
    char input[512];
    while (1) {
        printf("> ");
        fflush(stdout);
        
        if (!fgets(input, sizeof(input), stdin)) break;  // Ctrl+D
        input[strcspn(input, "\n")] = 0;  // remove newline
        if (strlen(input) == 0) continue;
        
        // Exit command
        if (strcmp(input, "exit") == 0 || strcmp(input, "quit") == 0) {
            printf("Goodbye!\n");
            send_logout();
            break;
        }
        
        // Help command
        if (strcmp(input, "help") == 0) {
            usage(argv[0]);
            continue;
        }
        
        // Parse input into arguments
        char *args[20];
        int count = 0;
        char *tok = strtok(input, " ");
        while (tok && count < 20) {
            args[count++] = tok;
            tok = strtok(NULL, " ");
        }
        
        if (count == 0) continue;
        
        // Create fake argv for command handler
        char *fake_argv[21];
        fake_argv[0] = argv[0];  // program name
        for (int i = 0; i < count; i++) {
            fake_argv[i + 1] = args[i];
        }
        
        // Call command handler
        handle_command(count + 1, fake_argv, 1);
    }
    
    return 0;
}

static void handle_command(int argc, char **argv, int argi) {
    const char *cmd = argv[argi];
    if (strcmp(cmd, "CREATE") == 0 && argc >= argi+2) {
        do_create(argv[argi+1]);
    } else if (strcmp(cmd, "VIEW") == 0) {
        const char *flags = (argc >= argi+2) ? argv[argi+1] : "";
        do_view(flags);
    } else if (strcmp(cmd, "INFO") == 0 && argc >= argi+2) {
        do_info(argv[argi+1]);
    } else if (strcmp(cmd, "READ") == 0 && argc >= argi+2) {
        // Resolve via NM
        Message m; memset(&m, 0, sizeof(m));
        m.op_code = OP_RESOLVE_READ; strcpy(m.command, OP_RESOLVE_READ_S);
        strncpy(m.username, username, sizeof(m.username)-1);
        strncpy(m.filename, argv[argi+1], sizeof(m.filename)-1);
        send_req(&m);
        if (m.status_code != SUCCESS) { printf("%s\n", m.payload); return; }
        char ip[64]; int port=0; sscanf(m.payload, "%63[^:]:%d", ip, &port);
    int ssock = connect_to_server(ip, port);
    if (ssock < 0) { printf("Storage server unavailable. Try again later.\n"); return; }
        Message rq; memset(&rq, 0, sizeof(rq)); rq.op_code = OP_READ; strcpy(rq.command, OP_READ_S);
        strncpy(rq.filename, argv[argi+1], sizeof(rq.filename)-1);
        strncpy(rq.username, username, sizeof(rq.username)-1);
    if (send_message(ssock, &rq) <= 0) { printf("Failed to send read request.\n"); close(ssock); return; }
        // Streamed READ: collect OP_STREAM chunks until OP_STREAM_END
        int any_ok = 0; int error_printed = 0;
        while (1) {
            Message rp; int n = receive_message(ssock, &rp);
            if (n <= 0) { if (!error_printed) printf("\nDisconnected during read.\n"); break; }
            if (rp.op_code == OP_STREAM_END || strcmp(rp.command, OP_STREAM_END_S) == 0) {
                break; // end of file
            }
            if (rp.op_code == OP_STREAM || strcmp(rp.command, OP_STREAM_S) == 0) {
                if (!any_ok) printf("--- Begin file ---\n");
                any_ok = 1;
                fputs(rp.payload, stdout);
                // Preserve original formatting; payload may already contain newlines
            } else if (rp.status_code != SUCCESS && !error_printed) {
                printf("ERROR %d: %s\n", rp.status_code, rp.payload);
                error_printed = 1; break;
            }
        }
        if (any_ok) printf("\n--- End file ---\n");
        close(ssock);
        log_event("logs/client.log", "CLIENT", "READ displayed");
    } else if (strcmp(cmd, "STREAM") == 0 && argc >= argi+2) {
        Message m; memset(&m, 0, sizeof(m));
        m.op_code = OP_RESOLVE_STREAM; strcpy(m.command, OP_RESOLVE_STREAM_S);
        strncpy(m.username, username, sizeof(m.username)-1);
        strncpy(m.filename, argv[argi+1], sizeof(m.filename)-1);
        send_req(&m);
        if (m.status_code != SUCCESS) { printf("%s\n", m.payload); return; }
        char ip[64]; int port=0; sscanf(m.payload, "%63[^:]:%d", ip, &port);
    int ssock = connect_to_server(ip, port);
    if (ssock < 0) { printf("Storage server unavailable. Try again later.\n"); return; }
        Message rq; memset(&rq, 0, sizeof(rq)); rq.op_code = OP_STREAM; strcpy(rq.command, OP_STREAM_S);
        strncpy(rq.filename, argv[argi+1], sizeof(rq.filename)-1);
        strncpy(rq.username, username, sizeof(rq.username)-1);
    if (send_message(ssock, &rq) <= 0) { printf("Failed to send stream request.\n"); close(ssock); return; }
        // keep reading until OP_STREAM_END
        while (1) {
            Message rp; int n = receive_message(ssock, &rp);
            if (n <= 0) { printf("\nError: storage server disconnected.\n"); break; }
            if (rp.op_code == OP_STREAM_END || strcmp(rp.command, OP_STREAM_END_S) == 0) { printf("\n"); break; }
            if (rp.op_code == OP_STREAM || strcmp(rp.command, OP_STREAM_S) == 0) {
                printf("%s ", rp.payload);
                fflush(stdout);
            } else if (rp.status_code != SUCCESS) {
                printf("\nERROR %d: %s\n", rp.status_code, rp.payload); break;
            }
        }
        close(ssock);
        log_event("logs/client.log", "CLIENT", "STREAM displayed");
    } else if (strcmp(cmd, "WRITE") == 0 && argc >= argi+3) {
        const char *fname = argv[argi+1]; int sidx = atoi(argv[argi+2]);
    // Resolve write via NM to get SS endpoint
    Message m; memset(&m, 0, sizeof(m));
    m.op_code = OP_WRITE_REQUEST; strcpy(m.command, OP_WRITE_REQUEST_S);
    strncpy(m.username, username, sizeof(m.username)-1);
    strncpy(m.filename, fname, sizeof(m.filename)-1);
    snprintf(m.payload, sizeof(m.payload), "%d", sidx);
    send_req(&m);
    if (m.status_code != SUCCESS) { printf("%s\n", m.payload); return; }
    char ip[64]; int port=0; sscanf(m.payload, "%63[^:]:%d", ip, &port);
    int ssock = connect_to_server(ip, port);
    if (ssock < 0) { printf("Storage server unavailable. Try again later.\n"); return; }
    // send write request to SS to acquire lock
    Message w; memset(&w,0,sizeof(w)); w.op_code=OP_WRITE_REQUEST; strcpy(w.command, OP_WRITE_REQUEST_S);
    strncpy(w.username, username, sizeof(w.username)-1); strncpy(w.filename, fname, sizeof(w.filename)-1);
    snprintf(w.payload, sizeof(w.payload), "%d", sidx);
    // propagate req_id from NM resolve to SS so all logs can be stitched
    if (m.req_id[0]) strncpy(w.req_id, m.req_id, sizeof(w.req_id)-1);
    if (send_message(ssock, &w) <= 0) { printf("Failed to send write request.\n"); close(ssock); return; }
    Message wr; if (receive_message(ssock, &wr)<=0 || wr.status_code!=SUCCESS) { printf("%s\n", wr.payload[0]?wr.payload:"Write lock failed."); close(ssock); return; }
        printf("Lock acquired. Enter edits as '<word_index> <text>' and type 'ETIRW' on a new line to save.\n");
        // interactive loop
        char line[2048];
        int error_occurred = 0;
        while (1) {
            if (!fgets(line, sizeof(line), stdin)) break;
            if (strncmp(line, "ETIRW", 5)==0) {
                Message end; memset(&end,0,sizeof(end)); end.op_code=OP_WRITE_END; strcpy(end.command, OP_WRITE_END_S);
                if (send_message(ssock, &end) <= 0) { printf("Write ended but SS disconnected.\n"); break; }
                // Break out of loop after sending ETIRW
                break;
            }
            // forward as edit payload: "<word_idx> <content>"
            Message e; memset(&e,0,sizeof(e)); e.op_code=OP_WRITE_EDIT; strcpy(e.command, OP_WRITE_EDIT_S);
            strncpy(e.payload, line, sizeof(e.payload)-1);
            if (send_message(ssock, &e) <= 0) { printf("SS disconnected during write.\n"); error_occurred = 1; break; }
            
            // Check for immediate error response (e.g., invalid word index or missing index)
            fd_set readfds; struct timeval tv; FD_ZERO(&readfds); FD_SET(ssock, &readfds);
            tv.tv_sec = 1; tv.tv_usec = 0; // wait up to 1s for error from server
            int sel = select(ssock + 1, &readfds, NULL, NULL, &tv);
            if (sel > 0) {
                Message err_check;
                int peek = receive_message(ssock, &err_check);
                if (peek > 0 && err_check.op_code == OP_WRITE_DENY) {
                    printf("%s\n", err_check.payload);
                    error_occurred = 1;
                    break;
                }
                // Any other message will be processed after ETIRW
            }
        }
        
        if (error_occurred) {
            close(ssock);
            log_event("logs/client.log", "CLIENT", "WRITE error");
            return;
        }
        
        // await final server response (ACK or DENY)
        Message ack; if (receive_message(ssock, &ack)>0) {
            if (ack.op_code==OP_WRITE_ACK) {
                printf("Write successful!\n");
            } else if (ack.op_code==OP_WRITE_DENY) {
                printf("%s\n", ack.payload[0]?ack.payload:"Write failed.");
            } else {
                printf("Write failed or disconnected.\n");
            }
        } else {
            printf("Write failed or disconnected.\n");
        }
        close(ssock);
        log_event("logs/client.log", "CLIENT", "WRITE complete");
    } else if (strcmp(cmd, "UNDO") == 0 && argc >= argi+2) {
        Message m; memset(&m, 0, sizeof(m));
        strcpy(m.command, OP_UNDO_S);
        strncpy(m.username, username, sizeof(m.username)-1);
        strncpy(m.filename, argv[argi+1], sizeof(m.filename)-1);
        send_req(&m);
        if (m.status_code == SUCCESS) {
            printf("Undo successful!\n");
        } else {
            printf("Error: %s\n", m.payload[0] ? m.payload : "No previous version found.");
        }
    } else if (strcmp(cmd, "LIST") == 0) {
        Message m; memset(&m, 0, sizeof(m)); strcpy(m.command, OP_LIST_S); strncpy(m.username, username, sizeof(m.username)-1);
        send_req(&m); if (m.status_code==SUCCESS) printf("%s", m.payload); else printf("Error: %s\n", m.payload);
    } else if (strcmp(cmd, "ADDACCESS") == 0 && argc >= argi+4) {
        int is_write = (strcmp(argv[argi+1], "-W")==0);
        if (!is_write && strcmp(argv[argi+1], "-R")!=0) { printf("Usage: ADDACCESS -R|-W <filename> <username>\n"); return; }
        Message m; memset(&m, 0, sizeof(m)); strcpy(m.command, OP_ADDACCESS_S);
        strncpy(m.username, username, sizeof(m.username)-1);
        strncpy(m.filename, argv[argi+2], sizeof(m.filename)-1);
        snprintf(m.payload, sizeof(m.payload), "%s|%s", is_write?"W":"R", argv[argi+3]);
        send_req(&m); if (m.status_code==SUCCESS) printf("Access updated.\n"); else printf("Error: %s\n", m.payload);
    } else if (strcmp(cmd, "REMACCESS") == 0 && argc >= argi+3) {
        Message m; memset(&m, 0, sizeof(m)); strcpy(m.command, OP_REMACCESS_S);
        strncpy(m.username, username, sizeof(m.username)-1);
        strncpy(m.filename, argv[argi+1], sizeof(m.filename)-1);
        strncpy(m.payload, argv[argi+2], sizeof(m.payload)-1);
        send_req(&m); if (m.status_code==SUCCESS) printf("Access removed.\n"); else printf("Error: %s\n", m.payload);
    } else if (strcmp(cmd, "DELETE") == 0 && argc >= argi+2) {
        Message m; memset(&m, 0, sizeof(m)); strcpy(m.command, OP_DELETE_S);
        strncpy(m.username, username, sizeof(m.username)-1);
        strncpy(m.filename, argv[argi+1], sizeof(m.filename)-1);
        send_req(&m); if (m.status_code==SUCCESS) printf("Delete successful.\n"); else printf("Error: %s\n", m.payload);
    } else if (strcmp(cmd, "EXEC") == 0 && argc >= argi+2) {
        // Ask NM to execute contents of file on server and stream output
        Message m; memset(&m, 0, sizeof(m)); strcpy(m.command, OP_EXEC_S);
        strncpy(m.username, username, sizeof(m.username)-1);
        strncpy(m.filename, argv[argi+1], sizeof(m.filename)-1);
        // We'll receive multiple messages: stream-like until STOP marker
    int sock = connect_to_server(nm_ip, nm_port_cfg);
        send_message(sock, &m);
        while (1) {
            Message r; int n = receive_message(sock, &r);
            if (n<=0) break;
            if (r.op_code==OP_STREAM_END || strcmp(r.command, OP_STREAM_END_S)==0 || strcmp(r.payload, "STOP")==0) break;
            if (r.status_code!=SUCCESS && r.payload[0]) { printf("%s\n", r.payload); break; }
            if (r.payload[0]) printf("%s\n", r.payload);
        }
        close(sock);
        log_event("logs/client.log", "CLIENT", "EXEC displayed");
    } else if (strcmp(cmd, "CREATEFOLDER") == 0 && argc >= argi+2) {
        Message m; memset(&m,0,sizeof(m)); strcpy(m.command, OP_CREATEFOLDER_S);
        strncpy(m.username, username, sizeof(m.username)-1);
        strncpy(m.filename, argv[argi+1], sizeof(m.filename)-1);
        send_req(&m);
        printf("%s\n", m.payload[0]?m.payload:(m.status_code==SUCCESS?"FOLDER OK":"ERROR"));
    } else if (strcmp(cmd, "MOVE") == 0 && argc >= argi+3) {
        Message m; memset(&m,0,sizeof(m)); strcpy(m.command, OP_MOVE_S);
        strncpy(m.username, username, sizeof(m.username)-1);
        strncpy(m.filename, argv[argi+1], sizeof(m.filename)-1);
        strncpy(m.payload, argv[argi+2], sizeof(m.payload)-1);
        send_req(&m);
        printf("%s\n", m.payload[0]?m.payload:(m.status_code==SUCCESS?"MOVE OK":"ERROR"));
    } else if (strcmp(cmd, "VIEWFOLDER") == 0 && argc >= argi+2) {
        Message m; memset(&m,0,sizeof(m)); strcpy(m.command, OP_VIEWFOLDER_S);
        strncpy(m.username, username, sizeof(m.username)-1);
        strncpy(m.filename, argv[argi+1], sizeof(m.filename)-1);
        send_req(&m);
        if (m.status_code==SUCCESS) printf("%s", m.payload);
        else printf("Error: %s\n", m.payload[0]?m.payload:"FAILED");
    } else if (strcmp(cmd, "CHECKPOINT") == 0 && argc >= argi+3) {
        Message m; memset(&m,0,sizeof(m)); strcpy(m.command, OP_CHECKPOINT_S);
        strncpy(m.username, username, sizeof(m.username)-1);
        strncpy(m.filename, argv[argi+1], sizeof(m.filename)-1);
        strncpy(m.payload, argv[argi+2], sizeof(m.payload)-1);
        send_req(&m);
        printf("%s\n", m.payload[0]?m.payload:(m.status_code==SUCCESS?"CHECKPOINT OK":"ERROR"));
    } else if (strcmp(cmd, "VIEWCHECKPOINT") == 0 && argc >= argi+3) {
        Message m; memset(&m,0,sizeof(m)); strcpy(m.command, OP_VIEWCHECKPOINT_S);
        strncpy(m.username, username, sizeof(m.username)-1);
        strncpy(m.filename, argv[argi+1], sizeof(m.filename)-1);
        strncpy(m.payload, argv[argi+2], sizeof(m.payload)-1);
        send_req(&m);
        if (m.status_code==SUCCESS) printf("%s\n", m.payload); else printf("Error: %s\n", m.payload);
    } else if (strcmp(cmd, "REVERT") == 0 && argc >= argi+3) {
        Message m; memset(&m,0,sizeof(m)); strcpy(m.command, OP_REVERT_S);
        strncpy(m.username, username, sizeof(m.username)-1);
        strncpy(m.filename, argv[argi+1], sizeof(m.filename)-1);
        strncpy(m.payload, argv[argi+2], sizeof(m.payload)-1);
        send_req(&m);
        printf("%s\n", m.payload[0]?m.payload:(m.status_code==SUCCESS?"REVERT OK":"ERROR"));
    } else if (strcmp(cmd, "LISTCHECKPOINTS") == 0 && argc >= argi+2) {
        Message m; memset(&m,0,sizeof(m)); strcpy(m.command, OP_LISTCHECKPOINTS_S);
        strncpy(m.username, username, sizeof(m.username)-1);
        strncpy(m.filename, argv[argi+1], sizeof(m.filename)-1);
        send_req(&m);
        if (m.status_code==SUCCESS) printf("%s", m.payload); else printf("Error: %s\n", m.payload);
    } else if (strcmp(cmd, "LIST") == 0 && argc >= argi+3 && strcmp(argv[argi+1], "checkpoints") == 0) {
        // Alias: "LIST checkpoints <filename>"
        Message m; memset(&m,0,sizeof(m)); strcpy(m.command, OP_LISTCHECKPOINTS_S);
        strncpy(m.username, username, sizeof(m.username)-1);
        strncpy(m.filename, argv[argi+2], sizeof(m.filename)-1);
        send_req(&m);
        if (m.status_code==SUCCESS) printf("%s", m.payload); else printf("Error: %s\n", m.payload);
    } else if (strcmp(cmd, "REQUESTACCESS") == 0 && argc >= argi+3) {
        // REQUESTACCESS -R|-W <filename>
        const char *mode = argv[argi+1]; const char *fname = argv[argi+2];
        if (strcmp(mode,"-R")!=0 && strcmp(mode,"-W")!=0) { printf("Usage: REQUESTACCESS -R|-W <filename>\n"); return; }
        Message m; memset(&m,0,sizeof(m)); strcpy(m.command, OP_REQUESTACCESS_S);
        strncpy(m.username, username, sizeof(m.username)-1);
        strncpy(m.filename, fname, sizeof(m.filename)-1);
        snprintf(m.payload, sizeof(m.payload), "%c", (mode[1]=='R'?'R':'W'));
        send_req(&m); printf("%s\n", m.payload[0]?m.payload:(m.status_code==SUCCESS?"REQUEST OK":"ERR"));
    } else if (strcmp(cmd, "VIEWREQUESTS") == 0) {
        // owner: lists all requests for files owned by this user
        Message m; memset(&m,0,sizeof(m)); strcpy(m.command, OP_VIEWREQUESTS_S);
        strncpy(m.username, username, sizeof(m.username)-1);
        send_req(&m); if (m.status_code==SUCCESS) printf("%s", m.payload); else printf("ERR\n");
    } else if (strcmp(cmd, "APPROVEREQUEST") == 0 && argc >= argi+4) {
        // APPROVEREQUEST <filename> -R|-W <username>
        const char *fname=argv[argi+1]; const char *mode=argv[argi+2]; const char *target=argv[argi+3];
        if (strcmp(mode,"-R")!=0 && strcmp(mode,"-W")!=0) { printf("Usage: APPROVEREQUEST <filename> -R|-W <username>\n"); return; }
        Message m; memset(&m,0,sizeof(m)); strcpy(m.command, OP_APPROVEREQUEST_S);
        strncpy(m.username, username, sizeof(m.username)-1);
        strncpy(m.filename, fname, sizeof(m.filename)-1);
        snprintf(m.payload, sizeof(m.payload), "%c|%s", (mode[1]=='R'?'R':'W'), target);
        send_req(&m); printf("%s\n", m.status_code==SUCCESS?"OK":"ERR");
    } else if (strcmp(cmd, "DENYREQUEST") == 0 && argc >= argi+4) {
        const char *fname=argv[argi+1]; const char *mode=argv[argi+2]; const char *target=argv[argi+3];
        if (strcmp(mode,"-R")!=0 && strcmp(mode,"-W")!=0) { printf("Usage: DENYREQUEST <filename> -R|-W <username>\n"); return; }
        Message m; memset(&m,0,sizeof(m)); strcpy(m.command, OP_DENYREQUEST_S);
        strncpy(m.username, username, sizeof(m.username)-1);
        strncpy(m.filename, fname, sizeof(m.filename)-1);
        snprintf(m.payload, sizeof(m.payload), "%c|%s", (mode[1]=='R'?'R':'W'), target);
        send_req(&m); printf("%s\n", m.status_code==SUCCESS?"OK":"ERR");
    } else {
        printf("Unknown command or missing arguments. Type 'help' for usage.\n");
    }
}
