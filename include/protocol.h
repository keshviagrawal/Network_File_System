#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stddef.h>
#define MAX_FILENAME_LEN 256
#define MAX_USERNAME_LEN 64
#define MAX_PAYLOAD_LEN 8192
#define CMD_LEN 32

// Operation codes
#define OP_REGISTER_SS "REGISTER_SS"
#define OP_CREATE      "OP_CREATE"
#define OP_VIEW        "OP_VIEW"
#define OP_INFO        "OP_INFO"

// Numeric op codes (for READ/STREAM flows)
#define OP_RESOLVE_READ   40
#define OP_RESOLVE_STREAM 41
#define OP_READ           42
#define OP_STREAM         43
#define OP_STREAM_END     44

// Optional string identifiers for new ops (backward-friendly)
#define OP_RESOLVE_READ_S   "OP_RESOLVE_READ"
#define OP_RESOLVE_STREAM_S "OP_RESOLVE_STREAM"
#define OP_READ_S           "OP_READ"
#define OP_STREAM_S         "OP_STREAM"
#define OP_STREAM_END_S     "OP_STREAM_END"

// Write operations
#define OP_WRITE_REQUEST   50
#define OP_WRITE_EDIT      51
#define OP_WRITE_END       52
#define OP_WRITE_ACK       53
#define OP_WRITE_DENY      54

// Notification from SS back to NM after a successful write/commit
#define OP_WRITE_NOTIFY    55

#define OP_WRITE_REQUEST_S "OP_WRITE_REQUEST"
#define OP_WRITE_EDIT_S    "OP_WRITE_EDIT"
#define OP_WRITE_END_S     "OP_WRITE_END"
#define OP_WRITE_ACK_S     "OP_WRITE_ACK"
#define OP_WRITE_DENY_S    "OP_WRITE_DENY"

#define OP_WRITE_NOTIFY_S  "OP_WRITE_NOTIFY"

// Undo operation
#define OP_UNDO            0x07
#define OP_UNDO_S          "OP_UNDO"

// List users
#define OP_LIST            0x08
#define OP_LIST_S          "OP_LIST"

// Access control
#define OP_ADDACCESS       0x09
#define OP_ADDACCESS_S     "OP_ADDACCESS"
#define OP_REMACCESS       0x0A
#define OP_REMACCESS_S     "OP_REMACCESS"

// Delete file
#define OP_DELETE          0x0B
#define OP_DELETE_S        "OP_DELETE"

// Exec on Name Server
#define OP_EXEC            0x0C
#define OP_EXEC_S          "OP_EXEC"

#define OP_LOGOUT          0x0D
#define OP_LOGOUT_S        "OP_LOGOUT"

// Bonus: Folder operations
#define OP_CREATEFOLDER_S  "OP_CREATEFOLDER"
#define OP_MOVE_S          "OP_MOVE"
#define OP_VIEWFOLDER_S    "OP_VIEWFOLDER"

// Bonus: Access request workflow
#define OP_REQUESTACCESS_S    "REQUESTACCESS"
#define OP_VIEWREQUESTS_S     "VIEWREQUESTS"
#define OP_APPROVEREQUEST_S   "APPROVEREQUEST"
#define OP_DENYREQUEST_S      "DENYREQUEST"

// Bonus: Checkpoint operations
#define OP_CHECKPOINT_S     "CHECKPOINT"
#define OP_VIEWCHECKPOINT_S "VIEWCHECKPOINT"
#define OP_REVERT_S         "REVERT"
#define OP_LISTCHECKPOINTS_S "LISTCHECKPOINTS"

// Replication and health
#define OP_REPLICATE_S      "REPLICATE"      // NM -> primary SS: replicate file to target SS (payload: target_ip=..,target_port=..,file=..)
#define OP_REPL_WRITE_S     "REPL_WRITE"     // SS(primary) -> SS(replica): begin replicate write for file; followed by OP_STREAM chunks and OP_STREAM_END
#define OP_PING_S           "PING"           // Optional: NM -> SS health probe

typedef struct {
    int op_code;                 // optional numeric op code (e.g., 40..44)
    char command[CMD_LEN];       // e.g. CREATE, READ, WRITE
    char filename[MAX_FILENAME_LEN];
    char username[MAX_USERNAME_LEN];
    char req_id[64];             // optional request id to trace across components
    char payload[MAX_PAYLOAD_LEN]; // message data (optional)
    int status_code;              // success/error
} Message;

// Registry helpers (forward declares to avoid exposing internal arrays)
int nm_move_file(const char *fname, const char *folder, char *errbuf, size_t errlen);
int nm_list_folder(const char *folder, const char *user, char *out, size_t outlen);
int nm_request_access(const char *fname, const char *user, char type);
int nm_list_requests(const char *owner, char *out, size_t outlen);
int nm_approve_request(const char *owner, const char *fname, const char *requester, char type);
int nm_deny_request(const char *owner, const char *fname, const char *requester, char type);
// Replication helpers
int nm_get_replica_ss_id(const char *filename);
int nm_get_primary_ss_id(const char *filename);
int nm_get_owner_name(const char *filename, char *out, size_t outlen);
int nm_list_files_by_role(int ss_id, char role, char *out, size_t outlen);
int nm_sync_recovered_ss(int ss_id);
// Internal NM helper (defined in nm_main.c)
void replicate_file_async(const char *filename);

#endif
