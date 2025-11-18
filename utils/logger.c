#include <stdio.h>
#include <time.h>
#include <string.h>

void log_event(const char *filename, const char *component, const char *event) {
    FILE *f = fopen(filename, "a");
    if (!f) return;
    time_t now = time(NULL);
    char buf[64];
    struct tm *tm_info = localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(f, "[%s] [%s] %s\n", buf, component, event);
    fclose(f);
}

// Enhanced logging with detailed context
void log_event_detailed(const char *filename, const char *component, 
                       const char *operation, const char *username,
                       const char *ip, int port, const char *details,
                       int display_terminal) {
    FILE *f = fopen(filename, "a");
    if (!f) return;
    
    time_t now = time(NULL);
    char buf[64];
    struct tm *tm_info = localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Log to file with all details
    if (username && username[0] && ip && port > 0) {
        fprintf(f, "[%s] [%s] Operation=%s User=%s IP=%s:%d %s\n", 
                buf, component, operation, username, ip, port, details ? details : "");
    } else if (ip && port > 0) {
        fprintf(f, "[%s] [%s] Operation=%s IP=%s:%d %s\n", 
                buf, component, operation, ip, port, details ? details : "");
    } else {
        fprintf(f, "[%s] [%s] %s %s\n", buf, component, operation, details ? details : "");
    }
    fclose(f);
    
    // Also display to terminal if requested (for NM/SS monitoring)
    if (display_terminal) {
        if (username && username[0] && ip && port > 0) {
            printf("[%s] %s by %s from %s:%d - %s\n", 
                   buf, operation, username, ip, port, details ? details : "OK");
        } else if (ip && port > 0) {
            printf("[%s] %s from %s:%d - %s\n", 
                   buf, operation, ip, port, details ? details : "OK");
        } else {
            printf("[%s] %s - %s\n", buf, operation, details ? details : "OK");
        }
        fflush(stdout);
    }
}

