#ifndef UTILS_H
#define UTILS_H

#include "protocol.h"

void log_event(const char *filename, const char *component, const char *event);

int create_server_socket(int port);
int connect_to_server(char *ip, int port);
int send_message(int sockfd, Message *msg);
int receive_message(int sockfd, Message *msg);
void list_folders(); // New function for folder listing
int get_server_count(); // New function for server count accessor

#endif
