#include "../include/constants.h"
#include "../include/protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

// Create a TCP server socket and bind to given port
int create_server_socket(int port) {
    int server_fd;
    struct sockaddr_in address;
    
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    // Bind on all interfaces by default; if you want a specific IP, change here to inet_pton on that IP.
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, BACKLOG) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    return server_fd;
}

// Connect to a server given IP and port
int connect_to_server(char *ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
    perror("Socket creation failed");
    return -1;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) { perror("Invalid address"); close(sock); return -1; }

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) { perror("Connection failed"); close(sock); return -1; }

    return sock;
}

// Send and receive Message structs
int send_message(int sockfd, Message *msg) {
    size_t total = 0;
    const char *ptr = (const char*)msg;
    size_t tosend = sizeof(Message);
    while (total < tosend) {
        ssize_t n = send(sockfd, ptr + total, tosend - total, 0);
        if (n <= 0) return (int)n;
        total += (size_t)n;
    }
    return (int)total;
}

int receive_message(int sockfd, Message *msg) {
    size_t total = 0;
    char *ptr = (char*)msg;
    size_t torecv = sizeof(Message);
    while (total < torecv) {
        ssize_t n = recv(sockfd, ptr + total, torecv - total, 0);
        if (n <= 0) return (int)n;
        total += (size_t)n;
    }
    return (int)total;
}
