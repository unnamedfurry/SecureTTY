//
// Created by unnamedfurry on 8/30/26.
//

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

// Shared variables and methods
#include "shared-variables.h"
extern bool EncryptPacket(ClientSession *session, const char* plaintext, char* out_buffer, size_t max_size);

bool sendPacket(int sock, const char *data, ClientSession *curr) {
    time_t rawtime;
    struct tm *info;
    char buffer[80];
    time(&rawtime);
    info = localtime(&rawtime);
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", info);
    if (sock <= 0 || data == NULL) return false;

    char packet[PACKET_SIZE-1] = {0};
    if (!curr) return false;

    if (!EncryptPacket(curr, data, packet, sizeof(packet)-1)) {
        printf("[%s][SEND] Encryption failed\n", buffer);
        return false;
    }

    packet[strlen(packet)]='\n';
    size_t length = strlen(packet), sent = 0;
    while (sent < length) {
        ssize_t n = send(sock, packet + sent, length - sent, MSG_NOSIGNAL);
        if (n <= 0) {
            if (errno == EPIPE || errno == ECONNRESET) {
                printf("[%s][SEND] Client disconnected (sock=%d)\n", buffer, sock);
            } else {
                printf("[%s][SEND] send() error: %s (sock=%d)\n", buffer, strerror(errno), sock);
            }
            return false;
        }
        sent += (size_t)n;
    }

    printf("[%s][SEND] Sent successfully: %s (sock=%d)\n", buffer, packet, sock);
    return true;
}