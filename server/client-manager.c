//
// Created by unnamedfurry on 8/30/26.
//

#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

// Shared variables and methods
#include "shared-variables.h"

// register client (before authorization)
void registerClient(long userId, int sock) {
    pthread_mutex_lock(&g_clients_lock);
    if (g_client_count < MAX_CLIENTS) {
        g_client_socks[g_client_count++] = sock;
    }
    pthread_mutex_unlock(&g_clients_lock);

    time_t rawtime;
    struct tm *info;
    char buffer[80];
    time(&rawtime);
    info = localtime(&rawtime);
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", info);

    pthread_mutex_lock(&clientsMutex);

    // looking for current (anonymous) session by sock
    ClientSession *mine = nullptr;
    for (ClientSession *c = activeClients; c; c = c->next)
        if (c->sock == sock) { mine = c; break; }

    // removing old stranger sessions with same userId (is not current sock)
    ClientSession *curr = activeClients, *prev = nullptr;
    while (curr) {
        if (curr->userId == userId && curr->sock != sock) {
            close(curr->sock);
            pthread_mutex_lock(&g_clients_lock);
            for (int i = 0; i < g_client_count; i++) {
                if (g_client_socks[i] == curr->sock) {
                    g_client_socks[i] = g_client_socks[--g_client_count];
                    break;
                }
            }
            pthread_mutex_unlock(&g_clients_lock);
            curr->closing = true;
            curr = curr->next;
            printf("[%s][NETWORK] Replacing old session for user %ld\n", buffer, userId);
            continue;
        }
        prev = curr; curr = curr->next;
    }

    if (mine) {
        mine->userId = userId;           // key and hasSessionKey are saved
        mine->loggedIn=false;
    }
    printf("[%s][NETWORK] Client registered: userId=%ld, sock=%d\n", buffer, userId, sock);
    pthread_mutex_unlock(&clientsMutex);
}

// remove client after disconnecting
void unregisterClient(ClientSession *curr) {
    if (!curr) return;
    pthread_mutex_lock(&g_clients_lock);
    for (int i = 0; i < g_client_count; i++) {
        if (g_client_socks[i] == curr->sock) {
            g_client_socks[i] = g_client_socks[--g_client_count];
            break;
        }
    }
    pthread_mutex_unlock(&g_clients_lock);

    time_t rawtime;
    struct tm *info;
    char buffer[80];
    time(&rawtime);
    info = localtime(&rawtime);
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", info);

    pthread_mutex_lock(&clientsMutex);
    ClientSession *c = activeClients, *prev = nullptr;
    while (c) {
        if (c == curr) {
            if (prev) prev->next = c->next; else activeClients = c->next;
            break;
        }
        prev = c; c = c->next;
    }
    pthread_mutex_unlock(&clientsMutex);

    printf("[%s][NETWORK] client disconnected: userId=%ld\n", buffer, curr->userId);
}