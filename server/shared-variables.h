//
// Created by unnamedfurry on 8/30/26.
//

#ifndef SECURETTY_SHARED_VARIABLES_H
#define SECURETTY_SHARED_VARIABLES_H

#include <pthread.h>
#include <mysql/mysql.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_box.h>

// COLORS
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"

#define BRED    "\033[1;31m"
#define BGREEN  "\033[1;32m"
#define BYELLOW "\033[1;33m"
#define BBLUE   "\033[1;34m"
#define BMAGENTA "\033[1;35m"
#define BCYAN   "\033[1;36m"
#define BWHITE  "\033[1;37m"

// SIZES
#define MAX_CLIENTS 1024
#define BUFFER_SIZE 7097
#define MAX_NAME 23
#define MAX_EMAIL 32
#define MAX_PASS 23
#define MAX_AVATAR 64
#define MAX_DESC 1024
#define MAX_MESS 2048
#define PACKET_SIZE 524288
#define MAX_RESPONSE (MAX_NAME + MAX_EMAIL + MAX_PASS + MAX_AVATAR + MAX_DESC + MAX_MESS)

// SERVER DATA
extern MYSQL *conn;
typedef struct ClientSession {
    long userId;
    int sock;
    unsigned char serverSessionKey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    bool hasSessionKey;
    bool loggedIn;
    bool closing;
    struct ClientSession *next;
} ClientSession;
extern ClientSession *activeClients;
extern pthread_mutex_t mysql_mutex;
extern pthread_mutex_t clientsMutex;
static pthread_mutex_t g_clients_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_server_fd = -1;
static int g_client_socks[MAX_CLIENTS];
static int g_client_count = 0;
extern bool finishedResponse;

// CRYPTOGRAPHY
static unsigned char serverPublicKey[crypto_box_PUBLICKEYBYTES];
static unsigned char serverPrivateKey[crypto_box_SECRETKEYBYTES];

#endif //SECURETTY_SHARED_VARIABLES_H