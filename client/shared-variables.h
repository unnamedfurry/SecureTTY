//
// Created by unnamedfurry on 8/28/26.
//

#ifndef SECURETTY_SHARED_VARIABLES_H
#define SECURETTY_SHARED_VARIABLES_H

#include <netinet/in.h>
#include <sodium/crypto_pwhash.h>
#include <pthread.h>
#include <sodium.h>

#include "raylib.h"

// COLORS
#define RESET   "\033[0m"
#define cRED     "\033[31m"
#define cGREEN   "\033[32m"
#define cYELLOW  "\033[33m"
#define cBLUE    "\033[34m"
#define cMAGENTA "\033[35m"
#define cCYAN    "\033[36m"

#define BRED    "\033[1;31m"
#define BGREEN  "\033[1;32m"
#define BYELLOW "\033[1;33m"
#define BBLUE   "\033[1;34m"
#define BMAGENTA "\033[1;35m"
#define BCYAN   "\033[1;36m"
#define BWHITE  "\033[1;37m"

extern Color backgroundColor;
extern Color background2Color;
extern Color mainColor;
extern Color secondaryColor;
extern Color secondary2Color;
extern Color plateColor;

// SIZES
#define CONFIG_FILE "conf.enc"
#define MAX_NAME 23
#define MAX_EMAIL 32
#define MAX_PASS 23
#define MAX_AVATAR 64
#define MAX_DESC 1024
#define MAX_MESS 2048
#define BUFFER_SIZE 7097
#define PACKET_SIZE 524288

// CLIENT DATA
typedef struct {
    bool isFirstUsed;
    long userId;
    char userName[MAX_NAME+1];
    char email[MAX_EMAIL+1];
    char passwordHash[crypto_pwhash_STRBYTES];
    char avatarUrl[MAX_AVATAR+1];
    char profileDescription[MAX_DESC+1];
} Config;
extern Config config;

typedef struct {
    char name[MAX_NAME+1];
    long userId;
    char profileDescription[MAX_DESC+1];
    char avatarUrl[MAX_AVATAR+1];
    int newMessageCount;
    bool triedLoadAvatar;
} Friend;
extern Friend friends[100];
extern Friend pendingFriends[100];

typedef struct {
    long messageId;
    long senderId;
    long receiverId;
    char message[2049];
    int cachedHeight;
    int cachedBubbleWidth;
} Message;
extern Message messages[1000000];
extern Texture2D userAvatarTexture;
extern Texture2D friendAvatarArr[100];
extern Texture2D pendingFriendAvatarArr[100];
extern bool requestedAvatarUpdate;
extern bool hasFriendRequests;
extern bool isUpdatedMessages;
extern bool isUpdatedFriends;
extern long currentFriendId;
extern int messagesCount;
extern int friendsCount;

// CRYPTO DATA
#define SALT_SIZE crypto_pwhash_SALTBYTES
#define HEADER_SIZE crypto_secretstream_xchacha20poly1305_HEADERBYTES
extern pthread_mutex_t clientStateMutex;
extern unsigned char clientSessionKey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
extern unsigned char clientPub[crypto_box_PUBLICKEYBYTES];
extern unsigned char clientPriv[crypto_box_SECRETKEYBYTES];
extern char masterPassword[MAX_PASS+1];
extern bool hasSessionKey;
extern bool sentKeyExchange;
extern long randomMessageId;

// NETWORK DATA
extern pthread_t thread_id;
extern int sock;
extern struct sockaddr_in serv_addr;
extern bool connected;
extern bool initedNetwork;
extern bool triedNetwork;
extern int profileUpdateCode;
extern int serverErrorCode;

#endif //SECURETTY_SHARED_VARIABLES_H