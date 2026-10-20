//
// Created by unnamedfurry on 8/28/26.
//

#include "shared-variables.h"

#include "raylib.h"

// COLORS
Color backgroundColor = {40, 40, 40, 255};
Color background2Color = {24, 24, 24, 255};
Color mainColor = {255, 255, 255, 255};
Color secondaryColor = {128, 128, 128, 255};
Color secondary2Color = {218, 165, 32, 255};
Color plateColor = {70, 70, 60, 255};

// CLIENT DATA
Config *config = nullptr;
Friend *friends[100] = {0};
Friend *pendingFriends[100] = {0};
Message *messages[1000000] = {0};
//Message *pendingMessages[100] = {0};
Texture2D userAvatarTexture = {0};
Texture2D friendAvatar[100] = {0};
Texture2D pendingFriendAvatar[100] = {0};
AppState currentState = STATE_MASTER_PASSWORD;
bool requestedAvatarUpdate = false;
bool chatAutoScrollAllowed = true;
bool hasFriendRequests = false;
bool isUpdatedMessages = false;
bool isUpdatedFriends = false;
bool hasMoreMessages = true;
bool processedQueue = false;
bool canUploadFile = false;
bool wrongPass = false;
bool loggedIn = false;
long currentFriendId = 0L;
int messagesCount = -2;
int friendsCount = -2;
int messageOffset = 0;
int loginCode = -3;

// CRYPTO DATA
pthread_mutex_t clientStateMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t pendingMessageMutex = PTHREAD_MUTEX_INITIALIZER;
unsigned char clientSessionKey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
unsigned char clientPub[crypto_box_PUBLICKEYBYTES];
unsigned char clientPriv[crypto_box_SECRETKEYBYTES];
char masterPassword[MAX_PASS+1] = {0};
bool hasSessionKey = false;
bool sentKeyExchange = false;
//long randomMessageId = -1L;

// NETWORK DATA
pthread_t thread_id;
int sock = -1;
struct sockaddr_in serv_addr;
bool connected = false;
bool initedNetwork = false;
bool triedNetwork = false;
int profileUpdateCode = -1;
int serverErrorCode = -1;