#include "raylib.h"
#define RAYGUI_IMPLEMENTATION
#include "raygui.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <dirent.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include "client.h"
#include <sys/stat.h>
#include <sodium.h>

#define CONFIG_FILE "conf.enc"
#define MAX_NAME 23
#define MAX_EMAIL 32
#define MAX_PASS 23
#define MAX_AVATAR 64
#define MAX_DESC 1024
#define MAX_MESS 2048
#define PACKET_SIZE 524288

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

typedef struct {
    bool isFirstUsed;
    long userId;
    char userName[MAX_NAME+1];
    char email[MAX_EMAIL+1];
    char passwordHash[MAX_PASS];
    char avatarUrl[MAX_AVATAR+1];
    char profileDescription[MAX_DESC+1];
} Config;
Config config = {0};
typedef struct {
    char name[MAX_NAME+1];
    long userId;
    char profileDescription[MAX_DESC+1];
    char avatarUrl[MAX_AVATAR+1];
    int newMessageCount;
} Friend;
Friend friends[100] = {0};
Friend pendingFriends[100] = {0};
typedef struct {
    long messageId;
    long senderId;
    long receiverId;
    char message[2049];
} Message;
Message messages[1000000] = {0};
long randomId = 0L;
long currentFriendId = 0L;
int messagesCount = 0;
static Texture2D friendAvatarArr[100] = {0};
static Texture2D pendingFriendAvatarArr[100] = {0};
bool requestedAvatarUpdate=false;
bool hasFriendRequests = false;

char masterPassword[MAX_PASS+1] = {0};
unsigned char clientSessionKey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
bool hasSessionKey = false;
bool sentKeyExchange = false;
unsigned char clientPub[crypto_box_PUBLICKEYBYTES];
unsigned char clientPriv[crypto_box_SECRETKEYBYTES];

// Base64 decode through OpenSSL
char* Base64Encode(const unsigned char* input, int length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, length);
    BIO_flush(bio);

    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);

    char* output = (char*)malloc(bufferPtr->length + 1);
    memcpy(output, bufferPtr->data, bufferPtr->length);
    output[bufferPtr->length] = '\0';

    BIO_free_all(bio);
    return output;
}
unsigned char* Base64Decode(const char* input, int* out_len) {
    BIO *bio, *b64;
    int input_len = strlen(input);

    unsigned char* output = (unsigned char*)malloc(input_len * 3 / 4 + 1);
    if (!output) return nullptr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input, input_len);
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *out_len = BIO_read(bio, output, input_len);

    BIO_free_all(bio);

    if (*out_len <= 0) {
        free(output);
        return nullptr;
    }
    return output;
}

//
//             NETWORK COMMUNICATION
//


#define BUFFER_SIZE 7097
static pthread_t thread_id;
static int sock = -1;
static struct sockaddr_in serv_addr;
bool connected = false;
bool initedNetwork = false;
int profileUpdateCode = -1;
int serverErrorCode = -1;
void sendMessage(const char *message);
bool LoadEncryptedConfig(Config *cfg, const char* master_password);
bool SaveEncryptedConfig(Config *cfg, const char* master_password);
// Decrypting received message
bool DecryptPacket(const char* encrypted_packet, char* out_plaintext, size_t max_out_size) {
    if (strncmp(encrypted_packet, "enc:", 4) != 0) {
        // Not encrypted
        strncpy(out_plaintext, encrypted_packet, max_out_size - 1);
        out_plaintext[max_out_size - 1] = '\0';
        return true;
    }

    // Format: enc:nonce_b64:ciphertext_b64
    char *nonce_b64 = strtok((char*)(encrypted_packet + 4), ":");
    char *ct_b64 = strtok(nullptr, ":");

    if (!nonce_b64 || !ct_b64) return false;

    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    unsigned char ciphertext[8192];
    size_t nonce_len = 0, ct_len = 0;

    sodium_base642bin(nonce, sizeof(nonce), nonce_b64, strlen(nonce_b64), nullptr, &nonce_len, nullptr, sodium_base64_VARIANT_ORIGINAL);
    sodium_base642bin(ciphertext, sizeof(ciphertext), ct_b64, strlen(ct_b64), nullptr, &ct_len, nullptr, sodium_base64_VARIANT_ORIGINAL);

    unsigned char decrypted[8192] = {0};
    unsigned long long decrypted_len;
    int ret;

    ret = crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, &decrypted_len,
            nullptr,
            ciphertext, ct_len,
            nullptr, 0, nonce, clientSessionKey);

    if (ret != 0) {
        printf("[DECRYPT] Error decrypting or bad key.\n");
        return false;
    }

    strncpy(out_plaintext, (char*)decrypted, max_out_size - 1);
    out_plaintext[max_out_size - 1] = '\0';
    return true;
}
void* recieveMessage(void* arg) {
    char localBuf[BUFFER_SIZE];
    char fullMessage[PACKET_SIZE];  // large buffer
    int totalReceived = 0;

        // reading till got atleast one full answer
        while (connected) {
            memset(localBuf, 0, sizeof(localBuf));
            int bytes = read(sock, localBuf, sizeof(localBuf)-1);
            if (bytes <= 0) {
                connected = false;
                printf("[RECEIVE] Connection lost\n");
                return NULL;
            }
            if (totalReceived + bytes > sizeof(fullMessage) - 1) {
                printf("[RECEIVE] Message too big! Clearing buffer.\n");
                totalReceived = 0;
            }
            memcpy(fullMessage + totalReceived, localBuf, bytes);
            totalReceived += bytes;
            fullMessage[totalReceived] = '\0';
            printf("[DEBUG] LocalBuf has %lu bytes, string is %lu chars long and contains text `%s`. FullMessage has %lu bytes, string is %lu chars long and contains `%s` message. TotalReceived is %d.\n", sizeof(localBuf), strlen(localBuf), localBuf, sizeof(fullMessage), strlen(fullMessage), fullMessage, totalReceived);

            char *newline;
            while ((newline = strchr(fullMessage, '\n')) != NULL) {
                *newline = '\0';
                printf("[RECEIVE MESSAGE] Got %d bytes from server\n", totalReceived);
                printf("[RECEIVE MESSAGE] Server said (full message): %s\n", fullMessage);

                if (strncmp(fullMessage, "keyexchange/ok/", 15) == 0 && hasSessionKey==false) {
                    char *serverPubB64 = fullMessage + 15;

                    unsigned char serverPub[crypto_box_PUBLICKEYBYTES];
                    size_t len = 0;
                    sodium_base642bin(serverPub, sizeof(serverPub), serverPubB64, strlen(serverPubB64),
                                     nullptr, &len, nullptr, sodium_base64_VARIANT_ORIGINAL);

                    printf("[CRYPTO] Received server pubkey, len = %zu\n", len);

                    if (len == crypto_box_PUBLICKEYBYTES) {
                        int ret = crypto_box_beforenm(clientSessionKey, serverPub, clientPriv);
                        if (ret == 0) {
                            hasSessionKey = true;
                            printf("[CRYPTO] Client session key: %p\n", (void*)clientSessionKey);
                        } else {
                            printf(cRED "[CRYPTO] crypto_box_beforenm failed with code %d\n" RESET, ret);
                        }
                    }
                } else {
                    char decrypted[PACKET_SIZE] = {0};
                    if (DecryptPacket(fullMessage, decrypted, sizeof(decrypted))) {
                        strncpy(fullMessage, decrypted, sizeof(fullMessage)-1);
                    }
                }
                if (strncmp(fullMessage, "save-profile/", 13) == 0) {
                    if (strncmp(fullMessage+13, "ok", 2) == 0) {
                        printf("[SAVE PROFILE] Profile successfully saved on server\n");
                        LoadEncryptedConfig(&config, masterPassword);
                        if (config.userId == 0) {
                            printf(cRED "[FATAL]" RESET "[SAVE PROFILE] User ID is 0, shutting down.\n");
                            exit(4);
                        }
                    } else if (strncmp(fullMessage+13, "error", 5) == 0) {
                        profileUpdateCode = 1;
                        char *parts2[2] = {0};
                        int cnt2 = 0;
                        char *token2 = strtok(fullMessage+19, "\x1E");
                        while (token2 && cnt2 < 2) {
                            parts2[cnt2++] = (token2 == NULL || strcmp(token2, "null") == 0 || strcmp(token2, "NULL") == 0) ? "" : token2;
                            token2 = strtok(nullptr, "\x1E");
                        }
                        strncpy(config.avatarUrl, parts2[4], MAX_AVATAR);
                        strncpy(config.profileDescription, parts2[5], MAX_DESC);
                        SaveEncryptedConfig(&config, masterPassword);
                        LoadEncryptedConfig(&config, masterPassword);
                    } else if (strncmp(fullMessage+13, "badformat", 9) == 0) {
                        profileUpdateCode = 2;
                        char *parts2[2] = {0};
                        int cnt2 = 0;
                        char *token2 = strtok(fullMessage+23, "\x1E");
                        while (cnt2 < 2) {
                            parts2[cnt2++] = (token2 == NULL || strcmp(token2, "null") == 0 || strcmp(token2, "NULL") == 0) ? "" : token2;
                            token2 = strtok(nullptr, "\x1E");
                        }
                        strncpy(config.avatarUrl, parts2[4], MAX_AVATAR);
                        strncpy(config.profileDescription, parts2[5], MAX_DESC);
                        SaveEncryptedConfig(&config, masterPassword);
                        LoadEncryptedConfig(&config, masterPassword);
                    }
                }
                else if (strncmp(fullMessage, "createId/user/", 14) == 0) {
                    long newId = atol(localBuf + 14);
                    if (newId > 0) {
                        config.userId = newId;
                        printf("[CREATE USER ID] Got new id from server: %ld\n", newId);
                        char msgBuf[BUFFER_SIZE];
                        snprintf(msgBuf, sizeof(msgBuf), "registerClient/%ld", newId);
                        sendMessage(msgBuf);
                    }
                }
                else if (strncmp(fullMessage, "createId/message/", 17) == 0) {
                    long newId = atol(localBuf + 17);
                    if (newId > 0) {
                        randomId = newId;
                        printf("[CREATE MESSAGE ID] Got new id from server: %ld\n", newId);
                    }
                }
                else if (strncmp(fullMessage, "getFriendsList/", 15) == 0) {
                    printf("[GET FRIENDS LIST] Received new list from server\n");

                    // clearing past friends
                    memset(friends, 0, sizeof(friends));
                    for (int i = 0; i < 100; i++) {
                        if (friendAvatarArr[i].id != 0) {
                            UnloadTexture(friendAvatarArr[i]);
                            friendAvatarArr[i].id = 0;
                        }
                    }

                    int count = 0;

                    // strtok_r — reentrant version (for safe embed using)
                    char *saveptr1 = nullptr;
                    char *saveptr2 = nullptr;

                    char *token = strtok_r(localBuf + 15, "\x1E", &saveptr1); // skipping self id
                    token = strtok_r(NULL, "\x1E", &saveptr1);   // first friend

                    while (token && count < 100) {
                        char tokenCopy[1024];
                        strncpy(tokenCopy, token, sizeof(tokenCopy)-1);
                        tokenCopy[sizeof(tokenCopy)-1] = '\0';

                        char *subtoken = strtok_r(tokenCopy, "\x1F", &saveptr2);
                        int field = 0;

                        while (subtoken && field < 4) {
                            if (field == 0) strncpy(friends[count].name, subtoken, MAX_NAME);
                            else if (field == 1) friends[count].userId = strtol(subtoken, nullptr, 10);
                            else if (field == 2) strncpy(friends[count].avatarUrl, subtoken, MAX_AVATAR);
                            else if (field == 3) strncpy(friends[count].profileDescription, subtoken, MAX_DESC);

                            field++;
                            subtoken = strtok_r(nullptr, "\x1F", &saveptr2);
                        }

                        if (friends[count].userId > 0) {
                            friends[count].newMessageCount = 0;
                            count++;
                        }

                        token = strtok_r(nullptr, "\x1E", &saveptr1);
                    }

                    printf("[GET FRIENDS LIST] Successfully loaded %d friends\n", count);
                    requestedAvatarUpdate = true;
                }
                else if (strncmp(fullMessage, "getChatHistory/", 15) == 0) {
                    char *dataStart = strchr(localBuf + 15, '\x1E');
                    if (!dataStart) {
                        printf("[GET CHAT HISTORY] History is empty\n");
                        messagesCount = 0;
                        currentFriendId = strtol(localBuf + 15, nullptr, 10);
                        return NULL;
                    }

                    dataStart++;
                    long friendId = strtol(localBuf + 15, nullptr, 10);

                    // copy all at a time
                    size_t dataLen = strlen(dataStart) + 1;
                    char *dataCopy = malloc(dataLen);
                    if (!dataCopy) return NULL;

                    memcpy(dataCopy, dataStart, dataLen);

                    messagesCount = 0;
                    int loaded = 0;

                    char *p = dataCopy;

                    while (p && *p && messagesCount < 999999) {
                        // locating the end of the block
                        char *record_end = strchr(p, '\x1E');
                        if (record_end) *record_end = '\0';   // temporary cutting

                        if (strlen(p) > 0) {
                            char *q = p;

                            // parsing three parts through \x1F
                            char *part1 = q;
                            char *part2 = strchr(q, '\x1F');
                            char *part3 = nullptr;
                            if (part2) {
                                *part2 = '\0';
                                q = part2 + 1;

                                part3 = strchr(q, '\x1F');
                                if (part3) {
                                    *part3 = '\0';
                                    q = part3 + 1;           // part3 is now our text
                                } else {
                                    q = nullptr;
                                }
                            } else {
                                q = nullptr;
                            }

                            if (part1 && part2 && part3 && strlen(q) > 0 && !strstr(q, "null")) {
                                messages[messagesCount].messageId = strtol(part1, nullptr, 10);
                                messages[messagesCount].senderId  = strtol(part2 + 1, nullptr, 10);  // +1 bc of \x1F
                                messages[messagesCount].receiverId =
                                    (messages[messagesCount].senderId == config.userId) ? friendId : config.userId;

                                strncpy(messages[messagesCount].message, q, 2048);
                                messages[messagesCount].message[2049] = '\0';

                                messagesCount++;
                                loaded++;
                            }

                        }
                        // jumping to next block
                        if (record_end) {
                            *record_end = '\x1E';   // restoring
                            p = record_end + 1;
                        } else {
                            p = nullptr;
                        }
                    }

                    free(dataCopy);
                    currentFriendId = friendId;

                    printf("[GET CHAT HISTORY] Loaded %d messages with %ld\n", loaded, friendId);
                }
                else if (strncmp(fullMessage, "err", 3) == 0) {
                    printf("[ERROR] Server returned error for past action\n");
                }
                else if (strncmp(fullMessage, "newMessage\x1E", 11) == 0) {
                    char *parts[4] = {0};
                    int cnt = 0;
                    char *token = strtok(localBuf + 11, "\x1F");

                    while (token && cnt < 4) {
                        parts[cnt++] = token;
                        token = strtok(nullptr, "\x1F");
                    }

                    if (cnt >= 3) {
                        long msgId     = strtol(parts[0], nullptr, 10);
                        long senderId  = strtol(parts[1], nullptr, 10);
                        const char *text = parts[2];
                        // const char *time = parts[3]; - may use later

                        // updating new message counter badge
                        for (int i = 0; i < 100; i++) {
                            if (friends[i].userId == senderId) {
                                friends[i].newMessageCount++;
                                break;
                            }
                        }

                        // if the chat is opened - adding to messages
                        if (currentFriendId == senderId) {
                            if (messagesCount < 1000000) {
                                messages[messagesCount].messageId = msgId;
                                messages[messagesCount].senderId = senderId;
                                messages[messagesCount].receiverId = config.userId;
                                strncpy(messages[messagesCount].message, text, 2048);
                                messagesCount++;
                            }
                        }

                        printf("[GET MESSAGE] Got new push-message from %ld: %s\n", senderId, text);
                    }
                }
                else if (strncmp(fullMessage, "newFriendRequest/", 17) == 0) {
                    memset(pendingFriends, 0, sizeof(pendingFriends));
                    for (int i=0; i<100; i++) {
                        if (pendingFriendAvatarArr[i].id != 0) {
                            UnloadTexture(pendingFriendAvatarArr[i]);
                            pendingFriendAvatarArr[i].id = 0;
                        }
                    }
                    hasFriendRequests = false;

                    char *ptr = localBuf+17;
                    char *saveptr = nullptr;
                    char *token = strtok_r(ptr, "\x1E", &saveptr);
                    int count = 0;

                    while (token && count < 100) {
                        char tokenCopy[1024];
                        strncpy(tokenCopy, token, sizeof(tokenCopy)-1);
                        tokenCopy[sizeof(tokenCopy)-1] = '\0';

                        char *parts[3] = {0};
                        char *sub = strtok(tokenCopy, "\x1F");
                        int p = 0;
                        while (sub && p < 3) {
                            parts[p++] = sub;
                            sub = strtok(nullptr, "\x1F");
                        }

                        if (parts[0]) {
                            hasFriendRequests=true;
                            pendingFriends[count].userId = strtol(parts[0], nullptr, 10);
                            if (parts[1]) strncpy(pendingFriends[count].name, parts[1], MAX_NAME);
                            if (parts[2]) strncpy(pendingFriends[count].profileDescription, parts[2], MAX_DESC);
                            count++;
                        }

                        token = strtok_r(nullptr, "\x1E", &saveptr);
                    }
                }
                else if (strncmp(fullMessage, "updateClient/messages", 21) == 0) {
                    char *ptr = localBuf + 21;

                    int totalNew = (int)strtol(ptr, &ptr, 10);
                    ptr = strchr(ptr, '\x1E');
                    if (!ptr) return NULL;
                    ptr++;  // getting right to the data while skipping header and \x1E

                    // clear old counters
                    for (int i = 0; i < 100; i++) {
                        friends[i].newMessageCount = 0;
                    }

                    char *token = strtok(ptr, "\x1E");
                    while (token) {
                        char *parts[2] = {0};
                        int c = 0;
                        char *t2 = strtok(token, "\x1F");
                        while (t2 && c < 2) {
                            parts[c++] = t2;
                            t2 = strtok(nullptr, "\x1F");
                        }

                        if (c == 2) {
                            long senderId = strtol(parts[0], nullptr, 10);
                            int count = atoi(parts[1]);

                            for (int i = 0; i < 100; i++) {
                                if (friends[i].userId == senderId) {
                                    friends[i].newMessageCount = count;
                                    break;
                                }
                            }
                        }
                        token = strtok(nullptr, "\x1E");
                    }

                    printf("[UPDATE CLIENT] Got %d new messages\n", totalNew);
                }
                else if (strncmp(fullMessage, "updateClient/friendRequests", 27) == 0) {
                    printf("[FRIEND REQUESTS] Received pending requests\n");

                    memset(pendingFriends, 0, sizeof(pendingFriends));
                    for (int i=0; i<100; i++) {
                        if (pendingFriendAvatarArr[i].id != 0) {
                            UnloadTexture(pendingFriendAvatarArr[i]);
                            pendingFriendAvatarArr[i].id = 0;
                        }
                    }
                    hasFriendRequests = false;

                    char *ptr = fullMessage+28;
                    char *saveptr = nullptr;
                    char *token = strtok_r(ptr, "\x1E", &saveptr);
                    int count = 0;

                    while (token && count < 100) {
                        char tokenCopy[1024];
                        strncpy(tokenCopy, token, sizeof(tokenCopy)-1);
                        tokenCopy[sizeof(tokenCopy)-1] = '\0';

                        char *parts[3] = {0};
                        char *sub = strtok(tokenCopy, "\x1F");
                        int p = 0;
                        while (sub && p < 2) {
                            parts[p++] = sub;
                            sub = strtok(nullptr, "\x1F");
                        }

                        if (parts[0]) {
                            hasFriendRequests=true;
                            pendingFriends[count].userId = strtol(parts[0], nullptr, 10);
                            if (parts[1]) strncpy(pendingFriends[count].name, parts[1], MAX_NAME);
                            if (parts[2]) strncpy(pendingFriends[count].profileDescription, parts[2], MAX_DESC);
                            count++;
                        }

                        token = strtok_r(nullptr, "\x1E", &saveptr);
                    }

                    printf("[FRIEND REQUESTS] Parsed %d pending requests\n", count);
                }
                if (strncmp(fullMessage, "getAvatarResponse/", 18) == 0) {
                    printf("[GET AVATAR] Received (%d bytes)\n", totalReceived);

                    char *ptr = fullMessage + 18;
                    long userId = strtol(ptr, &ptr, 10);

                    if (*ptr == '\x1E') {
                        char *b64_start = ptr + 1;
                        char *b64_end = strchr(b64_start, '\x1E');
                        if (b64_end) *b64_end = '\0';

                        int decoded_len = 0;
                        unsigned char* png_data = Base64Decode(b64_start, &decoded_len);

                        if (png_data && decoded_len > 1000) {
                            if (!DirectoryExists("avatars")) MakeDirectory("avatars");

                            char filepath[128];
                            snprintf(filepath, sizeof(filepath), "avatars/%ld.png", userId);

                            FILE *f = fopen(filepath, "wb");
                            if (f) {
                                size_t written = fwrite(png_data, 1, decoded_len, f);
                                fclose(f);
                                printf("[GET AVATAR] Saved %ld.png | Written: %zu / %d bytes\n",
                                   userId, written, decoded_len);
                            }
                            free(png_data);
                            requestedAvatarUpdate = true;
                        } else {
                            printf("[GET AVATAR] Decode failed or too small (%d bytes)\n", decoded_len);
                        }
                    }
                    requestedAvatarUpdate=true;
                }
                else if (strncmp(fullMessage, "requestPendingFriends/", 22) == 0) {
                    char req[34] = {0};
                    snprintf(req, 33, "requestPendingFriends/%ld", config.userId);
                    sendMessage(req);
                }
                else if (strncmp(fullMessage, "requestFriendUpdate/", 20) == 0) {
                    char req[34] = {0};
                    snprintf(req, 33, "getFriendsList/%ld", config.userId);
                    sendMessage(req);
                }
                else if (strncmp(fullMessage, "error", 5) == 0) {
                    char *ptr = fullMessage+5;
                    if (strcmp(ptr, "lockedThread") == 0) {
                        serverErrorCode=1;
                    } else if (strcmp(ptr, "unknownIssue") == 0) {
                        serverErrorCode=2;
                    }
                }

                // moving the end
                size_t processed = (newline + 1) - fullMessage;
                printf("[DEBUG] Processed if %lu.\n", processed);
                memmove(fullMessage, newline + 1, totalReceived - processed);
                totalReceived -= processed;
            }
        }
    return NULL;
}
bool initNetwork(void) {
    if (initedNetwork) return true;
    if (connected) return true;
    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    // Define server target
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr);
    // Connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf(cRED "[FATAL | NETWORK] Failed to connect to server\n" RESET);
        return false;
    }
    connected=true;
    // Create a listener
    if (pthread_create(&thread_id, nullptr, recieveMessage, NULL) != 0) {
        printf(cRED "[FATAL | NETWORK] Failed to create listener thread\n" RESET);
    }

    // Setting up session key
    if (sodium_init() < 0) {
        printf(cRED "[FATAL]" RESET "[CRYPTO] Failed to initialize sodium, exiting.\n");
        exit(5);
    }
    crypto_box_keypair(clientPub, clientPriv);
    // Sending keys and awaiting for response
    char packet1[512];
    char pub_b64[312];
    sodium_bin2base64(pub_b64, sizeof(pub_b64), clientPub, sizeof(clientPub), sodium_base64_VARIANT_ORIGINAL);
    snprintf(packet1, sizeof(packet1), "keyexchange/%s\x1D", pub_b64);
    ssize_t sent = send(sock, packet1, strlen(packet1), 0);
    if (sent < 0) {initedNetwork=false; connected = false;}
    sentKeyExchange=true;
    return true;
}
// Encrypting key before sending
bool EncryptPacket(const char* plaintext, char* out_ciphertext, size_t max_out_size) {
    if (!hasSessionKey) {
        // If key isnt set yet - sending as it is
        strncpy(out_ciphertext, plaintext, max_out_size - 1);
        out_ciphertext[max_out_size - 1] = '\0';
        return true;
    }

    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    memset(nonce, 0, sizeof(nonce));
    randombytes_buf(nonce, sizeof(nonce));

    size_t len = strlen(plaintext);
    unsigned char ciphertext[len + crypto_aead_xchacha20poly1305_ietf_ABYTES + 64];
    memset(ciphertext, 0, sizeof(ciphertext));
    unsigned long long ciphertext_len;

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, &ciphertext_len,
            (const unsigned char*)plaintext, len,
            nullptr, 0, nullptr, nonce, clientSessionKey) != 0) {
        return false;
            }

    // Formatting nonce + ciphertext in base64
    char nonce_b64[128] = {0};
    char ct_b64[524160] = {0};

    sodium_bin2base64(nonce_b64, sizeof(nonce_b64), nonce, sizeof(nonce), sodium_base64_VARIANT_ORIGINAL);
    sodium_bin2base64(ct_b64, sizeof(ct_b64), ciphertext, ciphertext_len, sodium_base64_VARIANT_ORIGINAL);

    snprintf(out_ciphertext, max_out_size, "enc:%s:%s", nonce_b64, ct_b64);
    return true;
}
void sendMessage(const char *message) {
    if (!connected || sock <= 0) {
        if (!initNetwork()) return;
    }

    // until the key is agreed upon, block all outgoing messages except the key exchange itself
    // (the key exchange is sent directly from initNetwork(), not via sendMessage)
    int waited = 0;
    while (!hasSessionKey && connected) {
        usleep(5000);
        waited += 5;
        if (waited > 5000) { // 5 sec — if the server doesnt respond, dont hang forever
            printf(cRED "[NETWORK] Timeout waiting for session key, message dropped: %s\n" RESET, message);
            return;
        }
    }
    if (!connected) return; // connection dropped while waiting

    char packet[PACKET_SIZE+1] = {0};
    if (!EncryptPacket(message, packet, sizeof(packet)-1)) {
        printf("[CRYPTO] Failed to encrypt message.\n");
        return;
    }

    packet[strlen(packet)]='\x1D';
    if (send(sock, packet, strlen(packet), 0) < 0) {
        printf("[NETWORK] Send error\n");
        connected = false;
        initedNetwork=false;
    } else {
        usleep(5000);
    }
    printf("[SEND] Sent message: %s", packet);
}


//
//             CONFIG LOAD AND SECURITY MODULE
//

#define SALT_SIZE crypto_pwhash_SALTBYTES
#define HEADER_SIZE crypto_secretstream_xchacha20poly1305_HEADERBYTES
// Generating master-key from password (Argon2id)
bool DeriveMasterKey(const char* password, unsigned char* master_key, const unsigned char* salt) {
    if (sodium_init() < 0) return false;

    return crypto_pwhash(master_key, crypto_secretstream_xchacha20poly1305_KEYBYTES,
                        password, strlen(password),
                        salt,
                        crypto_pwhash_OPSLIMIT_MODERATE,
                        crypto_pwhash_MEMLIMIT_MODERATE,
                        crypto_pwhash_ALG_ARGON2ID13) == 0;
}
bool LoadEncryptedConfig(Config *cfg, const char* master_password) {
    FILE *f = fopen(CONFIG_FILE, "rb");
    if (!f) {
        printf("[LOAD CONFIG FILE] conf.enc not found or corrupted. conf.enc will be recreated.\n");
        return false;
    }

    unsigned char salt[SALT_SIZE];
    unsigned char header[HEADER_SIZE];
    unsigned char master_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

    // Reading salt and header
    if (fread(salt, 1, sizeof(salt), f) != sizeof(salt)) {
        fclose(f);
        return false;
    }
    if (fread(header, 1, sizeof(header), f) != sizeof(header)) {
        fclose(f);
        return false;
    }

    if (!DeriveMasterKey(master_password, master_key, salt)) {
        fclose(f);
        return false;
    }

    crypto_secretstream_xchacha20poly1305_state state;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header, master_key) != 0) {
        fclose(f);
        return false;
    }

    // Reading encrypted data
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f) - sizeof(salt) - sizeof(header);
    fseek(f, sizeof(salt)+sizeof(header), SEEK_SET);
    unsigned char *encrypted = malloc(file_size);
    fread(encrypted, 1, file_size, f);
    fclose(f);

    unsigned char decrypted[8192] = {0};
    unsigned long long decrypted_len;
    unsigned char tag;

    if (crypto_secretstream_xchacha20poly1305_pull(&state, decrypted, &decrypted_len, &tag, encrypted, file_size, nullptr, 0) !=0) {
        free(encrypted);
        printf("[LOAD CONFIG FILE] Wrong master-password or corrupted file.\n");
        return false;
    }

    free(encrypted);

    char *line = strtok((char*)decrypted, "\n");
    while (line) {
        char *eq = strchr(line, '=');
        if (eq) {
            *eq = '\0';
            const char *key = line;
            const char *value = eq + 1;

            if (strcmp(key, "isFirstUsed") == 0) {
                cfg->isFirstUsed = (strcmp(value, "true") == 0);
            } else if (strcmp(key, "userId") == 0) {
                cfg->userId = strtol(value, NULL, 10);
            } else if (strcmp(key, "userName") == 0) {
                strncpy(cfg->userName, value, MAX_NAME);
            } else if (strcmp(key, "email") == 0) {
                strncpy(cfg->email, value, MAX_EMAIL);
            } else if (strcmp(key, "passwordHash") == 0) {
                strncpy(cfg->passwordHash, value, SHA256_DIGEST_LENGTH);
            } else if (strcmp(key, "avatarUrl") == 0) {
                strncpy(cfg->avatarUrl, value, MAX_AVATAR);
            } else if (strcmp(key, "profileDescription") == 0) {
                strncpy(cfg->profileDescription, value, MAX_DESC);
            }
        }
        line = strtok(nullptr, "\n");
    }
    return true;
}
bool SaveEncryptedConfig(Config *cfg, const char* master_password) {
    unsigned char salt[SALT_SIZE] = {0};
    unsigned char master_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char header[HEADER_SIZE];

    FILE *f = fopen(CONFIG_FILE, "wb");
    if (!f) return false;

    // Generating new salt if file is new
    // and reading existing salt if file is present
    if (!FileExists(CONFIG_FILE)) {
        randombytes_buf(salt, sizeof(salt));
        fwrite(salt, 1, sizeof(salt), f);
    } else {
        FILE *old = fopen(CONFIG_FILE, "rb");
        fread(salt, 1, sizeof(salt), old);
        fclose(old);
        fwrite(salt, 1, sizeof(salt), f);
    }

    if (!DeriveMasterKey(master_password, master_key, salt)) {
        printf("[SAVE ENCRYPTED CONFIG] Error generating key.\n");
        return false;
    }

    // Saving config to regular line
    char temp_config[16384] = {0};
    FILE *tmp = tmpfile();
    if (!tmp) return false;

    fprintf(tmp, "isFirstUsed=%s\n", cfg->isFirstUsed ? "true" : "false");
    fprintf(tmp, "userId=%ld\n", cfg->userId);
    fprintf(tmp, "userName=%s\n", cfg->userName);
    fprintf(tmp, "email=%s\n", cfg->email);
    fprintf(tmp, "passwordHash=%s\n", cfg->passwordHash);
    fprintf(tmp, "avatarUrl=%s\n", strlen(cfg->avatarUrl)==0 ? "null" : cfg->avatarUrl);
    fprintf(tmp, "profileDescription=%s\n", cfg->profileDescription);

    fseek(tmp, 0, SEEK_END);
    long size = ftell(tmp);
    fseek(tmp, 0, SEEK_SET);
    fread(temp_config, 1, size, tmp);
    fclose(tmp);

    crypto_secretstream_xchacha20poly1305_state state;
    crypto_secretstream_xchacha20poly1305_init_push(&state, header, master_key);
    fwrite(header, 1, sizeof(header), f); // header

    unsigned char out_buf[4096 + 32];
    unsigned long long out_len;

    crypto_secretstream_xchacha20poly1305_push(&state, out_buf, &out_len,
        (unsigned char*)temp_config, strlen(temp_config), nullptr, 0,
        crypto_secretstream_xchacha20poly1305_TAG_FINAL);

    fwrite(out_buf, 1, out_len, f);
    fclose(f);

    printf("[SAVE ENCRYPTED CONFIG] Saved config to file.\n");

    if (profileUpdateCode == -1) {
        // Sending sata to server
        char message[2048] = {0};
        snprintf(message, sizeof(message),
                 "save-profile/%ld\x1E%s\x1E%s\x1E%s\x1E%s\x1E%s",
                 cfg->userId,
                 cfg->userName,
                 cfg->email,
                 cfg->passwordHash,
                 (strcmp(cfg->avatarUrl, "") == 0 ? "null" : cfg->avatarUrl),
                 (strcmp(cfg->profileDescription, "") == 0 ? "null" : cfg->profileDescription));

        printf("[SAVE ENCRYPTED CONFIG] Sent data to server.\n");
        sendMessage(message);
    }
    return true;
}


//
//             BOXED TEXT RENDERING
//


void DrawTextBoxed(Font font, const char *text, Rectangle container, float fontSize, float spacing, Color tint) {
    int length = (int)TextLength(text);
    float scaleFactor = fontSize / (float)font.baseSize;

    float cursorX = 0.0f;
    float cursorY = 0.0f;

    for (int i = 0; i < length; i++) {
        int byteSize = 0;
        int codepoint = GetCodepoint(&text[i], &byteSize);
        int index = GetGlyphIndex(font, codepoint);

        // Handle Manual Newlines
        if (codepoint == '\n') {
            cursorY += ((float)font.baseSize + (float)font.baseSize / 2) * scaleFactor;
            cursorX = 0;
        } else {
            // Automatic Word Wrap Check
            if ((cursorX + ((float)font.glyphs[index].advanceX * scaleFactor)) > container.width) {
                cursorY += ((float)font.baseSize + (float)font.baseSize / 2) * scaleFactor;
                cursorX = 0;
            }

            // Draw character if it fits within the vertical bounds
            if ((cursorY + ((float)font.baseSize * scaleFactor)) <= container.height) {
                DrawTextCodepoint(font, codepoint, (Vector2){ container.x + cursorX, container.y + cursorY }, fontSize, tint);
            }

            // Advance cursor
            if (font.glyphs[index].advanceX == 0) cursorX += ((float)font.recs[index].width * scaleFactor + spacing);
            else cursorX += ((float)font.glyphs[index].advanceX * scaleFactor + spacing);
        }
        i += (byteSize - 1);
    }
}


//
//             MAIN METHOD
//

// go ask grok idk
int WrapText(const char* text, char* output, int maxOutputSize, int maxLineWidth,
             Font font, float fontSize, float spacing){
    if (!text || !output || maxOutputSize <= 0) return 0;

    output[0] = '\0';
    int totalHeight = 0;
    char currentLine[1024] = {0};

    const char* p = text;

    while (*p) {
        // skipping \n
        if (*p == '\n') {
            strcat(output, currentLine);
            strcat(output, "\n");
            totalHeight += (int)fontSize + 6;
            currentLine[0] = '\0';
            p++;
            continue;
        }

        // finding next word or chunk before space
        const char* wordStart = p;
        while (*p && *p != ' ' && *p != '\n') p++;
        int wordLen = (int)(p - wordStart);

        char word[512] = {0};
        if (wordLen > 0) {
            strncpy(word, wordStart, wordLen < 511 ? wordLen : 511);
        }

        // checking if the word is not crossing chat area
        char testLine[1024];
        if (currentLine[0] == '\0') {
            strcpy(testLine, word);
        } else {
            snprintf(testLine, sizeof(testLine), "%s %s", currentLine, word);
        }

        Vector2 size = MeasureTextEx(font, testLine, fontSize, spacing);

        if (size.x > maxLineWidth) {
            // if the solid word is going out of bounds -> we cut it
            if (currentLine[0] != '\0') {
                strcat(output, currentLine);
                strcat(output, "\n");
                totalHeight += (int)fontSize + 6;
                currentLine[0] = '\0';
            }

            // slicing the long world by symbols
            if (wordLen > 0) {
                float accumulatedWidth = 0.0f;
                char temp[2] = {0};

                for (int i = 0; i < wordLen; i++) {
                    temp[0] = word[i];
                    float charWidth = MeasureTextEx(font, temp, fontSize, spacing).x;

                    if (accumulatedWidth + charWidth > maxLineWidth && accumulatedWidth > 0) {
                        strcat(output, currentLine);
                        strcat(output, "\n");
                        totalHeight += (int)fontSize + 6;
                        currentLine[0] = '\0';
                        accumulatedWidth = 0;
                    }

                    strcat(currentLine, temp);
                    accumulatedWidth += charWidth;
                }
            }
        } else {
            strcpy(currentLine, testLine);
        }

        if (*p == ' ') p++; // skipping space
    }

    // appending last line
    if (currentLine[0] != '\0') {
        strcat(output, currentLine);
        totalHeight += (int)fontSize + 6;
    }

    return totalHeight;
}

// simplified wrapped text drawer
void DrawWrappedText(const char* text, Vector2 pos, Font font, float fontSize, float spacing, Color color){
    char line[1024] = {0};
    Vector2 currentPos = pos;

    for (const char* p = text; *p; ++p) {
        if (*p == '\n') {
            if (line[0]) {
                DrawTextEx(font, line, currentPos, fontSize, spacing, color);
            }
            currentPos.y += fontSize + 6;
            line[0] = '\0';
        } else {
            int len = (int)strlen(line);
            if (len < 1023) {
                line[len] = *p;
                line[len + 1] = '\0';
            }
        }
    }

    if (line[0]) {
        DrawTextEx(font, line, currentPos, fontSize, spacing, color);
    }
}

float clamp(float val, float min, float max) {
    if (val < min) return min;
    if (val > max) return max;
    return val;
}


/**
 * ## GuiFileSelector by @unnamed_furry
 *
 * This method helps the user easily select a file through a simple TUI interface.
 *
 * How it works:
 *
 * Step 1. The method attempts to read the root directory.
 *         If it fails, it falls back to the current working directory.
 *         If successful, it proceeds to step 2.
 *
 * Step 2. It scans all subfolders using scandir(), sorts them alphabetically
 *         and stores the result in the long-lived `rootFolders` array.
 *
 * Step 3. It scans all files using the same utility and stores the result
 *         in the long-lived `rootFiles` array.
 *
 * Step 4. The interface is rendered: path bar, folders panel and files panel.
 *
 * Step 5. Each panel listens for input events:
 *         - Left panel (folders): back arrow, mouse back, Delete key — go to parent directory.
 *         - Right panel (files): double-click or Enter — select the file and proceed to step 6.
 *
 * Step 6. When a file is selected (or Escape is pressed), the method enters
 *         the cleanup phase: frees all temporary memory and returns a pointer
 *         to the allocated full path string.
 *
 * Graphical explanation:
 *
 * @mermaid
 * flowchart TD
 *     A[Start: Allocate Memory] --> B[Draw UI Base and Headers]
 *     B --> C{Try to read root folder?}
 *     C -->|Success| D[Save folders to rootFolders]
 *     C -->|Failure| E[Read current directory]
 *     E --> D
 *     D --> F[Save files to rootFiles]
 *     F --> G[Render folders panel + input handling]
 *     G --> H[Render files panel + input handling]
 *     H --> I{File selected or Escape?}
 *     I -->|Yes| J[Cleanup and return path]
 *     I -->|No| G
 * @endmermaid
 */
char *path;
char *rootFolders[256] = {0};
typedef struct {
    char name[256];
    char dateTime[24];
    char size[24];
} RootFiles;
RootFiles *rootFiles[5120];
bool initialized = false;
float contentHeight = 0.0f;
float scrollOffset = 0.0f;
bool isDraggingScrollbar = false;
float scrollOffset2 = 0.0f;
bool isDraggingScrollbar2 = false;
float scrollVelocity = 0.0f;
float scrollFriction = 0.92f;
float scrollVelocity2 = 0.0f;
float scrollFriction2 = 0.92f;
bool readDirFiles = false;
int rootFoldersAmount = 0;
int rootFilesAmount = 0;
float filenameOffset = 0.0f;
int offsetedFileId = -1;
int selectedOnce = 0;
int offsetedPath = 0;
bool manualPath = false;
void format_size_pretty(uint64_t bytes, char *buf, size_t size){
    const char *units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    int unit = 0;
    double value = (double)bytes;

    while (value >= 1024.0 && unit < 4) {
        value /= 1024.0;
        unit++;
    }

    if (unit == 0)
        snprintf(buf, size, "%llu B", (unsigned long long)bytes);
    else if (value >= 100.0)
        snprintf(buf, size, "%.1f %s", value, units[unit]);
    else
        snprintf(buf, size, "%.2f %s", value, units[unit]);
}
void format_date_short(time_t timestamp, char *buffer, size_t bufsize){
    struct tm *tm_info = localtime(&timestamp);
    if (tm_info == NULL) {
        snprintf(buffer, bufsize, "unknown");
        return;
    }

    strftime(buffer, bufsize, "%d.%m.%Y %H:%M", tm_info);
}
char* GuiFileSelector(Rectangle bounds, char *text, Font font, Color primaryColor, Color secondaryColor, Color textColor) {
    // Defining window's size, can't be less than 400 by 600 pixels
    const int minWidth = 800;
    const int minHeight = 600;
    int width = ((int)bounds.width > minWidth) ? (int)bounds.width : minWidth;
    int height = ((int)bounds.height > minHeight) ? (int)bounds.height : minHeight;
    // Defining variables for left chunk that will display file tree
    if (initialized==false) {path = malloc(512 * sizeof(char)); manualPath=false;}

    // Drawing window base and moving header
    DrawRectangle((int)bounds.x, (int)bounds.y, width, height, secondaryColor);
    DrawRectangleLines((int)bounds.x, (int)bounds.y, width, height, primaryColor);
    int field2Width = width/3;
    int field2Height = height-78;
    DrawRectangleLines((int)bounds.x+4, (int)bounds.y+74, field2Width, field2Height, primaryColor);
    int field3Width = width-(width/3);
    int field3Height = height-78;
    DrawRectangleLines((int)bounds.x+field2Width, (int)bounds.y+74, field3Width-4, field3Height, primaryColor);
    DrawLine((int)bounds.x, (int)bounds.y+70, (int)bounds.x+width, (int)bounds.y+70, primaryColor);
    DrawLine((int)bounds.x, (int)bounds.y+30, (int)bounds.x+width, (int)bounds.y+30, primaryColor);
    DrawTextEx(font,text,(Vector2){bounds.x+2, bounds.y+4},28,2,textColor);
    if (!manualPath) {
        Vector2 measure = MeasureTextEx(font, path, (float)18, 2.0f);
        BeginScissorMode((int)bounds.x+8, (int)bounds.y+38, (int)bounds.width-8, 30);
        DrawTextEx(font,path,(Vector2){bounds.x+8-(float)offsetedPath, bounds.y+38},26,2,textColor);
        EndScissorMode();
        if (CheckCollisionPointRec(GetMousePosition(), (Rectangle){bounds.x+8, bounds.y+38, bounds.width-8, 30})) {
            offsetedPath = (int)((float)offsetedPath + 0.2f) * ((float)offsetedPath<measure.x);
        }
    } else {
        GuiTextBox((Rectangle){bounds.x+8, bounds.y+38, bounds.width-8, 30}, path, 512*sizeof(char), manualPath);
    }
    if (CheckCollisionPointRec(GetMousePosition(), (Rectangle){bounds.x+8, bounds.y+38, bounds.width-8, 30.0f})) manualPath=true;
    else manualPath=false;

    // ------------------------
    //
    // PRINT ERRORS USING PRINTF?
    //
    // ------------------------

    // Opening root folder
    static char lastPath[512] = {0};
    struct dirent **dir;
    if (path == NULL) {printf("\nError: not enough memory for directory listing.\n"); return nullptr;}
    if (initialized==false) {strncpy(path, "/", 256);}

    if (initialized==false) { // allocating memory if called firstly
        for (int i=0; i<256; i++) {rootFolders[i] = malloc(256 * sizeof(char)); if (rootFolders[i] == NULL) {printf("\nError: not enough memory for file listing.\n"); return nullptr;}}
        for (int i=0; i<5120; i++) {rootFiles[i] = malloc(sizeof(RootFiles)); if (rootFiles[i] == NULL) {printf("\nError: not enough memory for file listing.\n"); return nullptr;}}
        initialized=true;
    }

    // Trying ro read root folder: if succeeded - store files, if not - work with current program's directory
    if (!initialized || readDirFiles == false || strcmp(path, lastPath) != 0) {
        rootFoldersAmount = 0;
        rootFilesAmount = 0;
        int n = scandir(path, &dir, nullptr, alphasort);

        if (n < 0) {
            printf("scandir error on %s\n", path);
        }
        else if (n > 0) {
            for (int i=0; i<n; i++) {
                if (strcmp(dir[i]->d_name, ".") == 0 || strcmp(dir[i]->d_name, "..") == 0) continue; // skipping sub-files and sub-folders

                char fullpath[512] = {0};
                snprintf(fullpath, sizeof(fullpath), "%s%s", path, dir[i]->d_name);
                struct stat st;
                if (stat(fullpath, &st) != 0)
                    continue;

                if (S_ISDIR(st.st_mode)) {
                    // folder
                    if (rootFoldersAmount < 256) {
                        strncpy(rootFolders[rootFoldersAmount], dir[i]->d_name, 255);
                        rootFolders[rootFoldersAmount][255] = '\0';
                        rootFoldersAmount++;
                    }
                } else if (S_ISREG(st.st_mode)) {
                    // regular file
                    if (rootFilesAmount < 5120) {
                        strncpy(rootFiles[rootFilesAmount]->name, dir[i]->d_name, 255);
                        rootFiles[rootFilesAmount]->name[255] = '\0';
                        format_size_pretty(st.st_size, rootFiles[rootFilesAmount]->size, 23);
                        format_date_short(st.st_ctime, rootFiles[rootFilesAmount]->dateTime, 23);
                        rootFilesAmount++;
                    }
                }
            }
        }
    }

    readDirFiles=true;
    free(dir);
    // -------- Left Chunk (Folder List) --------
    {
        // Scroll settings
        float visibleHeight = (float)field2Height;
        float contentHeight2 = (float)rootFoldersAmount * 34.0f;
        float wheel;
        if (CheckCollisionPointRec(GetMousePosition(), (Rectangle){bounds.x+4, bounds.y+82, (float)field2Width, (float)field2Height})) wheel = GetMouseWheelMove();
        if (wheel != 0.0f) {
            scrollVelocity -= wheel * 15.0f;
        }
        scrollOffset += scrollVelocity;
        scrollVelocity *= scrollFriction;
        if (fabsf(scrollVelocity) < 0.5f) {
            scrollVelocity = 0.0f;
        }
        float maxScroll = fmaxf(0.0f, contentHeight2 - visibleHeight);
        scrollOffset = clamp(scrollOffset, 0.0f, maxScroll);
        // Setting up variables
        int x = (int)bounds.x + 8;
        int startY = (int)bounds.y + 82;
        float currentY = (float)startY - scrollOffset;
        for (int i = 0; i < rootFoldersAmount; i++) {
            Rectangle directoryRectangle = {
                (float)x,
                currentY,
                (float)field2Width - 26,
                30
            };

            // Rendering left chunk (only visible)
            if (currentY > (float)startY - 10 &&
                currentY < (float)startY + (float)field2Height - 34) {

                BeginScissorMode((int)directoryRectangle.x, (int)directoryRectangle.y, (int)directoryRectangle.width, (int)directoryRectangle.height);
                DrawRectangleLines(x, (int)currentY, field2Width - 26, 30, primaryColor);
                DrawTextEx(font, rootFolders[i],
                           (Vector2){(float)x + 4, currentY + 4}, 18, 2, textColor);
                EndScissorMode();

                if (CheckCollisionPointRec(GetMousePosition(), directoryRectangle)) {
                    DrawRectangleLines(x, (int)currentY, field2Width - 26, 30, SKYBLUE);

                    // Entering path clicked
                    if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON)) {
                        strncat(path, rootFolders[i], strlen(rootFolders[i]));
                        strncat(path, "/", 1);
                        readDirFiles=false;
                        rootFoldersAmount = 0;
                        rootFilesAmount = 0;
                        selectedOnce=0;
                    }
                }
            }

            currentY += 34.0f;
        }
        if (IsKeyPressed(KEY_BACKSPACE) || IsKeyPressed(KEY_BACK) || IsMouseButtonPressed(MOUSE_BUTTON_BACK) || IsMouseButtonPressed(MOUSE_BUTTON_SIDE)) {
            char *last = nullptr;
            char *pre_last = nullptr;
            char *current = path;
            int k=0;
            while ((current = strstr(current, "/")) != NULL) {
                pre_last = last;
                last = current;
                current++;
                k++;
            }
            if (k>2) {
                int index = pre_last ? (int)(pre_last - path) : -1;
                path[index+1] = '\0';
            } else if (k==2) {
                strncpy(path, "/", sizeof(path)-1);
            }
            readDirFiles=false;
            rootFoldersAmount = 0;
            rootFilesAmount = 0;
            selectedOnce=0;
        }
        // Rendering scrollbar
        if (contentHeight2 > (float)field2Height) {
            float scrollbarTrackHeight = (float)field2Height-14;
            float scrollbarHeight = ((float)field2Height / contentHeight2) * scrollbarTrackHeight;
            float scrollbarY = (float)startY + (scrollOffset / contentHeight2) * scrollbarTrackHeight;

            DrawRectangle(x + field2Width - 22, startY, 10, field2Height-14, Fade(BLACK, 0.3f));

            Color sbColor = isDraggingScrollbar ? WHITE : LIGHTGRAY;
            Rectangle scrollbarRect = {
                (float)(x + field2Width - 22),
                scrollbarY,
                10,
                scrollbarHeight
            };

            DrawRectangleRec(scrollbarRect, Fade(sbColor, 0.85f));

            Vector2 mouse = GetMousePosition();

            if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON)) {
                if (CheckCollisionPointRec(mouse, scrollbarRect)) {
                    isDraggingScrollbar = true;
                }
            }
            if (IsMouseButtonReleased(MOUSE_LEFT_BUTTON)) {
                isDraggingScrollbar = false;
            }
            if (isDraggingScrollbar) {
                float mouseRelative = mouse.y - scrollbarHeight / 2.0f - (float)startY;
                scrollOffset = (mouseRelative / (float)field2Height) * contentHeight2;
            }
        }
    }

    // -------- Right Chunk (File List) --------
    {
        // Scroll settings
        float visibleHeight = (float)field3Height;
        float contentHeight2 = (float)rootFilesAmount * 34.0f;
        float wheel;
        if (CheckCollisionPointRec(GetMousePosition(), (Rectangle){bounds.x+(float)field2Width+4, bounds.y+82, (float)field3Width, (float)field3Height})) wheel = GetMouseWheelMove();
        if (wheel != 0.0f) {
            scrollVelocity2 -= wheel * 15.0f;
        }
        scrollOffset2 += scrollVelocity2;
        scrollVelocity2 *= scrollFriction2;
        if (fabsf(scrollVelocity2) < 0.5f) {
            scrollVelocity2 = 0.0f;
        }
        float maxScroll = fmaxf(0.0f, contentHeight2 - visibleHeight);
        scrollOffset2 = clamp(scrollOffset2, 0.0f, maxScroll);
        // Setting up variables
        int x = (int)bounds.x + field2Width+8;
        int startY = (int)bounds.y + 82;
        float currentY = (float)startY - scrollOffset2;
        for (int i = 0; i < rootFilesAmount; i++) {
            Rectangle fileRectangle = {
                (float)x,
                currentY,
                (float)field3Width - 32,
                30
            };

            // Rendering right chunk (only visible)
            if (currentY > (float)startY - 10 &&
                currentY < (float)startY + (float)field3Height - 34) {

                // Date-Time and Size
                Vector2 tMeasure = MeasureTextEx(font, rootFiles[i]->name, (float)18, 2.0f);
                float maxTextLength = (35.4f*(fileRectangle.width/100));
                DrawRectangleLines(x, (int)currentY, field3Width - 32, 30, primaryColor);
                BeginScissorMode((int)fileRectangle.x, (int)fileRectangle.y, (int)fileRectangle.width, (int)fileRectangle.height);
                DrawTextEx(font, rootFiles[i]->dateTime,
                              (Vector2){(float)x + 1.2f*fileRectangle.width/3, currentY + 6}, 18, 2, textColor);
                DrawTextEx(font, rootFiles[i]->size,
                           (Vector2){(float)x + 2.34f*fileRectangle.width/3, currentY + 6}, 18, 2, textColor);
                EndScissorMode();

                // Cutting and moving FileName leftwards if name could collide with date-time text
                if (tMeasure.x >= maxTextLength) {
                    BeginScissorMode((int)fileRectangle.x+4, (int)fileRectangle.y, (int)maxTextLength, (int)fileRectangle.height);
                    DrawTextEx(font, rootFiles[i]->name,
                               (Vector2){(float)x + 4 - (float)(i==offsetedFileId)*filenameOffset, currentY + 6}, 18, 2, textColor);
                    EndScissorMode();
                } else {
                    DrawTextEx(font, rootFiles[i]->name,
                               (Vector2){(float)x + 4, currentY + 6}, 18, 2, textColor);
                }

                // Marking current file slot as wanted
                // Double-Click selects the wanted file and exits the window
                if (CheckCollisionPointRec(GetMousePosition(), fileRectangle)) {
                    filenameOffset = (filenameOffset + 0.2f) * (float)(filenameOffset<tMeasure.x);
                    DrawRectangleLines(x, (int)currentY, field3Width - 32, 30, SKYBLUE);

                    if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON)) { selectedOnce++; }
                    if (selectedOnce>=2 && offsetedFileId==i) {
                        strcat(path, rootFiles[i]->name);
                        goto exit;
                    } else if (i!=offsetedFileId) {
                        selectedOnce=0;
                    }
                    offsetedFileId=i;
                }
            }

            currentY += 34.0f;
        }
        if (IsKeyPressed(KEY_ENTER)) { goto exit; }
        // Rendering scrollbar
        if (contentHeight2 > (float)field3Height) {
            float scrollbarTrackHeight = (float)field3Height-14;
            float scrollbarHeight = ((float)field3Height / contentHeight2) * scrollbarTrackHeight;
            float scrollbarY = (float)startY + (scrollOffset2 / contentHeight2) * scrollbarTrackHeight;

            DrawRectangle(x + field3Width - 28, startY, 10, field3Height-14, Fade(BLACK, 0.3f));

            Color sbColor = isDraggingScrollbar2 ? WHITE : LIGHTGRAY;
            Rectangle scrollbarRect = {
                (float)(x + field3Width - 28),
                scrollbarY,
                10,
                scrollbarHeight
            };

            DrawRectangleRec(scrollbarRect, Fade(sbColor, 0.85f));

            Vector2 mouse = GetMousePosition();

            if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON)) {
                if (CheckCollisionPointRec(mouse, scrollbarRect)) {
                    isDraggingScrollbar2 = true;
                }
            }
            if (IsMouseButtonReleased(MOUSE_LEFT_BUTTON)) {
                isDraggingScrollbar2 = false;
            }
            if (isDraggingScrollbar2) {
                float mouseRelative = mouse.y - scrollbarHeight / 2.0f - (float)startY;
                scrollOffset2 = (mouseRelative / (float)field3Height) * contentHeight2;
            }
        }
    }

    if (IsKeyPressed(KEY_ESCAPE)) {
        exit:
        initialized=false;
        readDirFiles=false;
        rootFoldersAmount = 0;
        rootFilesAmount = 0;
        contentHeight = 0.0f;
        scrollOffset = 0.0f;
        isDraggingScrollbar = false;
        scrollOffset2 = 0.0f;
        isDraggingScrollbar2 = false;
        scrollVelocity = 0.0f;
        scrollFriction = 0.92f;
        scrollVelocity2 = 0.0f;
        scrollFriction2 = 0.92f;
        for (int k=0; k<256; k++) {free(rootFolders[k]);}
        for (int k=0; k<5120; k++) {free(rootFiles[k]);}
        return path;
    }
    return nullptr;
}




typedef enum {
    STATE_MASTER_PASSWORD,
    STATE_FIRST_SETUP,
    STATE_MAIN_CHAT
} AppState;
AppState currentState = STATE_MASTER_PASSWORD;
int main(void) {
    printf("\n");
    InitWindow(1600, 900, "UnChat - BETA 2.0");
    int codepoints[1024] = {0};
    int count = 0;
    for (int i = 32; i < 128; i++) codepoints[count++] = i;
    for (int i = 0x0400; i <= 0x04FF; i++) codepoints[count++] = i;
    InitAudioDevice();
    SetTargetFPS(140);
    SetTraceLogLevel(LOG_WARNING);
    SetExitKey(KEY_NULL);

    Font font = LoadFontEx("Pixellari.ttf", 64, codepoints, count);
    GenTextureMipmaps(&font.texture);
    SetTextureFilter(font.texture, TEXTURE_FILTER_BILINEAR);
    GuiSetFont(font);
    GuiSetStyle(DEFAULT, TEXT_SIZE, 24);

    static int activeField=-1;
    char newDesc[1025] = "";
    char message[2049] = "";
    bool isAddingFriend = false;
    char userId[15] = "";
    static Texture2D userAvatarTexture = {0};
    static char avatarPathInput[512] = {0};
    bool loadedAvatar = false;
    static float chatScrollOffset = 0.0f;
    static float chatScrollVelocity = 0.0f;     // inertion speed
    static float chatSrollFriction = 0.92f;    // fade out timne (0.85 - hard, 0.94 - soft)
    static bool chatIsDraggingScrollbar = false;
    static float friendScrollOffset = 0.0f;
    static float friendScrollVelocity = 0.0f;
    static float friendSrollFriction = 0.92f;
    static bool friendIsDraggingScrollbar = false;
    bool chatAutoScrollAllowed = true;
    bool friendAutoScrollAllowed = true;
    bool fileSelector = false;
    char *path2 = NULL;
    int warningTimer = 5000;
    Rectangle sliderBox = {201, 601, 98, 98};

    bool userAgreed = false;
    int editMode = -1;
    bool wrongPass = false;
    bool triedAvatar = false;

    while (!WindowShouldClose()) {
        float chatContentHeight = 0.0f;
        float friendContentHeight = 0.0f;
        float wheel = GetMouseWheelMove();
        if (wheel != 0.0f) {
            chatScrollVelocity -= wheel * 15.0f;        // bigger number = faster scroll
            friendScrollVelocity -= wheel * 15.0f;
            chatAutoScrollAllowed=false;
        }
        if (!chatIsDraggingScrollbar) {
            // regular scroollo with inertion
            chatScrollOffset += chatScrollVelocity;
            chatScrollVelocity *= chatSrollFriction;       // fadeout

            // if the speed is too slow -> resetting to zero
            if (fabsf(chatScrollVelocity) < 0.5f) {
                chatScrollVelocity = 0.0f;
            }
        }
        if (!friendIsDraggingScrollbar) {
            // regular scroollo with inertion
            friendScrollOffset += friendScrollVelocity;
            friendScrollVelocity *= friendSrollFriction;       // fadeout

            // if the speed is too slow -> resetting to zero
            if (fabsf(friendScrollVelocity) < 0.5f) {
                friendScrollVelocity = 0.0f;
            }
        }

        BeginDrawing();
        ClearBackground((Color){ 40, 40, 40, 255 });

        switch (currentState) {
            case STATE_MASTER_PASSWORD:

                initedNetwork = initNetwork();
                DrawTextEx(font, "Мастер-пароль приложения:", (Vector2){480, 100}, 48, 2, LIGHTGRAY);
                if (userAgreed==false) {
                    Rectangle sliderRail = {200, 600, 1200, 100};
                    DrawRectangleLinesEx(sliderRail, 2, LIGHTGRAY);
                    if (CheckCollisionPointRec(GetMousePosition(), sliderBox)) {
                        if (IsMouseButtonDown(MOUSE_BUTTON_LEFT)) {
                            sliderBox.x = GetMousePosition().x-48;
                            if (sliderBox.x < 201) sliderBox.x = 201;
                            if (sliderBox.x > 1299) userAgreed=true;
                        } else {
                            sliderBox.x = 201;
                        }
                    }
                    DrawTextEx(font, "пароль есть только у меня и его никто не видит", (Vector2){400, 632}, 32, 2, GRAY);
                    DrawRectangleRec(sliderBox, LIGHTGRAY);
                    DrawRectangleLinesEx(sliderBox, 2, GRAY);
                    GuiDrawIcon(115, (int)sliderBox.x+16, (int)sliderBox.y+16, 4, GRAY);
                    DrawRectangle(201, 601, (sliderBox.x - 201), 98, GRAY);
                } else {
                    if (GuiTextBox((Rectangle){200, 600, 1200, 100}, masterPassword, MAX_PASS, editMode==1)) {
                        editMode = (editMode == 1) ? -1 : 1;
                        wrongPass=false;
                    }
                    if (IsKeyPressed(KEY_ENTER)) {
                        if (strlen(masterPassword)>6) {
                            if (FileExists(CONFIG_FILE)) {
                                if (LoadEncryptedConfig(&config, masterPassword)) {
                                    memset(friends, 0, sizeof(friends));
                                    memset(pendingFriends, 0, sizeof(pendingFriends));
                                    if (config.userId != 0) {
                                        char msgBuf[BUFFER_SIZE] = {0};
                                        snprintf(msgBuf, sizeof(msgBuf), "login/%ld\x1E%s\x1E%s", config.userId, config.email, config.passwordHash);
                                        sendMessage(msgBuf);
                                        again:
                                        if (hasSessionKey) {
                                            memset(msgBuf, 0, BUFFER_SIZE);
                                            snprintf(msgBuf, sizeof(msgBuf), "updateClient/%ld", config.userId);
                                            sendMessage(msgBuf);
                                            memset(msgBuf, 0, sizeof(msgBuf));
                                            snprintf(msgBuf, sizeof(msgBuf), "getFriendsList/%ld", config.userId);
                                            sendMessage(msgBuf);
                                        } else {
                                            goto again;
                                        }
                                    } else {
                                        printf(cYELLOW "[WARN]" RESET "[APP INIT] User ID is 0.\n");
                                    }
                                    if (config.isFirstUsed) {
                                        strcpy(config.userName, "");
                                        strcpy(config.email, "");
                                        strcpy(config.passwordHash, "");
                                        strcpy(config.profileDescription, "");
                                        config.isFirstUsed=true;
                                        currentState=STATE_FIRST_SETUP;
                                    } else {
                                        currentState=STATE_MAIN_CHAT;
                                    }
                                } else {
                                    wrongPass=true;
                                }
                            } else {
                                initedNetwork = initNetwork();
                                memset(friends, 0, sizeof(friends));
                                memset(pendingFriends, 0, sizeof(pendingFriends));
                                currentState=STATE_FIRST_SETUP;
                                break;
                            }
                        }
                    }
                }
                if (wrongPass==true) {
                    DrawTextEx(font, "Неправильный пароль.", (Vector2){630, 500}, 32, 2, RED);
                    editMode=-1;
                }
                if (initedNetwork == false) {
                    Rectangle networkErrorRec = {1, 900/2-100, 1600, 200};
                    Color accentColor = {255, 79, 79, 255};
                    Color backgroundColor = {255, 157, 157, 255};
                    DrawRectangleRec(networkErrorRec, backgroundColor);
                    DrawRectangleLinesEx(networkErrorRec, 2, accentColor);
                    DrawTextEx(font, "Потеряно соединение с сервером!", (Vector2){1600/2-470, 900/2-20}, 60, 2, RED);
                }

                break;
            case STATE_FIRST_SETUP:

                DrawTextEx(font, "Привет. Пройди настройку профиля:", (Vector2){100, 50}, 40, 3, WHITE);
                if (GuiTextBox((Rectangle){100, 150, 400, 40}, config.userName, MAX_NAME, activeField==0)) {
                    activeField = (activeField == 0) ? -1 : 0;
                }
                if (GuiTextBox((Rectangle){100, 220, 400, 40}, config.email, MAX_EMAIL, activeField==1)) {
                    activeField = (activeField == 1) ? -1 : 1;
                }
                if (GuiTextBox((Rectangle){100, 290, 400, 40}, config.passwordHash, MAX_PASS, activeField==2)) {
                    activeField = (activeField == 2) ? -1 : 2;
                }
                if (GuiTextBox((Rectangle){100, 360, 400, 40}, config.profileDescription, MAX_DESC, activeField==3)) {
                    activeField = (activeField == 3) ? -1 : 3;
                }
                DrawTextEx(font,"Юзернейм", (Vector2){520, 160}, 20, 3, LIGHTGRAY);
                DrawTextEx(font, "Email", (Vector2){520, 230}, 20, 3, LIGHTGRAY);
                DrawTextEx(font, "Пароль", (Vector2){520, 300}, 20, 3, LIGHTGRAY);
                DrawTextEx(font, "Описание профиля (опционально)", (Vector2){520, 370}, 20, 3, LIGHTGRAY);

                if (GuiButton((Rectangle){100, 450, 200, 50}, "Сохранить и продолжить") || IsKeyPressed(KEY_ENTER)) {
                    config.isFirstUsed = false;

                    sendMessage("createId/user");
                    for (int i = 0; i < 2500 && config.userId == 0; i++) {
                        usleep(10000);
                    }
                    if (config.userId == 0) {
                        printf("[CREATE USER ID] Timed out while waiting ID from server. retrying\n");
                        config.isFirstUsed = true;
                        continue;
                    }
                    memset(config.avatarUrl, 0, MAX_AVATAR);
                    strncpy(config.avatarUrl, "null", 4);
                    if (strlen(config.avatarUrl)==0) strncpy(config.avatarUrl, "null", 4);

                    SaveEncryptedConfig(&config, masterPassword);
                    currentState=STATE_MAIN_CHAT;
                }
                if (initedNetwork == false) {
                    Rectangle networkErrorRec = {1, 900/2-100, 1600, 200};
                    Color accentColor = {255, 79, 79, 255};
                    Color backgroundColor = {255, 157, 157, 255};
                    DrawRectangleRec(networkErrorRec, backgroundColor);
                    DrawRectangleLinesEx(networkErrorRec, 2, accentColor);
                    DrawTextEx(font, "Потеряно соединение с сервером!", (Vector2){1600/2-470, 900/2-20}, 60, 2, RED);
                }
                break;
            case STATE_MAIN_CHAT:
                if (strlen(config.avatarUrl) != 0 && loadedAvatar==false) {
                    ssize_t len = readlink("/proc/self/exe", avatarPathInput, 255);
                    if (len == -1) {
                        printf("[LOAD SELF AVATAR] Readlink /proc/self/exe failed\n");
                        avatarPathInput[0] = '\0';
                    } else {
                        strncpy(avatarPathInput, config.avatarUrl, strlen(config.avatarUrl)+len);
                        Image img = LoadImage(avatarPathInput);
                        userAvatarTexture = LoadTextureFromImage(img);
                        UnloadImage(img);
                        printf("[LOAD SELF AVATAR] Current path: %s\n", avatarPathInput);
                    }
                    loadedAvatar=true;
                }

                DrawRectangleLines(1, 1, 300, 899, GRAY);
                DrawRectangleLines(301, 1, 1000, 899, GRAY);
                DrawRectangleLines(1301, 1, 299, 899, GRAY);
                DrawLine(1, 40, 1600, 40, GRAY);
                DrawTextEx(font, "Знакомые", (Vector2){87, 10}, 24, 2, WHITE);
                DrawTextEx(font, "Чат", (Vector2){760, 10}, 24, 2, WHITE);
                DrawTextEx(font, "Профиль", (Vector2){1400, 10}, 24, 2, WHITE);
                DrawLine(1, 80, 1300, 80, GRAY);

                // Profile section
                Rectangle avatarRect = {1320, 60, 128, 128};
                DrawRectangleRec(avatarRect, DARKGRAY);
                if (userAvatarTexture.id != 0) {
                    DrawTexturePro(userAvatarTexture,
                                   (Rectangle){0, 0, 128, 128},
                                   avatarRect,
                                   (Vector2){0, 0}, 0.0f, WHITE);
                } else {
                    DrawRectangleLinesEx(avatarRect, 4, LIGHTGRAY);
                    DrawTextEx(font, "нет\nаватарки", (Vector2){1333, 82}, 24, 2, GRAY);
                }
                if (CheckCollisionPointRec(GetMousePosition(), avatarRect) && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
                    fileSelector = true;
                }
                DrawTextEx(font, TextFormat("%s", config.userName), (Vector2){1320, 200}, 24, 1.0f, WHITE);
                Rectangle textBounds = { 1326, 278, 248, 388 };
                if (GuiTextBox((Rectangle){1320, 270, 260, 400}, newDesc, MAX_DESC, activeField==4)) {
                    activeField = (activeField == 4) ? -1 : 4;
                } else {
                    DrawTextBoxed(font, config.profileDescription, textBounds, 20, 1.0f, WHITE);
                }
                GuiSetStyle(DEFAULT, TEXT_SIZE, 16);
                if (GuiButton((Rectangle){1320, 230, 250, 30}, "скопировать код дружбы")) {
                    char copyToClipboard[13];
                    snprintf(copyToClipboard, 12, "%ld", config.userId);
                    SetClipboardText(copyToClipboard);
                }
                GuiSetStyle(DEFAULT, TEXT_SIZE, 24);
                if (GuiButton((Rectangle){1320, 690, 200, 50}, "Обновить")) {
                    if (newDesc[0] != 0) {
                        newDesc[1024]='\0';
                        strcpy(config.profileDescription, newDesc);
                        memset(newDesc, 0, sizeof(newDesc));
                    }
                    SaveEncryptedConfig(&config, masterPassword);
                }
                DrawTextEx(font, "Путь к аватарке:", (Vector2){1320, 760}, 20, 2, LIGHTGRAY);
                if (path2 == NULL && CheckCollisionPointRec(GetMousePosition(), (Rectangle){1320, 790, 260, 40})) {
                    path2 = malloc(255*sizeof(char));
                    if (path2 == NULL) {
                        printf(cRED "[FATAL]" RESET " Failed to allocate memory for self avatar path, exiting.");
                        exit(6);
                    }
                    memset(path2, 0, sizeof(path2));
                }
                if (GuiTextBox((Rectangle){1320, 790, 260, 40}, path2, 255, activeField == 7)) {
                    activeField = (activeField == 7) ? -1 : 7;
                }
                if (GuiButton((Rectangle){1320, 840, 200, 50}, "Загрузить")) {
                    if (path2 == NULL) {
                        path2 = malloc(255*sizeof(char));
                        if (path2 == NULL) {
                            printf(cRED "[FATAL]" RESET " Failed to allocate memory for self avatar path, exiting.");
                            exit(6);
                        }
                        memset(path2, 0, sizeof(path2));
                    }
                    if (strlen(path2) > 3) {
                        Image img = LoadImage(path2);

                        if (img.data != NULL) {
                            // square 128 by 128
                            int side = (img.width < img.height) ? img.width : img.height;   // taking smallest side

                            // crop to square
                            Rectangle cropRect = {
                                (float)(img.width - side) / 2.0f,      // x
                                (float)(img.height - side) / 2.0f,     // y
                                (float)side,                           // width
                                (float)side                            // height
                            };

                            ImageCrop(&img, cropRect);
                            ImageResize(&img, 128, 128);        // resize to 128x128

                            // saving near config file
                            const char *savePath = TextFormat("avatars/%ld.png", config.userId);

                            // folder is not exist
                            system("mkdir -p avatars");

                            if (ExportImage(img, savePath)) {
                                printf("[SAVE SELF AVATAR] Avatar was cropped and saved: %s\n", savePath);

                                // updating config
                                snprintf(config.avatarUrl, MAX_AVATAR, "avatars/%ld.png", config.userId);

                                // refreshing texture
                                if (userAvatarTexture.id != 0) UnloadTexture(userAvatarTexture);
                                userAvatarTexture = LoadTextureFromImage(img);

                                SaveEncryptedConfig(&config, masterPassword);        // save and pull to server

                                FILE *f = fopen(savePath, "rb");
                                if (f) {
                                    fseek(f, 0, SEEK_END);
                                    int fileSize = ftell(f);
                                    fseek(f, 0, SEEK_SET);

                                    unsigned char *pngData = malloc(fileSize);
                                    fread(pngData, 1, fileSize, f);
                                    fclose(f);

                                    char *b64 = Base64Encode(pngData, fileSize);
                                    free(pngData);

                                    if (b64) {
                                        char response1[PACKET_SIZE];
                                        snprintf(response1, sizeof(response1), "saveAvatar/%ld\x1E%s", config.userId, b64);
                                        sendMessage(response1);
                                        free(b64);
                                    }
                                }
                            } else {
                                printf("[SAVE SELF AVATAR] Failed to save avatar\n");
                            }

                            UnloadImage(img);
                        } else {
                            printf("[SAVE SELF AVATAR] Failed to load image: %s\n", path2);
                        }
                    }
                    memset(path2, 0, sizeof(path2));
                }

                // Error code show warning sections
                if (profileUpdateCode == 1) {
                    if (warningTimer > 1) {
                        Rectangle warningRec = {1352, 16, 232, 40};
                        Color accentColor = {255, 79, 79, 255};
                        Color backgroundColor = {255, 157, 157, 255};
                        DrawRectangleRec(warningRec, backgroundColor);
                        DrawRectangleLinesEx(warningRec, 2, accentColor);
                        DrawTextEx(font, "Ошибка сервера", (Vector2){warningRec.x+14, warningRec.y+8}, 24, 2, RED);
                        warningTimer-=1;
                    } else {
                        profileUpdateCode = -1;
                        warningTimer = 5000;
                    }
                } else if (profileUpdateCode == 2) {
                    if (warningTimer > 1) {
                        Rectangle warningRec = {1352, 16, 268, 40};
                        Color accentColor = {255, 79, 79, 255};
                        Color backgroundColor = {255, 157, 157, 255};
                        DrawRectangleRec(warningRec, backgroundColor);
                        DrawRectangleLinesEx(warningRec, 2, accentColor);
                        DrawTextEx(font, "Плохой синтаксис", (Vector2){warningRec.x+14, warningRec.y+8}, 24, 2, RED);
                        warningTimer-=1;
                    } else {
                        profileUpdateCode = -1;
                        warningTimer = 5000;
                    }
                }

                if (serverErrorCode == 1) {
                    if (warningTimer > 1) {
                        Rectangle warningRec = {1352, 16, 232, 40};
                        Color accentColor = {255, 79, 79, 255};
                        Color backgroundColor = {255, 157, 157, 255};
                        DrawRectangleRec(warningRec, backgroundColor);
                        DrawRectangleLinesEx(warningRec, 2, accentColor);
                        DrawTextEx(font, "Сервер занят", (Vector2){warningRec.x+14, warningRec.y+8}, 24, 2, RED);
                        warningTimer-=1;
                    } else {
                        serverErrorCode = -1;
                        warningTimer = 5000;
                    }
                } else if (serverErrorCode == 2) {
                    if (warningTimer > 1) {
                        Rectangle warningRec = {1352, 16, 268, 40};
                        Color accentColor = {255, 79, 79, 255};
                        Color backgroundColor = {255, 157, 157, 255};
                        DrawRectangleRec(warningRec, backgroundColor);
                        DrawRectangleLinesEx(warningRec, 2, accentColor);
                        DrawTextEx(font, "Ошибка сервера", (Vector2){warningRec.x+14, warningRec.y+8}, 24, 2, RED);
                        warningTimer-=1;
                    } else {
                        serverErrorCode = -1;
                        warningTimer = 5000;
                    }
                }

                // Friend section
                float friendStartY = 90.0f;
                for (int i = 0; i < 100 && friends[i].userId != 0; i++) {
                    Rectangle friendRect = { 10, friendStartY, 280, 70 };

                    if (CheckCollisionPointRec(GetMousePosition(), friendRect) && isAddingFriend==false && fileSelector==false) {
                        DrawRectangleRec(friendRect, (Color){60, 60, 70, 255});
                        if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON)) {
                            if (friends[i].userId != currentFriendId) {
                                currentFriendId = friends[i].userId;
                                messagesCount = 0;
                                friends[i].newMessageCount = 0;

                                char req[64];
                                snprintf(req, sizeof(req), "getChatHistory/%ld\x1E%ld", config.userId, currentFriendId);
                                sendMessage(req);
                            }

                            chatAutoScrollAllowed=true;
                        }
                    } else {
                        DrawRectangleRec(friendRect, (Color){50, 50, 60, 255});
                    }
                    DrawRectangleLinesEx(friendRect, 2, GRAY);

                    // friend avatar
                    Rectangle avatarRect2 = { 20, friendStartY + 8, 54, 54 };
                    DrawTexturePro(friendAvatarArr[i], (Rectangle){0, 0, 54, 54}, avatarRect2, (Vector2){0, 0}, 0.0f, WHITE);
                    DrawRectangleLinesEx(avatarRect2, 2, LIGHTGRAY);

                    // name + description
                    DrawTextEx(font, friends[i].name, (Vector2){85, friendStartY + 12}, 24, 2, WHITE);

                    if (friends[i].newMessageCount > 0) {
                        if (friends[i].userId != currentFriendId) {
                            char badge[16] = {0};
                            snprintf(badge, sizeof(badge), "%d", friends[i].newMessageCount);
                            int textW = MeasureText(badge, 20);
                            Rectangle badgeRect = {240, friendStartY + 12, (float)textW + 12, 24};

                            DrawRectangleRec(badgeRect, RED);
                            DrawText(badge, (int)badgeRect.x + 6, (int)badgeRect.y + 4, 20, WHITE);
                        }
                        chatAutoScrollAllowed=true;
                    }

                    if (strlen(friends[i].profileDescription) > 0) {
                        char shortDesc[71] = {0};
                        strncpy(shortDesc, friends[i].profileDescription, 70);
                        shortDesc[70] = '\0';
                        if (strlen(friends[i].profileDescription) > 30) {
                            // looking for last UTF-8 symbol before 30th slot
                            int pos = 30;
                            while (pos > 0 && (shortDesc[pos] & 0xC0) == 0x80) {
                                pos--;  // rolling back to the start of UTF-8 symbol
                            }

                            shortDesc[pos] = '\0';
                            strcat(shortDesc, "...");
                        }
                        DrawTextEx(font, shortDesc, (Vector2){85, friendStartY + 42}, 18, 2, LIGHTGRAY);
                    }

                    friendStartY += 80.0f;
                }

                // Update friend avatars section
                if (requestedAvatarUpdate==true) {
                    for (int i = 0; i < 100 && friends[i].userId != 0; i++) {
                        if (friendAvatarArr[i].id != 0) {
                            UnloadTexture(friendAvatarArr[i]);
                            friendAvatarArr[i].id = 0;
                        }
                        char path[128];
                        snprintf(path, sizeof(path), "avatars/%ld.png", friends[i].userId);

                        if (FileExists(path)) {
                            Image img = LoadImage(path);
                            if (img.data == NULL) {
                                printf("[LOAD FRIEND AVATAR] Couldnt load %ld's avatar with %s path\n", friends[i].userId, path);
                            } else {
                                ImageResize(&img, 54, 54);
                                friendAvatarArr[i] = LoadTextureFromImage(img);
                                UnloadImage(img);
                            }
                        } else if (triedAvatar==false) {
                            char req[64] = {0};
                            snprintf(req, sizeof(req), "getAvatar/%ld", friends[i].userId);
                            sendMessage(req);
                            printf("[AVATAR] Requested avatar for %ld\n", friends[i].userId);
                            triedAvatar=true;
                        }
                    }
                    requestedAvatarUpdate=false;
                }

                // Send message section
                if (GuiTextBox((Rectangle){300, 839, 861, 60}, message, MAX_MESS, activeField==5)) {
                    activeField = (activeField == 5) ? -1 : 5;
                }
                if (GuiButton((Rectangle){1141, 839, 160, 60}, "Отправить") || IsKeyPressed(KEY_ENTER)) {
                    if (strlen(message)!=0 && currentFriendId>0) {
                        sendMessage("createId/message");
                        message[2048]='\0';
                        char parsed[BUFFER_SIZE] = {0};
                        snprintf(parsed, sizeof(parsed), "receive-message/%ld\x1E%ld\x1E%ld\x1E%s", randomId, config.userId, currentFriendId, message);

                        sendMessage(parsed);
                        if (messagesCount < 1000000) {
                            messages[messagesCount].messageId = randomId;
                            messages[messagesCount].senderId = config.userId;
                            messages[messagesCount].receiverId = currentFriendId;
                            strncpy(messages[messagesCount].message, message, 2048);
                            messagesCount++;
                        }
                        memset(message, 0, sizeof(message));
                        memset(parsed, 0, strlen(parsed));
                        chatAutoScrollAllowed=true;
                    }
                }
                if (GuiButton((Rectangle){20, 45, 100, 30}, "+ Друг")) {
                    isAddingFriend=true;
                }
                if (hasFriendRequests==true) {
                    DrawCircle(121, 44, 6, RED);
                }
                if (GuiButton((Rectangle){155, 45, 120, 30}, "+ Группа")) {
                    // TODO версия 3.0
                }

                // Chat section
                Rectangle chatArea = {300, 80, 980, 700};
                for (int i = 0; i < messagesCount; i++) {
                    Message *m = &messages[i];
                    const int maxTextW = (int)chatArea.width - 120;

                    char dummy[2048] = {0};
                    int textH = WrapText(m->message, dummy, sizeof(dummy), maxTextW, font, 22, 2);
                    chatContentHeight += (float)textH + 25 + 18;   // text height + indents
                }
                if (chatContentHeight < 680) chatScrollOffset = 0;
                float maxScroll = fmaxf(0.0f, chatContentHeight - 680.0f);
                chatScrollOffset = clamp(chatScrollOffset, 0.0f, maxScroll);
                if (chatAutoScrollAllowed==true && messagesCount > 0) {
                    chatScrollOffset = maxScroll;
                }

                // chat header
                if (currentFriendId != 0) {
                    char *friendName = "Неизвестный";
                    for (int k=0; k<100; k++) {
                        if (friends[k].userId == currentFriendId) {
                            friendName = friends[k].name;
                            break;
                        }
                    }
                    DrawTextEx(font, TextFormat("Чат с %s", friendName), (Vector2){330, 50}, 28, 2, WHITE);
                }

                float currentY = 100 - chatScrollOffset;
                for (int i = 0; i < messagesCount; i++) {
                    Message *m = &messages[i];
                    bool isMine = (m->senderId == config.userId);

                    int maxBubbleWidth = (int)chatArea.width - 80;
                    int maxTextWidth = maxBubbleWidth - 40;
                    char wrapped[2048] = {0};
                    int textHeight = WrapText(m->message, wrapped, sizeof(wrapped), maxTextWidth,
                                             font, 22, 2);
                    Vector2 tMeasure = MeasureTextEx(font, wrapped, (float)22, 2.0f);
                    maxBubbleWidth = (int)tMeasure.x + 40;
                    int bubbleHeight = textHeight + 25;

                    Rectangle bubble = {
                        isMine ? (chatArea.x + chatArea.width - (float)maxBubbleWidth - 30) : (chatArea.x + 30),
                        currentY,
                        (float)maxBubbleWidth,
                        (float)bubbleHeight
                    };

                    if (bubble.y > 80 && bubble.y + (float)bubbleHeight < 840) {
                        Color bubbleColor = isMine ? (Color){0, 120, 215, 255} : (Color){60, 60, 70, 255};

                        DrawRectangleRec(bubble, bubbleColor);
                        DrawRectangleLinesEx(bubble, 2, isMine ? SKYBLUE : LIGHTGRAY);

                        DrawWrappedText(wrapped, (Vector2){bubble.x + 20, bubble.y + 12}, font, 22, 2, WHITE);
                    }

                    currentY += (float)bubbleHeight + 18;
                }

                if (chatContentHeight > 680) {
                    float scrollbarTrackHeight = 680;
                    float scrollbarHeight = (680 / chatContentHeight) * scrollbarTrackHeight;
                    float scrollbarY = 100 + (chatScrollOffset / chatContentHeight) * scrollbarTrackHeight;

                    Rectangle scrollbarRect = {
                        chatArea.x + chatArea.width - 14,
                        scrollbarY,
                        10,
                        scrollbarHeight
                    };

                    DrawRectangle(chatArea.x + chatArea.width - 14, 100, 10, 680, Fade(BLACK, 0.3f));

                    Color sbColor = chatIsDraggingScrollbar ? WHITE : LIGHTGRAY;
                    DrawRectangleRec(scrollbarRect, Fade(sbColor, 0.85f));

                    Vector2 mouse = GetMousePosition();

                    if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON)) {
                        if (CheckCollisionPointRec(mouse, scrollbarRect)) {
                            chatIsDraggingScrollbar = true;
                            chatAutoScrollAllowed=false;
                        }
                    }

                    if (IsMouseButtonReleased(MOUSE_LEFT_BUTTON)) {
                        chatIsDraggingScrollbar = false;
                        chatAutoScrollAllowed=false;
                    }

                    if (chatIsDraggingScrollbar) {
                        chatAutoScrollAllowed=false;
                        float mouseRelative = mouse.y - scrollbarHeight/2 - 100;
                        chatScrollOffset = (mouseRelative / 680) * chatContentHeight;
                    }
                }

                // Adding friend field section
                if (isAddingFriend == true && fileSelector==false) {
                    if (IsKeyPressed(KEY_ESCAPE)) isAddingFriend=false;
                    DrawRectangle(1600/2-200, 900/2-200, 400, 400, GRAY);
                    DrawRectangleLines(1600/2-200, 900/2-200, 400, 400, WHITE);
                    DrawRectangleLines(1600/2-190, 900/2-140, 381, 61, WHITE);
                    DrawTextEx(font, "Введи код дружбы:", (Vector2){1600/2-190, 900/2-180}, 20, 2, WHITE);
                    if (GuiTextBox((Rectangle){1600/2-190, 900/2-140, 380, 60}, userId, 14, activeField==6)) {
                        activeField = (activeField == 6) ? -1 : 6;
                    }
                    if (GuiButton((Rectangle){1600/2+66, 900/2+156, 130, 40}, "Отправить")) {
                        if (strlen(userId) == 0) continue;

                        char parsed[37] = {0};
                        snprintf(parsed, sizeof(parsed), "addFriend/%ld\x1E%s", config.userId, userId);
                        printf("[SEND FRIEND REQUEST] Sent request for %s: %s\n", userId, parsed);
                        sendMessage(parsed);
                        hasFriendRequests=false;
                    }
                    if (GuiButton((Rectangle){1600/2-196, 900/2+156, 130, 40}, "Принять")) {
                        if (strlen(userId) > 0) {
                            long targetId = strtol(userId, nullptr, 10);
                            if (targetId == 0) continue;
                            char cmd[100];
                            snprintf(cmd, sizeof(cmd), "acceptFriend/%ld\x1E%ld", config.userId, targetId);
                            sendMessage(cmd);
                            printf("[ACCEPT FRIEND] Accepted friend request from %ld\n", targetId);

                            // char req[64];
                            // snprintf(req, sizeof(req), "getFriendsList/%ld", config.userId);
                            // sendMessage(req);

                            for (int i=0; i<100 && pendingFriends[i].userId!=0; i++) {
                                char id[15] = {0};
                                snprintf(id, 14, "%ld", pendingFriends[i].userId);
                                if (strncmp(userId, id, 14) == 0) {
                                    pendingFriends[i].userId = 0L;
                                    memset(pendingFriends[i].avatarUrl, 0, sizeof(pendingFriends[i].avatarUrl));
                                    memset(pendingFriends[i].name, 0, sizeof(pendingFriends[i].name));
                                    memset(pendingFriends[i].profileDescription, 0, sizeof(pendingFriends[i].profileDescription));
                                    memset(userId, 0, 15);
                                }
                            }
                        }
                        hasFriendRequests=false;
                    }

                    float startY = 900/2.0f -70;
                    for (int i=0; i<100 && pendingFriends[i].userId!=0; i++) {
                        Rectangle friendRect = {1600/2-190, startY, 380, 68};
                        DrawRectangleLines(1600/2-189, startY+1, 378, 66, GRAY);
                        Rectangle avatarRect2 = { 1600/2-184, startY + 8, 54, 54 };

                        if (CheckCollisionPointRec(GetMousePosition(), friendRect)) {
                            DrawRectangleRec(friendRect, (Color){60, 60, 70, 255});
                            if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON)) {
                                snprintf(userId, 14, "%ld", pendingFriends[i].userId);
                            }
                        } else {
                            DrawRectangleRec(friendRect, (Color){50, 50, 60, 255});
                        }

                        if (pendingFriendAvatarArr[i].id != 0) {
                            DrawTexturePro(pendingFriendAvatarArr[i],
                                           (Rectangle){0, 0, 54, 54},
                                           avatarRect2,
                                           (Vector2){0, 0}, 0.0f, WHITE);
                        } else {
                            DrawRectangleRec(avatarRect2, GRAY);
                        }
                        DrawRectangleLinesEx(avatarRect2, 2, LIGHTGRAY);
                        DrawTextEx(font, pendingFriends[i].name, (Vector2){1600/2-190 + 70, startY + 12}, 24, 2, WHITE);

                        if (strlen(pendingFriends[i].profileDescription) > 0) {
                            char shortDesc[80];
                            strncpy(shortDesc, pendingFriends[i].profileDescription, 70);
                            shortDesc[70] = '\0';
                            if (strlen(pendingFriends[i].profileDescription) > 70) strcat(shortDesc, "...");
                            DrawTextEx(font, shortDesc, (Vector2){1600/2-190 + 70, startY + 42}, 18, 2, LIGHTGRAY);
                        }

                        startY += 80;
                    }
                }
                if (fileSelector == true && isAddingFriend==false) {
                    if (IsKeyPressed(KEY_ESCAPE)) {fileSelector=false;}
                    Rectangle bounds = {100, 100, 800, 600};
                    path2 = GuiFileSelector(bounds, "Выбор файла:", font, LIGHTGRAY, GRAY, WHITE);
                    if (path2!=NULL && strlen(path2)>1) {
                        fileSelector=false;
                        printf("\nend filename: %s", path2);
                    }
                }

                if (initedNetwork == false) {
                    Rectangle networkErrorRec = {1, 900/2-100, 1600, 200};
                    Color accentColor = {255, 79, 79, 255};
                    Color backgroundColor = {255, 157, 157, 255};
                    DrawRectangleRec(networkErrorRec, backgroundColor);
                    DrawRectangleLinesEx(networkErrorRec, 2, accentColor);
                    DrawTextEx(font, "Потеряно соединение с сервером!", (Vector2){1600/2-470, 900/2-20}, 60, 2, RED);
                }

                break;
        }

        EndDrawing();
    }
    // Close connection
    close(sock);
    free(path2);

    UnloadTexture(userAvatarTexture);
    UnloadFont(font);
    CloseAudioDevice();
    CloseWindow();
    return 0;
}