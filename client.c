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

#define CONFIG_FILE "conf.txt"
#define MAX_NAME 23
#define MAX_EMAIL 23
#define MAX_PASS 23
#define MAX_AVATAR 64
#define MAX_DESC 1024
#define MAX_MESS 2048

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
    unsigned char passwordHash[SHA256_DIGEST_LENGTH];
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


#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 63321
#define BUFFER_SIZE 7097
static pthread_t thread_id;
static int sock = -1;
static struct sockaddr_in serv_addr;
bool connected = false;

void sendMessage(const char *message);
void* recieveMessage(void* arg) {
    char localBuf[BUFFER_SIZE];
    char fullMessage[132000];  // large buffer
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

            char *newline;
            while ((newline = strchr(fullMessage, '\n')) != NULL) {
                *newline = '\0';
                printf("[RECEIVE MESSAGE] Got %d bytes from server\n", totalReceived);
                printf("[RECEIVE MESSAGE] Server said (full message): %s\n", fullMessage);

                if (strncmp(localBuf, "save-profile/", 13) == 0) {
                    printf("[SAVE PROFILE] Profile successfully saved on server\n");
                }
                else if (strncmp(localBuf, "createId/user/", 14) == 0) {
                    long newId = atol(localBuf + 14);
                    if (newId > 0) {
                        config.userId = newId;
                        printf("[CREATE USER ID] Got new id from server: %ld\n", newId);
                    }
                }
                else if (strncmp(localBuf, "createId/message/", 17) == 0) {
                    long newId = atol(localBuf + 17);
                    if (newId > 0) {
                        randomId = newId;
                        printf("[CREATE MESSAGE ID] Got new id from server: %ld\n", newId);
                    }
                }
                else if (strncmp(localBuf, "getFriendsList/", 15) == 0) {
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
                else if (strncmp(localBuf, "getChatHistory/", 15) == 0) {
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
                else if (strncmp(localBuf, "err", 3) == 0) {
                    printf("[ERROR] Server returned error for past action\n");
                }
                else if (strncmp(localBuf, "newMessage\x1E", 11) == 0) {
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
                else if (strncmp(localBuf, "newFriendRequest\x1E", 18) == 0) {
                    char *parts[5] = {0};
                    int cnt = 0;
                    char *token = strtok(localBuf + 18, "\x1F");
                    while (token && cnt < 5) {
                        parts[cnt++] = token;
                        token = strtok(nullptr, "\x1F");
                    }

                    if (cnt >= 4) {
                        long requestId = strtol(parts[0], nullptr, 10);
                        long senderId  = strtol(parts[1], nullptr, 10);
                        const char *username = parts[2];

                        printf("[NEW FRIEND REQUEST] Got friend request from %ld\n", senderId);

                        // Можно добавить в отдельный массив или просто вывести уведомление
                        // Позже можно сделать попап с кнопками "Принять / Отклонить"
                    }
                }
                else if (strncmp(localBuf, "updateClient/messages", 21) == 0) {
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
                else if (strncmp(localBuf, "updateClient/friendRequests", 27) == 0) {
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

                        char *parts[6] = {0};
                        char *sub = strtok(tokenCopy, "\x1F");
                        int p = 0;
                        while (sub && p < 6) {
                            parts[p++] = sub;
                            sub = strtok(nullptr, "\x1F");
                        }

                        if (parts[0] && parts[1]) {
                            hasFriendRequests=true;
                            pendingFriends[count].userId = strtol(parts[1], nullptr, 10);
                            if (parts[2]) strncpy(pendingFriends[count].name, parts[2], MAX_NAME);
                            if (parts[3]) strncpy(pendingFriends[count].profileDescription, parts[3], MAX_DESC);
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
                else if (strncmp(fullMessage, "requestFriendUpdate/", 20) == 0) {
                    char req[31] = {0};
                    snprintf(req, 30, "getFriendsList/%ld", config.userId);
                    sendMessage(req);
                    memset(req, 0, 31);
                    snprintf(req, 30, "updateClient/%ld", config.userId);
                    sendMessage(req);
                    continue;
                }

                // moving the end
                size_t processed = (newline + 1) - fullMessage;
                memmove(fullMessage, newline + 1, totalReceived - processed);
                totalReceived -= processed;
            }
        }
    return NULL;
}
bool initNetwork(void) {
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
    return true;
}
void sendMessage(const char *message) {
    if (!connected || sock <= 0) {
        if (!initNetwork()) return;
    }

    char packet[132000];
    snprintf(packet, sizeof(packet), "%s\n", message);

    if (send(sock, packet, strlen(packet), 0) < 0) {
        printf("[NETWORK] Send error\n");
        connected = false;
    } else {
        printf("[NETWORK] Sent: %s\n", message);
        usleep(5000);
    }
}


//
//             CONFIG LOAD
//


bool loadConfig(Config *cfg) {
    FILE *f = fopen(CONFIG_FILE, "r");
    if (!f) {
        printf("[LOAD CONFIG FILE] conf.txt not found or corrupted. conf.txt will be recreated.\n");
        return false;
    }
    memset(cfg, 0, sizeof(Config));
    cfg->isFirstUsed=true;
    cfg->userId=0000000000;
    char line[512];

    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == '\0' || line[0] == '3') continue;
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        const char *key = line;
        const char *value = eq+1;

        if (strcmp(key, "isFirstUsed") == 0) {
            cfg->isFirstUsed=(strcmp(value, "true")==0);
        }
        else if (strcmp(key, "userId") == 0) {
            char *endptr = nullptr;
            errno = 0;
            cfg->userId=strtol(value, &endptr, 10);
            if (errno !=0 || endptr == value) {
                printf("[LOAD CONFIG FILE] Bad userId: %s\n", value);
                cfg->isFirstUsed=true;
                return false;
            }
        }
        else if (strcmp(key, "userName") == 0) {
            strncpy(cfg->userName, value, sizeof(cfg->userName) -1);
            cfg->userName[sizeof(cfg->userName)-1] ='\0';
        }
        else if (strcmp(key, "email") == 0) {
            strncpy(cfg->email, value, sizeof(cfg->email) -1);
            cfg->email[sizeof(cfg->email)-1] ='\0';
        }
        else if (strcmp(key, "passwordHash") == 0) {
            for (int i=0; i<32 && value[i*2] && value[i*2+1]; i++) {
                unsigned int byte;
                if (sscanf(value + i*2, "%2x", &byte) == 1) {
                    cfg->passwordHash[i]=(unsigned char)byte;
                }
            }
        }
        else if (strcmp(key, "avatarUrl") == 0) {
            if (strcmp(value, "null") == 0) {
                cfg->avatarUrl[0] = '\0';
            } else {
                strncpy(cfg->avatarUrl, value, sizeof(cfg->avatarUrl)-1);
                cfg->avatarUrl[sizeof(cfg->avatarUrl)-1] = '\0';
            }
        }
        else if (strcmp(key, "profileDescription") == 0) {
            if (strcmp(value, "null") == 0) {
                cfg->profileDescription[0] = '\0';
            } else {
                strncpy(cfg->profileDescription, value, sizeof(cfg->profileDescription)-1);
                cfg->profileDescription[sizeof(cfg->profileDescription)-1] ='\0';
            }
        }
    }
    fclose(f);
    return true;
}

bool saveConfig(Config *cfg) {
    FILE *f = fopen(CONFIG_FILE, "w");
    if (!f) return false;

    fprintf(f, "isFirstUsed=%s\n", cfg->isFirstUsed ? "true" : "false");
    fprintf(f, "userId=%ld\n", cfg->userId);
    fprintf(f, "userName=%s\n", cfg->userName);
    fprintf(f, "email=%s\n", cfg->email);

    fprintf(f, "passwordHash=");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        fprintf(f, "%02x", cfg->passwordHash[i]);
    }
    fprintf(f, "\n");

    fprintf(f, "avatarUrl=%s\n", strlen(cfg->avatarUrl)==0 ? "null" : cfg->avatarUrl);
    fprintf(f, "profileDescription=%s\n", strlen(cfg->profileDescription)==0 ? "null" : cfg->profileDescription);
    fclose(f);

    char hashHex[65] = {0};
    for (int i = 0; i < 32; i++) {
        sprintf(hashHex + i*2, "%02x", cfg->passwordHash[i]);
    }

    char message[2048] = {0};
    snprintf(message, sizeof(message),
             "save-profile/%ld\x1E%s\x1E%s\x1E%s\x1E%s\x1E%s",
             cfg->userId,
             cfg->userName,
             cfg->email,
             hashHex,
             cfg->avatarUrl,
             cfg->profileDescription);

    printf("[SAVE PROFILE] saving %s\n", message);
    sendMessage(message);
    return true;
}

void HashPassword(const char* password, unsigned char* outHash) {
    SHA256((const unsigned char*)password, strlen(password), outHash);
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

int main(void) {
    printf("\n");
    InitWindow(1600, 900, "UnChat - BETA 1.0");
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

    bool initedNetwork = initNetwork();
    bool loadedConf = loadConfig(&config);
    usleep(1000000);
    memset(friends, 0, sizeof(friends));
    memset(pendingFriends, 0, sizeof(pendingFriends));
    char msgBuf[BUFFER_SIZE];
    snprintf(msgBuf, sizeof(msgBuf), "updateClient/%ld", config.userId);
    sendMessage(msgBuf);
    if (!loadedConf || config.isFirstUsed) {
        strcpy(config.userName, "");
        strcpy(config.email, "");
        strcpy(config.profileDescription, "");
        config.isFirstUsed=true;
    } else {
        char message[27] = {0};
        sprintf(message, "getFriendsList/%ld", config.userId);
        sendMessage(message);
    }

    char passwordInput[MAX_PASS+1] = {0};
    static int activeField=-1;
    char newDesc[1025] = "";
    char message[2049] = "";
    bool isAddingFriend = false;
    char userId[11] = "";
    static Texture2D userAvatarTexture = {0};
    static char avatarPathInput[512] = {0};
    if (strlen(config.avatarUrl) != 0) {
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
    }
    static float scrollOffset = 0.0f;
    static float scrollVelocity = 0.0f;     // inertion speed
    static float scrollFriction = 0.92f;    // fade out timne (0.85 - hard, 0.94 - soft)
    static bool isDraggingScrollbar = false;
    bool autoScrollAllowed = true;
    bool loadedChat = true;

    while (!WindowShouldClose()) {
        float contentHeight = 0.0f;
        float wheel = GetMouseWheelMove();
        if (wheel != 0.0f) {
            scrollVelocity -= wheel * 15.0f;        // bigger number = faster scroll
            autoScrollAllowed=false;
        }
        if (!isDraggingScrollbar) {
            // regular scroollo with inertion
            scrollOffset += scrollVelocity;
            scrollVelocity *= scrollFriction;       // fadeout

            // if the speed is too slow -> resetting to zero
            if (fabsf(scrollVelocity) < 0.5f) {
                scrollVelocity = 0.0f;
            }
        }

        BeginDrawing();
        ClearBackground((Color){ 40, 40, 40, 255 });

        if (config.isFirstUsed) {
            DrawTextEx(font, "Добро пожаловать. Пройди настройку профиля:", (Vector2){100, 50}, 40, 3, WHITE);
            if (GuiTextBox((Rectangle){100, 150, 400, 40}, config.userName, MAX_NAME, activeField==0)) {
                activeField = (activeField == 0) ? -1 : 0;
            }
            if (GuiTextBox((Rectangle){100, 220, 400, 40}, config.email, MAX_EMAIL, activeField==1)) {
                activeField = (activeField == 1) ? -1 : 1;
            }
            if (GuiTextBox((Rectangle){100, 290, 400, 40}, passwordInput, MAX_PASS, activeField==2)) {
                activeField = (activeField == 2) ? -1 : 2;
            }
            if (GuiTextBox((Rectangle){100, 360, 400, 40}, config.profileDescription, MAX_DESC, activeField==3)) {
                activeField = (activeField == 3) ? -1 : 3;
            }
            DrawTextEx(font,"Юзернейм", (Vector2){520, 160}, 20, 3, LIGHTGRAY);
            DrawTextEx(font, "Email", (Vector2){520, 230}, 20, 3, LIGHTGRAY);
            DrawTextEx(font, "Пароль", (Vector2){520, 300}, 20, 3, LIGHTGRAY);
            DrawTextEx(font, "Описание профиля (опционально)", (Vector2){520, 370}, 20, 3, LIGHTGRAY);

            if (GuiButton((Rectangle){100, 450, 200, 50}, "Сохранить и продолжить")) {
                if (strlen(config.userName) < 3) {
                    // log error?
                    continue;
                }

                HashPassword(passwordInput, config.passwordHash);
                config.isFirstUsed = false;

                sendMessage("createId/user");
                for (int i = 0; i < 500 && config.userId == 0; i++) {
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

                saveConfig(&config);
            }
        } else {
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
            DrawTextEx(font, TextFormat("%s", config.userName), (Vector2){1320, 200}, 24, 1.0f, WHITE);
            Rectangle textBounds = { 1326, 278, 248, 388 };
            if (GuiTextBox((Rectangle){1320, 270, 260, 400}, newDesc, MAX_DESC, activeField==4)) {
                activeField = (activeField == 4) ? -1 : 4;
            } else {
                DrawTextBoxed(font, config.profileDescription, textBounds, 20, 1.0f, WHITE);
            }
            GuiSetStyle(DEFAULT, TEXT_SIZE, 16);
            if (GuiButton((Rectangle){1320, 230, 250, 30}, "скопировать код дружбы")) {
                char copyToClipboard[11];
                snprintf(copyToClipboard, 10, "%ld", config.userId);
                SetClipboardText(copyToClipboard);
            }
            GuiSetStyle(DEFAULT, TEXT_SIZE, 24);
            if (GuiButton((Rectangle){1320, 690, 200, 50}, "Обновить")) {
                if (newDesc[0] != 0) {
                    newDesc[1024]='\0';
                    strcpy(config.profileDescription, newDesc);
                }
                saveConfig(&config);
                loadConfig(&config);
            }
            DrawTextEx(font, "Путь к аватарке:", (Vector2){1320, 760}, 20, 2, LIGHTGRAY);
            if (GuiTextBox((Rectangle){1320, 790, 260, 40}, avatarPathInput, 255, activeField == 7)) {
                activeField = (activeField == 7) ? -1 : 7;
            }
            if (GuiButton((Rectangle){1320, 840, 200, 50}, "Загрузить")) {
                if (strlen(avatarPathInput) > 3) {
                    Image img = LoadImage(avatarPathInput);

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

                            saveConfig(&config);        // save and pull to server

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
                                    char response1[132000];
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
                        printf("[SAVE SELF AVATAR] Failed to load image: %s\n", avatarPathInput);
                    }
                }
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
                    } else {
                        char req[64];
                        snprintf(req, sizeof(req), "getAvatar/%ld", friends[i].userId);
                        sendMessage(req);
                        printf("[AVATAR] Requested avatar for %ld\n", friends[i].userId);
                    }
                }
                requestedAvatarUpdate=false;
            }

            // Send message section
            if (GuiTextBox((Rectangle){300, 839, 861, 60}, message, MAX_MESS, activeField==5)) {
                activeField = (activeField == 5) ? -1 : 5;
            }
            if (GuiButton((Rectangle){1141, 839, 160, 60}, "Отправить") || IsKeyPressed(KEY_ENTER)) {
                if (strlen(message) != 0) {
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
                    autoScrollAllowed=true;
                }
            }
            if (GuiButton((Rectangle){20, 45, 100, 30}, "+ Друг")) {
                isAddingFriend=true;
            }
            if (hasFriendRequests==true) {
                DrawCircle(121, 44, 6, RED);
            }
            if (GuiButton((Rectangle){155, 45, 120, 30}, "+ Группа")) {
                // TODO версия 2.0
            }

            // Friend section
            float friendStartY = 90.0f;
            for (int i = 0; i < 100 && friends[i].userId != 0; i++) {
                Rectangle friendRect = { 10, friendStartY, 280, 70 };

                if (CheckCollisionPointRec(GetMousePosition(), friendRect)) {
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

                        autoScrollAllowed=true;
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
                        char badge[16];
                        snprintf(badge, sizeof(badge), "%d", friends[i].newMessageCount);
                        int textW = MeasureText(badge, 20);
                        Rectangle badgeRect = {240, friendStartY + 12, (float)textW + 12, 24};

                        DrawRectangleRec(badgeRect, RED);
                        DrawText(badge, (int)badgeRect.x + 6, (int)badgeRect.y + 4, 20, WHITE);
                    }
                    autoScrollAllowed=true;
                }

                if (strlen(friends[i].profileDescription) > 0) {
                    char shortDesc[80];
                    strncpy(shortDesc, friends[i].profileDescription, 70);
                    shortDesc[70] = '\0';
                    if (strlen(friends[i].profileDescription) > 70) strcat(shortDesc, "...");
                    DrawTextEx(font, shortDesc, (Vector2){85, friendStartY + 42}, 18, 2, LIGHTGRAY);
                }

                friendStartY += 80.0f;
            }

            // Chat section
            Rectangle chatArea = {300, 80, 980, 700};
            for (int i = 0; i < messagesCount; i++) {
                Message *m = &messages[i];
                const int maxTextW = (int)chatArea.width - 120;

                char dummy[2048] = {0};
                int textH = WrapText(m->message, dummy, sizeof(dummy), maxTextW, font, 22, 2);
                contentHeight += (float)textH + 25 + 18;   // text height + indents
            }
            if (contentHeight < 680) scrollOffset = 0;
            float maxScroll = fmaxf(0.0f, contentHeight - 680.0f);
            scrollOffset = clamp(scrollOffset, 0.0f, maxScroll);
            if (autoScrollAllowed==true && messagesCount > 0) {
                scrollOffset = maxScroll;
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

            float currentY = 100 - scrollOffset;
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

            if (contentHeight > 680) {
                float scrollbarTrackHeight = 680;
                float scrollbarHeight = (680 / contentHeight) * scrollbarTrackHeight;
                float scrollbarY = 100 + (scrollOffset / contentHeight) * scrollbarTrackHeight;

                Rectangle scrollbarRect = {
                    chatArea.x + chatArea.width - 14,
                    scrollbarY,
                    10,
                    scrollbarHeight
                };

                DrawRectangle(chatArea.x + chatArea.width - 14, 100, 10, 680, Fade(BLACK, 0.3f));

                Color sbColor = isDraggingScrollbar ? WHITE : LIGHTGRAY;
                DrawRectangleRec(scrollbarRect, Fade(sbColor, 0.85f));

                Vector2 mouse = GetMousePosition();

                if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON)) {
                    if (CheckCollisionPointRec(mouse, scrollbarRect)) {
                        isDraggingScrollbar = true;
                        autoScrollAllowed=false;
                    }
                }

                if (IsMouseButtonReleased(MOUSE_LEFT_BUTTON)) {
                    isDraggingScrollbar = false;
                    autoScrollAllowed=false;
                }

                if (isDraggingScrollbar) {
                    autoScrollAllowed=false;
                    float mouseRelative = mouse.y - scrollbarHeight/2 - 100;
                    scrollOffset = (mouseRelative / 680) * contentHeight;
                }
            }

            // Adding friend field section
            if (isAddingFriend == true) {
                hasFriendRequests=false;
                if (IsKeyPressed(KEY_ESCAPE)) isAddingFriend=false;
                DrawRectangle(1600/2-200, 900/2-200, 400, 400, GRAY);
                DrawRectangleLines(1600/2-200, 900/2-200, 400, 400, WHITE);
                DrawRectangleLines(1600/2-190, 900/2-140, 381, 61, WHITE);
                DrawTextEx(font, "Введи код дружбы:", (Vector2){1600/2-190, 900/2-180}, 20, 2, WHITE);
                if (GuiTextBox((Rectangle){1600/2-190, 900/2-140, 380, 60}, userId, 11, activeField==6)) {
                    activeField = (activeField == 6) ? -1 : 6;
                }
                if (GuiButton((Rectangle){1600/2+66, 900/2+156, 130, 40}, "Отправить")) {
                    if (strlen(userId) == 0) continue;

                    char parsed[32] = {0};
                    snprintf(parsed, sizeof(parsed), "addFriend/%ld\x1E%s", config.userId, userId);
                    printf("[SEND FRIEND REQUEST] Sent request for %s: %s\n", userId, parsed);
                    sendMessage(parsed);
                }
                if (GuiButton((Rectangle){1600/2-196, 900/2+156, 130, 40}, "Принять")) {
                    if (strlen(userId) > 0) {
                        long targetId = strtol(userId, nullptr, 10);
                        if (targetId == 0) continue;
                        char cmd[100];
                        snprintf(cmd, sizeof(cmd), "acceptFriend/%ld\x1E%ld", config.userId, targetId);
                        sendMessage(cmd);
                        printf("[ACCEPT FRIEND] Accepted friend request from %ld\n", targetId);

                        char req[64];
                        snprintf(req, sizeof(req), "getFriendsList/%ld", config.userId);
                        sendMessage(req);

                        for (int i=0; i<100 && pendingFriends[i].userId!=0; i++) {
                            char id[11] = {0};
                            snprintf(id, 10, "%ld", pendingFriends[i].userId);
                            if (strncmp(userId, id, 10) == 0) {
                                pendingFriends[i].userId = 0L;
                                memset(pendingFriends[i].avatarUrl, 0, sizeof(pendingFriends[i].avatarUrl));
                                memset(pendingFriends[i].name, 0, sizeof(pendingFriends[i].name));
                                memset(pendingFriends[i].profileDescription, 0, sizeof(pendingFriends[i].profileDescription));
                                memset(userId, 0, 11);
                            }
                        }
                    }
                }

                float startY = 900/2.0f -70;
                for (int i=0; i<100 && pendingFriends[i].userId!=0; i++) {
                    Rectangle friendRect = {1600/2-190, startY, 380, 68};
                    DrawRectangleLines(1600/2-189, startY+1, 378, 66, GRAY);
                    Rectangle avatarRect2 = { 1600/2-184, startY + 8, 54, 54 };

                    if (CheckCollisionPointRec(GetMousePosition(), friendRect)) {
                        DrawRectangleRec(friendRect, (Color){60, 60, 70, 255});
                        if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON)) {
                            snprintf(userId, 10, "%ld", pendingFriends[i].userId);
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
        }

        if (initedNetwork == false) {
            DrawRectangle(1, 900/2-100, 1600, 200, GRAY);
            DrawRectangleLines(1, 900/2-100, 1599, 199, RED);
            DrawTextEx(font, "Потеряно соединение с сервером!", (Vector2){1600/2-470, 900/2-20}, 60, 2, RED);
        }

        EndDrawing();
    }
    // Close connection
    close(sock);

    UnloadTexture(userAvatarTexture);
    UnloadFont(font);
    CloseAudioDevice();
    CloseWindow();
    return 0;
}