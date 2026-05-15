#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <mysql.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <libgen.h>

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

int port = 63321;
#define BUFFER_SIZE 7097
int server_fd, new_socket;
struct sockaddr_in address;
int addrlen = sizeof(address);
char incomingBuffer[BUFFER_SIZE] = {0};
char outgoingBuffer[BUFFER_SIZE] = {0};
static pthread_t thread_id;

#define MAX_NAME 23
#define MAX_EMAIL 23
#define MAX_PASS 23
#define MAX_AVATAR 64
#define MAX_DESC 1024
#define MAX_MESS 2048
#define MAX_RESPONSE MAX_NAME + MAX_EMAIL + MAX_PASS + MAX_AVATAR + MAX_DESC + MAX_MESS
MYSQL *conn;

//
//      DATABASE STRUCTRURE
//
//        UnChat Database
//       /               \
// users table       messages table
//
//        users table:
// | userId | userName | email | passwordHash | avatarUrl | profileDescription |
//   long     char       char    char           char        char
//
//        messages table:
// | userId | messageId | senderId | messageContent |
//   long     long        long       char
//
//        friends table:
// | userId | relatedUsersIds |
//   long     long,long,long...
//

//                     PUSH MODEL

typedef struct ClientSession {
    long userId;
    int sock;
    struct ClientSession *next;
} ClientSession;

static ClientSession *activeClients = nullptr;
static pthread_mutex_t clientsMutex = PTHREAD_MUTEX_INITIALIZER;

bool sendPacket(int sock, const char *data) {
    char packet[132000];
    snprintf(packet, sizeof(packet), "%s\n", data);
    return send(sock, packet, strlen(packet), MSG_NOSIGNAL) > 0;
}
// register client (after authorization)
void registerClient(long userId, int sock) {
    pthread_mutex_lock(&clientsMutex);

    // removing old
    ClientSession *curr = activeClients, *prev = nullptr;
    while (curr) {
        if (curr->userId == userId) {
            close(curr->sock);
            if (prev) prev->next = curr->next;
            else activeClients = curr->next;
            free(curr);
            break;
        }
        prev = curr;
        curr = curr->next;
    }

    // new
    ClientSession *session = malloc(sizeof(ClientSession));
    session->userId = userId;
    session->sock = sock;
    session->next = activeClients;
    activeClients = session;

    printf(YELLOW "[NETWORK] client connected: userId=%ld, sock=%d\n" RESET, userId, sock);
    pthread_mutex_unlock(&clientsMutex);
}

// remove client after disconnecting
void unregisterClient(int sock) {
    pthread_mutex_lock(&clientsMutex);
    ClientSession *curr = activeClients, *prev = nullptr;

    while (curr) {
        if (curr->sock == sock) {
            printf(YELLOW "[NETWORK] client disconnected: userId=%ld\n" RESET, curr->userId);
            if (prev) prev->next = curr->next;
            else activeClients = curr->next;
            free(curr);
            break;
        }
        prev = curr;
        curr = curr->next;
    }
    pthread_mutex_unlock(&clientsMutex);
}

// sending messages to online client
bool pushToUser(long userId, const char *data) {
     pthread_mutex_lock(&clientsMutex);
     ClientSession *curr = activeClients;

     while (curr) {
         if (curr->userId == userId) {
             int sent = sendPacket(curr->sock, data);
             pthread_mutex_unlock(&clientsMutex);
             return sent > 0;
         }
         curr = curr->next;
     }

     pthread_mutex_unlock(&clientsMutex);
     return false; // client offline
}

void getClientUpdates(long userId, int sock) {
    { // MESSAGES
        int size = sizeof(char)*1050;
        char *response = malloc(size);
        if (response == NULL) {
            printf("[FATAL | CLIENT UPDATES] Not enough memory for updateClient answer");
            snprintf(response, 29, "updateClient/messages/error");
            sendPacket(sock, response);
            free(response);
            return;
        }
        int offset = 0;
        offset += snprintf(response+offset, size-offset, "updateClient/messages\x1E");

        char query[512];
        snprintf(query, sizeof(query),
                "SELECT senderId, COUNT(*) as cnt "
                      "FROM messages "
                      "WHERE receiverId = %ld AND isRead = FALSE "
                      "GROUP BY senderId", userId);
        if (mysql_query(conn, query) == 0) {
            MYSQL_RES *res = mysql_store_result(conn);
            if (res) {
                MYSQL_ROW row;
                int totalNew = 0;
                char message[MAX_MESS+1] = {0};
                int messageOffset = 0;

                while ((row = mysql_fetch_row(res))) {
                    long sender = strtol(row[0], nullptr, 10);
                    int count = atoi(row[1]);
                    totalNew += count;

                    messageOffset += snprintf(message+messageOffset, size-messageOffset,
                                      "%ld\x1F%d\x1E", sender, count);
                }
                mysql_free_result(res);

                offset += snprintf(response+offset, size-offset,
                                 "%d\x1E%s", totalNew, message);
            } else {
                offset += snprintf(response+offset, size-offset, "0\x1E");
            }
        } else {
            offset += snprintf(response+offset, size-offset, "0\x1E");
        }
        response[++offset] = '\0';
        sendPacket(sock, response);
        printf("[GET CLIENT UPDATES] Sent messages update for %ld: %s\n", userId, response);
        free(response);
    }

    { // FRIEND REQUESTS
        int size = sizeof(char)*1024;
        char *response = malloc(size);
        if (response == NULL) {
            printf("[FATAL | CLIENT UPDATES] Not enough memory for updateClient answer\n");
            snprintf(response, 35, "updateClient/friendRequests/error");
            sendPacket(sock, response);
            free(response);
            return;
        }
        int offset = 0;
        offset += snprintf(response+offset, size-offset, "updateClient/friendRequests\x1E");

        char query[512];
        snprintf(query, sizeof(query),
                "SELECT fr.id, fr.senderId, u.username, u.profileDesc "
                      "FROM friend_requests fr "
                      "JOIN users u ON fr.senderId = u.userId "
                      "WHERE fr.receiverId = %ld AND fr.status = 'pending' "
                      "ORDER BY fr.createdAt DESC LIMIT 30", userId);

        if (mysql_query(conn, query) == 0) {
            MYSQL_RES *res = mysql_store_result(conn);
            if (res) {
                MYSQL_ROW row;
                char message[MAX_RESPONSE] = {0};
                int messageOffset = 0;

                while ((row = mysql_fetch_row(res))) {
                    messageOffset += snprintf(message+messageOffset, size-messageOffset,
                        "%s\x1F%s\x1F%s\x1F%s\x1F%s\x1E",   // id, senderId, username, profileDesc, avatarUrl
                        row[0] ? row[0] : "0",
                        row[1] ? row[1] : "0",
                        row[2] ? row[2] : "",
                        row[3] ? row[3] : "",
                        ""
                    );
                }
                mysql_free_result(res);

                int tempOffset = snprintf(response+offset, size-offset, "%s", message);
                if (tempOffset+offset > size) {
                    size+=2560;
                    char *newServerResponce = realloc(response, size);
                    if (newServerResponce) {
                        response=newServerResponce;
                        snprintf(response+offset, size-offset, "%s", message);
                    }
                }
                offset+=tempOffset;
            } else {
                offset += snprintf(response+offset, size-offset, "0\x1E");
            }
        } else {
            offset += snprintf(response+offset, size-offset, "0\x1E");
        }
        response[++offset] = '\0';
        sendPacket(sock, response);
        printf("[GET CLIENT UPDATES] Sent friend request update for %ld: %s\n", userId, response);
        free(response);
    }
}

void getChatHistory(long userId, long friendId, int sock) {
    int bufSize = BUFFER_SIZE;
    char *response = malloc(bufSize);
    if (!response) {
        printf("[FATAL | GET CHAT HISTORY] Not enough memory for getChatHistory answer\n");
        snprintf(response, 23, "getChatHistory/error");
        sendPacket(sock, response);
        free(response);
        return;
    }
    int offset = snprintf(response, bufSize, "getChatHistory/%ld\x1E", friendId);

    char query[512];
    snprintf(query, sizeof(query),
        "SELECT messageId, senderId, message, sentAt "
        "FROM messages "
        "WHERE (senderId = %ld AND receiverId = %ld) "
           "OR (senderId = %ld AND receiverId = %ld) "
        "ORDER BY sentAt ASC LIMIT 500",
        userId, friendId, friendId, userId);

    if (mysql_query(conn, query)) {
        snprintf(response, 23, "getChatHistory/error");
        sendPacket(sock, response);
        free(response);
        return;
    }

    MYSQL_RES *res = mysql_store_result(conn);
    if (!res) {
        response[++offset] = '\0';
        snprintf(response, 23, "getChatHistory/empty");
        sendPacket(sock, response);
        free(response);
        return;
    }

    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res))) {
        if (offset+1024 > bufSize) {
            bufSize+=BUFFER_SIZE;
            char *newResponse = realloc(response, bufSize);
            if (!newResponse) { printf("[FATAL | GET CHAT HISTORY] Not enough memory for getChatHistory answer\n"); free(response); continue; }
            response = newResponse;
        }
        long msgId = strtol(row[0], nullptr, 10);
        long sender = strtol(row[1], nullptr, 10);
        const char *text = row[2] ? row[2] : "null";

        offset += snprintf(response+offset, bufSize-offset,
            "%ld\x1F%ld\x1F%s\x1E",
            msgId, sender, text);
    }

    mysql_free_result(res);

    if (offset > 20) {
        response[++offset] = '\0';
        sendPacket(sock, response);
        printf("[GET CHAT HISTORY] sent %zu bytes for %ld <-> %ld\n", strlen(response), userId, friendId);
    } else {
        snprintf(response, 23, "getChatHistory/empty");
        sendPacket(sock, response);
    }
    free(response);
}

bool saveUserToDB(long userId, const char *username, const char *email,
                  const char *passwordHashHex, const char *avatarUrl, const char *profileDesc) {

    char esc_username[MAX_NAME*2 + 10];
    char esc_email[MAX_EMAIL*2 + 10];
    char esc_hash[SHA256_DIGEST_LENGTH*2 + 10];
    char esc_avatar[MAX_AVATAR*2 + 10];
    char esc_desc[MAX_DESC*2 + 100];

    mysql_real_escape_string(conn, esc_username, username, strlen(username));
    mysql_real_escape_string(conn, esc_email,    email,    strlen(email));
    mysql_real_escape_string(conn, esc_hash,     passwordHashHex, strlen(passwordHashHex));
    mysql_real_escape_string(conn, esc_avatar,   avatarUrl, strlen(avatarUrl));
    mysql_real_escape_string(conn, esc_desc,     profileDesc, strlen(profileDesc));

    char query[8192];
    int written = snprintf(query, sizeof(query),
        "INSERT INTO users (userId, username, email, passwordHash, avatarUrl, profileDesc) "
        "VALUES (%ld, '%s', '%s', '%s', '%s', '%s') "
        "ON DUPLICATE KEY UPDATE "
        "username=VALUES(username), "
        "email=VALUES(email), "
        "passwordHash=VALUES(passwordHash), "
        "avatarUrl=VALUES(avatarUrl), "
        "profileDesc=VALUES(profileDesc)",
        userId,
        esc_username,
        esc_email,
        esc_hash,
        esc_avatar,
        esc_desc);

    if (written < 0 || written >= sizeof(query)) {
        printf("[SAVE USER TO DB] Query buffer too small, needed %d bytes\n", written);
        return false;
    }

    if (mysql_query(conn, query)) {
        printf("[SAVE USER TO DB] users table error: %s\n", mysql_error(conn));
        return false;
    }

    printf("[SAVE USER TO DB] User %ld saved/updated successfully\n", userId);
    return true;
}

bool saveMessageToDB(long messageId, long senderId, long receiverId, const char *message) {
    char escaped_message[ MAX_MESS*2 + 1 ];
    mysql_real_escape_string(conn, escaped_message, message, strlen(message));

    char query[4096];
    snprintf(query, sizeof(query),
        "INSERT INTO messages (messageId, senderId, receiverId, message) "
        "VALUES (%ld, %ld, %ld, '%s') "
        "ON DUPLICATE KEY UPDATE "
        "message=VALUES(message)",
        messageId,
        senderId,
        receiverId,
        escaped_message);

    if (mysql_query(conn, query)) {
        fprintf(stderr, "\n[SAVE MESSAGE TO DB] Error: %s", mysql_error(conn));
        return false;
    }
    return true;
}

void getFriends(long userId, int sock) {

}

// bool getUsers(void) {
//     if (mysql_query(conn, "SELECT userid, username FROM users")) {
//         printf("[GET USER LIST] SELECT err: %s\n", mysql_error(conn));
//         return false;
//     } else {
//         MYSQL_RES *res = mysql_store_result(conn); // loading result ro memory
//         if (res == NULL) return false;
//
//         MYSQL_ROW row; // line array (char *)
//         int num_fields = (int)mysql_num_fields(res); // number of columns
//
//         while ((row = mysql_fetch_row(res))) {
//             for(int i = 0; i < num_fields; i++) {
//                 printf("%s ", row[i] ? row[i] : "NULL");
//             }
//             printf("\n");
//         }
//
//         mysql_free_result(res); // free memory
//     }
//     return true;
// }

bool sendFriendRequest(long senderId, long receiverId) {
    if (senderId == receiverId) {
        printf("[SEND FRIEND REQUEST] Can't add yourself\n");
        return false;
    }

    char check[256];
    snprintf(check, sizeof(check),
             "SELECT 1 FROM users WHERE userId = %ld", receiverId);

    if (mysql_query(conn, check) == 0) {
        MYSQL_RES *res = mysql_store_result(conn);
        if (res && mysql_num_rows(res) == 0) {
            mysql_free_result(res);
            printf("[SEND FRIEND REQUEST] %ld doesn't exist\n", receiverId);
            return false;
        }
        if (res) mysql_free_result(res);
    }

    char query[512];
    snprintf(query, sizeof(query),
        "INSERT INTO friend_requests (senderId, receiverId) "
        "VALUES (%ld, %ld) ON DUPLICATE KEY UPDATE status='pending'",
        senderId, receiverId);

    if (mysql_query(conn, query)) {
        printf("[SEND FRIEND REQUEST] Query error: %s\n", mysql_error(conn));
        return false;
    }

    printf("[SEND FRIEND REQUEST] Friend request saved successfully in DB: %ld -> %ld\n", senderId, receiverId);
    return true;
}

bool acceptFriendRequest(long receiverId, long senderId) {
    // changing status
    char query[512];
    snprintf(query, sizeof(query),
        "UPDATE friend_requests SET status='accepted' "
        "WHERE senderId=%ld AND receiverId=%ld AND status='pending'",
        senderId, receiverId);

    if (mysql_query(conn, query)) {
        printf("[ACCEPT FRIEND] Update error: %s\n", mysql_error(conn));
        return false;
    }

    // one-way friendship request
    snprintf(query, sizeof(query),
        "INSERT IGNORE INTO friends (userId, relatedUserId) VALUES (%ld, %ld), (%ld, %ld)",
        senderId, receiverId, receiverId, senderId);

    if (mysql_query(conn, query)) {
        printf("[ACCEPT FRIEND] Insert friends error: %s\n", mysql_error(conn));
        return false;
    }
    return true;
}

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

bool finishedResponse = false;
void* acceptMessage(void *arg) {
    int sock = *(int*)arg;
    free(arg);
    char response[132000] = {0};
    char localBuf[BUFFER_SIZE];
    char fullMessage[132000];
    int totalReceived;

    while (1) {
        totalReceived = 0;
        memset(fullMessage, 0, sizeof(fullMessage));
        finishedResponse = false;

        while (1) { // splitting or combining packets based on \n persistence in the end of the packet
            memset(localBuf, 0, sizeof(localBuf));
            int bytes = read(sock, localBuf, sizeof(localBuf) - 1);
            if (bytes <= 0) {
                printf("[ACCEPT MESSAGE] Client disconnected (sock %d)\n", sock);
                goto client_disconnect;
            }

            memcpy(fullMessage + totalReceived, localBuf, bytes);
            totalReceived += bytes;
            fullMessage[totalReceived] = '\0';

            if (strchr(localBuf, '\n') || bytes < sizeof(localBuf)-1) {
                break;
            }
        }

        fullMessage[strcspn(fullMessage, "\n")] = '\0';
        printf("[ACCEPT MESSAGE] Got %d bytes from client (sock %d)\n", totalReceived, sock);
        printf("[ACCEPT MESSAGE] Client said (single message): %s\n", localBuf);
        printf("[ACCEPT MESSAGE] Client said (full message): %s\n", fullMessage);

        if (strcmp(fullMessage, "test/") == 0) {
            strcpy(response, "ok\n");
        }
        else if (strncmp(fullMessage, "receive-message/", 16) == 0) {
            printf("[RECEIVE MESSAGE] Saving message: %s\n", fullMessage);
            char *parts[4] = {0};
            int count = 0;
            char *token = strtok(fullMessage + 16, "\x1E");
            while (token && count < 4) {
                parts[count++] = token;
                token = strtok(nullptr, "\x1E");
            }
            long messageId = strtol(parts[0], nullptr, 10);
            long senderId = strtol(parts[1], nullptr, 10);
            long receiverId = strtol(parts[2], nullptr, 10);
            if (saveMessageToDB(messageId, senderId, receiverId, parts[3])) {
                printf("[RECEIVE MESSAGE] Message saved: %ld -> %ld\n", senderId, receiverId);

                char pushPacket[BUFFER_SIZE];
                snprintf(pushPacket, sizeof(pushPacket), "newMessage\x1E%ld\x1F%ld\x1F%s\x1F%s\n", messageId, senderId, parts[3], "now");

                if (!pushToUser(receiverId, pushPacket)) {
                    printf("[RECEIVE MESSAGE] Receiver %ld is offline, message will be saved to DB\n", receiverId);
                }
            } else {
                printf("[RECEIVE MESSAGE] Failed to save message to db: %ld, %ld\n", senderId, messageId);
                strcpy(response, "err\n");
            }
        }
        else if (strncmp(fullMessage, "createId/user", 13) == 0) {
            srand(time(NULL) ^ clock());
            // generating 10-digit number from 1000000000 to 9999999999
            long id = 1000000000L + (rand() % 9000000000L);
            sprintf(response, "createId/user/%ld\n", id);
            printf("[CREATE USER ID] New Id generated for user: %ld\n", id);
        }
        else if (strncmp(fullMessage, "createId/message", 16) == 0) {
            srand(time(NULL) ^ clock());
            // generating 10-digit number from 1000000000 to 9999999999
            long id = 1000000000L + (rand() % 9000000000L);
            sprintf(response, "createId/message/%ld\n", id);
            printf("[CREATE MESSAGE ID] New Id generated for message: %ld\n", id);
        }
        else if (strncmp(fullMessage, "save-profile/", 13) == 0) {

            char *parts[6] = {0};
            int count = 0;
            char *token = strtok(fullMessage + 13, "\x1E");

            while (token && count < 6) {
                parts[count++] = token;
                token = strtok(nullptr, "\x1E");
            }

            if (count >= 6) {
                long uid = strtol(parts[0], nullptr, 10);
                printf("[SAVE PROFILE] received for %ld\n", uid);
                bool success = saveUserToDB(uid,
                                            parts[1], parts[2], parts[3],
                                            parts[4], parts[5]);

                if (success) {
                    sendPacket(sock, "save-profile/ok");
                } else {
                    sendPacket(sock, "save-profile/error");
                }
            } else {
                sendPacket(sock, "save-profile/badformat");
            }
        }
        else if (strncmp(fullMessage, "getFriendsList/", 15) == 0) {
            long userId = strtol(fullMessage + 15, nullptr, 10);
            if (userId <= 0) continue;
            int offset = snprintf(response, sizeof(response), "getFriendsList/%ld\x1E", userId);

            // getting relatedUserId
            char query[512];
            snprintf(query, sizeof(query),
                     "SELECT receiverId FROM friend_requests WHERE senderId = %ld", userId);

            if (mysql_query(conn, query)) {
                printf("[GET FRIEND LIST] Failed to query friends for user %ld: %s\n", userId, mysql_error(conn));
                response[++offset] = '\0';
                snprintf(response, sizeof(response), "getFriendList/error");
                sendPacket(sock, response);
                continue;
            }

            MYSQL_RES *res = mysql_store_result(conn);
            if (res == NULL) {
                response[++offset] = '\0';
                snprintf(response, sizeof(response), "getFriendList/empty");
                sendPacket(sock, response);
                continue;
            }

            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res))) {
                if (row[0] == NULL) continue;

                long friend_id = strtol(row[0], nullptr, 10);
                if (friend_id <= 0) continue;

                // requesting data
                snprintf(query, sizeof(query),
                         "SELECT username, avatarUrl, profileDesc "
                         "FROM users WHERE userId = %ld", friend_id);

                if (mysql_query(conn, query) == 0) {
                    MYSQL_RES *fres = mysql_store_result(conn);
                    if (fres) {
                        MYSQL_ROW frow = mysql_fetch_row(fres);
                        if (frow && frow[0]) {
                            offset += snprintf(response + offset, sizeof(response) - offset,
                                "%s\x1F%ld\x1F%s\x1F%s\x1E",
                                frow[0],                    // username
                                friend_id,
                                frow[1] ? frow[1] : "",     // avatarUrl
                                frow[2] ? frow[2] : "");    // profileDesc
                        }
                        mysql_free_result(fres);
                    }
                }
            }
            mysql_free_result(res);

            // sending result
            if (offset > 15) {   // if there is atleast one friend
                response[++offset] = '\0';
                sendPacket(sock, response);
                printf("[GET FRIENDS LIST] Sent for %ld\n", userId);
            } else {
                response[++offset] = '\0';
                snprintf(response, sizeof(response), "getFriendList/empty");
                sendPacket(sock, response);
            }
        }
        else if (strncmp(fullMessage, "addFriend/", 10) == 0) {
            char *parts[2] = {0};
            int count = 0;
            char *token = strtok(fullMessage + 10, "\x1E");
            while (token && count < 2) {
                parts[count++] = token;
                token = strtok(nullptr, "\x1E");
            }

            if (count == 2) {
                long senderId = strtol(parts[0], nullptr, 10);
                long receiverId = strtol(parts[1], nullptr, 10);
                printf("[ADD FRIEND] received for %ld -> %ld\n", senderId, receiverId);

                if (senderId > 0 && receiverId > 0) {
                    if (sendFriendRequest(senderId, receiverId)) {
                        sendPacket(sock, "requestFriendUpdate/");
                        printf("[ADD FRIEND] Sent successfully %ld -> %ld\n", senderId, receiverId);
                        char notify[128];
                        snprintf(notify, sizeof(notify), "requestFriendUpdate/");
                        pushToUser(senderId, notify);
                    } else {
                        printf("[ADD FRIEND] Failed to save request\n");
                        strncpy(response, "addFriend/error\n", 16);
                    }
                } else {
                    printf("[ADD FRIEND] Bad ID\n");
                    strncpy(response, "addFriend/error\n", 16);
                }
            } else {
                printf("[ADD FRIEND] Bad format, got %d/2 parts\n", count);
                strncpy(response, "addFriend/badformat\n", 20);
            }
        }
        else if (strncmp(fullMessage, "acceptFriend/", 13) == 0) {
            char *parts[2] = {0};
            int count = 0;
            char *token = strtok(fullMessage + 13, "\x1E");
            while (token && count < 2) {
                parts[count++] = token;
                token = strtok(nullptr, "\x1E");
            }

            if (count == 2) {
                long receiverId = strtol(parts[0], nullptr, 10);
                long senderId   = strtol(parts[1], nullptr, 10);

                if (acceptFriendRequest(receiverId, senderId)) {
                    // updating both clients
                    pushToUser(senderId, "requestFriendUpdate/");
                    pushToUser(receiverId, "requestFriendUpdate/");

                    char updateCmd[64];
                    snprintf(updateCmd, sizeof(updateCmd), "updateClient/%ld", receiverId);
                    pushToUser(receiverId, updateCmd);
                } else {
                    sendPacket(sock, "acceptFriend/error");
                }
            } else {
                sendPacket(sock, "acceptFriend/badformat");
            }
        }
        else if (strncmp(fullMessage, "updateClient/", 13) == 0) {
            long userId = strtol(fullMessage + 13, nullptr, 10);
            printf("[UPDATE CLIENT] Received for client/user %ld\n", userId);
            if (userId > 0) {
                registerClient(userId, sock);
                getClientUpdates(userId, sock);
                continue;
            }
        }
        else if (strncmp(fullMessage, "getChatHistory/", 15) == 0) {
            char *parts[2] = {0};
            int count = 0;
            char *token = strtok(fullMessage + 15, "\x1E");
            while (token && count < 2) {
                parts[count++] = token;
                token = strtok(nullptr, "\x1E");
            }

            if (count == 2) {
                long userId = strtol(parts[0], nullptr, 10);
                long friendId = strtol(parts[1], nullptr, 10);
                printf("[GET CHAT HISTORY] Received history request from %ld with %ld\n", userId, friendId);

                if (userId > 0 && friendId > 0) {
                    getChatHistory(userId, friendId, sock);
                }
            }
            continue;
        }
        else if (strncmp(fullMessage, "getAvatar/", 10) == 0) {
            long sender = strtol(fullMessage + 10, nullptr, 10);
            long reciever = strtol(fullMessage + 20, nullptr, 10);
            printf("[GET AVATAR] %ld requested %ld's avatar\n", sender, reciever);

            char filepath[256];
            snprintf(filepath, sizeof(filepath), "avatars/%ld.png", reciever);

            FILE *f = fopen(filepath, "rb");
            if (f) {
                fseek(f, 0, SEEK_END);
                long fileSize = ftell(f);
                fseek(f, 0, SEEK_SET);

                unsigned char *pngData = malloc(fileSize);
                fread(pngData, 1, fileSize, f);
                fclose(f);

                char *b64 = Base64Encode(pngData, fileSize);
                free(pngData);

                if (b64) {
                    snprintf(response, sizeof(response), "getAvatarResponse/%ld\x1E%s", reciever, b64);
                    free(b64);
                    printf("[GET AVATAR] sent %ld's avatar for %ld (%ld bytes)\n", reciever, sender, fileSize);
                }
            } else {
                // if theres no avatar - sending null
                //char response1[64];
                snprintf(response, sizeof(response), "getAvatarResponse/%ld\x1E", reciever);
                //sendPacket(sock, response1);
                printf("[GET AVATAR] %ld's avatar not found\n", reciever);
            }
        }
        else if (strncmp(fullMessage, "saveAvatar/", 11) == 0) {
            char *ptr = fullMessage + 11;
            long userId = strtol(ptr, &ptr, 10);

            if (userId <= 0 || *ptr != '\x1E') {
                printf("[SAVE AVATAR] Parse error: invalid userId or missing separator\n");
                printf("[SAVE AVATAR] Received: %.100s...\n", fullMessage);
                continue;
            }

            char *b64_data = ptr + 1; // base64 start
            if (strlen(b64_data) < 100) {
                printf("[SAVE AVATAR] Base64 data too short (%zu chars)\n", strlen(b64_data));
                continue;
            }

            int decoded_len = 0;
            unsigned char* png_data = Base64Decode(b64_data, &decoded_len);

            if (!png_data || decoded_len < 500) { // minimal PNG size
                printf("[SAVE AVATAR] Decode failed or image too small (%d bytes)\n", decoded_len);
                free(png_data);
                continue;
            }

            char binary_path[PATH_MAX] = {0};
            char avatars_dir[PATH_MAX] = {0};
            ssize_t len = readlink("/proc/self/exe", binary_path, sizeof(binary_path)-1);
            if (len > 0) {
                binary_path[len] = '\0';
                snprintf(avatars_dir, sizeof(avatars_dir), "%s/avatars", dirname(binary_path));
            } else {
                strcpy(avatars_dir, "avatars");
            }

            mkdir(avatars_dir, 0755);
            char filepath[PATH_MAX];
            snprintf(filepath, sizeof(filepath), "%s/%ld.png", avatars_dir, userId);

            FILE *f = fopen(filepath, "wb");
            if (f) {
                size_t written = fwrite(png_data, 1, decoded_len, f);
                fclose(f);

                if (written == (size_t)decoded_len) {
                    if (decoded_len > 8 &&
                        png_data[0] == 0x89 && png_data[1] == 'P' &&
                        png_data[2] == 'N' && png_data[3] == 'G') {

                        printf("[SAVE AVATAR] Good PNG signature, saved %ld's avatar successfully (%d bytes)\n", userId, decoded_len);
                    } else {
                        printf("[SAVE AVATAR] Bad PNG signature, saved possibly corrupted %ld's avatar\n" RESET, userId);
                    }
                } else {
                    printf("[SAVE AVATAR] Write error: only %zu of %d bytes written\n", written, decoded_len);
                }
            } else {
                perror("[SAVE AVATAR] fopen failed");
            }

            free(png_data);
        }

        if (strlen(response) > 0) {
            sendPacket(sock, response);
            printf("[ACCEPT MESSAGE] Sent response for request: %s -> %s\n", fullMessage, response);
        }
    }

    client_disconnect:
    close(sock);
    return NULL;
}

int main(void) {
    printf("\n");
    // if we don't connect to database, chat probably won't work
    printf("[MYSQL] Connecting ro mysql\n");
    conn = mysql_init(nullptr);

    if (mysql_real_connect(conn, "localhost", "root", "681137", "unchat", 0, nullptr, 0) == NULL) {
        printf("[MYSQL] Failed to connect to database: %s\n", mysql_error(conn));
        mysql_close(conn);
        return 0;
    }

    printf("[MYSQL] Connected to database successfully\n");

    // we also need to initialize tables
    const char *queries[] = {
        // users
        "CREATE TABLE IF NOT EXISTS users ("
            "userId BIGINT UNSIGNED NOT NULL PRIMARY KEY,"          // main column
            "username VARCHAR(24) NOT NULL,"
            "email VARCHAR(24) NOT NULL UNIQUE,"                    // email (unique)
            "passwordHash VARCHAR(64) NOT NULL,"                    // SHA-256 in hex = 64 syms
            "avatarUrl VARCHAR(64) NOT NULL DEFAULT '',"
            "profileDesc VARCHAR(1025) NOT NULL DEFAULT ''"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",

        // friends (many-to-many)
        "CREATE TABLE IF NOT EXISTS friend_requests ("
            "id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,"
            "senderId BIGINT UNSIGNED NOT NULL,"
            "receiverId BIGINT UNSIGNED NOT NULL,"
            "status ENUM('pending', 'accepted', 'rejected') DEFAULT 'pending',"
            "createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,"
            "UNIQUE KEY unique_request (senderId, receiverId),"
            "FOREIGN KEY (senderId) REFERENCES users(userId) ON DELETE CASCADE,"
            "FOREIGN KEY (receiverId) REFERENCES users(userId) ON DELETE CASCADE"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",

        // messages (lite version)
        "CREATE TABLE IF NOT EXISTS messages ("
            "messageId BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,"
            "senderId BIGINT UNSIGNED NOT NULL,"
            "receiverId BIGINT UNSIGNED NOT NULL,"
            "message TEXT NOT NULL,"
            "sentAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
            "isRead BOOLEAN NOT NULL DEFAULT FALSE,"
            "FOREIGN KEY (senderId) REFERENCES users(userId),"
            "FOREIGN KEY (receiverId) REFERENCES users(userId)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"
    };

    for (int i = 0; i < 3; i++) {
        if (mysql_query(conn, queries[i])) {
            printf("[MYSQL] Error creating table %d: %s\n", i, mysql_error(conn));
        } else {
            printf("[MYSQL] Table %d created successfully\n", i);
        }
    }

    int num_queries = sizeof(queries) / sizeof(queries[0]);

    for (int i = 0; i < num_queries; i++) {
        if (mysql_query(conn, queries[i])) {
            printf("[MYSQL] Error creating table %d: %s\n", i, mysql_error(conn));
        } else {
            printf("[MYSQL] Table %d created successfully\n", i);
        }
    }

    // and then network
    // Create socket v4
    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    // Define server address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces
    address.sin_port = htons(port);

    // Bind port
    bind(server_fd, (struct sockaddr *)&address, sizeof(address));

    // Start listening
    listen(server_fd, 10);
    printf("[NETWORK] Server is listening on port %d\n", port);

    while (1) {
        new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (new_socket < 0) continue;

        // CRITICAL: We must allocate memory for the socket ID so it isn't
        // overwritten by the next accept() before the thread starts!
        int* client_sock_ptr = malloc(sizeof(int));
        *client_sock_ptr = new_socket;

        if (pthread_create(&thread_id, nullptr, acceptMessage, client_sock_ptr) == 0) {
            // Tell the OS to reclaim thread resources automatically on exit
            pthread_detach(thread_id);
        } else {
            close(new_socket);
            free(client_sock_ptr);
        }
    }
    return 0;

    // Cleanup
    close(new_socket);
    close(server_fd);
    printf("\n");
    return 0;
}