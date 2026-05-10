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

    printf(GREEN "\n[PUSH] client connected: userId=%ld, sock=%d" RESET, userId, sock);
    pthread_mutex_unlock(&clientsMutex);
}

// remove client after disconnecting
void unregisterClient(int sock) {
    pthread_mutex_lock(&clientsMutex);
    ClientSession *curr = activeClients, *prev = nullptr;

    while (curr) {
        if (curr->sock == sock) {
            printf(YELLOW "\n[PUSH] client disconnected: userId=%ld" RESET, curr->userId);
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
            int sent = (int)send(curr->sock, data, strlen(data), MSG_NOSIGNAL);
            pthread_mutex_unlock(&clientsMutex);
            return sent > 0;
        }
        curr = curr->next;
    }

    pthread_mutex_unlock(&clientsMutex);
    return false; // client offline
}

void getClientUpdates(long userId) {
    { // MESSAGES
        int size = sizeof(char)*1050;
        char *serverResponse = malloc(size);
        if (serverResponse == NULL) { printf(RED "\nNot enough memory for updateClient answer." RESET); return; }
        int offset = 0;
        offset += snprintf(serverResponse+offset, sizeof(serverResponse) - offset, "updateClient/messages\x1E");

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
                char message[1000] = {0};
                int messageOffset = 0;

                while ((row = mysql_fetch_row(res))) {
                    long sender = strtol(row[0], nullptr, 10);
                    int count = atoi(row[1]);
                    totalNew += count;

                    messageOffset += snprintf(message + messageOffset, sizeof(message) - messageOffset,
                                      "%ld\x1F%d\x1E", sender, count);
                }
                mysql_free_result(res);

                offset += snprintf(serverResponse+offset, sizeof(serverResponse)-offset,
                                 "%d\x1E%s", totalNew, message);
            } else {
                offset += snprintf(serverResponse+offset, sizeof(serverResponse)-offset, "0\x1E");
            }
        } else {
            offset += snprintf(serverResponse+offset, sizeof(serverResponse)-offset, "0\x1E");
        }
        serverResponse[++offset] = '\0';
        pushToUser(userId, serverResponse);
        free(serverResponse);
    }

    { // FRIEND REQUESTS
        int size = sizeof(char)*1024;
        char *serverResponse = malloc(size);
        if (serverResponse == NULL) { printf(RED "\nNot enough memory for updateClient answer." RESET); return; }
        int offset = 0;
        offset += snprintf(serverResponse+offset, sizeof(serverResponse) - offset, "updateClient/friendRequests\x1E");

        char query[512];
        snprintf(query, sizeof(query),
                "SELECT fr.id, fr.senderId, u.username, u.avatarUrl, u.profileDesc "
                      "FROM friend_requests fr "
                      "JOIN users u ON fr.senderId = u.userId "
                      "WHERE fr.receiverId = %ld AND fr.status = 'pending' "
                      "ORDER BY fr.createdAt DESC LIMIT 30", userId);

        if (mysql_query(conn, query) == 0) {
            MYSQL_RES *res = mysql_store_result(conn);
            if (res) {
                MYSQL_ROW row;
                char message[5120] = {0};
                int messageOffset = 0;

                while ((row = mysql_fetch_row(res))) {
                    messageOffset += snprintf(message+messageOffset, sizeof(message)-messageOffset,
                    "%s\x1F%s\x1F%s\x1F%s\x1F%s\x1F%s\x1E",
                          row[0], row[1], row[2], row[3] ? row[3] : "", row[4] ? row[4] : "", row[5]);

                }
                mysql_free_result(res);

                int tempOffset = snprintf(serverResponse+offset, sizeof(serverResponse)-offset, "%s", message);
                if (tempOffset+offset > size) {
                    size+=2560;
                    char *newServerResponce = realloc(serverResponse, size);
                    if (newServerResponce) {
                        serverResponse=newServerResponce;
                        snprintf(serverResponse+offset, sizeof(serverResponse)-offset, "%s", message);
                    }
                }
                offset+=tempOffset;
            } else {
                offset += snprintf(serverResponse+offset, sizeof(serverResponse)-offset, "0");
            }
        } else {
            offset += snprintf(serverResponse+offset, sizeof(serverResponse)-offset, "0");
        }
        serverResponse[++offset] = '\0';
        pushToUser(userId, serverResponse);
        free(serverResponse);
    }
}

void getChatHistory(long userId, long friendId, int sock) {
    int bufSize = BUFFER_SIZE;
    char *response = malloc(bufSize);
    if (!response) { printf(RED "\nnot enough memory for answer." RESET); return;}
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
        response[++offset] = '\0';
        send(sock, "getChatHistory/error", 20, 0);
        free(response);
        return;
    }

    MYSQL_RES *res = mysql_store_result(conn);
    if (!res) {
        response[++offset] = '\0';
        send(sock, "getChatHistory/empty", 21, 0);
        free(response);
        return;
    }

    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res))) {
        if (offset+1024 > bufSize) {
            bufSize+=BUFFER_SIZE;
            char *newResponse = realloc(response, bufSize);
            if (!newResponse) { printf(RED "\nnot enough memory for answer" RESET); free(response); break; }
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
        send(sock, response, strlen(response), 0);
        printf(GREEN "\n[getChatHistory] sent %zu bytes for %ld <-> %ld" RESET, strlen(response), userId, friendId);
    } else {
        response[++offset] = '\0';
        send(sock, "getChatHistory/empty", 21, 0);
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
        fprintf(stderr, RED "\nsaveUserToDB: query buffer too small! Needed %d bytes" RESET, written);
        return false;
    }

    if (mysql_query(conn, query)) {
        fprintf(stderr, RED "\nsaveUserToDB error: %s" RESET, mysql_error(conn));
        return false;
    }

    printf(GREEN "\nUser %ld saved/updated successfully" RESET, userId);
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
        fprintf(stderr, RED "\nsaveMessageToDB error: %s" RESET, mysql_error(conn));
        return false;
    }
    return true;
}

void getFriends(long user_id, int sock) {
    char response[8192] = {0};
    int offset = snprintf(response, sizeof(response), "getFriendsList/%ld\x1E", user_id);

    // getting relatedUserId
    char query[512];
    snprintf(query, sizeof(query),
             "SELECT relatedUserId FROM friends WHERE userId = %ld", user_id);

    if (mysql_query(conn, query)) {
        printf(RED "\ngetFriends: failed to query friends for user %ld" RESET, user_id);
        response[++offset] = '\0';
        send(sock, "getFriendsList/error", 21, 0);
        return;
    }

    MYSQL_RES *res = mysql_store_result(conn);
    if (res == NULL) {
        response[++offset] = '\0';
        send(sock, "getFriendsList/empty", 21, 0);
        return;
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
        send(sock, response, strlen(response), 0);
        printf(GREEN "\ngetFriends: sent %zu bytes for user %ld" RESET, strlen(response), user_id);
    } else {
        response[++offset] = '\0';
        send(sock, "getFriendsList/empty", 21, 0);
    }
}

void getUsers(void) {
    if (mysql_query(conn, "SELECT userid, username FROM users")) {
        fprintf(stderr, "\n" RED "SELECT err: %s" RESET, mysql_error(conn));
    } else {
        MYSQL_RES *res = mysql_store_result(conn); // loading result ro memory
        if (res == NULL) return;

        MYSQL_ROW row; // line array (char *)
        int num_fields = (int)mysql_num_fields(res); // number of columns

        while ((row = mysql_fetch_row(res))) {
            for(int i = 0; i < num_fields; i++) {
                printf("%s ", row[i] ? row[i] : "NULL");
            }
            printf("\n");
        }

        mysql_free_result(res); // free memory
    }
}

bool sendFriendRequest(long senderId, long receiverId) {
    if (senderId == receiverId) {
        printf(RED "\nнельзя добавить себя" RESET);
        return false;
    }

    char check[256];
    snprintf(check, sizeof(check),
             "SELECT 1 FROM users WHERE userId = %ld", receiverId);

    if (mysql_query(conn, check) == 0) {
        MYSQL_RES *res = mysql_store_result(conn);
        if (res && mysql_num_rows(res) == 0) {
            mysql_free_result(res);
            printf(RED "\nполучатель %ld не существует в базе" RESET, receiverId);
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
        fprintf(stderr, RED "\nsendFriendRequest FK error: %s" RESET, mysql_error(conn));
        return false;
    }

    printf(GREEN "\nзапрос в друзья сохранён %ld -> %ld" RESET, senderId, receiverId);
    return true;
}

bool acceptFriendRequest(long receiverId, long senderId) {
    // changing status
    char query[512];
    snprintf(query, sizeof(query),
        "UPDATE friend_requests SET status='accepted' "
        "WHERE senderId=%ld AND receiverId=%ld AND status='pending'",
        senderId, receiverId);

    if (mysql_query(conn, query)) return false;

    // two-way friendship
    snprintf(query, sizeof(query),
        "INSERT IGNORE INTO friends (userId, relatedUserId) VALUES (%ld, %ld), (%ld, %ld)",
        senderId, receiverId, receiverId, senderId);

    return mysql_query(conn, query) == 0;
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

void* acceptMessage(void *arg) {
    int sock = *(int*)arg;
    free(arg);
    char buffer[BUFFER_SIZE] = {0};
    char response[128] = {0};

    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        int valread = (int)read(sock, buffer, BUFFER_SIZE - 1);

        if (valread <= 0) {
            printf("\n" YELLOW "client disconnected (sock %d)" RESET, sock);
            break;
        }

        buffer[valread] = '\0';
        printf("\n\n" YELLOW "received from client: %s" RESET, buffer);

        if (strcmp(buffer, "test/") == 0) {
            strcpy(response, "ok");
        }
        else if (strncmp(buffer, "receive-message/", 16) == 0) {
            printf("\n" GREEN "saving message: %s" YELLOW, buffer);
            char *parts[4] = {0};
            int count = 0;
            char *token = strtok(buffer + 16, "\x1E");
            while (token && count < 4) {
                parts[count++] = token;
                token = strtok(nullptr, "\x1E");
            }
            long messageId = strtol(parts[0], nullptr, 10);
            long senderId = strtol(parts[1], nullptr, 10);
            long receiverId = strtol(parts[2], nullptr, 10);
            if (saveMessageToDB(messageId, senderId, receiverId, parts[3])) {
                printf(GREEN "\nmessage saved: %ld -> %ld" RESET, senderId, receiverId);

                char pushPacket[BUFFER_SIZE];
                snprintf(pushPacket, sizeof(pushPacket), "newMessage\x1E%ld\x1F%ld\x1F%s\x1F%s", messageId, senderId, parts[3], "now");

                if (!pushToUser(receiverId, pushPacket)) {
                    printf(YELLOW "\nreceiver %ld is offline, message saved to DB" RESET, receiverId);
                }
            } else {
                printf(RED "\nfailed to save message to db: %ld, %ld" RESET, senderId, messageId);
                strcpy(response, "err");
            }
        }
        else if (strncmp(buffer, "createId/user", 13) == 0) {
            srand(time(nullptr) + clock());
            long id = rand()%2147483647;
            sprintf(response, "createId/user/%ld", id);
            printf("\n" GREEN "newId generated for user: %ld" RESET, id);
        }
        else if (strncmp(buffer, "createId/message", 16) == 0) {
            srand(time(nullptr) + clock());
            long id = rand()%2147483647;
            sprintf(response, "createId/message/%ld", id);
            printf("\n" GREEN "newId generated for message: %ld" RESET, id);
        }
        else if (strncmp(buffer, "save-profile/", 13) == 0) {
            printf(GREEN "\nsave-profile received" RESET);

            char *parts[6] = {0};
            int count = 0;
            char *token = strtok(buffer + 13, "\x1E");

            while (token && count < 6) {
                parts[count++] = token;
                token = strtok(nullptr, "\x1E");
            }

            if (count >= 6) {
                long uid = strtol(parts[0], nullptr, 10);
                bool success = saveUserToDB(uid,
                                            parts[1], parts[2], parts[3],
                                            parts[4], parts[5]);

                if (success) {
                    send(sock, "save-profile/ok", 15, 0);
                } else {
                    send(sock, "save-profile/error", 18, 0);
                }
            } else {
                send(sock, "save-profile/badformat", 22, 0);
            }
        }
        else if (strncmp(buffer, "getFriendsList/", 15) == 0) {
            long user_id = strtol(buffer + 15, nullptr, 10);
            if (user_id > 0) {
                getFriends(user_id, sock);
                // return NULL;
                // continue;   maybe better???
            }
            continue;
        }
        else if (strncmp(buffer, "addFriend/", 10) == 0) {
            printf(GREEN "\naddFriend received: %s" RESET, buffer);

            char *parts[2] = {0};
            int count = 0;
            char *token = strtok(buffer + 10, "\x1E");
            while (token && count < 2) {
                parts[count++] = token;
                token = strtok(nullptr, "\x1E");
            }

            if (count == 2) {
                long senderId = strtol(parts[0], nullptr, 10);
                long receiverId = strtol(parts[1], nullptr, 10);

                printf("\nparsed: sender=%ld, receiver=%ld", senderId, receiverId);

                if (senderId > 0 && receiverId > 0) {
                    if (sendFriendRequest(senderId, receiverId)) {
                        printf(GREEN "\nзапрос в друзья отправлен %ld -> %ld" RESET, senderId, receiverId);
                    } else {
                        printf(RED "\nне удалось сохранить запрос" RESET);
                    }
                } else {
                    printf(RED "\naddFriend: некорректные ID" RESET);
                }
            } else {
                printf(RED "\naddFriend: плохой формат, получено %d частей" RESET, count);
            }
        }
        else if (strncmp(buffer, "acceptFriend/", 13) == 0) {
            char *parts[2] = {0};
            int count = 0;
            char *token = strtok(buffer + 13, "\x1E");
            while (token && count < 2) {
                parts[count++] = token;
                token = strtok(nullptr, "\x1E");
            }

            if (count == 2) {
                long receiverId = strtol(parts[0], nullptr, 10);
                long senderId   = strtol(parts[1], nullptr, 10);

                if (acceptFriendRequest(receiverId, senderId)) {
                    printf(GREEN "\n%ld принял заявку от %ld" RESET, receiverId, senderId);

                    char friendsListCmd[64];
                    snprintf(friendsListCmd, sizeof(friendsListCmd), "getFriendsList/%ld", receiverId);
                } else {
                    printf(RED "\nне получилось принять в друзья: %ld -> %ld" RESET, senderId, receiverId);
                }
            }
        }
        else if (strncmp(buffer, "updateClient/", 13) == 0) {
            long userId = strtol(buffer + 13, nullptr, 10);
            if (userId > 0) {
                registerClient(userId, sock);
                getClientUpdates(userId);
            }
        }
        else if (strncmp(buffer, "getChatHistory/", 15) == 0) {
            char *parts[2] = {0};
            int count = 0;
            char *token = strtok(buffer + 15, "\x1E");
            while (token && count < 2) {
                parts[count++] = token;
                token = strtok(nullptr, "\x1E");
            }

            if (count == 2) {
                long userId = strtol(parts[0], nullptr, 10);
                long friendId = strtol(parts[1], nullptr, 10);

                if (userId > 0 && friendId > 0) {
                    getChatHistory(userId, friendId, sock);
                }
            }
            continue;
        }
        else if (strncmp(buffer, "getAvatar/", 10) == 0) {
            long sender = strtol(buffer + 10, nullptr, 10);
            long reciever = strtol(buffer + 20, nullptr, 10);
            printf("[AVATAR] Запрос аватарки для user %ld\n", reciever);

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
                    char response1[131072];
                    snprintf(response1, sizeof(response1), "getAvatarResponse/%ld\x1E%s", reciever, b64);
                    pushToUser(sender, response1);
                    free(b64);
                    printf("[AVATAR] Отправлена аватарка %ld (%ld байт)\n", reciever, fileSize);
                }
            } else {
                // if theres no avatar - sending null
                char response1[64];
                snprintf(response1, sizeof(response1), "getAvatarResponse/%ld\x1E", reciever);
                pushToUser(sender, response1);
                printf("[AVATAR] Аватарка %ld не найдена\n", reciever);
            }
        }
        else if (strncmp(buffer, "saveAvatar/", 11) == 0) {
            // TODO fix the splitting
            char *ptr = buffer + 18;
            long userId = strtol(ptr, &ptr, 10);

            if (*ptr == '\x1E') {
                char *b64_data = ptr + 1;

                int decoded_len = 0;
                unsigned char* png_data = Base64Decode(b64_data, &decoded_len);

                if (png_data && decoded_len > 1000) {   // minimum
                    char path[PATH_MAX];
                    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
                    if (len != -1) {
                        path[len] = '\0';
                        char *dir = dirname(path); // get the folder containing the binary
                        snprintf(path, sizeof(path), "%s/avatars", dir); // safely join path and folder
                        mkdir(path, 0777); // create it; if it exists, it just returns -1 (no harm done)
                    }

                    char filepath[128];
                    snprintf(filepath, sizeof(filepath), "avatars/%ld.png", userId);

                    FILE *f = fopen(filepath, "wb");
                    if (f) {
                        fwrite(png_data, 1, decoded_len, f);
                        fclose(f);
                    }
                    FILE *f2 = fopen(filepath, "wb");
                    if (f2) {
                        fwrite(png_data, 1, decoded_len, f2);
                        fclose(f2);

                        if (decoded_len > 8) {
                            if (png_data[0] == 0x89 && png_data[1] == 'P' && png_data[2] == 'N' && png_data[3] == 'G') {
                                printf(GREEN "PNG сигнатура корректная\n" RESET);
                            } else {
                                printf(RED "неверная PNG сигнатура (первые 4 байта: %02X %02X %02X %02X)\n" RESET,
                                       png_data[0], png_data[1], png_data[2], png_data[3]);
                            }
                        }
                    }
                    free(png_data);
                } else {
                    printf(RED "ошибка декодирования аватарки или пустые данные\n" RESET);
                }
            }
        }

        send(sock, response, strlen(response), 0);
        printf("\n" YELLOW "sent response for request: %s -> %s" RESET, buffer, response);
    }

    close(sock);
    return NULL;
}

int main(void) {
    // if we don't connect to database, chat probably won't work
    printf("\n" YELLOW "connecting ro mysql" RESET);
    conn = mysql_init(nullptr);

    if (mysql_real_connect(conn, "localhost", "root", "681137", "unchat", 0, nullptr, 0) == NULL) {
        fprintf(stderr, "\n" RED "failed to connect to database: %s" RESET, mysql_error(conn));
        mysql_close(conn);
        return 0;
    }

    printf("\n" YELLOW "connected to database successfully" RESET);

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
            "status ENUM('pending', 'accepted', 'rejected') NOT NULL DEFAULT 'pending',"
            "createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
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
            fprintf(stderr, RED "\nОшибка создания таблицы %d: %s" RESET, i, mysql_error(conn));
        } else {
            printf(GREEN "\nТаблица %d создана успешно!" RESET, i);
        }
    }

    int num_queries = sizeof(queries) / sizeof(queries[0]);

    for (int i = 0; i < num_queries; i++) {
        if (mysql_query(conn, queries[i])) {
            fprintf(stderr, "\n" RED "error creating table %d: %s" RESET, i, mysql_error(conn));
        } else {
            printf("\n" GREEN "table %d created successfully!" RESET, i);
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
    printf("\n" YELLOW "server is listening on port %d" YELLOW, port);

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