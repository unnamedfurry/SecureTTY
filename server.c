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
#include "server.h"
#include <sodium.h>
#include <errno.h>
#include <signal.h>

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
static pthread_attr_t attr;
#define MAX_CLIENTS 1024
static volatile sig_atomic_t g_shutdown = 0;
static int g_server_fd = -1;
static int g_client_socks[MAX_CLIENTS];
static int g_client_count = 0;
static pthread_mutex_t g_clients_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned char serverPublicKey[crypto_box_PUBLICKEYBYTES];
static unsigned char serverPrivateKey[crypto_box_SECRETKEYBYTES];
void handle_signal(int sig) {
    g_shutdown = 1;
    shutdown(server_fd, SHUT_RDWR); // будит accept()
}

#define MAX_NAME 23
#define MAX_EMAIL 32
#define MAX_PASS 23
#define MAX_AVATAR 64
#define MAX_DESC 1024
#define MAX_MESS 2048
#define PACKET_SIZE 524288
#define MAX_RESPONSE (MAX_NAME + MAX_EMAIL + MAX_PASS + MAX_AVATAR + MAX_DESC + MAX_MESS)
MYSQL *conn;
pthread_mutex_t mysql_mutex = PTHREAD_MUTEX_INITIALIZER;

//
//      DATABASE STRUCTRURE
//
//      securetty Database
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
    unsigned char serverSessionKey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    bool hasSessionKey;
    bool loggedIn;
    bool closing;
    struct ClientSession *next;
} ClientSession;

ClientSession *activeClients = nullptr;
pthread_mutex_t clientsMutex = PTHREAD_MUTEX_INITIALIZER;

// Encrypting packet to client
bool EncryptPacket(ClientSession *session, const char* plaintext, char* out_buffer, size_t max_size) {
    if (!session || !plaintext || !out_buffer || max_size < 2) return false;
    if (!session->hasSessionKey) {
        if (strncmp(plaintext, "keyexchange_ok/", 15) == 0) {
            session->hasSessionKey=true;
        }
        strncpy(out_buffer, plaintext, max_size - 1);
        out_buffer[max_size - 1] = '\0';
        return true;
    }

    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    size_t len = strlen(plaintext);
    unsigned char ct[len + crypto_aead_xchacha20poly1305_ietf_ABYTES + 32];
    unsigned long long ct_len;

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(ct, &ct_len,
            (const unsigned char*)plaintext, len,
            nullptr, 0, nullptr, nonce, session->serverSessionKey) != 0) {
        return false;
    }

    char nonce_b64[128], ct_b64[PACKET_SIZE/2];
    sodium_bin2base64(nonce_b64, sizeof(nonce_b64), nonce, sizeof(nonce), sodium_base64_VARIANT_ORIGINAL);
    sodium_bin2base64(ct_b64, sizeof(ct_b64), ct, ct_len, sodium_base64_VARIANT_ORIGINAL);

    snprintf(out_buffer, max_size, "enc:%s:%s", nonce_b64, ct_b64);
    return true;
}
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

// sending messages to online client
bool pushToUser(long userId, const char *data, ClientSession *curr) {
    time_t rawtime;
    struct tm *info;
    char buffer[80];
    time(&rawtime);
    info = localtime(&rawtime);
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", info);

    if (!curr || !data || userId <= 0) return false;
    pthread_mutex_lock(&clientsMutex);
    ClientSession *target = nullptr;
    for (ClientSession *c = activeClients; c; c = c->next) {
        if (c->userId == userId && !c->closing && c->loggedIn && c->hasSessionKey) { target = c; break; }
    }
    bool ok = target ? sendPacket(target->sock, data, target) : false;
    pthread_mutex_unlock(&clientsMutex);

    if (!ok) {
        printf("[%s][PUSH] Failed to send to user %ld.\n", buffer, userId);
    }
    return ok;
}

void getClientUpdates(long userId, int sock, ClientSession *curr) {
    time_t rawtime;
    struct tm *info;
    char buffer[80];
    time(&rawtime);
    info = localtime(&rawtime);
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", info);
    { // MESSAGES
        int size = PACKET_SIZE;
        char *response = malloc(size * sizeof(char));
        if (response == NULL) {
            printf("[%s][FATAL | CLIENT UPDATES] Not enough memory for updateClient answer", buffer);
            return;
        }
        int offset = 0;
        offset += snprintf(response+offset, size-offset, "updateClient/messages/");

        char query[512] = {0};
        snprintf(query, sizeof(query),
                "SELECT senderId, COUNT(*) as cnt "
                      "FROM messages "
                      "WHERE receiverId = %ld AND isRead = FALSE "
                      "GROUP BY senderId", userId);
        pthread_mutex_lock(&mysql_mutex);
        if (mysql_query(conn, query) == 0) {
            MYSQL_RES *res = mysql_store_result(conn);
            if (res) {
                MYSQL_ROW row;
                int totalNew = 0;

                while ((row = mysql_fetch_row(res))) {
                    long sender = strtol(row[0], nullptr, 10);
                    int count = atoi(row[1]);
                    totalNew += count;

                    if (offset < size - 1) {
                        int written = snprintf(response + offset, size - offset,
                                               "%ld\x1F%d\x1E", sender, count);
                        if (written > 0) offset += written < size - offset ? written : size - offset - 1;
                    }
                }
                mysql_free_result(res);
            } else {
                offset += snprintf(response+offset, size-offset, "0\x1E");
            }
        } else {
            offset += snprintf(response+offset, size-offset, "0\x1E");
        }
        pthread_mutex_unlock(&mysql_mutex);
        sendPacket(sock, response, curr);
        printf("[%s][GET CLIENT UPDATES] Sent messages update for %ld: %s\n", buffer, userId, response);
        free(response);
    }

    { // FRIEND REQUESTS
        int size = PACKET_SIZE;
        char *response = malloc(size * sizeof(char));
        if (response == NULL) {
            printf("[%s][FATAL | CLIENT UPDATES] Not enough memory for updateClient answer\n", buffer);
            return;
        }
        int offset = 0;
        offset += snprintf(response+offset, size-offset, "updateClient/friendRequests\x1E");

        char query[512] = {0};
        snprintf(query, sizeof(query),
            "SELECT u.userId, u.username, u.profileDesc "
                  "FROM users u "
                  "WHERE u.userId IN ("
                  "SELECT senderId FROM friend_requests "
                  "WHERE receiverId = %ld AND status = 'pending')", userId);

        pthread_mutex_lock(&mysql_mutex);
        if (mysql_query(conn, query) == 0) {
            MYSQL_RES *res = mysql_store_result(conn);
            if (res) {
                MYSQL_ROW row;
                char message[MAX_RESPONSE] = {0};
                int messageOffset = 0;

                while ((row = mysql_fetch_row(res))) {
                    if (messageOffset >= (int)sizeof(message) - 1) break;
                    int written = snprintf(message+messageOffset, sizeof(message)-messageOffset,
                        "%s\x1F%s\x1F%s\x1E",   // userId, username, profileDesc
                        row[0] ? row[0] : "0",
                        row[1] ? row[1] : "0",
                        row[2] ? row[2] : ""
                    );
                    if (written < 0) break;
                    messageOffset += written;
                    if (messageOffset >= (int)sizeof(message)) {
                        messageOffset = sizeof(message) - 1;
                        message[messageOffset] = '\0';
                        break;
                    }
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
        pthread_mutex_unlock(&mysql_mutex);
        sendPacket(sock, response, curr);
        printf("[%s][GET CLIENT UPDATES] Sent friend request update for %ld: %s\n", buffer, userId, response);
        free(response);
    }
}

void getChatHistory(long userId, long friendId, int sock, ClientSession *curr) {
    time_t rawtime;
    struct tm *info;
    char buffer[80];
    time(&rawtime);
    info = localtime(&rawtime);
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", info);

    int bufSize = BUFFER_SIZE;
    char *response = malloc(bufSize * sizeof(char));
    if (!response) {
        printf("[%s][FATAL | GET CHAT HISTORY] Not enough memory for getChatHistory answer\n", buffer);
        return;
    }
    memset(response, 0, bufSize);
    int offset = snprintf(response, bufSize, "getChatHistory/%ld\x1E", friendId);

    char query[512] = {0};
    snprintf(query, sizeof(query),
        "SELECT messageId, senderId, message, sentAt "
        "FROM messages "
        "WHERE (senderId = %ld AND receiverId = %ld) "
           "OR (senderId = %ld AND receiverId = %ld) "
        "ORDER BY sentAt ASC LIMIT 500",
        userId, friendId, friendId, userId);

    pthread_mutex_lock(&mysql_mutex);
    if (mysql_query(conn, query)) {
        snprintf(response, 23, "getChatHistory/error");
        sendPacket(sock, response, curr);
        free(response);
        pthread_mutex_unlock(&mysql_mutex);
        return;
    }

    MYSQL_RES *res = mysql_store_result(conn);
    if (!res) {
        snprintf(response, 23, "getChatHistory/empty\x1E%ld", friendId);
        sendPacket(sock, response, curr);
        free(response);
        pthread_mutex_unlock(&mysql_mutex);
        return;
    }

    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res))) {
        size_t needed = strlen(row[2] ? row[2] : "null") + 64;
        if ((size_t)offset + needed >= (size_t)bufSize) {
            while ((size_t)offset + needed >= (size_t)bufSize) bufSize += BUFFER_SIZE;
            char *newResponse = realloc(response, bufSize);
            if (!newResponse) {
                printf(RED "[%s][FATAL | GET CHAT HISTORY]" RESET " Not enough memory for getChatHistory answer\n", buffer);
                free(response);
                mysql_free_result(res);
                pthread_mutex_unlock(&mysql_mutex);
                return;
            }
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
    pthread_mutex_unlock(&mysql_mutex);

    if (offset > 32) {
        sendPacket(sock, response, curr);
        printf("[%s][GET CHAT HISTORY] sent %zu bytes for %ld <-> %ld\n", buffer, strlen(response), userId, friendId);
    } else {
        snprintf(response, 23, "getChatHistory/empty\x1E%ld", friendId);
        sendPacket(sock, response, curr);
    }
    free(response);
}

bool saveUserToDB(long userId, const char *username, const char *email,
                  const char *password, const char *avatarUrl, const char *profileDesc){
    time_t rawtime;
    struct tm *info;
    char buffer[80];
    time(&rawtime);
    info = localtime(&rawtime);
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", info);

    char passwordHashed[crypto_pwhash_STRBYTES];
    char esc_username[MAX_NAME*2 + 10];
    char esc_email[MAX_EMAIL*2 + 10];
    char esc_password[crypto_pwhash_STRBYTES*2+10];
    char esc_avatar[MAX_AVATAR*2 + 10];
    char esc_desc[MAX_DESC*2 + 100];
    if (strcmp(profileDesc, "null") == 0) profileDesc="";
    bool ok = crypto_pwhash_str(passwordHashed, password, strlen(password),
                              crypto_pwhash_OPSLIMIT_MODERATE,
                              crypto_pwhash_MEMLIMIT_MODERATE) == 0;
    if (!ok) {
        printf("[%s][FATAL][SAVE USER TO DB] Failed to calculate pwhashed password for user %s\n", buffer, username);
        return false;
    }

    pthread_mutex_lock(&mysql_mutex);
    mysql_real_escape_string(conn, esc_username, username, strlen(username));
    mysql_real_escape_string(conn, esc_email,    email,    strlen(email));
    mysql_real_escape_string(conn, esc_password, passwordHashed, strlen(passwordHashed));
    mysql_real_escape_string(conn, esc_avatar,   avatarUrl, strlen(avatarUrl));
    mysql_real_escape_string(conn, esc_desc,     profileDesc, strlen(profileDesc));

    char query[8192];
    int written = snprintf(query, sizeof(query),
        "INSERT INTO users (userId, username, email, passwordHash, avatarUrl, profileDesc) "
        "VALUES (%ld, '%s', '%s', '%s', '%s', '%s') "
        "ON DUPLICATE KEY UPDATE "
        "avatarUrl=VALUES(avatarUrl), "
        "profileDesc=VALUES(profileDesc)",
        userId,
        esc_username,
        esc_email,
        esc_password,
        esc_avatar,
        esc_desc);

    if (written < 0 || written >= sizeof(query)) {
        printf("[%s][SAVE USER TO DB] Query buffer too small, needed %d bytes\n", buffer, written);
        pthread_mutex_unlock(&mysql_mutex);
        return false;
    }

    if (mysql_query(conn, query)) {
        printf("[%s][SAVE USER TO DB] users table error: %s\n", buffer, mysql_error(conn));
        pthread_mutex_unlock(&mysql_mutex);
        return false;
    }

    printf("[%s][SAVE USER TO DB] User %ld saved/updated successfully\n", buffer, userId);
    pthread_mutex_unlock(&mysql_mutex);
    return true;
}

bool saveMessageToDB(long messageId, long senderId, long receiverId, const char *message) {
    char escaped_message[ MAX_MESS*2 + 1 ];
    pthread_mutex_lock(&mysql_mutex);
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
        pthread_mutex_unlock(&mysql_mutex);
        return false;
    }
    pthread_mutex_unlock(&mysql_mutex);
    return true;
}

char* getUserFromDB(long userId) {
    char query[64] = {0};
    char *response = malloc(1960 * sizeof(char));
    if (!response) return nullptr;
    response[0] = '\0';
    snprintf(query, sizeof(query), "SELECT avatarUrl, profileDesc FROM users WHERE userId = %ld", userId);
    pthread_mutex_lock(&mysql_mutex);
    if (mysql_query(conn, query)) {
        printf("[GET USER FROM DB] SELECT err: %s\n", mysql_error(conn));
        pthread_mutex_unlock(&mysql_mutex);
        free(response);
        return nullptr;
    } else {
        MYSQL_RES *res = mysql_store_result(conn); // loading result ro memory
        if (res == NULL) {
            mysql_free_result(res);
            pthread_mutex_unlock(&mysql_mutex);
            free(response);
            return nullptr;
        }

        MYSQL_ROW row; // line array (char *)
        //int num_fields = (int)mysql_num_fields(res); // number of columns

        while ((row = mysql_fetch_row(res))) {
            snprintf(response, 1960, "%s\x1E%s", row[0] ? row[0] : "", row[1] ? row[1] : "");
            break;
        }

        mysql_free_result(res); // free memory
    }
    pthread_mutex_unlock(&mysql_mutex);
    return response;
}

bool sendFriendRequest(long senderId, long receiverId) {
    time_t rawtime;
    struct tm *info;
    char buffer[80];
    time(&rawtime);
    info = localtime(&rawtime);
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", info);

    if (senderId == receiverId) {
        printf("[%s][SEND FRIEND REQUEST] Can't add yourself\n", buffer);
        return false;
    }

    // do both clients exist?
    char check[256];
    snprintf(check, sizeof(check), "SELECT 1 FROM users WHERE userId = %ld", receiverId);

    pthread_mutex_lock(&mysql_mutex);
    if (mysql_query(conn, check) == 0) {
        MYSQL_RES *res = mysql_store_result(conn);
        if (res && mysql_num_rows(res) == 0) {
            mysql_free_result(res);
            printf("[%s][SEND] User %ld doesn't exist\n", buffer, receiverId);
            pthread_mutex_unlock(&mysql_mutex);
            return false;
        }
        mysql_free_result(res);
    }

    // avoid-mess-checks
    char query[1024];

    // 1 are we already friends now?
    snprintf(query, sizeof(query),
        "SELECT 1 FROM friend_requests WHERE (senderId = %ld AND receiverId = %ld) "
        "OR (senderId = %ld AND receiverId = %ld)",
        senderId, receiverId, receiverId, senderId);

    if (mysql_query(conn, query) == 0) {
        MYSQL_RES *res = mysql_store_result(conn);
        if (res && mysql_num_rows(res) > 0) {
            mysql_free_result(res);
            printf("[%s][SEND] Already friends: %ld <-> %ld\n", buffer, senderId, receiverId);
            pthread_mutex_unlock(&mysql_mutex);
            return false;
        }
        mysql_free_result(res);
    }

    // 2 do we have older requests?
    snprintf(query, sizeof(query),
        "SELECT senderId, status FROM friend_requests "
        "WHERE (senderId = %ld AND receiverId = %ld) "
        "   OR (senderId = %ld AND receiverId = %ld) "
        "LIMIT 1",
        senderId, receiverId, receiverId, senderId);

    if (mysql_query(conn, query) == 0) {
        MYSQL_RES *res = mysql_store_result(conn);
        if (res && mysql_num_rows(res) > 0) {
            MYSQL_ROW row = mysql_fetch_row(res);
            long existing_sender = atoll(row[0]);
            const char* status = row[1];

            mysql_free_result(res);

            if (strcmp(status, "accepted") == 0) {
                printf("[%s][SEND] Already friends (accepted request)\n", buffer);
            } else if (existing_sender == senderId) {
                printf("[%s][SEND] Request already sent\n", buffer);
            } else {
                printf("[%s][SEND] Request already received from the other side\n", buffer);
            }
            pthread_mutex_unlock(&mysql_mutex);
            return false;
        }
        mysql_free_result(res);
    }

    // sending new request
    // TODO: создать зеркальную запись
    snprintf(query, sizeof(query),
        "INSERT INTO friend_requests (senderId, receiverId, status) "
        "VALUES (%ld, %ld, 'pending') "
        "ON DUPLICATE KEY UPDATE status='pending', createdAt=CURRENT_TIMESTAMP",
        senderId, receiverId);

    if (mysql_query(conn, query)) {
        printf("[%s][SEND] DB error: %s\n", buffer, mysql_error(conn));
        pthread_mutex_unlock(&mysql_mutex);
        return false;
    }

    printf("[%s][SEND FRIEND REQUEST] Success: %ld -> %ld\n", buffer, senderId, receiverId);
    pthread_mutex_unlock(&mysql_mutex);
    return true;
}

bool acceptFriendRequest(long receiverId, long senderId) {
    time_t rawtime;
    struct tm *info;
    char buffer[80];
    time(&rawtime);
    info = localtime(&rawtime);
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", info);

    char query[1024];

    // 1 updating request status
    snprintf(query, sizeof(query),
        "UPDATE friend_requests "
         "SET status = 'accepted' "
         "WHERE senderId = %ld "
           "AND receiverId = %ld "
           "AND status = 'pending' ",
        senderId, receiverId);

    pthread_mutex_lock(&mysql_mutex);
    if (mysql_query(conn, query)) {
        printf("[%s][ACCEPT FRIEND REQUEST] Update error: %s\n", buffer, mysql_error(conn));
        pthread_mutex_unlock(&mysql_mutex);
        return false;
    }

    if (mysql_affected_rows(conn) == 0) {
        printf("[%s][ACCEPT FRIEND REQUEST] There is no pending-request or request is already accepted\n", buffer);
        pthread_mutex_unlock(&mysql_mutex);
        return false;
    }

    // 2 creating two mirrored records to chat appear on both clients
    snprintf(query, sizeof(query),
        "INSERT IGNORE INTO friend_requests (senderId, receiverId, status) "
         "VALUES (%ld, %ld, 'accepted')",
        senderId,   receiverId);   // first record: sender -> receiver
    if (mysql_query(conn, query)) {
        printf("[%s][ACCEPT FRIEND REQUEST] Insert friends error (1): %s\n", buffer, mysql_error(conn));
        pthread_mutex_unlock(&mysql_mutex);
        return false;
    }

    memset(query, 0, 1024);

    snprintf(query, sizeof(query),
        "INSERT IGNORE INTO friend_requests (senderId, receiverId, status) "
         "VALUES (%ld, %ld, 'accepted')",
        receiverId,   senderId);   // second record: receiver -> sender
    if (mysql_query(conn, query)) {
        printf("[%s][ACCEPT FRIEND REQUEST] Insert friends error (2): %s\n", buffer, mysql_error(conn));
        pthread_mutex_unlock(&mysql_mutex);
        return false;
    }

    printf("[%s][ACCEPT FRIEND REQUEST] Frienship created: %ld <-> %ld\n", buffer, senderId, receiverId);
    pthread_mutex_unlock(&mysql_mutex);
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

    char* output = (char*)malloc(bufferPtr->length + 1 * sizeof(char));
    memcpy(output, bufferPtr->data, bufferPtr->length);
    output[bufferPtr->length] = '\0';

    BIO_free_all(bio);
    return output;
}
unsigned char* Base64Decode(const char* input, int* out_len) {
    BIO *bio, *b64;
    int input_len = (int)strlen(input);

    unsigned char* output = (unsigned char*)malloc(input_len * 3 / 4 + 1 * sizeof(unsigned char));
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
// Decrypting received packet
bool DecryptPacket(unsigned char serverSessionKey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES], const char* input, char* out_plain, size_t max_size) {
    if (!serverSessionKey || !input || !out_plain || max_size < 2) return false;
    if (strncmp(input, "enc:", 4) != 0) {
        strncpy(out_plain, input, max_size - 1);
        out_plain[max_size - 1] = '\0';
        return true;
    }

    char *nonce_b64 = strtok((char*)(input + 4), ":");
    char *ct_b64 = strtok(nullptr, ":");

    if (!nonce_b64 || !ct_b64) return false;

    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    unsigned char ct[PACKET_SIZE/2];
    size_t nlen = 0, clen = 0;

    if (sodium_base642bin(nonce, sizeof(nonce), nonce_b64, strlen(nonce_b64), nullptr, &nlen, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0 ||
        nlen != sizeof(nonce) ||
        sodium_base642bin(ct, sizeof(ct), ct_b64, strlen(ct_b64), nullptr, &clen, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0 ||
        clen < crypto_aead_xchacha20poly1305_ietf_ABYTES) return false;

    unsigned char decrypted[PACKET_SIZE] = {0};
    unsigned long long decrypted_len;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, &decrypted_len, nullptr,
            ct, clen, nullptr, 0, nonce, serverSessionKey) != 0) {
        return false;
    }

    strncpy(out_plain, (char*)decrypted, max_size - 1);
    out_plain[max_size - 1] = '\0';
    return true;
}
void* acceptMessage(void *arg) {
    int sock = *(int*)arg;
    free(arg);
    char response[PACKET_SIZE] = {0};
    char localBuf[BUFFER_SIZE];
    char recvBuf[PACKET_SIZE] = {0};   // raw storage from the socket — read/shift only; never parse directly.
    char fullMessage[PACKET_SIZE] = {0}; // working copy of a SINGLE message — it is safe to perform decrypt and strtok on it
    int totalReceived = 0;
    pthread_t id = pthread_self();
    ClientSession *curr = nullptr;

    while (1) {
        memset(localBuf, 0, sizeof(localBuf));
        int bytes = read(sock, localBuf, sizeof(localBuf) - 1);
        time_t rawtime;
        struct tm *info;
        char buffer[80];
        time(&rawtime);
        info = localtime(&rawtime);
        strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", info);

        if (bytes <= 0) {
            printf(GREEN "[%s][ACCEPT MESSAGE][Thread %lu]" RESET " Client disconnected (sock %d)\n", buffer, id, sock);
            goto client_disconnect;
        }

        if (totalReceived + bytes > (int)sizeof(recvBuf) - 1) {
            printf(RED "[ACCEPT MESSAGE] Incoming data exceeds PACKET_SIZE, dropping buffered data (sock %d)\n" RESET, sock);
            totalReceived = 0;
        }

        memcpy(recvBuf + totalReceived, localBuf, bytes);
        totalReceived += bytes;
        recvBuf[totalReceived] = '\0';

        // multiple newline-separated messages might arrive in a single read() —
        // parse everything that has accumulated in recvBuf, not just the first one
        char *newlinePos;
        while ((newlinePos = memchr(recvBuf, '\x1D', totalReceived)) != NULL) {
            size_t msgLen = (size_t)(newlinePos - recvBuf);
            if (msgLen >= sizeof(fullMessage)) msgLen = sizeof(fullMessage) - 1;

            // Copy the message to a separate working buffer: recvBuf remains
            // untouched, and subsequent messages in the queue are safe
            // regardless of what decrypt/strtok do to fullMessage.
            memcpy(fullMessage, recvBuf, msgLen);
            fullMessage[msgLen] = '\0';
            finishedResponse = false;
            unsigned char serverSessionKey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
            {
                pthread_mutex_lock(&clientsMutex);
                ClientSession *curr2 = activeClients;
                while (curr2) {
                    if (curr2->sock == sock) {
                        curr = curr2;
                        memcpy(serverSessionKey, curr2->serverSessionKey, sizeof(curr2->serverSessionKey));
                    }
                    curr2 = curr2->next;
                }
                pthread_mutex_unlock(&clientsMutex);
            }
            printf(GREEN "[%s][ACCEPT MESSAGE][Thread %lu]" RESET " Client said (full message, %zu bytes): %s\n", buffer, id, msgLen, fullMessage);

            if (strncmp(fullMessage, "keyexchange/", 12) == 0) {
                char *clientPubB64 = fullMessage + 12;

                unsigned char clientPubKey[crypto_box_PUBLICKEYBYTES] = {0};
                size_t decoded_len = 0;

                if (sodium_base642bin(clientPubKey, sizeof(clientPubKey), clientPubB64,
                    strlen(clientPubB64), nullptr, &decoded_len, nullptr,
                    sodium_base64_VARIANT_ORIGINAL) != 0 ||
                    decoded_len != crypto_box_PUBLICKEYBYTES) {
                        printf("[CRYPTO] Bad public key from client\n");
                        snprintf(response, sizeof(response), "keyexchange/error");
                        goto onfail;
                }

                unsigned char *serverPub = serverPublicKey;
                unsigned char *serverPriv = serverPrivateKey;
                if (!curr) {
                    curr = malloc(sizeof(ClientSession));
                    if (!curr) { snprintf(response, sizeof(response), "keyexchange/error"); goto onfail; }
                    curr->userId = 0;               // not authenticated yet
                    curr->sock = sock;
                    curr->hasSessionKey = false;
                    curr->loggedIn = false;
                    curr->closing = false;
                    pthread_mutex_lock(&clientsMutex);
                    curr->next = activeClients;
                    activeClients = curr;
                    pthread_mutex_unlock(&clientsMutex);
                }

                if (crypto_box_beforenm(curr->serverSessionKey, clientPubKey, serverPriv) == 0) {
                    printf("[CRYPTO] Server session key: %p\n", (void*)curr->serverSessionKey);
                    char pub_b64[128] = {0};
                     sodium_bin2base64(pub_b64, sizeof(pub_b64), serverPub, crypto_box_PUBLICKEYBYTES, sodium_base64_VARIANT_ORIGINAL);
                    snprintf(response, sizeof(response), "keyexchange/myturn/%s", pub_b64);
                    goto onfail;
                } else {
                    printf(RED "[CRYPTO] crypto_box_beforenm failed on server\n" RESET);
                }
            }

            char decrypted[PACKET_SIZE] = {0};
            if (DecryptPacket(serverSessionKey, fullMessage, decrypted, sizeof(decrypted))) {
                // fullMessage is already an isolated copy of a single message
                // (we leave recvBuf and the queue of remaining messages untouched),
                // so we simply copy the decrypted text without using strncpy —
                // that would unnecessarily zero out PACKET_SIZE bytes for every message
                size_t dlen = strlen(decrypted);
                if (dlen >= sizeof(fullMessage)) dlen = sizeof(fullMessage) - 1;
                memcpy(fullMessage, decrypted, dlen);
                fullMessage[dlen] = '\0';
                if (curr) curr->hasSessionKey=true;
            }

            if (!curr) goto onfail;

            if (strcmp(fullMessage, "test/") == 0) {
                snprintf(response, sizeof(response), "ok");
            }
            else if (strncmp(fullMessage, "receive-message/", 16) == 0) {
                printf("[%s][RECEIVE MESSAGE] Saving message: %s\n", buffer, fullMessage);

                char *parts[4] = {0};
                int count = 0;
                char *token = strtok(fullMessage + 16, "\x1E");
                while (token && count < 4) {
                    parts[count++] = token;
                    token = strtok(nullptr, "\x1E");
                }
                if (count != 4 || parts[3] == nullptr) {
                    snprintf(response, sizeof(response), "receive-message/badformat");
                    goto onfail;
                }
                long messageId = strtol(parts[0], nullptr, 10);
                long senderId = strtol(parts[1], nullptr, 10);
                long receiverId = strtol(parts[2], nullptr, 10);
                if (senderId != curr->userId || receiverId <= 0) {
                    snprintf(response, sizeof(response), "receive-message/unauthorized");
                    goto onfail;
                }
                if (saveMessageToDB(messageId, senderId, receiverId, parts[3])) {
                    printf("[%s][RECEIVE MESSAGE] Message saved: %ld -> %ld\n", buffer, senderId, receiverId);
                    char pushPacket[BUFFER_SIZE];
                    snprintf(pushPacket, sizeof(pushPacket), "newMessage\x1E%ld\x1F%ld\x1F%s\x1F%s\n", messageId, senderId, parts[3], "now");

                    if (!pushToUser(receiverId, pushPacket, curr)) {
                        printf("[%s][RECEIVE MESSAGE] Receiver %ld is offline, message will be saved to DB\n", buffer, receiverId);
                    }
                } else {
                    printf("[%s][RECEIVE MESSAGE] Failed to save message to db: %ld, %ld\n", buffer, senderId, messageId);
                    snprintf(response, sizeof(response), "receive-message/error");
                }
            }
            else if (strncmp(fullMessage, "createId/user", 13) == 0) {
                srand(time(nullptr) ^ clock());
                // generating 10-digit number from 1000000000 to 9999999999
                long userId = 1000000000L + (rand() % 9000000000L);
                snprintf(response, sizeof(response), "createId/user/%ld", userId);
                printf("[%s][CREATE USER ID] New Id generated for user: %ld\n", buffer, userId);
            }
            else if (strncmp(fullMessage, "createId/message", 16) == 0) {
                srand(time(nullptr) ^ clock());
                // generating 10-digit number from 1000000000 to 9999999999
                long userId = 1000000000L + (rand() % 9000000000L);
                snprintf(response, sizeof(response), "createId/message/%ld", userId);
                printf("[%s][CREATE MESSAGE ID] New Id generated for message: %ld\n", buffer, userId);
            }
            else if (strncmp(fullMessage, "save-profile/", 13) == 0) {
                if (curr->hasSessionKey==false) {
                    printf(RED "[%s][SAVE PROFILE]" RESET " %d attempted unsecured save profile access\n", buffer, sock);
                    goto onfail;
                }
                char *parts[6] = {0};
                int count = 0;
                char *token = strtok(fullMessage + 13, "\x1E");

                while (token && count < 6) {
                    parts[count++] = token;
                    token = strtok(nullptr, "\x1E");
                }

                if (count >= 6) {
                    long uid = strtol(parts[0], nullptr, 10);
                    if (uid != curr->userId || !curr->loggedIn) {
                        snprintf(response, sizeof(response), "save-profile/unauthorized");
                        goto onfail;
                    }
                    printf("[%s][SAVE PROFILE] received for %ld\n", buffer, uid);
                    bool success = saveUserToDB(uid,
                                                parts[1], parts[2], parts[3],
                                                parts[4], parts[5]);

                    if (success) {
                        snprintf(response, sizeof(response), "save-profile/ok/");
                    } else {
                        snprintf(response, sizeof(response), "save-profile/error/");
                        char *profile = getUserFromDB(uid);
                        if (profile) {
                            snprintf(response+19, sizeof(response)-19, "%s", profile);
                            free(profile);
                        }
                    }
                } else {
                    snprintf(response, sizeof(response), "save-profile/badformat/");
                    if (parts[0]) {
                        char *profile = getUserFromDB(strtol(parts[0], nullptr, 10));
                        if (profile) {
                            snprintf(response+23, sizeof(response)-24, "%s", profile);
                            free(profile);
                        }
                    }
                }
            }

            else if (strncmp(fullMessage, "getFriendsList/", 15) == 0) {
                if (curr->loggedIn==false || curr->hasSessionKey==false) {
                    printf(RED "[%s][GET FRIENDS LIST]" RESET " %d attempted unauthorized friend list access\n", buffer, sock);
                    goto onfail;
                }
                long userId = strtol(fullMessage + 15, nullptr, 10);
                if (userId != curr->userId) { snprintf(response, sizeof(response), "getFriendsList/unauthorized"); goto onfail; }
                if (userId <= 0) goto onfail;
                int offset = snprintf(response, sizeof(response), "getFriendsList/");

                // getting relatedUserId
                char query[1024];
                snprintf(query, sizeof(query),
                         "SELECT u.username, u.userId, u.avatarUrl, u.profileDesc "
                         "FROM users u "
                         "INNER JOIN friend_requests fr ON u.userId = fr.receiverId "
                         "WHERE fr.senderId = %ld AND fr.status = 'accepted'", userId);

                pthread_mutex_lock(&mysql_mutex);
                if (mysql_query(conn, query) == 0) {
                    MYSQL_RES *res = mysql_store_result(conn);
                    if (res) {
                        MYSQL_ROW row;
                        while ((row = mysql_fetch_row(res))) {
                            offset += snprintf(response + offset, sizeof(response) - offset,
                                "%s\x1F%ld\x1F%s\x1F%s\x1E",
                                row[0],                             // username
                                strtol(row[1], nullptr, 10),        // friend_id
                                row[2] ? row[2] : "",               // avatarUrl
                                row[3] ? row[3] : "");              // profileDesc
                        }
                        mysql_free_result(res);
                    }
                }
                pthread_mutex_unlock(&mysql_mutex);

                // sending result
                if (offset > 15) {   // if there is atleast one friend
                    printf("[%s][GET FRIENDS LIST] Sent for %ld\n", buffer, userId);
                } else {
                    snprintf(response, sizeof(response), "getFriendsList/empty");
                }
            }
            else if (strncmp(fullMessage, "addFriend/", 10) == 0) {
                if (curr->loggedIn==false || curr->hasSessionKey==false) {
                    printf(RED "[%s][ADD FRIEND]" RESET " %d attempted unauthorized friend addition\n", buffer, sock);
                    goto onfail;
                }
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
                    if (senderId != curr->userId) { snprintf(response, sizeof(response), "addFriend/unauthorized"); goto onfail; }
                    printf("[%s][ADD FRIEND] received for %ld -> %ld\n", buffer, senderId, receiverId);
                    if (senderId > 0 && receiverId > 0) {
                        if (sendFriendRequest(senderId, receiverId)) {
                            pushToUser(receiverId, "requestPendingFriends/", curr);
                            printf("[%s][ADD FRIEND] Sent successfully %ld -> %ld\n", buffer, senderId, receiverId);
                        } else {
                            printf("[%s][ADD FRIEND] Failed to save request\n", buffer);
                            strncpy(response, "addFriend/error", 16);
                        }
                    } else {
                        printf("[%s][ADD FRIEND] Bad ID\n", buffer);
                        strncpy(response, "addFriend/error", 16);
                    }
                } else {
                    printf("[%s][ADD FRIEND] Bad format, got %d/2 parts\n", buffer, count);
                    strncpy(response, "addFriend/badformat", 20);
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
                    if (receiverId != curr->userId) { snprintf(response, sizeof(response), "acceptFriend/unauthorized"); goto onfail; }

                    if (acceptFriendRequest(receiverId, senderId)) {
                        // updating both clients
                        pushToUser(senderId, "requestFriendUpdate/", curr);
                        pushToUser(receiverId, "requestFriendUpdate/", curr);
                    } else {
                        snprintf(response, sizeof(response), "acceptFriend/error");
                    }
                } else {
                    snprintf(response, sizeof(response), "acceptFriend/badformat");
                }
            }
            else if (strncmp(fullMessage, "updateClient/", 13) == 0) {
                if (curr->loggedIn==false || curr->hasSessionKey==false) {
                    printf(RED "[%s][UPDATE CLIENT]" RESET " %d attempted unauthorized client update access\n", buffer, sock);
                    goto onfail;
                }
                long userId = strtol(fullMessage + 13, nullptr, 10);
                printf("[%s][UPDATE CLIENT] Received for client/user %ld\n", buffer, userId);
                if (userId == curr->userId) {
                    getClientUpdates(userId, sock, curr);
                } else {
                    snprintf(response, sizeof(response), "updateClient/unauthorized");
                }
            }
            else if (strncmp(fullMessage, "registerClient/", 15) == 0) {
                long userId = strtol(fullMessage + 15, nullptr, 10);
                printf("[%s][REGISTER CLIENT] Received for client/user %ld\n", buffer, userId);
                if (curr->userId == 0 && !curr->loggedIn && userId > 0) {
                    registerClient(userId, sock);
                } else {
                    snprintf(response, sizeof(response), "registerClient/unauthorized");
                }
            }
            else if (strncmp(fullMessage, "login/", 6) == 0) {
                char *parts[3] = {0};
                int count = 0;
                char *token = strtok(fullMessage + 6, "\x1E");
                while (token && count < 3) {
                    parts[count++] = token;
                    token = strtok(nullptr, "\x1E");
                }
                if (count != 3) {
                    printf("[%s][LOGIN] Not enough parameters for login\n", buffer);
                    goto onfail;
                }
                long userId = strtol(parts[0], nullptr, 10);
                char esc_email[MAX_EMAIL*2 + 10] = {0};
                char password[crypto_pwhash_STRBYTES+10] = {0};
                pthread_mutex_lock(&mysql_mutex);
                mysql_real_escape_string(conn, esc_email,    parts[1],    strlen(parts[1]));
                char query[256];
                snprintf(query, 256, "SELECT passwordHash FROM users WHERE userId = %ld AND email = '%s' LIMIT 1", userId, esc_email);
                if (mysql_query(conn, query)) {
                    printf("[%s][LOGIN CLIENT] Query Error: %s\n", buffer, mysql_error(conn));
                    pthread_mutex_unlock(&mysql_mutex);
                    unregisterClient(curr);
                    free(curr);
                    curr = nullptr;
                    close(sock);
                    goto client_disconnect;
                }
                MYSQL_RES *result = mysql_store_result(conn);
                if (result == NULL) {
                    mysql_free_result(result);
                    pthread_mutex_unlock(&mysql_mutex);
                    unregisterClient(curr);
                    free(curr);
                    curr = nullptr;
                    close(sock);
                    goto client_disconnect;
                }
                MYSQL_ROW row = mysql_fetch_row(result);
                if (row != NULL && row[0] != NULL) {
                    strncpy(password, row[0], sizeof(password) - 1);
                } else {
                    printf("[%s][LOGIN CLIENT] No matching user found.\n", buffer);
                    unregisterClient(curr);
                    free(curr);
                    curr = nullptr;
                    close(sock);
                    goto client_disconnect;
                }
                mysql_free_result(result);
                pthread_mutex_unlock(&mysql_mutex);
                bool ok = false;
                if (strlen(password) > 0) {ok = crypto_pwhash_str_verify(password, parts[2], strlen(parts[2])) == 0;}

                printf("[%s][LOGIN CLIENT] Received for client/user %ld\n", buffer, userId);
                if (userId > 0 && ok == true) {
                    registerClient(userId, sock);
                    curr->loggedIn=true;
                    printf("[%s][LOGIN CLIENT] User %ld\n authorized successfully\n", buffer, userId);
                } else {
                    printf("[%s][LOGIN CLIENT] User %ld\n failed to authorize: incorrect data\n", buffer, userId);
                    unregisterClient(curr);
                    close(sock);
                }
            }
            else if (strncmp(fullMessage, "getChatHistory/", 15) == 0) {
                if (curr->loggedIn==false || curr->hasSessionKey==false) {
                    printf(RED "[%s][GET CHAT HISTORY]" RESET " %d attempted unauthorized chat history access\n", buffer, sock);
                    goto onfail;
                }
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
                    printf("[%s][GET CHAT HISTORY] Received history request from %ld with %ld\n", buffer, userId, friendId);

                    if (userId == curr->userId && friendId > 0) {
                        getChatHistory(userId, friendId, sock, curr);
                    }
                }
            }
            else if (strncmp(fullMessage, "getAvatar/", 10) == 0) {
                if (curr->loggedIn==false || curr->hasSessionKey==false) {
                    printf(RED "[%s][GET AVATAR]" RESET " %d attempted unauthorized avatar downloading\n", buffer, sock);
                    goto onfail;
                }
                long uid = strtol(fullMessage + 10, nullptr, 10);
                if (uid <= 0) { snprintf(response, sizeof(response), "getAvatar/badformat"); goto onfail; }
                printf("[%s][GET AVATAR] requested %ld's avatar\n", buffer, uid);
                char filepath[256];
                snprintf(filepath, sizeof(filepath), "avatars/%ld.png", uid);

                FILE *f = fopen(filepath, "rb");
                if (f) {
                    fseek(f, 0, SEEK_END);
                    long fileSize = ftell(f);
                    fseek(f, 0, SEEK_SET);

                    if (fileSize <= 0 || fileSize > PACKET_SIZE) {
                        fclose(f);
                        snprintf(response, sizeof(response), "getAvatar/error");
                        goto onfail;
                    }

                    unsigned char *pngData = malloc(fileSize * sizeof(unsigned char));
                    if (!pngData) {
                        fclose(f);
                        snprintf(response, sizeof(response), "getAvatar/error");
                        goto onfail;
                    }
                    memset(pngData, 0, (size_t)fileSize);
                    fread(pngData, 1, fileSize, f);
                    fclose(f);

                    char *b64 = Base64Encode(pngData, (int)fileSize);
                    free(pngData);

                    if (b64) {
                        snprintf(response, PACKET_SIZE, "getAvatarResponse/%ld\x1E%s", uid, b64);
                        free(b64);
                        printf("[%s][GET AVATAR] sent avatar for %ld (%ld bytes)\n", buffer, uid, fileSize);
                    }
                } else {
                    // if theres no avatar - sending null
                    snprintf(response, sizeof(response), "getAvatarResponse/%ld\x1E", uid);
                    printf("[%s][GET AVATAR] %ld's avatar not found\n", buffer,uid);
                }
            }
            else if (strncmp(fullMessage, "saveAvatar/", 11) == 0) {
                if (curr->loggedIn==false || curr->hasSessionKey==false) {
                    printf(RED "[%s][SAVE AVATAR]" RESET " %d attempted unauthorized avatar saving\n", buffer, sock);
                    goto onfail;
                }
                char *ptr = fullMessage + 11;
                long userId = strtol(ptr, &ptr, 10);

                if (userId != curr->userId || *ptr != '\x1E') {
                    printf("[%s][SAVE AVATAR] Parse error: invalid userId or missing separator\n", buffer);
                    printf("[%s][SAVE AVATAR] Received: %.100s...\n", buffer, fullMessage);
                    snprintf(response, sizeof(response), "saveAvatar/unauthorized");
                    goto onfail;
                }

                char *b64_data = ptr + 1; // base64 start
                if (strlen(b64_data) < 100) {
                    printf("[%s][SAVE AVATAR] Base64 data too short (%zu chars)\n", buffer, strlen(b64_data));
                }

                int decoded_len = 0;
                unsigned char* png_data = Base64Decode(b64_data, &decoded_len);

                if (!png_data || decoded_len < 500) { // minimal PNG size
                    printf("[%s][SAVE AVATAR] Decode failed or image too small (%d bytes)\n", buffer, decoded_len);
                    free(png_data);
                    goto onfail;
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

                            printf("[%s][SAVE AVATAR] Good PNG signature, saved %ld's avatar successfully (%d bytes)\n", buffer, userId, decoded_len);
                        } else {
                            printf("[%s][SAVE AVATAR] Bad PNG signature, saved possibly corrupted %ld's avatar\n" RESET, buffer, userId);
                        }
                    } else {
                        printf("[%s][SAVE AVATAR] Write error: only %zu of %d bytes written\n", buffer, written, decoded_len);
                    }
                } else {
                    printf("[%s][SAVE AVATAR] fopen failed: %s", buffer, filepath);
                }

                free(png_data);
            }
            else if (strncmp(fullMessage, "requestPendingFriends/", 22) == 0) {
                if (curr->loggedIn==false || curr->hasSessionKey==false) {
                    printf(RED "[%s][REQUEST PENDING FRIENDS]" RESET " %d attempted unauthorized friend list access\n", buffer, sock);
                    goto onfail;
                }
                 char *ptr = fullMessage + 22;
                 long userId = strtol(ptr, &ptr, 10);
                 if (userId != curr->userId) {
                     snprintf(response, sizeof(response), "requestPendingFriends/unauthorized");
                     goto onfail;
                 }
                { // FRIEND REQUESTS
                    int size = PACKET_SIZE;
                    int offset = 0;
                    offset += snprintf(response+offset, size-offset, "newFriendRequest/");

                    char query[512] = {0};
                    snprintf(query, sizeof(query),
                        "SELECT u.userId, u.username, u.profileDesc "
                              "FROM users u "
                              "WHERE u.userId IN ("
                              "SELECT senderId FROM friend_requests "
                              "WHERE receiverId = %ld AND status = 'pending')", userId);

                    pthread_mutex_lock(&mysql_mutex);
                    if (mysql_query(conn, query) == 0) {
                        MYSQL_RES *res = mysql_store_result(conn);
                        if (res) {
                            MYSQL_ROW row;
                            char message[MAX_RESPONSE] = {0};
                            int messageOffset = 0;

                            while ((row = mysql_fetch_row(res))) {
                                if (messageOffset >= (int)sizeof(message) - 1) break;
                                int written = snprintf(message + messageOffset, sizeof(message) - messageOffset,
                                    "%s\x1F%s\x1F%s\x1E",   // userId, username, profileDesc
                                    row[0] ? row[0] : "0",
                                    row[1] ? row[1] : "0",
                                    row[2] ? row[2] : ""
                                );
                                if (written <= 0) break;
                                messageOffset += written < (int)sizeof(message) - messageOffset ? written : (int)sizeof(message) - messageOffset - 1;
                            }
                            mysql_free_result(res);

                if (offset < size - 1) {
                    int written = snprintf(response + offset, size - offset, "%s", message);
                    if (written > 0) offset += written < size - offset ? written : size - offset - 1;
                }
                        } else {
                            offset += snprintf(response+offset, size-offset, "0\x1E");
                        }
                    } else {
                        offset += snprintf(response+offset, size-offset, "0\x1E");
                    }
                    pthread_mutex_unlock(&mysql_mutex);
                    printf("[%s][GET CLIENT UPDATES] Sent friend request update for %ld: %s\n", buffer, userId, response);
                }
            }
            onfail:
            if (strlen(response) > 0) {
                sendPacket(sock, response, curr);
                printf(GREEN "[%s][ACCEPT MESSAGE][Thread %lu]" RESET " Responding for request (sock %d): %s -> %s\n", buffer, id, sock, fullMessage, response);
                memset(response, 0, PACKET_SIZE);
            }
            // shift the remainder following the current message to the beginning of recvBuf —
            // recvBuf was not modified during processing, so subsequent
            // messages in the queue remain intact regardless of what happened to fullMessage
                {
                    size_t processed = msgLen + 1; // +1 bc of '\n'
                    if (processed > (size_t)totalReceived) processed = (size_t)totalReceived;
                    memmove(recvBuf, recvBuf + processed, totalReceived - processed);
                    totalReceived -= (int)processed;
                    recvBuf[totalReceived] = '\0';
                }
        } // end of while (newlinePos) — parsing all messages accumulated in recvBuf
    }

    client_disconnect:
    unregisterClient(curr);
    free(curr);
    pthread_exit(NULL);
}

int main(void) {
    printf("\n");
    if (sodium_init() < 0) {
        fprintf(stderr, "[CRYPTO] sodium initialization failed\n");
        return 1;
    }
    const char *secret_b64 = getenv("SECURETTY_SERVER_SECRET_KEY");
    size_t secret_len = 0;
    if (secret_b64 && sodium_base642bin(serverPrivateKey, sizeof(serverPrivateKey), secret_b64,
                                        strlen(secret_b64), nullptr, &secret_len, nullptr,
                                        sodium_base64_VARIANT_ORIGINAL) == 0 &&
        secret_len == sizeof(serverPrivateKey)) {
        crypto_scalarmult_base(serverPublicKey, serverPrivateKey);
    } else {
        fprintf(stderr, "[CRYPTO] SECURETTY_SERVER_SECRET_KEY is required\n");
        return 1;
    }
    char public_b64[128] = {0};
    sodium_bin2base64(public_b64, sizeof(public_b64), serverPublicKey,
                      sizeof(serverPublicKey), sodium_base64_VARIANT_ORIGINAL);
    printf("[CRYPTO] Set SECURETTY_SERVER_PUBKEY=%s on clients\n", public_b64);
    // if we don't connect to database, chat probably won't work
    {
        time_t rawtime;
        struct tm *info;
        char buffer[80];
        time(&rawtime);
        info = localtime(&rawtime);
        strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", info);
        printf("[%s][MYSQL] Connecting ro mysql\n", buffer);
    }
    conn = mysql_init(nullptr);

    if (mysql_real_connect(conn, HOST, MYSQL_USER, MYSQL_PASSWORD, "securetty", 0, nullptr, 0) == NULL) {
    //if (mysql_real_connect(conn, "localhost", "root", "681137", "securetty", 0, nullptr, 0) == NULL) {
        time_t rawtime;
        struct tm *info;
        char buffer[80];
        time(&rawtime);
        info = localtime(&rawtime);
        strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", info);
        printf("[%s][MYSQL] Failed to connect to database: %s\n", buffer, mysql_error(conn));
        mysql_close(conn);
        return 0;
    }

    {
        time_t rawtime;
        struct tm *info;
        char buffer[80];
        time(&rawtime);
        info = localtime(&rawtime);
        strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", info);
        printf("[%s][MYSQL] Connected to database successfully\n", buffer);
    }

    // we also need to initialize tables
    const char *queries[] = {
        // users
        "CREATE TABLE IF NOT EXISTS users ("
            "userId BIGINT UNSIGNED NOT NULL PRIMARY KEY,"          // main column
            "username VARCHAR(24) NOT NULL,"
            "email VARCHAR(24) NOT NULL,"
            "passwordHash VARCHAR(256) NOT NULL,"
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
            time_t rawtime;
            struct tm *info;
            char buffer[80];
            time(&rawtime);
            info = localtime(&rawtime);
            strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", info);
            printf("[%s][MYSQL] Error creating table %d: %s\n", buffer, i, mysql_error(conn));
        } else {
            time_t rawtime;
            struct tm *info;
            char buffer[80];
            time(&rawtime);
            info = localtime(&rawtime);
            strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", info);
            printf("[%s][MYSQL] Table %d created successfully\n", buffer, i);
        }
    }

    int num_queries = sizeof(queries) / sizeof(queries[0]);

    for (int i = 0; i < num_queries; i++) {
        if (mysql_query(conn, queries[i])) {
            time_t rawtime;
            struct tm *info;
            char buffer[80];
            time(&rawtime);
            info = localtime(&rawtime);
            strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", info);
            printf("[%s][MYSQL] Error creating table %d: %s\n", buffer, i, mysql_error(conn));
        } else {
            time_t rawtime;
            struct tm *info;
            char buffer[80];
            time(&rawtime);
            info = localtime(&rawtime);
            strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", info);
            printf("[%s][MYSQL] Table %d created successfully\n", buffer, i);
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
    time_t rawtime;
    struct tm *info;
    char buffer[80];
    time(&rawtime);
    info = localtime(&rawtime);
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", info);
    printf("[%s][NETWORK] Server is listening on port %d\n", buffer, port);

    pthread_attr_init(&attr);
    size_t required_stack = 8 * 1024 * 1024;
    pthread_attr_setstacksize(&attr, required_stack);

    g_server_fd = server_fd;

    struct sigaction sa = {0};
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    while (!g_shutdown) {
        new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
        if (new_socket < 0) {
            if (g_shutdown) break;
            continue;
        }

        int* client_sock_ptr = malloc(sizeof(int));
        if (!client_sock_ptr) {
            close(new_socket);
            continue;
        }
        *client_sock_ptr = new_socket;

        if (pthread_create(&thread_id, &attr, acceptMessage, client_sock_ptr) == 0) {
            pthread_detach(thread_id);
        } else {
            close(new_socket);
            free(client_sock_ptr);
        }
    }

    // Cleanup
    pthread_mutex_lock(&clientsMutex);
    for (ClientSession *c = activeClients; c; c = c->next) {
        shutdown(c->sock, SHUT_RDWR);
    }
    pthread_mutex_unlock(&clientsMutex);
    usleep(200000);
    pthread_attr_destroy(&attr);
    close(new_socket);
    close(server_fd);
    printf("\nExiting.\n");
    return 0;
}
