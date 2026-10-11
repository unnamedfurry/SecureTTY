//
// Created by unnamedfurry on 8/30/26.
//

#include <stdio.h>
#include <string.h>
#include <sodium/crypto_pwhash.h>

// Shared variables and methods
#include "shared-variables.h"
extern bool sendPacket(int sock, const char *data, ClientSession *curr);
extern bool appendf(char *buf, size_t size, size_t *off, const char *fmt, ...);

// sending messages to an online client
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
        size_t offset = 0;
        appendf(response, size, &offset, "updateClient/messages/");

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
                        size_t written = 0;
                        appendf(response, size, &written,
                                               "%ld\x1F%d\x1E", sender, count);
                        if (written > 0) offset += written < size - offset ? written : size - offset - 1;
                    }
                }
                mysql_free_result(res);
            } else {
                appendf(response, size, &offset, "0\x1E");
            }
        } else {
            appendf(response, size, &offset,"0\x1E");
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
        size_t offset = 0;
        appendf(response, size, &offset, "updateClient/friendRequests\x1E");

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
                    size_t written = 0;
                    appendf(message, sizeof(message), &written,
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

                size_t tempOffset = 0;
                appendf(response, size, &tempOffset, "%s", message);
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
                appendf(response, size, &offset, "0\x1E");
            }
        } else {
            appendf(response, size, &offset, "0\x1E");
        }
        pthread_mutex_unlock(&mysql_mutex);
        sendPacket(sock, response, curr);
        printf("[%s][GET CLIENT UPDATES] Sent friend request update for %ld: %s\n", buffer, userId, response);
        free(response);
    }
}

void getChatHistory(long userId, long friendId, int sock, int offset, ClientSession *curr) {
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
    size_t written = 0;

    char query[512] = {0};
    snprintf(query, sizeof(query),
        "SELECT messageId, senderId, message, sentAt "
        "FROM messages "
        "WHERE (senderId = %ld AND receiverId = %ld) "
           "OR (senderId = %ld AND receiverId = %ld) "
        "ORDER BY sentAt ASC LIMIT 101 OFFSET %d",
        userId, friendId, friendId, userId, offset);

    pthread_mutex_lock(&mysql_mutex);
    if (mysql_query(conn, query)) {
        snprintf(response, 23, "getChatHistory/error");
        sendPacket(sock, response, curr);
        free(response);
        pthread_mutex_unlock(&mysql_mutex);
        return;
    }

    MYSQL_RES *res = mysql_store_result(conn);
    size_t rows = mysql_num_rows(res);
    appendf(response, bufSize, &written, "getChatHistory/%ld%s\x1E", friendId, (rows > 100 ? "true_" : "false"));
    if (!res) {
        snprintf(response, 23, "getChatHistory/empty\x1E%ld", friendId);
        sendPacket(sock, response, curr);
        free(response);
        pthread_mutex_unlock(&mysql_mutex);
        return;
    }

    MYSQL_ROW row;
    int messageCounter = 0;
    while (((row = mysql_fetch_row(res))) && messageCounter < rows) {
        size_t needed = strlen(row[2] ? row[2] : "null") + 64;
        if (written + needed >= (size_t)bufSize) {
            while (written + needed >= (size_t)bufSize) bufSize += BUFFER_SIZE;
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

        appendf(response, bufSize, &written,
            "%ld\x1F%ld\x1F%s\x1E",
            msgId, sender, text);
        messageCounter++;
    }

    mysql_free_result(res);
    pthread_mutex_unlock(&mysql_mutex);

    if (written > 32) {
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
    if (strlen(username) > MAX_NAME || strlen(email) > MAX_EMAIL || strlen(password) > MAX_PASS || strlen(avatarUrl) > MAX_AVATAR || strlen(profileDesc) > MAX_DESC) return false;
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
    size_t written = 0;
    appendf(query, sizeof(query), &written,
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
        "VALUES (%ld, %ld, %ld, '%s') ",
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
