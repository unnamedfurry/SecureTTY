//
// Created by unnamedfurry on 8/30/26.
//

#include <libgen.h>
#include <mysql.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/utils.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/statvfs.h>

// Shared variables and methods
#include <errno.h>
#include <netinet/in.h>

#include "shared-variables.h"
extern void registerClient(long userId, int sock);
extern void unregisterClient(ClientSession *curr);
extern bool DecryptPacket(unsigned char serverSessionKey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES], const char* input, char* out_plain, size_t max_size);
extern bool DecryptBinary(unsigned char serverSessionKey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES], const unsigned char* input, size_t in_len, unsigned char* out_plain, size_t max_out_size, size_t* out_len);
extern bool EncryptPacket(ClientSession *session, const char* plaintext, char* out_buffer, size_t max_size);
extern bool sendPacket(int sock, const char *data, ClientSession *curr);
extern char* Base64Encode(const unsigned char* input, int length);
extern unsigned char* Base64Decode(const char* input, int* out_len);
extern bool appendf(char *buf, size_t size, size_t *off, const char *fmt, ...);
extern void get_blake3_hash(const char *input, size_t input_len, uint8_t output[BLAKE3_OUT_LEN]);
extern void bytes_to_hex_string(const uint8_t *hash_bytes, char *output_buffer);
extern void removeUpload(FileUpload *target, const char *files_dir, bool deleteUnfinished);

// Client actions
extern bool pushToUser(long userId, const char *data, ClientSession *curr);
extern void getClientUpdates(long userId, int sock, ClientSession *curr);
extern void getChatHistory(long userId, long friendId, int sock, int offset, ClientSession *curr);
extern long registerUserInDB(const char *username, const char *email, const char *password);
extern bool updateProfileInDB(long userId, const char *avatarUrl, const char *profileDesc);
extern long saveMessageToDB(long senderId, long receiverId, const char *message);
extern char* getUserFromDB(long userId);
extern bool sendFriendRequest(long senderId, long receiverId);
extern bool acceptFriendRequest(long receiverId, long senderId);

int processBinary(ClientSession *currC, FileUpload *currF, int sock, char time_formatted[80], char recvBuf[PACKET_SIZE], char fullMessage[PACKET_SIZE], uint32_t n, unsigned char serverSessionKey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES], long currentUserId);
void* acceptMessage(void *arg) {
    int sock = *(int*)arg;
    free(arg);
    // Network buffers
    char response[PACKET_SIZE] = {0};
    char localBuf[BUFFER_SIZE];
    char recvBuf[PACKET_SIZE] = {0};   // raw storage from the socket — read/shift only; never parse directly.
    char fullMessage[PACKET_SIZE] = {0}; // working copy of a SINGLE message — it is safe to perform decrypt and strtok on it
    int totalReceived = 0;
    pthread_t id = pthread_self();
    ClientSession *currC = nullptr;
    FileUpload *currF = nullptr;

    // Network listener
    while (1) {
        // Reading
        memset(localBuf, 0, sizeof(localBuf));
        int bytes = read(sock, localBuf, sizeof(localBuf) - 1);
        time_t rawtime;
        struct tm *info;
        char time_formatted[80];
        time(&rawtime);
        info = localtime(&rawtime);
        strftime(time_formatted, 80, "%Y-%m-%d %H:%M:%S", info);

        // Validating syntax
        if (bytes <= 0) {
            printf(GREEN "[%s][ACCEPT MESSAGE][Thread %lu]" RESET " Client disconnected (sock %d)\n", time_formatted, id, sock);
            goto client_disconnect;
        }

        if (totalReceived + bytes > (int)sizeof(recvBuf) - 1) {
            printf(RED "[ACCEPT MESSAGE] Incoming data exceeds PACKET_SIZE, dropping buffered data (sock %d)\n" RESET, sock);
            totalReceived = 0;
        }

        // Appending to main buffer
        memcpy(recvBuf + totalReceived, localBuf, bytes);
        totalReceived += bytes;
        recvBuf[totalReceived] = '\0';

        if (totalReceived >= 8 && strncmp(recvBuf+4, "bnc:", 4) == 0) {
            unsigned char serverSessionKey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
            long currentUserId = 0;
            {
                // Finding and assigning current client
                pthread_mutex_lock(&clientsMutex);
                ClientSession *curr2 = activeClients;
                while (curr2) {
                    if (curr2->sock == sock) {
                        currC = curr2;
                        currentUserId = curr2->userId;
                        memcpy(serverSessionKey, curr2->serverSessionKey, sizeof(curr2->serverSessionKey));
                    }
                    curr2 = curr2->next;
                }
                pthread_mutex_unlock(&clientsMutex);
            }
            {
                // Finding and assigning current file upload
                pthread_mutex_lock(&filesMutex);
                FileUpload *curr2 = activeUploads;
                while (curr2) {
                    if (curr2->userId > 0 && curr2->userId == currentUserId) {
                        currF = curr2;
                    }
                    curr2 = curr2->next;
                }
                pthread_mutex_unlock(&filesMutex);
            }

            uint32_t n = 0;
            memcpy(&n, recvBuf, 4);
            n = ntohl(n);
            if (totalReceived < 4+n) continue; // not enough data yet
            bool deleteFile = false;

            int code = processBinary(currC, currF, sock, time_formatted, recvBuf+4, fullMessage, n, serverSessionKey, currentUserId);
            switch (code) {

                case 0:
                    memset(recvBuf, 0, PACKET_SIZE);
                    memset(localBuf, 0, BUFFER_SIZE);
                    memset(fullMessage, 0, PACKET_SIZE);
                    totalReceived = 0;
                    snprintf(response, sizeof(response), "uploadFile/continue");
                    goto next_message;

                case -1:
                    memset(recvBuf, 0, PACKET_SIZE);
                    memset(localBuf, 0, BUFFER_SIZE);
                    memset(fullMessage, 0, PACKET_SIZE);
                    totalReceived = 0;
                    snprintf(response, sizeof(response), "uploadFile/error/bad-packet-math");
                    break;

                case -2:
                    memset(recvBuf, 0, PACKET_SIZE);
                    memset(localBuf, 0, BUFFER_SIZE);
                    memset(fullMessage, 0, PACKET_SIZE);
                    totalReceived = 0;
                    snprintf(response, sizeof(response), "uploadFile/error/bad-file-math");
                    break;

                case -3:
                    memset(recvBuf, 0, PACKET_SIZE);
                    memset(localBuf, 0, BUFFER_SIZE);
                    memset(fullMessage, 0, PACKET_SIZE);
                    totalReceived = 0;
                    snprintf(response, sizeof(response), "uploadFile/error/open-path");
                    break;

                case -4:
                    memset(recvBuf, 0, PACKET_SIZE);
                    memset(localBuf, 0, BUFFER_SIZE);
                    memset(fullMessage, 0, PACKET_SIZE);
                    totalReceived = 0;
                    snprintf(response, sizeof(response), "uploadFile/error/write-data");
                    deleteFile=true;
                    break;

                case -5:
                    memset(recvBuf, 0, PACKET_SIZE);
                    memset(localBuf, 0, BUFFER_SIZE);
                    memset(fullMessage, 0, PACKET_SIZE);
                    totalReceived = 0;
                    snprintf(response, sizeof(response), "uploadFile/error/close-file");
                    deleteFile=true;
                    break;

                case -6:
                    memset(recvBuf, 0, PACKET_SIZE);
                    memset(localBuf, 0, BUFFER_SIZE);
                    memset(fullMessage, 0, PACKET_SIZE);
                    totalReceived = 0;
                    snprintf(response, sizeof(response), "uploadFile/error/decryption-failed");
                    break;

                case -7:
                    memset(recvBuf, 0, PACKET_SIZE);
                    memset(localBuf, 0, BUFFER_SIZE);
                    memset(fullMessage, 0, PACKET_SIZE);
                    totalReceived = 0;
                    snprintf(response, sizeof(response), "uploadFile/error/unauthorized");
                    break;
            }
            removeUpload(currF, currF->path, deleteFile);
            next_message:
            sendPacket(sock, response, currC);
            printf(GREEN "[%s][ACCEPT MESSAGE][Thread %lu]" RESET " Responding for request (sock %d): %s -> %s\n", time_formatted, id, sock, fullMessage, response);
            memset(response, 0, PACKET_SIZE);
            continue;
        }

        // multiple newline-separated messages might arrive in a single read() —
        // parse everything that has accumulated in recvBuf, not just the first one
        char *newlinePos;
        while ((newlinePos = memchr(recvBuf, '\x1D', totalReceived)) != NULL) {
            currC = nullptr;
            currF = nullptr;

            // Checking for overload
            size_t msgLen = (size_t)(newlinePos - recvBuf);
            if (msgLen >= sizeof(fullMessage)) msgLen = sizeof(fullMessage) - 1;

            // Copy the message to a separate working buffer: recvBuf remains
            // untouched, and subsequent messages in the queue are safe
            // regardless of what decrypt/strtok do to fullMessage.
            memcpy(fullMessage, recvBuf, msgLen);
            fullMessage[msgLen] = '\0';
            unsigned char serverSessionKey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
            long currentUserId = 0;
            {
                // Finding and assigning current client
                pthread_mutex_lock(&clientsMutex);
                ClientSession *curr2 = activeClients;
                while (curr2) {
                    if (curr2->sock == sock) {
                        currC = curr2;
                        currentUserId = curr2->userId;
                        memcpy(serverSessionKey, curr2->serverSessionKey, sizeof(curr2->serverSessionKey));
                    }
                    curr2 = curr2->next;
                }
                pthread_mutex_unlock(&clientsMutex);
            }
            {
                // Finding and assigning current file upload
                pthread_mutex_lock(&filesMutex);
                FileUpload *curr2 = activeUploads;
                while (curr2) {
                    if (curr2->userId > 0 && curr2->userId == currentUserId) {
                        currF = curr2;
                    }
                    curr2 = curr2->next;
                }
                pthread_mutex_unlock(&filesMutex);
            }



            //
            //      CREATE ID, TEST, CRYPTO AND LOGIN COMMANDS
            //


            // The only 3 things that should be available
            // to user at any cost

            // Key exchanging
            if (strncmp(fullMessage, "keyexchange/", 12) == 0) {
                char *clientPubB64 = fullMessage + 12;

                unsigned char clientPubKey[crypto_box_PUBLICKEYBYTES] = {0};
                size_t decoded_len = 0;

                // Converting text to binary
                // and validating key
                if (sodium_base642bin(clientPubKey, sizeof(clientPubKey), clientPubB64,
                    strlen(clientPubB64), nullptr, &decoded_len, nullptr,
                    sodium_base64_VARIANT_ORIGINAL) != 0 ||
                    decoded_len != crypto_box_PUBLICKEYBYTES) {
                        printf("[CRYPTO] Bad public key from client\n");
                        snprintf(response, sizeof(response), "keyexchange/error");
                        goto nextMessage;
                }

                // Assigning key to current user
                //unsigned char *serverPub = serverPublicKey;
                //unsigned char *serverPriv = serverPrivateKey;
                unsigned char serverPub[crypto_box_PUBLICKEYBYTES] = {0};
                unsigned char serverPriv[crypto_box_SECRETKEYBYTES] = {0};
                crypto_box_keypair(serverPub, serverPriv);
                if (!currC) {

                    // Checking for space
                    currC = calloc(1, sizeof(ClientSession));
                    if (!currC) { snprintf(response, sizeof(response), "keyexchange/error"); goto nextMessage; }

                    // Creating new user
                    currC->userId = 0;               // not authenticated yet
                    currC->sock = sock;
                    currC->hasSessionKey = false;
                    currC->loggedIn = false;
                    currC->closing = false;
                    pthread_mutex_lock(&clientsMutex);
                    currC->next = activeClients;
                    activeClients = currC;
                    pthread_mutex_unlock(&clientsMutex);
                }

                // Creating a pair of keys
                if (crypto_box_beforenm(currC->serverSessionKey, clientPubKey, serverPriv) == 0) {
                    printf("[CRYPTO] Server session key: %p\n", (void*)currC->serverSessionKey);

                    // Sending keys to client
                    char pub_b64[128] = {0};
                    sodium_bin2base64(pub_b64, sizeof(pub_b64), serverPub, crypto_box_PUBLICKEYBYTES, sodium_base64_VARIANT_ORIGINAL);
                    snprintf(response, sizeof(response), "keyexchange/myturn/%s", pub_b64);

                    goto nextMessage;
                } else {
                    printf(RED "[CRYPTO] crypto_box_beforenm failed on server\n" RESET);
                }
            }

            // Decrypting packet
            if (!currC) goto nextMessage;
            char decrypted[PACKET_SIZE] = {0};
            bool decryptedState = false;
            if (DecryptPacket(serverSessionKey, fullMessage, decrypted, sizeof(decrypted))) {

                // fullMessage is already an isolated copy of a single message
                // (we leave recvBuf and the queue of remaining messages untouched),
                // so we simply copy the decrypted text without using strncpy —
                // that would unnecessarily zero out PACKET_SIZE bytes for every message
                size_t dlen = strlen(decrypted);
                if (dlen >= sizeof(fullMessage)) dlen = sizeof(fullMessage) - 1;
                memcpy(fullMessage, decrypted, dlen);
                fullMessage[dlen] = '\0';
                decryptedState = true;
                currC->hasSessionKey=true;
            }

            printf(GREEN "[%s][ACCEPT MESSAGE][Thread %lu]" RESET " Client said (full message, %zu bytes): %s\n", time_formatted, id, msgLen, fullMessage);

            if (strncmp(fullMessage, "register/", 9) == 0 && !currC->loggedIn) {
                // Splitting login data
                char *parts[3] = {0};
                int count = 0;
                char *token = strtok(fullMessage + 9, "\x1E");
                while (token && count < 3) {
                    parts[count++] = token;
                    token = strtok(nullptr, "\x1E");
                }

                // Validating syntax
                if (count != 3 || strlen(parts[1]) > MAX_EMAIL || strlen(parts[0]) > MAX_NAME || strlen(parts[2]) > MAX_PASS) {
                    printf("[%s][LOGIN] Not enough parameters for login\n", time_formatted);
                    goto nextMessage;
                }

                long newId = registerUserInDB(parts[0], parts[1], parts[2]);
                if (newId == -1) {
                    snprintf(response, sizeof(response), "register/error");
                    goto nextMessage;
                } else if (newId == 0) {
                    snprintf(response, sizeof(response), "register/taken");
                    goto nextMessage;
                    // should we notify about email already used by another person?
                } else if (newId > 0) {
                    snprintf(response, sizeof(response), "register/%ld", newId);
                    registerClient(newId, sock);
                    currC->loggedIn=true;
                    printf("[%s][REGISTER CLIENT] User %ld\n authorized successfully\n", time_formatted, newId);
                    goto nextMessage;
                }
            }
            else if (strncmp(fullMessage, "login/", 6) == 0 && !currC->loggedIn) {

                // Splitting login data
                char *parts[4] = {0};
                int count = 0;
                char *token = strtok(fullMessage + 6, "\x1E");
                while (token && count < 4) {
                    parts[count++] = token;
                    token = strtok(nullptr, "\x1E");
                }

                // Validating syntax
                if (count != 4 || strlen(parts[1]) > MAX_EMAIL || strlen(parts[3]) > MAX_NAME || strlen(parts[2]) > MAX_PASS) {
                    printf("[%s][LOGIN] Not enough parameters for login\n", time_formatted);
                    goto nextMessage;
                }

                // Screening sensitive data
                long userId = strtol(parts[0], nullptr, 10);
                char esc_email[MAX_EMAIL*2 + 10] = {0};
                char esc_name[MAX_NAME*2 + 10] = {0};
                char password[crypto_pwhash_STRBYTES+10] = {0};
                pthread_mutex_lock(&mysql_mutex);
                mysql_real_escape_string(conn, esc_email,    parts[1],    strlen(parts[1]));
                mysql_real_escape_string(conn, esc_name,     parts[3],    strlen(parts[3]));
                char query[512];
                snprintf(query, 512, "SELECT passwordHash FROM users WHERE userId = %ld AND email = '%s' AND username = '%s' LIMIT 1", userId, esc_email, esc_name);

                // Fetching table with query
                if (mysql_query(conn, query)) {
                    printf("[%s][LOGIN CLIENT] Query Error: %s\n", time_formatted, mysql_error(conn));
                    pthread_mutex_unlock(&mysql_mutex);
                    unregisterClient(currC);
                    goto client_disconnect;
                }
                MYSQL_RES *result = mysql_store_result(conn);
                if (result == NULL) {
                    mysql_free_result(result);
                    pthread_mutex_unlock(&mysql_mutex);
                    unregisterClient(currC);
                    goto client_disconnect;
                }

                // Getting password from result
                MYSQL_ROW row = mysql_fetch_row(result);
                if (row != NULL && row[0] != NULL) {
                    strncpy(password, row[0], sizeof(password) - 1);
                } else {
                    // Closing connection
                    printf("[%s][LOGIN CLIENT] No matching user found.\n", time_formatted);
                    mysql_free_result(result);
                    pthread_mutex_unlock(&mysql_mutex);
                    unregisterClient(currC);
                    goto client_disconnect;
                }
                mysql_free_result(result);
                pthread_mutex_unlock(&mysql_mutex);

                // Comparing passwords
                bool ok = false;
                if (strlen(password) > 0) ok = crypto_pwhash_str_verify(password, parts[2], strlen(parts[2])) == 0;

                printf("[%s][LOGIN CLIENT] Received for client/user %ld\n", time_formatted, userId);
                if (userId > 0 && ok == true) {

                    // Authorizing client
                    registerClient(userId, sock);
                    currC->loggedIn=true;
                    printf("[%s][LOGIN CLIENT] User %ld\n authorized successfully\n", time_formatted, userId);
                    snprintf(response, sizeof(response), "login/ok");
                } else {

                    // Closing connection
                    printf("[%s][LOGIN CLIENT] User %ld\n failed to authorize: incorrect data\n", time_formatted, userId);
                    snprintf(response, sizeof(response), "login/error");
                    unregisterClient(currC);
                    goto client_disconnect;
                }
            }


            //
            //        REGULAR MESSAGES BLOCK
            //


            // Checking for secured channel
            if (currC->loggedIn==false || currC->hasSessionKey==false || decryptedState==false) {
                printf(RED "[%s][RECEIVE MESSAGE]" RESET " %d attempted unauthorized action\n", time_formatted, sock);
                goto nextMessage;
            }

            if (strncmp(fullMessage, "receive-message/", 16) == 0) {
                printf("[%s][RECEIVE MESSAGE] Saving message: %s\n", time_formatted, fullMessage);

                // Splitting message data
                char *parts[3] = {0};
                int count = 0;
                char *token = strtok(fullMessage + 16, "\x1E");
                while (token && count < 3) {
                    parts[count++] = token;
                    token = strtok(nullptr, "\x1E");
                }

                // Validating syntax
                if (count != 3 || parts[2] == nullptr) {
                    snprintf(response, sizeof(response), "receive-message/badformat");
                    goto nextMessage;
                }

                // Assigning to temp variables
                // Creating an id for a new message

                long senderId = strtol(parts[0], nullptr, 10);
                long receiverId = strtol(parts[1], nullptr, 10);

                // Checking for authorization
                if (senderId != currC->userId || receiverId <= 0) {
                    snprintf(response, sizeof(response), "receive-message/unauthorized");
                    goto nextMessage;
                }

                // Saving message
                long messageId = saveMessageToDB(senderId, receiverId, parts[2]);
                if (messageId != -1) {

                    // Sending message to receiver
                    printf("[%s][RECEIVE MESSAGE] Message saved: %ld -> %ld\n", time_formatted, senderId, receiverId);
                    char pushPacket[BUFFER_SIZE];
                    snprintf(pushPacket, sizeof(pushPacket), "newMessage\x1E%ld\x1F%ld\x1F%s\x1F%s\n", messageId, senderId, parts[2], "now");
                    snprintf(response, sizeof(response), "createId/message/%ld", messageId);

                    if (!pushToUser(receiverId, pushPacket, currC)) {
                        printf("[%s][RECEIVE MESSAGE] Receiver %ld is offline, message will be saved to DB\n", time_formatted, receiverId);
                    }
                } else {
                    printf("[%s][RECEIVE MESSAGE] Failed to save message to db: %ld, %ld\n", time_formatted, senderId, messageId);
                    snprintf(response, sizeof(response), "receive-message/error");
                }
            }
            else if (strncmp(fullMessage, "save-profile/", 13) == 0) {

                // Splitting profile data
                char *parts[3] = {0};
                int count = 0;
                char *token = strtok(fullMessage + 13, "\x1E");

                while (token && count < 3) {
                    parts[count++] = token;
                    token = strtok(nullptr, "\x1E");
                }

                // Validating syntax
                if (count >= 3) {

                    // Checking for authorization
                    long uid = strtol(parts[0], nullptr, 10);
                    if (uid != currC->userId || !currC->loggedIn) {
                        snprintf(response, sizeof(response), "save-profile/unauthorized");
                        goto nextMessage;
                    }

                    // Saving profile
                    printf("[%s][SAVE PROFILE] received for %ld\n", time_formatted, uid);
                    bool success = updateProfileInDB(uid, parts[1], parts[2]);

                    if (success) {
                        snprintf(response, sizeof(response), "save-profile/ok/");
                    } else {

                        // Reporting error to client
                        snprintf(response, sizeof(response), "save-profile/error/");
                        char *profile = getUserFromDB(uid);
                        if (profile) {
                            snprintf(response+19, sizeof(response)-19, "%s", profile);
                            free(profile);
                        }
                    }
                } else {

                    // Reporting error to client
                    snprintf(response, sizeof(response), "save-profile/badformat/");
                    if (parts[0] == nullptr) goto nextMessage;

                    long uid = strtol(parts[0], nullptr, 10);
                    if (uid == currC->userId) {
                        char *profile = getUserFromDB(uid);
                        if (profile) {
                            snprintf(response+23, sizeof(response)-24, "%s", profile);
                            free(profile);
                        }
                    }
                }
            }
            else if (strncmp(fullMessage, "getFriendsList/", 15) == 0) {

                // Checking for authorization
                long userId = strtol(fullMessage + 15, nullptr, 10);
                if (userId != currC->userId) { snprintf(response, sizeof(response), "getFriendsList/unauthorized"); goto nextMessage; }
                if (userId <= 0) goto nextMessage;
                size_t offset = 0;
                appendf(response, sizeof(response), &offset, "getFriendsList/");

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
                            appendf(response, sizeof(response), &offset,
                                "%s\x1F%ld\x1F%s\x1F%s\x1E",
                                row[0],                                        // username
                                strtol(row[1], nullptr, 10),        // friend_id
                                row[2] ? row[2] : "",                          // avatarUrl
                                row[3] ? row[3] : "");                         // profileDesc
                        }
                        mysql_free_result(res);
                    }
                }
                pthread_mutex_unlock(&mysql_mutex);

                // sending result
                if (offset > 15) {
                    // if there is atleast one friend

                    printf("[%s][GET FRIENDS LIST] Sent for %ld\n", time_formatted, userId);
                } else {
                    snprintf(response, sizeof(response), "getFriendsList/empty");
                }
            }
            else if (strncmp(fullMessage, "addFriend/", 10) == 0) {

                // Splitting friend data
                char *parts[2] = {0};
                int count = 0;
                char *token = strtok(fullMessage + 10, "\x1E");
                while (token && count < 2) {
                    parts[count++] = token;
                    token = strtok(nullptr, "\x1E");
                }

                // Validating syntax
                if (count == 2) {

                    // Checking for authorization
                    long senderId = strtol(parts[0], nullptr, 10);
                    long receiverId = strtol(parts[1], nullptr, 10);
                    if (senderId != currC->userId) { snprintf(response, sizeof(response), "addFriend/unauthorized"); goto nextMessage; }
                    printf("[%s][ADD FRIEND] received for %ld -> %ld\n", time_formatted, senderId, receiverId);

                    // Validating ids
                    if (senderId > 0 && receiverId > 0 && senderId != receiverId) {

                        // Attempting request save
                        if (sendFriendRequest(senderId, receiverId)) {

                            // Pushing update request to receiver
                            pushToUser(receiverId, "requestPendingFriends/", currC);
                            printf("[%s][ADD FRIEND] Sent successfully %ld -> %ld\n", time_formatted, senderId, receiverId);
                        } else {

                            // Reporting error to sender
                            printf("[%s][ADD FRIEND] Failed to save request\n", time_formatted);
                            strncpy(response, "addFriend/error", 16);
                        }
                    } else {

                        // Reporting error to sender
                        printf("[%s][ADD FRIEND] Bad ID\n", time_formatted);
                        strncpy(response, "addFriend/error", 16);
                    }
                } else {

                    // Reporting error to sender
                    printf("[%s][ADD FRIEND] Bad format, got %d/2 parts\n", time_formatted, count);
                    strncpy(response, "addFriend/badformat", 20);
                }
            }
            else if (strncmp(fullMessage, "acceptFriend/", 13) == 0) {

                // Splitting user data
                char *parts[2] = {0};
                int count = 0;
                char *token = strtok(fullMessage + 13, "\x1E");
                while (token && count < 2) {
                    parts[count++] = token;
                    token = strtok(nullptr, "\x1E");
                }

                // Validating syntax
                if (count == 2) {

                    // Checking for authorization
                    long receiverId = strtol(parts[0], nullptr, 10);
                    long senderId   = strtol(parts[1], nullptr, 10);
                    if (receiverId != currC->userId) { snprintf(response, sizeof(response), "acceptFriend/unauthorized"); goto nextMessage; }

                    if (acceptFriendRequest(receiverId, senderId)) {
                        // updating both clients
                        pushToUser(senderId, "requestFriendUpdate/", currC);
                        pushToUser(receiverId, "requestFriendUpdate/", currC);
                    } else {
                        snprintf(response, sizeof(response), "acceptFriend/error");
                    }
                } else {
                    snprintf(response, sizeof(response), "acceptFriend/badformat");
                }
            }
            else if (strncmp(fullMessage, "updateClient/", 13) == 0) {

                // Getting updates
                long userId = strtol(fullMessage + 13, nullptr, 10);
                printf("[%s][UPDATE CLIENT] Received for client/user %ld\n", time_formatted, userId);
                if (userId == currC->userId) {
                    getClientUpdates(userId, sock, currC);
                } else {
                    snprintf(response, sizeof(response), "updateClient/unauthorized");
                }
            }
            else if (strncmp(fullMessage, "getChatHistory/", 15) == 0) {

                // Splitting user data
                char *parts[3] = {0};
                int count = 0;
                char *token = strtok(fullMessage + 15, "\x1E");
                while (token && count < 3) {
                    parts[count++] = token;
                    token = strtok(nullptr, "\x1E");
                }

                // Validating syntax
                if (count == 3) {
                    long userId = strtol(parts[0], nullptr, 10);
                    long friendId = strtol(parts[1], nullptr, 10);
                    int offset = atoi(parts[2]);
                    printf("[%s][GET CHAT HISTORY] Received history request from %ld with %ld\n", time_formatted, userId, friendId);

                    if (userId == currC->userId && friendId > 0) {
                        getChatHistory(userId, friendId, sock, offset, currC);
                    }
                }
            }
            else if (strncmp(fullMessage, "getAvatar/", 10) == 0) {

                // Validating syntax
                long uid = strtol(fullMessage + 10, nullptr, 10);
                if (uid <= 0) { snprintf(response, sizeof(response), "getAvatar/badformat"); goto nextMessage; }
                printf("[%s][GET AVATAR] requested %ld's avatar\n", time_formatted, uid);

                // Getting current folder
                char self_path[PATH_MAX] = {0};
                char avatars_subdir[PATH_MAX] = {0};
                ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path)-1);
                if (len > 0) {
                    self_path[len] = '\0';
                    snprintf(avatars_subdir, sizeof(avatars_subdir), "%s/avatars", dirname(self_path));
                } else {
                    strcpy(avatars_subdir, "avatars");
                }
                // Creating a folder if does not exist
                mkdir(avatars_subdir, 0755);
                char filepath[PATH_MAX];
                snprintf(filepath, sizeof(filepath), "%s/%ld.png", avatars_subdir, uid);

                // Opening file
                FILE *f = fopen(filepath, "rb");
                if (f) {

                    // Validating sizes
                    fseek(f, 0, SEEK_END);
                    long fileSize = ftell(f);
                    fseek(f, 0, SEEK_SET);

                    if (fileSize <= 0 || fileSize > MAX_AVATAR_FILE_SIZE) {
                        fclose(f);
                        snprintf(response, sizeof(response), "getAvatar/error");
                        goto nextMessage;
                    }

                    // Reading data
                    unsigned char *pngData = malloc(fileSize * sizeof(unsigned char));
                    if (!pngData) {
                        fclose(f);
                        snprintf(response, sizeof(response), "getAvatar/error");
                        goto nextMessage;
                    }
                    memset(pngData, 0, (size_t)fileSize);
                    fread(pngData, 1, fileSize, f);
                    fclose(f);

                    // Encoding data
                    char *b64 = Base64Encode(pngData, (int)fileSize);
                    free(pngData);

                    if (b64) {

                        // Sending packet
                        snprintf(response, PACKET_SIZE, "getAvatarResponse/%ld\x1E%s", uid, b64);
                        free(b64);
                        printf("[%s][GET AVATAR] sent avatar for %ld (%ld bytes)\n", time_formatted, uid, fileSize);
                    }
                } else {
                    // Sending null
                    snprintf(response, sizeof(response), "getAvatarResponse/%ld\x1E", uid);
                    printf("[%s][GET AVATAR] %ld's avatar not found\n", time_formatted,uid);
                }
            }
            else if (strncmp(fullMessage, "saveAvatar/", 11) == 0) {

                char *ptr = fullMessage + 11;
                long userId = strtol(ptr, &ptr, 10);

                // Checking for authorization
                if (userId != currC->userId || *ptr != '\x1E') {
                    printf("[%s][SAVE AVATAR] Parse error: invalid userId or missing separator\n", time_formatted);
                    printf("[%s][SAVE AVATAR] Received: %.100s...\n", time_formatted, fullMessage);
                    snprintf(response, sizeof(response), "saveAvatar/unauthorized");
                    goto nextMessage;
                }

                char *b64_data = ptr + 1; // base64 start
                if (strlen(b64_data) < 100) {
                    printf("[%s][SAVE AVATAR] Base64 data too short (%zu chars)\n", time_formatted, strlen(b64_data));
                }

                // Decoding text
                int decoded_len = 0;
                unsigned char* png_data = Base64Decode(b64_data, &decoded_len);

                if (!png_data || decoded_len < 500 || decoded_len > MAX_AVATAR_FILE_SIZE ||
                    memcmp(png_data, "\x89PNG\r\n\x1a\n", 8) != 0) {

                    free(png_data);
                    snprintf(response, sizeof(response), "saveAvatar/error");
                    printf("[%s][SAVE AVATAR] Decode failed or image too small (%d bytes)\n", time_formatted, decoded_len);
                    goto nextMessage;
                }

                // Getting current path
                char binary_path[PATH_MAX] = {0};
                char avatars_dir[PATH_MAX] = {0};
                ssize_t len = readlink("/proc/self/exe", binary_path, sizeof(binary_path)-1);
                if (len > 0) {
                    binary_path[len] = '\0';
                    snprintf(avatars_dir, sizeof(avatars_dir), "%s/avatars", dirname(binary_path));
                } else {
                    strcpy(avatars_dir, "avatars");
                }

                // Creating folder ...
                mkdir(avatars_dir, 0755);
                char filepath[PATH_MAX];
                snprintf(filepath, sizeof(filepath), "%s/%ld.png", avatars_dir, userId);

                // ... and file
                FILE *f = fopen(filepath, "wb");
                if (f) {
                    size_t written = fwrite(png_data, 1, decoded_len, f);
                    fclose(f);

                    // Validating format
                    if (written == (size_t)decoded_len) {
                        if (decoded_len > 8 &&
                            png_data[0] == 0x89 && png_data[1] == 'P' &&
                            png_data[2] == 'N' && png_data[3] == 'G') {

                            printf("[%s][SAVE AVATAR] Good PNG signature, saved %ld's avatar successfully (%d bytes)\n", time_formatted, userId, decoded_len);
                        } else {
                            printf("[%s][SAVE AVATAR] Bad PNG signature, saved possibly corrupted %ld's avatar\n" RESET, time_formatted, userId);
                        }
                    } else {
                        printf("[%s][SAVE AVATAR] Write error: only %zu of %d bytes written\n", time_formatted, written, decoded_len);
                    }
                } else {
                    printf("[%s][SAVE AVATAR] fopen failed: %s", time_formatted, filepath);
                }

                free(png_data);
            }
            else if (strncmp(fullMessage, "requestPendingFriends/", 22) == 0) {

                // Checking for authorization
                char *ptr = fullMessage + 22;
                long userId = strtol(ptr, &ptr, 10);
                if (userId != currC->userId) {
                    snprintf(response, sizeof(response), "requestPendingFriends/unauthorized");
                    goto nextMessage;
                }

                // FRIEND REQUESTS
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
                                "%s\x1F%s\x1F%s\x1E",
                                row[0] ? row[0] : "0",     // userId
                                row[1] ? row[1] : "0",     // userName
                                row[2] ? row[2] : ""       // profileDesc
                                );
                            if (written <= 0) break;
                            messageOffset += written < (int)sizeof(message) - messageOffset ? written : (int)sizeof(message) - messageOffset - 1;
                        }
                        mysql_free_result(res);

                        // Checking sizes and appending offsets
                        if (offset < size - 1) {
                            int written = snprintf(response + offset, size - offset, "%s", message);
                            if (written > 0) offset += written < size - offset ? written : size - offset - 1;
                        }
                    } else {
                        // No requests
                        offset += snprintf(response+offset, size-offset, "0\x1E");
                    }
                } else {
                    // No frienda
                    offset += snprintf(response+offset, size-offset, "0\x1E");
                }
                pthread_mutex_unlock(&mysql_mutex);
                printf("[%s][GET CLIENT UPDATES] Sent friend request update for %ld: %s\n", time_formatted, userId, response);
            } else if (strncmp(fullMessage, "check-space/", 12) == 0) {

                // Initializing file upload
                if (!currF) {

                    // Checking for space
                    currF = calloc(1, sizeof(FileUpload));
                    if (!currF) { snprintf(response, sizeof(response), "check-space/error"); goto nextMessage; }

                    // Creating new file
                    pthread_mutex_lock(&filesMutex);
                    currF->userId = currentUserId;
                    currF->next = activeUploads;
                    activeUploads = currF;
                    pthread_mutex_unlock(&filesMutex);
                }

                const char *p = fullMessage + 12;
                char *end;
                errno = 0;
                // Validating received size format
                unsigned long long req = (*p >= '0' && *p <= '9') ? strtoull(p, &end, 10) : 0;
                bool ok = false;
                struct statvfs st;
                // Checking for avail space
                if (req > 0 && req <= MAX_FILE_SIZE && !errno && *end == '\0' && statvfs(".", &st) == 0) {
                    unsigned long long avail = (unsigned long long)st.f_bavail * st.f_frsize;
                    const unsigned long long reserve = 5ULL << 30;
                    ok = avail > reserve && (avail - reserve) > req;
                }
                // Writing result to struct and sending it
                pthread_mutex_lock(&filesMutex);
                currF->allowedToUpload = ok;
                pthread_mutex_unlock(&filesMutex);
                snprintf(response, sizeof(response), ok ? "check-space/allowed" : "check-space/prohibited");
            }
            else if (strncmp(fullMessage, "uploadFileInfo/", 15) == 0) {

                // Checking secure connection state
                if (currF == nullptr || currF->allowedToUpload==false || currF->userId!=currentUserId) {
                    printf(RED "[%s][PREPARE FILE DOWNLOAD]" RESET " %d attempted unauthorized file saving\n", time_formatted, sock);
                    goto nextMessage;
                }

                // Splitting user data
                char *parts[4] = {0};
                int count = 0;
                char *saveptr = nullptr;

                char *token = strtok_r(fullMessage + 15, "/", &saveptr);
                while (token && count < 3) {          // first 3 numbers (steps, chunkSize and fileSize)
                    parts[count++] = token;
                    token = strtok_r(nullptr, "/", &saveptr);
                }
                // the only thing left is fileName
                if (count == 3 && saveptr && *saveptr != '\0') {
                    parts[3] = saveptr;
                    count = 4;
                }

                if (count != 4) {
                    printf(RED "[%s][UPLOAD]" RESET " %d sent malformed uploadFileData\n", time_formatted, sock);
                    goto nextMessage;
                }

                // Safe number parser
                char *end;
                errno = 0;
                long steps = strtol(parts[0], &end, 10);
                if (errno || *end != '\0' || steps <= 0) goto badParams;

                errno = 0;
                size_t chunkSize = strtoul(parts[1], &end, 10);
                if (errno || *end != '\0' || chunkSize == 0 || chunkSize > MAX_CHUNK_SIZE) goto badParams;

                errno = 0;
                size_t fileSize = strtoul(parts[2], &end, 10);
                if (errno || *end != '\0' || fileSize == 0 || fileSize > MAX_FILE_SIZE) goto badParams;

                // Consistency: steps * chunkSize must cover fileSize
                if ((unsigned long)steps * chunkSize < fileSize) goto badParams;

                // Name check
                size_t nameLen = strlen(parts[3]);
                if (nameLen == 0 || nameLen >= sizeof(currF->path) ||
                    strchr(parts[3], '/') || strchr(parts[3], '\\') ||
                    strstr(parts[3], "..")) {
                    goto badParams;
                }

                char binary_path[PATH_MAX] = {0};
                char files_dir[PATH_MAX] = {0};
                ssize_t len = readlink("/proc/self/exe", binary_path, sizeof(binary_path)-1);
                if (len > 0) {
                    binary_path[len] = '\0';
                    snprintf(files_dir, sizeof(files_dir), "%s/files", dirname(binary_path));
                    mkdir(files_dir, 0755);
                } else {
                    strcpy(files_dir, "files");
                    mkdir(files_dir, 0755);
                }
                snprintf(files_dir+strlen(files_dir), sizeof(files_dir)-strlen(files_dir), "/%ld", currentUserId);
                mkdir(files_dir, 0755);

                char filepath[PATH_MAX] = {0};
                snprintf(filepath, sizeof(filepath), "%s/%s", files_dir, parts[3]);

                pthread_mutex_lock(&filesMutex);
                currF->steps = (int)steps;
                currF->chunkSize = chunkSize;
                currF->fileSize = fileSize;
                snprintf(currF->path, sizeof(currF->path), "%s", filepath);
                pthread_mutex_unlock(&filesMutex);
                goto nextMessage;

                badParams:
                currF->allowedToUpload=false;
                printf(RED "[%s][UPLOAD]" RESET " %d sent invalid upload parameters\n", time_formatted, sock);
                snprintf(response, sizeof(response), "uploadFileInfo/banned/bad-format");
            }
            else if (strncmp(fullMessage, "uploadFileCheck/", 16) == 0) {
                // Checking secure connection state
                if (currF == nullptr || currF->allowedToUpload==false || currF->userId!=currentUserId) {
                    printf(RED "[%s][PREPARE FILE DOWNLOAD]" RESET " %d attempted unauthorized file saving\n", time_formatted, sock);
                    goto nextMessage;
                }

                char binary_path[PATH_MAX] = {0};
                char files_dir[PATH_MAX] = {0};
                ssize_t len = readlink("/proc/self/exe", binary_path, sizeof(binary_path)-1);
                if (len > 0) {
                    binary_path[len] = '\0';
                    snprintf(files_dir, sizeof(files_dir), "%s/files/%ld", dirname(binary_path), currentUserId);
                } else {
                    strcpy(files_dir, "files");
                }

                char filepath[PATH_MAX];
                snprintf(filepath, sizeof(filepath), "%s/%s", files_dir, currF->path);

                char *hashHex = fullMessage+16;
                if (strncmp(hashHex, currF->hashHex, BLAKE3_OUT_LEN * 2 + 1) != 0) {

                    // Deleting current instance and clearing out unfinished file
                    removeUpload(currF, filepath, true);
                    goto nextMessage;
                }

                if (currF->steps == 0) {
                    if (currF->fileSize != currF->read_offset) {

                        // same process
                        removeUpload(currF, filepath, true);
                        goto nextMessage;
                    }
                }

                snprintf(response, sizeof(response), "uploadFileCheck/continue");
            }


            nextMessage:
            if (strlen(response) > 0) {
                sendPacket(sock, response, currC);
                printf(GREEN "[%s][ACCEPT MESSAGE][Thread %lu]" RESET " Responding for request (sock %d): %s -> %s\n", time_formatted, id, sock, fullMessage, response);
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
    if (currC) { unregisterClient(currC); }
    if (currF) { removeUpload(currF, currF->path, true); }
    close(sock);
    pthread_exit(NULL);
}

int processBinary(ClientSession *currC, FileUpload *currF, int sock, char time_formatted[80], char recvBuf[PACKET_SIZE], char fullMessage[PACKET_SIZE], uint32_t n, unsigned char serverSessionKey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES], long currentUserId) {
    // if user's length prefix is smaller than minimum overhead, packet is broken, do exit and notify user
    // if user's length prefix is bigger than maximum packet size, packet is broken, exit and notify user
    if (n < 4 + 16 + 24 || n > PACKET_SIZE) { printf(RED "[%s][PROCESS BINARY]" RESET " Bad packet math\n", time_formatted); return -1; } // bad packet math

    size_t out_length = 0;

    // checking for user's authorization
    if (currC != NULL && currF != NULL && currC->sock == sock && currC->hasSessionKey == true && currC->loggedIn == true && currF->allowedToUpload == true) {
        if (DecryptBinary(serverSessionKey, (const unsigned char*)recvBuf, n, (unsigned char*)fullMessage, MAX_CHUNK_SIZE, &out_length)) {

            if (out_length != currF->chunkSize || currF->read_offset + out_length > currF->fileSize || currF->steps < 0)  { printf(RED "[%s][PROCESS BINARY]" RESET " Bad file math\n", time_formatted); return -2; } // bad file math

            // validating file chunk's hash
            uint8_t raw_hash[BLAKE3_OUT_LEN];
            char hashHex[BLAKE3_OUT_LEN * 2 + 1];
            get_blake3_hash((const char*)fullMessage, out_length, raw_hash);
            bytes_to_hex_string(raw_hash, hashHex);
            pthread_mutex_lock(&filesMutex);
            snprintf(currF->hashHex, BLAKE3_OUT_LEN * 2 + 1, "%s", hashHex);
            pthread_mutex_unlock(&filesMutex);

            FILE *f = fopen(currF->path, currF->read_offset==0 ? "wb" : "ab");
            if (!f) { printf(RED "[%s][PROCESS BINARY]" RESET " Failed to open file (path = %s)\n", time_formatted, currF->path); return -3; }

            size_t written = fwrite(fullMessage, 1, out_length, f);
            if (written != out_length) {
                printf(RED "[%s][PROCESS BINARY]" RESET " Failed to write user's data to file (%ld of %ld bytes processed)\n", time_formatted, written, out_length);
                fclose(f);
                return -4;
            }

            pthread_mutex_lock(&filesMutex);
            currF->steps--;
            currF->read_offset += written;
            pthread_mutex_unlock(&filesMutex);

            if (fclose(f) != 0) {
                printf(RED "[%s][PROCESS BINARY]" RESET " Failed to close file (write data on disk)\n", time_formatted);
                return -5;
            }

            return 0; // reset buffers
        } else {
            return -6; // continue
        }
    } else {
        printf(RED "[%s][PROCESS BINARY]" RESET " User's (%ld) authorization failed\n", time_formatted, currentUserId);
        return -7;
    }
}
