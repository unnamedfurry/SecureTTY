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

#include "shared-variables.h"
extern void registerClient(long userId, int sock);
extern void unregisterClient(ClientSession *curr);
extern bool DecryptPacket(unsigned char serverSessionKey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES], const char* input, char* out_plain, size_t max_size);
extern bool EncryptPacket(ClientSession *session, const char* plaintext, char* out_buffer, size_t max_size);
extern bool sendPacket(int sock, const char *data, ClientSession *curr);
extern char* Base64Encode(const unsigned char* input, int length);
extern unsigned char* Base64Decode(const char* input, int* out_len);
extern bool appendf(char *buf, size_t size, size_t *off, const char *fmt, ...);

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
        char buffer[80];
        time(&rawtime);
        info = localtime(&rawtime);
        strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", info);

        // Validating syntax
        if (bytes <= 0) {
            printf(GREEN "[%s][ACCEPT MESSAGE][Thread %lu]" RESET " Client disconnected (sock %d)\n", buffer, id, sock);
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

            //if (currC->closing==true) goto client_disconnect;


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
                    currC = malloc(sizeof(ClientSession));
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

            printf(GREEN "[%s][ACCEPT MESSAGE][Thread %lu]" RESET " Client said (full message, %zu bytes): %s\n", buffer, id, msgLen, fullMessage);

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
                if (count != 3) {
                    printf("[%s][LOGIN] Not enough parameters for login\n", buffer);
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
                    printf("[%s][REGISTER CLIENT] User %ld\n authorized successfully\n", buffer, newId);
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
                if (count != 4) {
                    printf("[%s][LOGIN] Not enough parameters for login\n", buffer);
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
                    printf("[%s][LOGIN CLIENT] Query Error: %s\n", buffer, mysql_error(conn));
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
                    printf("[%s][LOGIN CLIENT] No matching user found.\n", buffer);
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

                printf("[%s][LOGIN CLIENT] Received for client/user %ld\n", buffer, userId);
                if (userId > 0 && ok == true) {

                    // Authorizing client
                    registerClient(userId, sock);
                    currC->loggedIn=true;
                    printf("[%s][LOGIN CLIENT] User %ld\n authorized successfully\n", buffer, userId);
                    snprintf(response, sizeof(response), "login/ok");
                } else {

                    // Closing connection
                    printf("[%s][LOGIN CLIENT] User %ld\n failed to authorize: incorrect data\n", buffer, userId);
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
                printf(RED "[%s][RECEIVE MESSAGE]" RESET " %d attempted unauthorized action\n", buffer, sock);
                goto nextMessage;
            }

            if (strncmp(fullMessage, "receive-message/", 16) == 0) {
                printf("[%s][RECEIVE MESSAGE] Saving message: %s\n", buffer, fullMessage);

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
                    printf("[%s][RECEIVE MESSAGE] Message saved: %ld -> %ld\n", buffer, senderId, receiverId);
                    char pushPacket[BUFFER_SIZE];
                    snprintf(pushPacket, sizeof(pushPacket), "newMessage\x1E%ld\x1F%ld\x1F%s\x1F%s\n", messageId, senderId, parts[2], "now");
                    snprintf(response, sizeof(response), "createId/message/%ld", messageId);

                    if (!pushToUser(receiverId, pushPacket, currC)) {
                        printf("[%s][RECEIVE MESSAGE] Receiver %ld is offline, message will be saved to DB\n", buffer, receiverId);
                    }
                } else {
                    printf("[%s][RECEIVE MESSAGE] Failed to save message to db: %ld, %ld\n", buffer, senderId, messageId);
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
                    printf("[%s][SAVE PROFILE] received for %ld\n", buffer, uid);
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
                    long uid = strtol(parts[0], nullptr, 10);
                    if (parts[0] && uid == currC->userId) {
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

                    printf("[%s][GET FRIENDS LIST] Sent for %ld\n", buffer, userId);
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
                    printf("[%s][ADD FRIEND] received for %ld -> %ld\n", buffer, senderId, receiverId);

                    // Validating ids
                    if (senderId > 0 && receiverId > 0 && senderId != receiverId) {

                        // Attempting request save
                        if (sendFriendRequest(senderId, receiverId)) {

                            // Pushing update request to receiver
                            pushToUser(receiverId, "requestPendingFriends/", currC);
                            printf("[%s][ADD FRIEND] Sent successfully %ld -> %ld\n", buffer, senderId, receiverId);
                        } else {

                            // Reporting error to sender
                            printf("[%s][ADD FRIEND] Failed to save request\n", buffer);
                            strncpy(response, "addFriend/error", 16);
                        }
                    } else {

                        // Reporting error to sender
                        printf("[%s][ADD FRIEND] Bad ID\n", buffer);
                        strncpy(response, "addFriend/error", 16);
                    }
                } else {

                    // Reporting error to sender
                    printf("[%s][ADD FRIEND] Bad format, got %d/2 parts\n", buffer, count);
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
                printf("[%s][UPDATE CLIENT] Received for client/user %ld\n", buffer, userId);
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
                    printf("[%s][GET CHAT HISTORY] Received history request from %ld with %ld\n", buffer, userId, friendId);

                    if (userId == currC->userId && friendId > 0) {
                        getChatHistory(userId, friendId, sock, offset, currC);
                    }
                }
            }
            else if (strncmp(fullMessage, "getAvatar/", 10) == 0) {

                // Validating syntax
                long uid = strtol(fullMessage + 10, nullptr, 10);
                if (uid <= 0) { snprintf(response, sizeof(response), "getAvatar/badformat"); goto nextMessage; }
                printf("[%s][GET AVATAR] requested %ld's avatar\n", buffer, uid);

                // Getting current folder
                char binary_path[PATH_MAX] = {0};
                char avatars_dir[PATH_MAX] = {0};
                ssize_t len = readlink("/proc/self/exe", binary_path, sizeof(binary_path)-1);
                if (len > 0) {
                    binary_path[len] = '\0';
                    snprintf(avatars_dir, sizeof(avatars_dir), "%s/avatars", dirname(binary_path));
                } else {
                    strcpy(avatars_dir, "avatars");
                }
                // Creating a folder if does not exist
                mkdir(avatars_dir, 0755);
                char filepath[PATH_MAX];
                snprintf(filepath, sizeof(filepath), "%s/%ld.png", avatars_dir, uid);

                // Opening file
                FILE *f = fopen(filepath, "rb");
                if (f) {

                    // Validating sizes
                    fseek(f, 0, SEEK_END);
                    long fileSize = ftell(f);
                    fseek(f, 0, SEEK_SET);

                    if (fileSize <= 0 || fileSize > PACKET_SIZE) {
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
                        printf("[%s][GET AVATAR] sent avatar for %ld (%ld bytes)\n", buffer, uid, fileSize);
                    }
                } else {
                    // Sending null
                    snprintf(response, sizeof(response), "getAvatarResponse/%ld\x1E", uid);
                    printf("[%s][GET AVATAR] %ld's avatar not found\n", buffer,uid);
                }
            }
            else if (strncmp(fullMessage, "saveAvatar/", 11) == 0) {

                char *ptr = fullMessage + 11;
                long userId = strtol(ptr, &ptr, 10);

                // Checking for authorization
                if (userId != currC->userId || *ptr != '\x1E') {
                    printf("[%s][SAVE AVATAR] Parse error: invalid userId or missing separator\n", buffer);
                    printf("[%s][SAVE AVATAR] Received: %.100s...\n", buffer, fullMessage);
                    snprintf(response, sizeof(response), "saveAvatar/unauthorized");
                    goto nextMessage;
                }

                char *b64_data = ptr + 1; // base64 start
                if (strlen(b64_data) < 100) {
                    printf("[%s][SAVE AVATAR] Base64 data too short (%zu chars)\n", buffer, strlen(b64_data));
                }

                // Decoding text
                int decoded_len = 0;
                unsigned char* png_data = Base64Decode(b64_data, &decoded_len);

                if (!png_data || decoded_len < 500) { // minimal PNG size
                    printf("[%s][SAVE AVATAR] Decode failed or image too small (%d bytes)\n", buffer, decoded_len);
                    free(png_data);
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
                printf("[%s][GET CLIENT UPDATES] Sent friend request update for %ld: %s\n", buffer, userId, response);
            } else if (strncmp(fullMessage, "check-space/", 12) == 0) {

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
                if (currF) { currF->allowedToUpload = ok; if (ok) currF->userId = currentUserId; }
                pthread_mutex_unlock(&filesMutex);
                snprintf(response, sizeof(response), ok ? "check-space/allowed" : "check-space/prohibited");
            }
            else if (strncmp(fullMessage, "uploadFileData/", 15) == 0) {

                // Checking secure connection state
                if (currF != nullptr || currF->allowedToUpload==false || currF->userId!=currentUserId) {
                    printf(RED "[%s][PREPARE FILE DOWNLOAD]" RESET " %d attempted unauthorized file saving\n", buffer, sock);
                    goto nextMessage;
                }

                // Splitting user data
                char *parts[4] = {0};
                int count = 0;
                char *saveptr = nullptr;

                char *token = strtok_r(fullMessage + 15, "/", &saveptr);
                while (token && count < 3) {          // first 3 numbers
                    parts[count++] = token;
                    token = strtok_r(nullptr, "/", &saveptr);
                }
                // the only thing left is name
                if (count == 3 && saveptr && *saveptr != '\0') {
                    parts[3] = saveptr;
                    count = 4;
                }

                if (count != 4) {
                    printf(RED "[%s][UPLOAD]" RESET " %d sent malformed uploadFileData\n", buffer, sock);
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
                if (nameLen == 0 || nameLen >= sizeof(currF->name) ||
                    strchr(parts[3], '/') || strchr(parts[3], '\\') ||
                    strstr(parts[3], "..")) goto badParams;

                pthread_mutex_lock(&filesMutex);
                currF->steps = (int)steps;
                currF->chunkSize = chunkSize;
                currF->fileSize = fileSize;
                snprintf(currF->name, sizeof(currF->name), "%s", parts[3]);
                pthread_mutex_unlock(&filesMutex);
                goto nextMessage;

                badParams:
                printf(RED "[%s][UPLOAD]" RESET " %d sent invalid upload parameters\n", buffer, sock);
            }


            nextMessage:
            if (strlen(response) > 0) {
                sendPacket(sock, response, currC);
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
    if (currC) { unregisterClient(currC); free(currC); }
    close(sock);
    pthread_exit(NULL);
}
