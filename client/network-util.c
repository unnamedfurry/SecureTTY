//
// Created by unnamedfurry on 8/28/26.
//

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sodium/core.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_box.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>
#include <sys/socket.h>

// External variables and methods
#include "client.h"
#include "raylib.h"
#include "shared-variables.h"
extern unsigned char* Base64Decode(const char* input, int* out_len);
extern bool LoadEncryptedConfig(Config *cfg, const char* master_password);
extern bool SaveEncryptedConfig(Config *cfg, const char* master_password);
extern bool DecryptPacket(const char* encrypted_packet, char* out_plaintext, size_t max_out_size);
extern bool EncryptPacket(const char* plaintext, char* out_ciphertext, size_t max_out_size);

// Recursive calls
void sendMessage(const char *message);

void* recieveMessage(void* arg) {
    // Large buffers
    char localBuf[BUFFER_SIZE] = {0};
    char fullMessage[PACKET_SIZE] = {0};
    char recvBuf[PACKET_SIZE] = {0};
    int totalReceived = 0;

        // reading till got atleast one full answer
        while (connected) {

            memset(localBuf, 0, sizeof(localBuf));
            int bytes = (int)read(sock, localBuf, sizeof(localBuf)-1);

            // In case connection dropped
            if (bytes <= 0) {
                connected = false;
                printf("[RECEIVE] Connection lost\n");
                break;
            }

            // In case message is to big
            if (totalReceived + bytes > sizeof(fullMessage) - 1) {
                printf("[RECEIVE] Message too big! Clearing buffer.\n");
                totalReceived = 0;
            }

            // Appending received text to main buffer
            memcpy(recvBuf + totalReceived, localBuf, bytes);
            totalReceived += bytes;
            recvBuf[totalReceived] = '\0';

            // Splitting solid packets by \n symbol
            char *newlinePos;
            while ((newlinePos = memchr(recvBuf, '\n', totalReceived)) != NULL) {

                // If text length if larger than maximum value
                // set it to max - 1
                size_t msgLen = (size_t)(newlinePos - recvBuf);
                if (msgLen >= sizeof(fullMessage)) msgLen = sizeof(fullMessage) - 1;

                // Copy the message to a separate working buffer: recvBuf remains
                // untouched, and subsequent messages in the queue are safe
                // regardless of what decrypt/strtok do to fullMessage.
                memcpy(fullMessage, recvBuf, msgLen);
                fullMessage[msgLen] = '\0';

                pthread_mutex_lock(&clientStateMutex);
                printf("[RECEIVE MESSAGE] Got %d bytes from server\n", totalReceived);
                printf("[RECEIVE MESSAGE] Server said (full message): %s\n", fullMessage);

                // Get key and establish connection
                if (strncmp(fullMessage, "keyexchange/myturn/", 19) == 0 && hasSessionKey==false) {
                    char *serverPubB64 = fullMessage + 19;

                    unsigned char serverPub[crypto_box_PUBLICKEYBYTES] = {0};
                    size_t len = 0;
                    sodium_base642bin(serverPub, sizeof(serverPub), serverPubB64, strlen(serverPubB64),
                                     nullptr, &len, nullptr, sodium_base64_VARIANT_ORIGINAL);

                    printf("[CRYPTO] Received server pubkey, len = %zu\n", len);

                    // Checking if key is valid
                    // by comparing server one's length
                    // with standardized size
                    if (len == crypto_box_PUBLICKEYBYTES) {

                        const char *pinned = getenv("SECURETTY_SERVER_PUBKEY");
                        char received[128] = {0};
                        sodium_bin2base64(received, sizeof(received), serverPub, sizeof(serverPub), sodium_base64_VARIANT_ORIGINAL);

                        // In case key was modified
                        if (!pinned || strcmp(pinned, received) != 0) {
                            printf("[CR] Server public key does not match SECURETTY_SERVER_PUBKEY\n");
                            connected = false;
                            goto next;
                        }

                        int ret = crypto_box_beforenm(clientSessionKey, serverPub, clientPriv);

                        if (ret == 0) {
                            hasSessionKey = true;
                            printf("[CRYPTO] Client session key: %p\n", (void*)clientSessionKey);
                        } else {
                            printf(cRED "[CRYPTO] crypto_box_beforenm failed with code %d\n" RESET, ret);
                        }
                    }
                }
                // else if (strncmp(fullMessage, "error", 5) == 0) {
                //
                //     char *ptr = fullMessage+6;
                //     if (strcmp(ptr, "lockedThread") == 0) {
                //         serverErrorCode=1;
                //     } else if (strcmp(ptr, "unknownIssue") == 0) {
                //         serverErrorCode=2;
                //     }
                // }
                else {
                    // Decrypt packet with existing key
                    char decrypted[PACKET_SIZE] = {0};
                    if (DecryptPacket(fullMessage, decrypted, sizeof(decrypted))) {
                        strncpy(fullMessage, decrypted, sizeof(fullMessage)-1);
                    }
                }


                if (strncmp(fullMessage, "save-profile/", 13) == 0) {

                    if (strncmp(fullMessage+13, "ok", 2) == 0) {
                        // Reload config

                        profileUpdateCode = 0;
                        printf("[SAVE PROFILE] Profile successfully saved on server\n");
                        LoadEncryptedConfig(&config, masterPassword);

                        // Re-validating config
                        if (config.userId == 0) {
                            printf(cRED "[FATAL]" RESET "[SAVE PROFILE] User ID is 0, shutting down.\n");
                            exit(4);
                        }

                    } else if (strncmp(fullMessage+13, "error", 5) == 0) {
                        // Reload from server and display error

                        profileUpdateCode = 1;

                        // Splitting server profile to parts
                        char *parts2[2] = {0};
                        int cnt2 = 0;
                        char *token2 = strtok(fullMessage+19, "\x1E");
                        while (token2 && cnt2 < 2) {
                            parts2[cnt2++] = (token2 == NULL || strcmp(token2, "null") == 0 || strcmp(token2, "NULL") == 0) ? "" : token2;
                            token2 = strtok(nullptr, "\x1E");
                        }

                        // Saving current server profile
                        if (cnt2 > 0) snprintf(config.avatarUrl, sizeof(config.avatarUrl), "%s", parts2[0]);
                        if (cnt2 > 1) snprintf(config.profileDescription, sizeof(config.profileDescription), "%s", parts2[1]);

                        // Attempting reload
                        SaveEncryptedConfig(&config, masterPassword);
                        LoadEncryptedConfig(&config, masterPassword);


                    } else if (strncmp(fullMessage+13, "badformat", 9) == 0) {
                        // Reload from server and display error

                        profileUpdateCode = 2;

                        // Splitting server profile to parts
                        char *parts2[2] = {0};
                        int cnt2 = 0;
                        char *token2 = strtok(fullMessage+23, "\x1E");
                        while (cnt2 < 2) {
                            parts2[cnt2++] = (token2 == NULL || strcmp(token2, "null") == 0 || strcmp(token2, "NULL") == 0) ? "" : token2;
                            token2 = strtok(nullptr, "\x1E");
                        }

                        // Saving current server profile
                        if (cnt2 > 0) snprintf(config.avatarUrl, sizeof(config.avatarUrl), "%s", parts2[0]);
                        if (cnt2 > 1) snprintf(config.profileDescription, sizeof(config.profileDescription), "%s", parts2[1]);

                        // Attempting reload
                        SaveEncryptedConfig(&config, masterPassword);
                        LoadEncryptedConfig(&config, masterPassword);
                    }
                }
                else if (strncmp(fullMessage, "createId/user/", 14) == 0) {
                    // Getting user from first setup

                    long newId = atol(fullMessage + 14);
                    if (newId > 0) {
                        // Saving value
                        config.userId = newId;
                        printf("[CREATE USER ID] Got new id from server: %ld\n", newId);

                        // Initializing structure slot for new client
                        char msgBuf[BUFFER_SIZE];
                        snprintf(msgBuf, sizeof(msgBuf), "registerClient/%ld", newId);
                        sendMessage(msgBuf);
                    }
                }
                else if (strncmp(fullMessage, "createId/message/", 17) == 0) {
                    // Assigning new id to current message

                    long newId = atol(fullMessage + 17);
                    if (newId > 0) {
                        randomMessageId = newId;
                        printf("[CREATE MESSAGE ID] Got new id from server: %ld\n", newId);
                    }
                }
                else if (strncmp(fullMessage, "getFriendsList/", 15) == 0) {
                    printf("[GET FRIENDS LIST] Received new list from server\n");

                    // clearing past friends
                    memset(pendingFriendAvatarArr, 0, sizeof(pendingFriendAvatarArr));
                    memset(friends, 0, sizeof(friends));
                    friendsCount = -1;
                    isUpdatedFriends = true;

                    // strtok_r — reentrant version (for safe embed using)
                    char *saveptr1 = nullptr;
                    char *saveptr2 = nullptr;

                    char *token = strtok_r(fullMessage + 15, "\x1E", &saveptr1); // skipping packet domain

                    // Saving list
                    while (token && friendsCount < 100) {
                        // Friend profile

                        friendsCount++;
                        char tokenCopy[1024];
                        strncpy(tokenCopy, token, sizeof(tokenCopy)-1);
                        tokenCopy[sizeof(tokenCopy)-1] = '\0';

                        char *subtoken = strtok_r(tokenCopy, "\x1F", &saveptr2);
                        int field = 0;

                        while (subtoken && field < 4) {
                            // Friend profile data

                            if (field == 0) strncpy(friends[friendsCount].name, subtoken, MAX_NAME);
                            else if (field == 1) friends[friendsCount].userId = strtol(subtoken, nullptr, 10);
                            else if (field == 2) strncpy(friends[friendsCount].avatarUrl, subtoken, MAX_AVATAR);
                            else if (field == 3) strncpy(friends[friendsCount].profileDescription, subtoken, MAX_DESC);

                            field++;
                            subtoken = strtok_r(nullptr, "\x1F", &saveptr2);
                        }

                        // Setting unread message counters
                        if (friends[friendsCount].userId > 0) {
                            friends[friendsCount].newMessageCount = 0;
                        }

                        token = strtok_r(nullptr, "\x1E", &saveptr1);
                    }

                    printf("[GET FRIENDS LIST] Successfully loaded %d friends\n", friendsCount);
                    requestedAvatarUpdate = true;
                }
                else if (strncmp(fullMessage, "getChatHistory/", 15) == 0) {
                    // removed memset - possible freezes

                    // reading directly fullMessage as we no longer need dataStart (killed a potential memory leak)
                    if (strncmp(fullMessage + 15, "empty", 5) == 0) {
                        printf("[GET CHAT HISTORY] History is empty\n");
                        goto next;
                    }

                    long friendId = strtol(fullMessage + 15, nullptr, 10);

                    // looking for \x1E after friend id
                    char *historyStart = strchr(fullMessage + 15, '\x1E');
                    if (!historyStart) goto next; // if theres no one or packet was cursed - exiting

                    historyStart++; // moving a pointer a step further to skip \x1F

                    // safely cpying only messages
                    char *dataCopy = strdup(historyStart);
                    if (!dataCopy) goto next;

                    messagesCount = 0;
                    isUpdatedMessages = true;
                    char *p = dataCopy;

                    while (p && *p && messagesCount < 999999) {
                        messagesCount++;
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
                                messages[messagesCount].message[2048] = '\0';
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

                    printf("[GET CHAT HISTORY] Loaded %d messages with %ld\n", messagesCount, friendId);
                }
                else if (strncmp(fullMessage, "newMessage\x1E", 11) == 0) {

                    // Parsing messages
                    char *field[4] = {0};
                    int fieldCounter = 0;
                    char *copy = malloc(sizeof(char)*(strlen(fullMessage)+2));
                    memcpy(copy, fullMessage, strlen(fullMessage)+1);
                    char *token = strtok(copy + 11, "\x1F");

                    while (token && fieldCounter < 4) {
                        field[fieldCounter++] = token;
                        token = strtok(nullptr, "\x1F");
                    }

                    if (fieldCounter >= 3) {
                        long msgId     = strtol(field[0], nullptr, 10);
                        long senderId  = strtol(field[1], nullptr, 10);
                        const char *text = field[2];
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
                            if (messagesCount < 0) messagesCount = 0;
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
                    free(copy);
                    copy=nullptr;
                }
                else if (strncmp(fullMessage, "newFriendRequest/", 17) == 0) {
                    memset(pendingFriends, 0, sizeof(pendingFriends));
                    memset(pendingFriendAvatarArr, 0, sizeof(pendingFriendAvatarArr));
                    hasFriendRequests = false;

                    // Splitting users
                    char *ptr = fullMessage+17;
                    char *saveptr = nullptr;
                    char *token = strtok_r(ptr, "\x1E", &saveptr);
                    int count = 0;

                    while (token && count < 100) {

                        // Splitting user data
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

                            // Add to pending friend requests
                            hasFriendRequests=true;
                            pendingFriends[count].userId = strtol(parts[0], nullptr, 10);
                            if (parts[1]) strncpy(pendingFriends[count].name, parts[1], MAX_NAME);
                            if (parts[2]) strncpy(pendingFriends[count].profileDescription, parts[2], MAX_DESC);

                            // Get pending friend's avatar
                            char packet[64] = {0};
                            snprintf(packet, 64, "getAvatar/%s", parts[0]);
                            sendMessage(packet);

                            count++;
                        }

                        // Next user
                        token = strtok_r(nullptr, "\x1E", &saveptr);
                    }
                }
                else if (strncmp(fullMessage, "updateClient/messages/", 22) == 0) {
                    char *ptr = malloc(sizeof(char)*(strlen(fullMessage)+2));
                    if (!ptr) {
                        printf(cRED "[UPDATE CLIENT | MESSAGES | FATAL]" RESET " Out of memory\n");
                        goto next;
                    }
                    memcpy(ptr, fullMessage, strlen(fullMessage)+1);
                    int totalNew = 0;

                    // clear old message counters
                    for (int i = 0; i < 100; i++) {
                        friends[i].newMessageCount = 0;
                    }

                    // Splitting messages
                    char *token = strtok(ptr, "\x1E");
                    while (token) {

                        // Splitting message data
                        char *parts[2] = {0};
                        int c = 0;
                        char *t2 = strtok(token, "\x1F");
                        while (t2 && c < 2) {
                            parts[c++] = t2;
                            t2 = strtok(nullptr, "\x1F");
                        }

                        if (c == 2) {
                            // Adding message to render
                            long senderId = strtol(parts[0], nullptr, 10);
                            int count = atoi(parts[1]);

                            // Display unread messages counter
                            for (int i = 0; i < 100; i++) {
                                if (friends[i].userId == senderId) {
                                    friends[i].newMessageCount = count;
                                    break;
                                }
                            }
                            totalNew+=count;
                        }

                        // Next message
                        token = strtok(nullptr, "\x1E");
                    }

                     printf("[UPDATE CLIENT | MESSAGES] Got %d new messages\n", totalNew);
                     free(ptr);
                }
                else if (strncmp(fullMessage, "updateClient/friendRequests", 27) == 0) {
                    printf("[FRIEND REQUESTS] Received pending requests\n");

                    memset(pendingFriends, 0, sizeof(pendingFriends));
                    memset(pendingFriendAvatarArr, 0, sizeof(pendingFriendAvatarArr));
                    hasFriendRequests = false;

                    // Splitting users
                    char *ptr = fullMessage+28;
                    char *saveptr = nullptr;
                    char *token = strtok_r(ptr, "\x1E", &saveptr);
                    int count = 0;

                    while (token && count < 100) {

                        // Avoid editing original buffer
                        char tokenCopy[1024];
                        strncpy(tokenCopy, token, sizeof(tokenCopy)-1);
                        tokenCopy[sizeof(tokenCopy)-1] = '\0';

                        // Splitting user data
                        char *parts[3] = {0};
                        char *sub = strtok(tokenCopy, "\x1F");
                        int p = 0;
                        while (sub && p < 2) {
                            parts[p++] = sub;
                            sub = strtok(nullptr, "\x1F");
                        }

                        if (parts[0]) {
                            // Adding friend request
                            hasFriendRequests=true;
                            pendingFriends[count].userId = strtol(parts[0], nullptr, 10);
                            if (parts[1]) strncpy(pendingFriends[count].name, parts[1], MAX_NAME);
                            if (parts[2]) strncpy(pendingFriends[count].profileDescription, parts[2], MAX_DESC);
                            count++;
                        }

                        // Next request
                        token = strtok_r(nullptr, "\x1E", &saveptr);
                    }

                    printf("[FRIEND REQUESTS] Parsed %d pending requests\n", count);
                }
                if (strncmp(fullMessage, "getAvatarResponse/", 18) == 0) {
                    printf("[GET AVATAR] Received (%d bytes)\n", totalReceived);

                    char *ptr = fullMessage + 18;
                    long userId = strtol(ptr, &ptr, 10);

                    // Splitting name and file content
                    if (*ptr == '\x1E') {

                        // File content
                        char *b64_start = ptr + 1;
                        char *b64_end = strchr(b64_start, '\x1E');
                        if (b64_end) *b64_end = '\0';

                        // Decoding text
                        int decoded_len = 0;
                        unsigned char* png_data = Base64Decode(b64_start, &decoded_len);

                        // Saving image
                        if (png_data && decoded_len > 1000) {
                            if (!DirectoryExists("avatars")) MakeDirectory("avatars");

                            char filepath[128];
                            snprintf(filepath, sizeof(filepath), "avatars/%ld.png", userId);

                            // Write binary to file
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
                // else if (strncmp(fullMessage, "error", 5) == 0) {
                //     char *ptr = fullMessage+6;
                //     if (strcmp(ptr, "lockedThread") == 0) {
                //         serverErrorCode=1;
                //     } else if (strcmp(ptr, "unknownIssue") == 0) {
                //         serverErrorCode=2;
                //     }
                // }
                next:

                pthread_mutex_unlock(&clientStateMutex);

                // moving the end
                size_t processed = msgLen + 1; // +1 bc of '\n'
                printf("[DEBUG] Processed if %lu.\n", processed);
                if (processed > (size_t)totalReceived) processed = (size_t)totalReceived;
                memmove(recvBuf, recvBuf + processed, totalReceived - processed);
                totalReceived -= (int)processed;
                recvBuf[totalReceived] = '\0';
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
        printf(cRED "[FATAL | NETWORK]" RESET " Failed to connect to server\n");
        close(sock);
        sock = -1;
        return false;
    }
    connected=true;

    // Create a listener
    if (pthread_create(&thread_id, nullptr, recieveMessage, NULL) != 0) {
        printf(cRED "[FATAL | NETWORK]" RESET " Failed to create listener thread\n");
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
    size_t packetLen = strlen(packet1), sent = 0;

    while (sent < packetLen) {
        ssize_t n = send(sock, packet1 + sent, packetLen - sent, MSG_NOSIGNAL);
        if (n <= 0) { initedNetwork=false; connected = false; close(sock); sock = -1; break; }
        sent += (size_t)n;
    }
    sentKeyExchange=true;

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

        // 5 sec — if the server doesnt respond, dont hang forever
        if (waited > 5000) {
            printf(cRED "[NETWORK] Timed out waiting for session key, message dropped: %s\n" RESET, message);
            return;
        }
    }

    // connection dropped while waiting
    if (!connected) return;

    // Attempting to encrypt
    char packet[PACKET_SIZE+1] = {0};
    if (!EncryptPacket(message, packet, sizeof(packet)-1)) {
        printf("[CRYPTO] Failed to encrypt message.\n");
        return;
    }

    // Sending data
    packet[strlen(packet)]='\x1D';
    size_t packetLen = strlen(packet), sent = 0;
    while (sent < packetLen) {

        // MSG_NOSIGNAL - do not let connection crash
        ssize_t n = send(sock, packet + sent, packetLen - sent, MSG_NOSIGNAL);

        // Server closed connection
        if (n <= 0) {
            printf("[NETWORK] Send error\n");
            connected = false;
            initedNetwork=false;
            return;
        }
        sent += (size_t)n;
    }

    // Prevent server flooding
    usleep(5000);
    printf("[SEND] Sent message: %s\n", packet);
}