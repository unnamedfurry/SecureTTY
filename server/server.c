#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <mysql.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "server.h"
#include <sodium.h>
#include <signal.h>

// Shared variables and methods
#include "shared-variables.h"
extern void* acceptMessage(void *arg);

// Local variables
int port = 63321;
int server_fd, new_socket;
struct sockaddr_in address;
int addrlen = sizeof(address);
char incomingBuffer[BUFFER_SIZE] = {0};
char outgoingBuffer[BUFFER_SIZE] = {0};
static pthread_t thread_id;
static pthread_attr_t attr;
static volatile sig_atomic_t g_shutdown = 0;
void handle_signal(int sig) {
    g_shutdown = 1;
    shutdown(server_fd, SHUT_RDWR);
}

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
