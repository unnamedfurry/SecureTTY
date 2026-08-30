//
// Created by unnamedfurry on 8/28/26.
//


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sodium/core.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <sodium/randombytes.h>

#include "raylib.h"
#include "shared-variables.h"

extern void sendMessage(const char *message);

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

    // Reading binary data
    FILE *f = fopen(CONFIG_FILE, "rb");
    if (!f) {
        printf("[LOAD CONFIG FILE] conf.enc not found or corrupted. conf.enc will be recreated.\n");
        return false;
    }

    unsigned char salt[SALT_SIZE];
    unsigned char header[HEADER_SIZE];
    unsigned char master_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

    // Reading salt ...
    if (fread(salt, 1, sizeof(salt), f) != sizeof(salt)) {
        fclose(f);
        return false;
    }
    // ... and header
    if (fread(header, 1, sizeof(header), f) != sizeof(header)) {
        fclose(f);
        return false;
    }

    // Get master key
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
    long file_size = ftell(f) - (long)sizeof(salt) - (long)sizeof(header);
    if (file_size <= 0 || file_size > 16384) {
        fclose(f);
        return false;
    }
    fseek(f, sizeof(salt)+sizeof(header), SEEK_SET);
    unsigned char *encrypted = malloc(file_size);
    if (!encrypted) {
        fclose(f);
        return false;
    }
    fread(encrypted, 1, file_size, f);
    fclose(f);

    // Decrypting variables
    unsigned char *decrypted = calloc(1, (size_t)file_size + 1);
    if (!decrypted) {
        free(encrypted);
        return false;
    }
    unsigned long long decrypted_len;
    unsigned char tag;

    // Decrypting config
    if (crypto_secretstream_xchacha20poly1305_pull(&state, decrypted, &decrypted_len, &tag, encrypted, file_size, nullptr, 0) !=0) {
        free(encrypted);
        free(decrypted);
        printf("[LOAD CONFIG FILE] Wrong master-password or corrupted file.\n");
        return false;
    }

    free(encrypted);

    // Loading values from config
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
                cfg->userId = strtol(value, nullptr, 10);
            } else if (strcmp(key, "userName") == 0) {
                strncpy(cfg->userName, value, MAX_NAME);
            } else if (strcmp(key, "email") == 0) {
                strncpy(cfg->email, value, MAX_EMAIL);
            } else if (strcmp(key, "passwordHash") == 0) {
                snprintf(cfg->passwordHash, sizeof(cfg->passwordHash), "%s", value);
            } else if (strcmp(key, "avatarUrl") == 0) {
                strncpy(cfg->avatarUrl, value, MAX_AVATAR);
            } else if (strcmp(key, "profileDescription") == 0) {
                strncpy(cfg->profileDescription, value, MAX_DESC);
            }
        }
        line = strtok(nullptr, "\n");
    }

    free(decrypted);
    return true;
}

bool SaveEncryptedConfig(Config *cfg, const char* master_password) {

    // Un-encrypted variables
    unsigned char salt[SALT_SIZE] = {0};
    unsigned char master_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char header[HEADER_SIZE];
    bool existed = FileExists(CONFIG_FILE);

    // Generating new salt in case file is new
    if (!existed) {
        randombytes_buf(salt, sizeof(salt));
    } else {

        // Reading existing salt
        FILE *old = fopen(CONFIG_FILE, "rb");
        if (!old || fread(salt, 1, sizeof(salt), old) != sizeof(salt)) {
            if (old) fclose(old);
            return false;
        }
        fclose(old);
    }

    // Copying salt to temporary test config
    char tempPath[sizeof(CONFIG_FILE) + 5];
    snprintf(tempPath, sizeof(tempPath), "%s.tmp", CONFIG_FILE);
    FILE *f = fopen(tempPath, "wb");
    if (!f) return false;
    fwrite(salt, 1, sizeof(salt), f);

    // Getting master key from password
    if (!DeriveMasterKey(master_password, master_key, salt)) {
        printf("[SAVE ENCRYPTED CONFIG] Error generating key.\n");
        fclose(f);
        unlink(tempPath);
        return false;
    }

    // Checking for space
    char temp_config[16384] = {0};
    FILE *tmp = tmpfile();
    if (!tmp) {
        fclose(f);
        unlink(tempPath);
        return false;
    }

    // Saving config to regular line
    fprintf(tmp, "isFirstUsed=%s\n", cfg->isFirstUsed ? "true" : "false");
    fprintf(tmp, "userId=%ld\n", cfg->userId);
    fprintf(tmp, "userName=%s\n", cfg->userName);
    fprintf(tmp, "email=%s\n", cfg->email);
    fprintf(tmp, "passwordHash=%s\n", cfg->passwordHash);
    fprintf(tmp, "avatarUrl=%s\n", strlen(cfg->avatarUrl)==0 ? "null" : cfg->avatarUrl);
    fprintf(tmp, "profileDescription=%s\n", cfg->profileDescription);

    // Writing and closing file
    fseek(tmp, 0, SEEK_END);
    long size = ftell(tmp);
    fseek(tmp, 0, SEEK_SET);
    fread(temp_config, 1, size, tmp);
    fclose(tmp);

    // Adding header to test file
    crypto_secretstream_xchacha20poly1305_state state;
    crypto_secretstream_xchacha20poly1305_init_push(&state, header, master_key);
    fwrite(header, 1, sizeof(header), f);

    unsigned char out_buf[4096 + 32];
    unsigned long long out_len;

    // Trying to encrypt config
    crypto_secretstream_xchacha20poly1305_push(&state, out_buf, &out_len,
        (unsigned char*)temp_config, strlen(temp_config), nullptr, 0,
        crypto_secretstream_xchacha20poly1305_TAG_FINAL);

    // Moving temp data to config file
    fwrite(out_buf, 1, out_len, f);
    fclose(f);
    if (rename(tempPath, CONFIG_FILE) != 0) {
        unlink(tempPath);
        return false;
    }

    printf("[SAVE ENCRYPTED CONFIG] Saved config to file.\n");

    // Sending sata to server
    if (profileUpdateCode == -1) {

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