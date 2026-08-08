//
// Created by unnamedfurry on 8/3/26.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sodium.h>

#define CONFIG_FILE         "conf.enc"
#define SALT_SIZE           crypto_pwhash_SALTBYTES
#define HEADER_SIZE         crypto_secretstream_xchacha20poly1305_HEADERBYTES
#define MAX_NAME 23
#define MAX_EMAIL 32
#define MAX_PASS 23
#define MAX_AVATAR 64
#define MAX_DESC 1024
#define MAX_MESS 2048
#define SHA256_DIGEST_LENGTH 65   // hex-строка + '\0'

typedef struct {
    bool isFirstUsed;
    long userId;
    char userName[MAX_NAME+1];
    char email[MAX_EMAIL+1];
    char passwordHash[MAX_PASS];
    char avatarUrl[MAX_AVATAR+1];
    char profileDescription[MAX_DESC+1];
} Config;
Config config = {0};

// ====================== Вспомогательные функции ======================

bool FileExists(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f) {
        fclose(f);
        return true;
    }
    return false;
}

bool DeriveMasterKey(const char *password, unsigned char *out_key, const unsigned char *salt) {
    if (crypto_pwhash(out_key,
                      crypto_secretstream_xchacha20poly1305_KEYBYTES,
                      password,
                      strlen(password),
                      salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        return false;
    }
    return true;
}

// ====================== Ваши функции (немного подчищены) ======================

bool LoadEncryptedConfig(Config *cfg, const char *master_password) {
    FILE *f = fopen(CONFIG_FILE, "rb");
    if (!f) {
        printf("[LOAD CONFIG FILE] conf.enc not found or corrupted. conf.enc will be recreated.\n");
        return false;
    }

    unsigned char salt[SALT_SIZE];
    unsigned char header[HEADER_SIZE];
    unsigned char master_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

    if (fread(salt, 1, sizeof(salt), f) != sizeof(salt) ||
        fread(header, 1, sizeof(header), f) != sizeof(header)) {
        fclose(f);
        return false;
    }

    if (!DeriveMasterKey(master_password, master_key, salt)) {
        fclose(f);
        return false;
    }

    crypto_secretstream_xchacha20poly1305_state state;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header, master_key) != 0) {
        fclose(f);
        return false;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f) - (long)sizeof(salt) - (long)sizeof(header);
    if (file_size <= 0) {
        fclose(f);
        return false;
    }
    fseek(f, sizeof(salt) + sizeof(header), SEEK_SET);

    unsigned char *encrypted = malloc((size_t)file_size);
    if (!encrypted) {
        fclose(f);
        return false;
    }
    if (fread(encrypted, 1, (size_t)file_size, f) != (size_t)file_size) {
        free(encrypted);
        fclose(f);
        return false;
    }
    fclose(f);

    unsigned char decrypted[8192] = {0};
    unsigned long long decrypted_len = 0;
    unsigned char tag;

    if (crypto_secretstream_xchacha20poly1305_pull(&state,
                                                   decrypted, &decrypted_len, &tag,
                                                   encrypted, (unsigned long long)file_size,
                                                   NULL, 0) != 0) {
        free(encrypted);
        printf("[LOAD CONFIG FILE] Wrong master-password or corrupted file.\n");
        return false;
    }
    free(encrypted);

    // Обнуляем структуру
    memset(cfg, 0, sizeof(Config));
    cfg->isFirstUsed = true;
    cfg->userId = 0;

    char *saveptr = NULL;
    char *line = strtok_r((char *)decrypted, "\n", &saveptr);
    while (line) {
        char *eq = strchr(line, '=');
        if (eq) {
            *eq = '\0';
            const char *key = line;
            const char *value = eq + 1;

            if (strcmp(key, "isFirstUsed") == 0) {
                cfg->isFirstUsed = (strcmp(value, "true") == 0);
            } else if (strcmp(key, "userId") == 0) {
                cfg->userId = strtol(value, NULL, 10);
            } else if (strcmp(key, "userName") == 0) {
                strncpy(cfg->userName, value, MAX_NAME - 1);
            } else if (strcmp(key, "email") == 0) {
                strncpy(cfg->email, value, MAX_EMAIL - 1);
            } else if (strcmp(key, "passwordHash") == 0) {
                strncpy(cfg->passwordHash, value, SHA256_DIGEST_LENGTH - 1);
            } else if (strcmp(key, "avatarUrl") == 0) {
                strncpy(cfg->avatarUrl, value, MAX_AVATAR - 1);
            } else if (strcmp(key, "profileDescription") == 0) {
                strncpy(cfg->profileDescription, value, MAX_DESC - 1);
            }
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }
    return true;
}

bool SaveEncryptedConfig(Config *cfg, const char *master_password) {
    unsigned char salt[SALT_SIZE] = {0};
    unsigned char master_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char header[HEADER_SIZE];

    // Всегда генерируем новый salt при сохранении (или читаем старый — как вам удобнее)
    // Здесь оставляем логику "если файл есть — берём старый salt"
    if (FileExists(CONFIG_FILE)) {
        FILE *old = fopen(CONFIG_FILE, "rb");
        if (!old || fread(salt, 1, sizeof(salt), old) != sizeof(salt)) {
            if (old) fclose(old);
            randombytes_buf(salt, sizeof(salt));
        } else {
            fclose(old);
        }
    } else {
        randombytes_buf(salt, sizeof(salt));
    }

    FILE *f = fopen(CONFIG_FILE, "wb");
    if (!f) return false;

    fwrite(salt, 1, sizeof(salt), f);

    if (!DeriveMasterKey(master_password, master_key, salt)) {
        printf("[SAVE ENCRYPTED CONFIG] Error generating key.\n");
        fclose(f);
        return false;
    }

    // Собираем текст конфига
    char temp_config[16384] = {0};
    snprintf(temp_config, sizeof(temp_config),
             "isFirstUsed=%s\n"
             "userId=%ld\n"
             "userName=%s\n"
             "email=%s\n"
             "passwordHash=%s\n"
             "avatarUrl=%s\n"
             "profileDescription=%s\n",
             cfg->isFirstUsed ? "true" : "false",
             cfg->userId,
             cfg->userName,
             cfg->email,
             cfg->passwordHash,
             (cfg->avatarUrl[0] == '\0' ? "null" : cfg->avatarUrl),
             cfg->profileDescription);

    crypto_secretstream_xchacha20poly1305_state state;
    crypto_secretstream_xchacha20poly1305_init_push(&state, header, master_key);
    fwrite(header, 1, sizeof(header), f);

    unsigned char out_buf[16384 + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned long long out_len;

    if (crypto_secretstream_xchacha20poly1305_push(
            &state, out_buf, &out_len,
            (unsigned char *)temp_config, strlen(temp_config),
            NULL, 0,
            crypto_secretstream_xchacha20poly1305_TAG_FINAL) != 0) {
        fclose(f);
        return false;
    }

    fwrite(out_buf, 1, out_len, f);
    fclose(f);

    printf("[SAVE ENCRYPTED CONFIG] Saved config to file.\n");
    return true;
}

// ====================== Консольный интерфейс ======================

void print_config(const Config *cfg) {
    printf("\n========== ТЕКУЩИЙ КОНФИГ ==========\n");
    printf("isFirstUsed        : %s\n", cfg->isFirstUsed ? "true" : "false");
    printf("userId             : %ld\n", cfg->userId);
    printf("userName           : %s\n", cfg->userName);
    printf("email              : %s\n", cfg->email);
    printf("passwordHash       : %s\n", cfg->passwordHash);
    printf("avatarUrl          : %s\n", cfg->avatarUrl[0] ? cfg->avatarUrl : "(пусто)");
    printf("profileDescription : %s\n", cfg->profileDescription[0] ? cfg->profileDescription : "(пусто)");
    printf("====================================\n\n");
}

void set_string_field(char *dest, size_t max_len, const char *prompt) {
    printf("%s", prompt);
    char buf[1024];
    if (fgets(buf, sizeof(buf), stdin)) {
        buf[strcspn(buf, "\n")] = 0;
        strncpy(dest, buf, max_len - 1);
        dest[max_len - 1] = '\0';
    }
}

void edit_menu(Config *cfg) {
    int choice;
    do {
        print_config(cfg);
        printf("Что изменить?\n");
        printf("1. isFirstUsed\n");
        printf("2. userId\n");
        printf("3. userName\n");
        printf("4. email\n");
        printf("5. passwordHash\n");
        printf("6. avatarUrl\n");
        printf("7. profileDescription\n");
        printf("0. Назад\n");
        printf("Выбор: ");
        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n');
            continue;
        }
        while (getchar() != '\n'); // очистка буфера

        switch (choice) {
            case 1: {
                printf("isFirstUsed (1 = true, 0 = false): ");
                int v;
                if (scanf("%d", &v) == 1) cfg->isFirstUsed = (v != 0);
                while (getchar() != '\n');
                break;
            }
            case 2: {
                printf("userId: ");
                long v;
                if (scanf("%ld", &v) == 1) cfg->userId = v;
                while (getchar() != '\n');
                break;
            }
            case 3:
                set_string_field(cfg->userName, MAX_NAME, "userName: ");
                break;
            case 4:
                set_string_field(cfg->email, MAX_EMAIL, "email: ");
                break;
            case 5:
                set_string_field(cfg->passwordHash, SHA256_DIGEST_LENGTH, "passwordHash: ");
                break;
            case 6:
                set_string_field(cfg->avatarUrl, MAX_AVATAR, "avatarUrl: ");
                break;
            case 7:
                set_string_field(cfg->profileDescription, MAX_DESC, "profileDescription: ");
                break;
        }
    } while (choice != 0);
}

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "Не удалось инициализировать libsodium\n");
        return 1;
    }

    char master_password[256];
    printf("Введите master-password: ");
    if (!fgets(master_password, sizeof(master_password), stdin)) {
        return 1;
    }
    master_password[strcspn(master_password, "\n")] = 0;

    Config cfg = {0};
    cfg.isFirstUsed = true;

    bool loaded = LoadEncryptedConfig(&cfg, master_password);
    if (!loaded) {
        printf("Конфиг не загружен. Создаём новый.\n");
        // Можно задать значения по умолчанию
        strcpy(cfg.userName, "NewUser");
        strcpy(cfg.email, "user@example.com");
        strcpy(cfg.passwordHash, "dummyhash");
        strcpy(cfg.avatarUrl, "");
        strcpy(cfg.profileDescription, "");
    }

    int choice;
    do {
        printf("\n=== МЕНЮ ===\n");
        printf("1. Показать конфиг\n");
        printf("2. Изменить конфиг\n");
        printf("3. Сохранить конфиг\n");
        printf("0. Выход\n");
        printf("Выбор: ");
        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n');
            continue;
        }
        while (getchar() != '\n');

        switch (choice) {
            case 1:
                print_config(&cfg);
                break;
            case 2:
                edit_menu(&cfg);
                break;
            case 3:
                if (SaveEncryptedConfig(&cfg, master_password)) {
                    printf("Конфиг успешно сохранён.\n");
                } else {
                    printf("Ошибка при сохранении.\n");
                }
                break;
        }
    } while (choice != 0);

    sodium_memzero(master_password, sizeof(master_password));
    return 0;
}