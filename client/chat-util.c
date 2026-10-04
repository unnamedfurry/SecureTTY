//
// Created by unnamedfurry on 10/2/26.
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "blake3.h"
#include "shared-variables.h"

extern void sendMessage(const char *message);
extern void get_blake3_hash(const char *input, size_t input_len, uint8_t output[BLAKE3_OUT_LEN]);
extern void bytes_to_hex_string(const uint8_t *hash_bytes, char *output_buffer);
extern bool sendBinaryMessage(unsigned char *data, uint32_t size);

struct stat st;
size_t offset = 0;
size_t fileSize = 0;
int steps = 1;
int progress = 0;
int packetSize = 5 * 1024 * 1024;

int UploadFile(char* filePath) {

    // Checking file existence and size
    if (stat(filePath, &st) == 0) {
        fileSize = st.st_size;
        if (fileSize == 0) {
            return -3;
        }
    } else {
        return -1;
    }

    char requestPacket[42] = {0};
    snprintf(requestPacket, 42, "check-space/%lu", fileSize);
    sendMessage(requestPacket);

    if (canUploadFile) {

        FILE *file = fopen(filePath, "rb");
        if (file == NULL) return -1;

        // If file is smaller than default chunk size,
        // we shrink it to match file size
        // And we also should calculate how many packets we will be sending to server
        size_t chunkSize = packetSize;
        if (fileSize < chunkSize) chunkSize=fileSize;
        steps = (int)((fileSize + chunkSize - 1) / chunkSize);

        // Uploading name, next chunk size and general file size
        char infoPacket[256] = {0};
        char *last_slash = strrchr(filePath, '/');
        char *name = last_slash ? last_slash + 1 : filePath;
        snprintf(infoPacket, 256, "uploadFileInfo/%d/%lu/%lu/%s", steps, chunkSize, fileSize, name);
        sendMessage(infoPacket);

        unsigned char *packet = malloc(15 + chunkSize);
        if (!packet) { fclose(file); return -2; }

        for (int i = 0; i < steps; i++) {
            memcpy(packet, "uploadFileData/", 15);

            size_t n = fread(packet + 15, 1, chunkSize, file);
            if (n == 0) break;

            if (!sendBinaryMessage(packet, 15 + n)) {
                free(packet); fclose(file); return -4;
            }
            offset += n;

            uint8_t raw_hash[BLAKE3_OUT_LEN];
            char hashHex[BLAKE3_OUT_LEN * 2 + 1];
            get_blake3_hash((const char*)packet + 15, n, raw_hash);
            bytes_to_hex_string(raw_hash, hashHex);

            char checkPacket[128];
            snprintf(checkPacket, sizeof checkPacket, "uploadFileCheck/%zu,%s", n, hashHex);
            sendMessage(checkPacket);

            memset(packet, 0, 15+chunkSize);
        }
        free(packet);
        fclose(file);

        fclose(file);
    } else {
        return 1;
    }

    return 0;
}

/**
 * Концепт:
 * чел хочет загрузить файл -> ищем файл по пути -> читаем размер ->
 * -> спрашиваем у сервера про свободное место -> на ответе да читаем binary data, шифруем и шлем как есть без b64 ->
 * -> после 10 кусков спрашиваем у сервера можно ли отправить еще -> на ответе да отправляем следующие 10 кусков
 *
 * Структура пакетов:
 * первый пакет (проверка памяти сервера) -    check-space/fileSize -> ожидание
 * второй пакет -                              uploadFileInfo/имя-файла/количество-оставшихся-шагов/размер-следующего-чанка/общий-размер-файла (чанк = 10 частей * 5 мбайт)
 * третий пакет -                              uploadFileData/бинарные-данные
 * ...
 * тринадцатый пакет (первый чанк passed) -    uploadFileCheck/howManyReceived,giveHash -> ожидание -> сравнение -> переотправка на ошибке
 * четырнадцатый пакет -                       uploadFileInfo/имя-файла/количество-оставшихся-шагов/размер-следующего-чанка/общий-размер-файла
 * пятнадцатый пакет (второй чанк начался) -   uploadFileData/бинарные-данные
 * ...
 * до конца
 *
 * Коды:
 * 0 - завершили отправку без ошибок
 * 1 - ожидаем разрешения на отправку от сервера
 * -1 - файл не найден / не получается открыть
 * -2 - ошибка выделения памяти
 * -3 - файл пустой
 * -4 - ошибка сети
 */