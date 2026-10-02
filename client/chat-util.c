//
// Created by unnamedfurry on 10/2/26.
//

#include <stdio.h>
#include <sys/stat.h>
#include "shared-variables.h"

extern void sendMessage(const char *message);

int UploadFile(char* filePath) {

    // Checking file existence and size
    struct stat st;
    long long fileSize = 0;

    if (stat(filePath, &st) == 0) {
        fileSize = st.st_size;
    } else {
        return -1;
    }

    char packet[70] = {0};
    snprintf(packet, 70, "check-space/%lld", fileSize);
    sendMessage(packet);

    if (canUploadFile) {

        FILE *file = fopen(filePath, "rb");
        if (file == NULL) return -1;


        fclose(file);
    } else {
        return -2;
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
 * второй пакет -                              uploadFileInfo/имя-файла/размер-следующего-чанка/общий-размер-пакета (чанк = 10 частей * 10 мбайт)
 * третий пакет -                              uploadFileData/бинарные-данные
 * ...
 * тринадцатый пакет (первый чанк passed) -    uploadFileCheck/ -> ожидание -> сравнение -> переотправка на ошибке
 * четырнадцатый пакет -                       uploadFileInfo/имя-файла/размер-следующего-чанка/общий-размер-пакета
 * пятнадцатый пакет (второй чанк начался) -   uploadFileData/бинарные-данные
 * ...
 * до конца
 */