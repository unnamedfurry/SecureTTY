//
// Created by unnamedfurry on 8/30/26.
//

#include <string.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/types.h>

// Shared variables and methods
#include "shared-variables.h"

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

bool appendf(char *buf, size_t size, size_t *off, const char *fmt, ...) {
    size_t o = *off;                          // дальше обычная арифметика
    if (o >= size) return false;
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf + o, size - o, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= size - o) {
        buf[o] = '\0';                        // откат: выбрасываем обрезанный хвост
        return false;                         // *off не меняем
    }
    *off = o + (size_t)n;
    return true;
}

void bytes_to_hex_string(const uint8_t *hash_bytes, char *output_buffer) {
    for (int i = 0; i < BLAKE3_OUT_LEN; i++) {
        // %02x converts 1 byte into 2 hexadecimal characters (e.g., 15 -> "0f")
        // Writing occurs at offset i * 2 in your buffer
        sprintf(output_buffer + (i * 2), "%02x", hash_bytes[i]);
    }
    // Make sure to null-terminate the string so that functions like printf or strlen work correctly
    output_buffer[BLAKE3_OUT_LEN * 2] = '\0';
}

void get_blake3_hash(const char *input, size_t input_len, uint8_t output[BLAKE3_OUT_LEN]) {
    blake3_hasher hasher;

    // Initializing hasher
    blake3_hasher_init(&hasher);

    // Transmit data (size strictly in bytes; suitable for binary packets)
    blake3_hasher_update(&hasher, input, input_len);

    // Export the final hash
    blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);
}