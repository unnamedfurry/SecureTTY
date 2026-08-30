//
// Created by unnamedfurry on 8/30/26.
//

#include <stdio.h>
#include <string.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>

// Shared variables and methods
#include "shared-variables.h"

// Decrypting received packet
bool DecryptPacket(unsigned char serverSessionKey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES], const char* input, char* out_plain, size_t max_size) {
    if (!serverSessionKey || !input || !out_plain || max_size < 2) return false;
    if (strncmp(input, "enc:", 4) != 0) {
        strncpy(out_plain, input, max_size - 1);
        out_plain[max_size - 1] = '\0';
        return true;
    }

    char *nonce_b64 = strtok((char*)(input + 4), ":");
    char *ct_b64 = strtok(nullptr, ":");

    if (!nonce_b64 || !ct_b64) return false;

    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    unsigned char ct[PACKET_SIZE/2];
    size_t nlen = 0, clen = 0;

    if (sodium_base642bin(nonce, sizeof(nonce), nonce_b64, strlen(nonce_b64), nullptr, &nlen, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0 ||
        nlen != sizeof(nonce) ||
        sodium_base642bin(ct, sizeof(ct), ct_b64, strlen(ct_b64), nullptr, &clen, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0 ||
        clen < crypto_aead_xchacha20poly1305_ietf_ABYTES) return false;

    unsigned char decrypted[PACKET_SIZE] = {0};
    unsigned long long decrypted_len;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, &decrypted_len, nullptr,
            ct, clen, nullptr, 0, nonce, serverSessionKey) != 0) {
        return false;
            }

    strncpy(out_plain, (char*)decrypted, max_size - 1);
    out_plain[max_size - 1] = '\0';
    return true;
}

// Encrypting packet to client
bool EncryptPacket(ClientSession *session, const char* plaintext, char* out_buffer, size_t max_size) {
    if (!session || !plaintext || !out_buffer || max_size < 2) return false;
    if (!session->hasSessionKey) {
        if (strncmp(plaintext, "keyexchange_ok/", 15) == 0) {
            session->hasSessionKey=true;
        }
        strncpy(out_buffer, plaintext, max_size - 1);
        out_buffer[max_size - 1] = '\0';
        return true;
    }

    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    size_t len = strlen(plaintext);
    unsigned char ct[len + crypto_aead_xchacha20poly1305_ietf_ABYTES + 32];
    unsigned long long ct_len;

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(ct, &ct_len,
            (const unsigned char*)plaintext, len,
            nullptr, 0, nullptr, nonce, session->serverSessionKey) != 0) {
        return false;
            }

    char nonce_b64[128], ct_b64[PACKET_SIZE/2];
    sodium_bin2base64(nonce_b64, sizeof(nonce_b64), nonce, sizeof(nonce), sodium_base64_VARIANT_ORIGINAL);
    sodium_bin2base64(ct_b64, sizeof(ct_b64), ct, ct_len, sodium_base64_VARIANT_ORIGINAL);

    snprintf(out_buffer, max_size, "enc:%s:%s", nonce_b64, ct_b64);
    return true;
}