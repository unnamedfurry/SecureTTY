//
// Created by unnamedfurry on 8/30/26.
//

#include <stddef.h>
#include <string.h>

#include "shared-variables.h"

// Decrypting received message
bool DecryptPacket(const char* encrypted_packet, char* out_plaintext, size_t max_out_size) {
    if (strncmp(encrypted_packet, "enc:", 4) != 0) {
        // Not encrypted
        strncpy(out_plaintext, encrypted_packet, max_out_size - 1);
        out_plaintext[max_out_size - 1] = '\0';
        return true;
    }

    // Format: enc:nonce_b64:ciphertext_b64
    char *nonce_b64 = strtok((char*)(encrypted_packet + 4), ":");
    char *ct_b64 = strtok(nullptr, ":");

    if (!nonce_b64 || !ct_b64) return false;

    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    unsigned char ciphertext[PACKET_SIZE-256];
    size_t nonce_len = 0, ct_len = 0;

    // Converting text into binary variables
    if (sodium_base642bin(nonce, sizeof(nonce), nonce_b64, strlen(nonce_b64), nullptr, &nonce_len, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0 ||
        nonce_len != sizeof(nonce) ||
        sodium_base642bin(ciphertext, sizeof(ciphertext), ct_b64, strlen(ct_b64), nullptr, &ct_len, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0 ||
        ct_len < crypto_aead_xchacha20poly1305_ietf_ABYTES) return false;

    unsigned char decrypted[PACKET_SIZE-256] = {0};
    unsigned long long decrypted_len;
    int returnValue;

    // Decrypting packet
    returnValue = crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, &decrypted_len,
            nullptr,
            ciphertext, ct_len,
            nullptr, 0, nonce, clientSessionKey);

    if (returnValue != 0) {
        printf("[DECRYPT] Error decrypting or bad key.\n");
        return false;
    }

    strncpy(out_plaintext, (char*)decrypted, max_out_size - 1);
    out_plaintext[max_out_size - 1] = '\0';
    return true;
}

// Encrypting key before sending
bool EncryptPacket(const char* plaintext, char* out_ciphertext, size_t max_out_size) {

    if (!hasSessionKey) {
        // If key isnt set yet - sending as it is
        strncpy(out_ciphertext, plaintext, max_out_size - 1);
        out_ciphertext[max_out_size - 1] = '\0';
        return true;
    }

    // Salt for message
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    memset(nonce, 0, sizeof(nonce));
    randombytes_buf(nonce, sizeof(nonce));

    // Encoded message itself
    size_t len = strlen(plaintext);
    unsigned char ciphertext[len + crypto_aead_xchacha20poly1305_ietf_ABYTES + 64];
    memset(ciphertext, 0, sizeof(ciphertext));
    unsigned long long ciphertext_len;

    // Encoding message
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, &ciphertext_len,
            (const unsigned char*)plaintext, len,
            nullptr, 0, nullptr, nonce, clientSessionKey) != 0) {
        return false;
            }

    // Formatting nonce + ciphertext in base64
    char nonce_b64[128] = {0};
    char ct_b64[524160] = {0};

    // Converting binary to base64
    sodium_bin2base64(nonce_b64, sizeof(nonce_b64), nonce, sizeof(nonce), sodium_base64_VARIANT_ORIGINAL);
    sodium_bin2base64(ct_b64, sizeof(ct_b64), ciphertext, ciphertext_len, sodium_base64_VARIANT_ORIGINAL);

    snprintf(out_ciphertext, max_out_size, "enc:%s:%s", nonce_b64, ct_b64);
    return true;
}