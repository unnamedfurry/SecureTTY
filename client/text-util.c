//
// Created by unnamedfurry on 8/27/26.
//

#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/types.h>

#include "raylib.h"

static void appendText(char *dst, size_t cap, const char *src) {
    size_t used = strlen(dst);
    if (used < cap - 1) snprintf(dst + used, cap - used, "%s", src);
}

int WrapText(const char* text, char* output, int maxOutputSize, int maxLineWidth,
             Font font, float fontSize, float spacing){
    if (!text || !output || maxOutputSize <= 0) return 0;

    output[0] = '\0';
    int totalHeight = 0;
    char currentLine[1024] = {0};

    const char* p = text;

    while (*p) {
        // skipping \n
        if (*p == '\n') {
            appendText(output, maxOutputSize, currentLine);
            appendText(output, maxOutputSize, "\n");
            totalHeight += (int)fontSize + 6;
            currentLine[0] = '\0';
            p++;
            continue;
        }

        // finding next word or chunk before space
        const char* wordStart = p;
        while (*p && *p != ' ' && *p != '\n') p++;
        int wordLen = (int)(p - wordStart);
        if (wordLen > 511) wordLen = 511;

        char word[512] = {0};
        if (wordLen > 0) {
            strncpy(word, wordStart, wordLen < 511 ? wordLen : 511);
        }

        // checking if the word is not crossing chat area
        char testLine[1024];
        if (currentLine[0] == '\0') {
            strcpy(testLine, word);
        } else {
            snprintf(testLine, sizeof(testLine), "%s %s", currentLine, word);
        }

        Vector2 size = MeasureTextEx(font, testLine, fontSize, spacing);

        if (size.x > (float)maxLineWidth) {
            // if the solid word is going out of bounds -> we cut it
            if (currentLine[0] != '\0') {
                appendText(output, maxOutputSize, currentLine);
                appendText(output, maxOutputSize, "\n");
                totalHeight += (int)fontSize + 6;
                currentLine[0] = '\0';
            }

            // slicing the long world by symbols
            if (wordLen > 0) {
                float accumulatedWidth = 0.0f;
                char temp[2] = {0};

                for (int i = 0; i < wordLen; i++) {
                    temp[0] = word[i];
                    float charWidth = MeasureTextEx(font, temp, fontSize, spacing).x;

                    if (accumulatedWidth + charWidth > (float)maxLineWidth && accumulatedWidth > 0) {
                        appendText(output, maxOutputSize, currentLine);
                        appendText(output, maxOutputSize, "\n");
                        totalHeight += (int)fontSize + 6;
                        currentLine[0] = '\0';
                        accumulatedWidth = 0;
                    }

                    appendText(currentLine, sizeof(currentLine), temp);
                    accumulatedWidth += charWidth;
                }
            }
        } else {
            snprintf(currentLine, sizeof(currentLine), "%s", testLine);
        }

        if (*p == ' ') p++; // skipping space
    }

    // appending last line
    if (currentLine[0] != '\0') {
        appendText(output, maxOutputSize, currentLine);
        totalHeight += (int)fontSize + 6;
    }

    return totalHeight;
}

// simplified wrapped text drawer
void DrawWrappedText(const char* text, Vector2 pos, Font font, float fontSize, float spacing, Color color){
    char line[1024] = {0};
    Vector2 currentPos = pos;

    for (const char* p = text; *p; ++p) {
        if (*p == '\n') {
            if (line[0]) {
                DrawTextEx(font, line, currentPos, fontSize, spacing, color);
            }
            currentPos.y += fontSize + 6;
            line[0] = '\0';
        } else {
            int len = (int)strlen(line);
            if (len < 1023) {
                line[len] = *p;
                line[len + 1] = '\0';
            }
        }
    }

    if (line[0]) {
        DrawTextEx(font, line, currentPos, fontSize, spacing, color);
    }
}

void DrawTextBoxed(Font font, const char *text, Rectangle container, float fontSize, float spacing, Color tint) {
    int length = (int)TextLength(text);
    float scaleFactor = fontSize / (float)font.baseSize;

    float cursorX = 0.0f;
    float cursorY = 0.0f;

    for (int i = 0; i < length; i++) {
        int byteSize = 0;
        int codepoint = GetCodepoint(&text[i], &byteSize);
        int index = GetGlyphIndex(font, codepoint);

        // Handle Manual Newlines
        if (codepoint == '\n') {
            cursorY += ((float)font.baseSize + (float)font.baseSize / 2) * scaleFactor;
            cursorX = 0;
        } else {
            // Automatic Word Wrap Check
            if ((cursorX + ((float)font.glyphs[index].advanceX * scaleFactor)) > container.width) {
                cursorY += ((float)font.baseSize + (float)font.baseSize / 2) * scaleFactor;
                cursorX = 0;
            }

            // Draw character if it fits within the vertical bounds
            if ((cursorY + ((float)font.baseSize * scaleFactor)) <= container.height) {
                DrawTextCodepoint(font, codepoint, (Vector2){ container.x + cursorX, container.y + cursorY }, fontSize, tint);
            }

            // Advance cursor
            if (font.glyphs[index].advanceX == 0) cursorX += ((float)font.recs[index].width * scaleFactor + spacing);
            else cursorX += ((float)font.glyphs[index].advanceX * scaleFactor + spacing);
        }
        i += (byteSize - 1);
    }
}

// Base64 decode through OpenSSL
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

    char* output = (char*)malloc(bufferPtr->length + 1);
    memcpy(output, bufferPtr->data, bufferPtr->length);
    output[bufferPtr->length] = '\0';

    BIO_free_all(bio);
    return output;
}
unsigned char* Base64Decode(const char* input, int* out_len) {
    BIO *bio, *b64;
    int input_len = (int)strlen(input);

    unsigned char* output = (unsigned char*)malloc(input_len * 3 / 4 + 1);
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