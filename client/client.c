#include "raylib.h"
#define RAYGUI_IMPLEMENTATION
#include "raygui.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/buffer.h>
#include "client.h"
#include <sodium.h>

// VARIABLES AND FUNCTIONS
#include "shared-variables.h"
extern bool initNetwork(void);
extern void sendMessage(const char *message);
extern bool LoadEncryptedConfig(Config *cfg, const char* master_password);
extern bool SaveEncryptedConfig(Config *cfg, const char* master_password);
extern void DrawTextBoxed(Font font, const char *text, Rectangle container, float fontSize, float spacing, Color tint);
extern void DrawWrappedText(const char* text, Vector2 pos, Font font, float fontSize, float spacing, Color color);
extern char* Base64Encode(const unsigned char* input, int length);
extern char* Base64Decode(const unsigned char* input, int length);
extern int WrapText(const char* text, char* output, int maxOutputSize, int maxLineWidth,
                    Font font, float fontSize, float spacing);
extern float clamp(float val, float min, float max);
extern char* GuiFileSelector(Rectangle bounds, char *text, Font font, Color primaryColor, Color secondaryColor, Color textColor);


// GLOBAL VARIABLES
typedef enum {
    STATE_MASTER_PASSWORD,
    STATE_FIRST_SETUP,
    STATE_MAIN_CHAT
} AppState;
AppState currentState = STATE_MASTER_PASSWORD;
Font font;
char *path2 = nullptr;
bool userAgreed = false;
bool wrongPass = false;
bool loggedIn = false;
bool passwordSecretMode = true;
bool sendsMessage = false;
int currentInputField = -1;
int profilePage = 1;
int warningTimer = 5000;
int activeField=-1;
// Scroll
float chatScrollOffset = 0.0f;
float chatScrollVelocity = 0.0f;    // inertion speed
float chatSrollFriction = 0.92f;    // fade out timne (0.85 - hard, 0.94 - soft)
float friendScrollOffset = 0.0f;
float friendScrollVelocity = 0.0f;
float friendSrollFriction = 0.92f;
float chatContentHeight = 0.0f;
float friendContentHeight = 0.0f;
bool chatAutoScrollAllowed = true;
bool chatIsDraggingScrollbar = false;
bool friendIsDraggingScrollbar = false;
Rectangle sliderBox = {201, 601, 98, 98};

int MasterPasswordState() {
    initedNetwork = initNetwork();

    DrawTextEx(font, "Мастер-пароль приложения:", (Vector2){480, 100}, 48, 2, mainColor);
    // If user ensures his password is strong
    // by dragging slider, we switch to
    // password input state
    if (userAgreed==false) {
        Rectangle sliderRail = {200, 600, 1200, 100};
        DrawRectangleLinesEx(sliderRail, 2, mainColor);

        if (CheckCollisionPointRec(GetMousePosition(), sliderBox)) {
            if (IsMouseButtonDown(MOUSE_BUTTON_LEFT)) {
                // Moving slider box to align
                // with mouse position on X axis
                sliderBox.x = GetMousePosition().x-48;
                if (sliderBox.x < 201) sliderBox.x = 201;
                if (sliderBox.x > 1298) userAgreed=true;
            } else {
                // If user released button,
                // we send box to start
                sliderBox.x = 201;
            }
        }
        // Mini Terms Of Service
        DrawTextEx(font, "пароль сильный и хранится только у меня", (Vector2){470, 632}, 32, 2, secondaryColor);
        DrawRectangleRec(sliderBox, mainColor);
        DrawRectangleLinesEx(sliderBox, 2, mainColor);
        GuiDrawIcon(115, (int)sliderBox.x+16, (int)sliderBox.y+16, 4, secondaryColor);
        DrawRectangle(201, 601, ((int)sliderBox.x - 201), 98, secondaryColor);
    } else {
        // Password input box
        if (GuiPasswordBox((Rectangle){200, 600, 1200, 100}, masterPassword, MAX_PASS, currentInputField==1)) {
            currentInputField = (currentInputField == 1) ? -1 : 1;
            wrongPass=false;
        }
        if (IsKeyPressed(KEY_ENTER)) {
            // If password is too short we dont accept it
            if (strlen(masterPassword)>5) {
                // Checking if config file exists
                if (FileExists(CONFIG_FILE)) {
                    // Loading config using password user just typed
                    if (LoadEncryptedConfig(&config, masterPassword)) {
                        // Zeroing all values from possible garbage
                        memset(friends, 0, sizeof(friends));
                        memset(pendingFriends, 0, sizeof(pendingFriends));

                        // If config has valid data we attempt login
                        if (config.isFirstUsed==false && config.userId != 0) {
                            char msgBuf[BUFFER_SIZE] = {0};
                            snprintf(msgBuf, sizeof(msgBuf), "login/%ld\x1E%s\x1E%s", config.userId, config.email, config.passwordHash);
                            sendMessage(msgBuf);
                            loggedIn=true;

                            // Checking if client established secure connection
                            // before requesting sensitive data
                            if (hasSessionKey) {
                                memset(msgBuf, 0, BUFFER_SIZE);
                                snprintf(msgBuf, sizeof(msgBuf), "getFriendsList/%ld", config.userId);
                                sendMessage(msgBuf);
                                memset(msgBuf, 0, sizeof(msgBuf));
                                snprintf(msgBuf, sizeof(msgBuf), "updateClient/%ld", config.userId);
                                sendMessage(msgBuf);
                            } else {
                                // exiting the cycle and jumping to draw end
                                return 1;
                            }
                            currentState=STATE_MAIN_CHAT;
                        } else {
                            // Preparing app for user profile creation
                            printf(cYELLOW "[WARN]" RESET "[APP INIT] User ID is 0.\n");
                            strcpy(config.userName, "");
                            strcpy(config.email, "");
                            strcpy(config.passwordHash, "");
                            strcpy(config.profileDescription, "");
                            config.isFirstUsed=true;
                            currentState=STATE_FIRST_SETUP;
                        }
                    } else {
                        wrongPass=true;
                    }
                } else {
                    // Switch to fist setup directly
                    memset(friends, 0, sizeof(friends));
                    memset(pendingFriends, 0, sizeof(pendingFriends));
                    currentState=STATE_FIRST_SETUP;
                    return 1;
                }
            }
        }
    }
    if (wrongPass==true) {
        DrawTextEx(font, "Неправильный пароль.", (Vector2){630, 500}, 32, 2, RED);
        currentInputField=-1;
    }

    // Lost connection warning
    if (initedNetwork == false || connected == false) {
        Rectangle networkErrorRec = {1, 350, 1600, 200};
        Color accentPlateColor = {255, 79, 79, 255};
        Color backgroundPlateColor = {255, 157, 157, 255};

        // Full-screen warning line
        DrawRectangleRec(networkErrorRec, backgroundPlateColor);
        DrawRectangleLinesEx(networkErrorRec, 2, accentPlateColor);
        DrawTextEx(font, "Потеряно соединение с сервером!", (Vector2){330, 430}, 60, 2, RED);
    }

    if (serverErrorCode == 1) { // Server is busy
        if (warningTimer > 1) {
            Rectangle warningRec = {1352, 16, 232, 40};
            Color accentPlateColor = {255, 79, 79, 255};
            Color backgroundPlateColor = {255, 157, 157, 255};

            DrawRectangleRec(warningRec, backgroundPlateColor);
            DrawRectangleLinesEx(warningRec, 2, accentPlateColor);

            // Hiding alert manually
            if (CheckCollisionPointRec(GetMousePosition(), warningRec)) {
                if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON) || IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
                    warningTimer=5000;
                    serverErrorCode=-1;
                }
            }
            DrawTextEx(font, "Сервер занят", (Vector2){warningRec.x+14, warningRec.y+8}, 24, 2, RED);
            warningTimer-=1;
        } else {
            // Hiding alert after 15 seconds
            serverErrorCode = -1;
            warningTimer = 5000;
        }
    } else if (serverErrorCode == 2) { // Server got an error
        if (warningTimer > 1) {
            Rectangle warningRec = {1352, 16, 268, 40};
            Color accentPlateColor = {255, 79, 79, 255};
            Color backgroundPlateColor = {255, 157, 157, 255};

            DrawRectangleRec(warningRec, backgroundPlateColor);
            DrawRectangleLinesEx(warningRec, 2, accentPlateColor);

            // Hiding alert manually
            if (CheckCollisionPointRec(GetMousePosition(), warningRec)) {
                if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON) || IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
                    warningTimer=5000;
                    serverErrorCode=-1;
                }
            }
            DrawTextEx(font, "Ошибка сервера", (Vector2){warningRec.x+14, warningRec.y+8}, 24, 2, RED);
            warningTimer-=1;
        } else {
            // Hiding alert after 15 seconds
            serverErrorCode = -1;
            warningTimer = 5000;
        }
    }
    return 0;
}

int FirstSetupState() {
    // Welcome message
    DrawTextEx(font, "Привет. Пройди настройку профиля:", (Vector2){100, 50}, 40, 3, WHITE);

    // Input fields
    if (GuiTextBox((Rectangle){100, 150, 400, 40}, config.userName, MAX_NAME, activeField==0)) {
        activeField = (activeField == 0) ? -1 : 0;
    }
    if (GuiTextBox((Rectangle){100, 220, 400, 40}, config.email, MAX_EMAIL, activeField==1)) {
                    activeField = (activeField == 1) ? -1 : 1;
    }
    if (GuiTextBox((Rectangle){100, 290, 400, 40}, config.passwordHash, MAX_PASS, activeField==2)) {
        activeField = (activeField == 2) ? -1 : 2;
    }
    if (GuiTextBox((Rectangle){100, 360, 400, 40}, config.profileDescription, MAX_DESC, activeField==3)) {
        activeField = (activeField == 3) ? -1 : 3;
    }

    // Descriptions
    DrawTextEx(font,"Юзернейм", (Vector2){520, 160}, 20, 3, mainColor);
    DrawTextEx(font, "Email", (Vector2){520, 230}, 20, 3, mainColor);
    DrawTextEx(font, "Пароль", (Vector2){520, 300}, 20, 3, mainColor);
    DrawTextEx(font, "Описание профиля (опционально)", (Vector2){520, 370}, 20, 3, mainColor);

    // Register
    if (GuiButton((Rectangle){100, 450, 200, 50}, "Сохранить и продолжить") || IsKeyPressed(KEY_ENTER)) {
        config.isFirstUsed = false;

        // Getting new id from server
        sendMessage("createId/user");
        // Awaiting for responce
        for (int i = 0; i < 2500 && config.userId == 0; i++) {
            usleep(10000);
        }

        // No user id = no further working
        if (config.userId == 0) {
            printf("[CREATE USER ID] Timed out while waiting ID from server. retrying\n");

            // Resetting values in case user restarts app
            connected=false;
            config.isFirstUsed = true;
            return 1;
        }

        // Last preparing
        memset(config.avatarUrl, 0, MAX_AVATAR);
        strncpy(config.avatarUrl, "null", 4);
        if (strlen(config.avatarUrl)==0) strncpy(config.avatarUrl, "null", 4);

        // Save and switch to main state
        SaveEncryptedConfig(&config, masterPassword);
        currentState=STATE_MAIN_CHAT;
    }

    // Lost connection warning
    if (initedNetwork == false || connected == false) {
        Rectangle networkErrorRec = {1, 350, 1600, 200};
        Color accentPlateColor = {255, 79, 79, 255};
        Color backgroundPlateColor = {255, 157, 157, 255};

        // Full-screen warning line
        DrawRectangleRec(networkErrorRec, backgroundPlateColor);
        DrawRectangleLinesEx(networkErrorRec, 2, accentPlateColor);
        DrawTextEx(font, "Потеряно соединение с сервером!", (Vector2){330, 430}, 60, 2, RED);
    }

    if (serverErrorCode == 1) { // Server is busy
        if (warningTimer > 1) {
            Rectangle warningRec = {1352, 16, 232, 40};
            Color accentPlateColor = {255, 79, 79, 255};
            Color backgroundPlateColor = {255, 157, 157, 255};

            DrawRectangleRec(warningRec, backgroundPlateColor);
            DrawRectangleLinesEx(warningRec, 2, accentPlateColor);

            // Hiding alert manually
            if (CheckCollisionPointRec(GetMousePosition(), warningRec)) {
                if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON) || IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
                    warningTimer=5000;
                    serverErrorCode=-1;
                }
            }
            DrawTextEx(font, "Сервер занят", (Vector2){warningRec.x+14, warningRec.y+8}, 24, 2, RED);
            warningTimer-=1;
        } else {
            // Hiding alert after 15 seconds
            serverErrorCode = -1;
            warningTimer = 5000;
        }
    } else if (serverErrorCode == 2) { // Server got and error
        if (warningTimer > 1) {
            Rectangle warningRec = {1352, 16, 268, 40};
            Color accentPlateColor = {255, 79, 79, 255};
            Color backgroundPlateColor = {255, 157, 157, 255};

            DrawRectangleRec(warningRec, backgroundPlateColor);
            DrawRectangleLinesEx(warningRec, 2, accentPlateColor);

            // Hiding alert manually
            if (CheckCollisionPointRec(GetMousePosition(), warningRec)) {
                if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON) || IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
                    warningTimer=5000;
                    serverErrorCode=-1;
                }
            }
            DrawTextEx(font, "Ошибка сервера", (Vector2){warningRec.x+14, warningRec.y+8}, 24, 2, RED);
            warningTimer-=1;
        } else {
            // Hiding alert after 15 seconds
            serverErrorCode = -1;
            warningTimer = 5000;
        }
    }
    return 0;
}

int MainState() {
    // Local variables
    char newDesc[1025] = "";
    char message[2049] = "";
    char userId[15] = "";
    char avatarPathInput[512] = {0};

    bool isAddingFriend = false;
    bool loadedAvatar = false;
    bool fileSelector = false;

    // Loading self avatar
    if (strlen(config.avatarUrl) != 0 && loadedAvatar==false) {
        ssize_t len = readlink("/proc/self/exe", avatarPathInput, 255);
        if (len == -1) {
            printf("[LOAD SELF AVATAR] Readlink /proc/self/exe failed\n");
            avatarPathInput[0] = '\0';
        } else {
            strncpy(avatarPathInput, config.avatarUrl, strlen(config.avatarUrl)+len);
            Image img = LoadImage(avatarPathInput);
            userAvatarTexture = LoadTextureFromImage(img);
            UnloadImage(img);
            printf("[LOAD SELF AVATAR] Current path: %s\n", avatarPathInput);
        }
        loadedAvatar=true;
    }
    if (loggedIn == false) {
        char msgBuf[BUFFER_SIZE] = {0};
        snprintf(msgBuf, sizeof(msgBuf), "login/%ld\x1E%s\x1E%s", config.userId, config.email, config.passwordHash);
        sendMessage(msgBuf);
        loggedIn=true;
    }

    DrawRectangleLines(1, 1, 300, 899, mainColor);
    DrawRectangleLines(301, 1, 1000, 899, mainColor);
    DrawRectangleLines(1301, 1, 299, 899, mainColor);
    DrawLine(1, 40, 1600, 40, mainColor);
    DrawTextEx(font, "Знакомые", (Vector2){87, 10}, 24, 2, mainColor);
    DrawTextEx(font, "Чат", (Vector2){760, 10}, 24, 2, mainColor);
    DrawTextEx(font, "Профиль", (Vector2){1400, 10}, 24, 2, mainColor);
    DrawLine(1, 80, 1600, 80, mainColor);

    if (currentFriendId!=0) {
        if (GuiButton((Rectangle){1310, 45, 30, 30}, "<") && profilePage>1) {
            profilePage--;
        }
        if (GuiButton((Rectangle){1550, 45, 30, 30}, ">") && profilePage<3) {
            profilePage++;
        }
    }
    // Drawing self profile when selected
    if (profilePage == 1) {
        DrawTextEx(font, "Мой профиль", (Vector2){1356, 50}, 24, 2.0f, mainColor);
        // Avatar
        Rectangle avatarRect = {1320, 90, 128, 128};
        DrawRectangleRec(avatarRect, background2Color);
        if (userAvatarTexture.id != 0) {
            DrawTexturePro(userAvatarTexture,
                           (Rectangle){0, 0, 128, 128},
                           avatarRect,
                           (Vector2){0, 0}, 0.0f, WHITE);
        } else {
            DrawRectangleLinesEx(avatarRect, 4, background2Color);
            DrawTextEx(font, "нет\nаватарки", (Vector2){1333, 102}, 24, 2, secondaryColor);
        }
        if (CheckCollisionPointRec(GetMousePosition(), avatarRect) && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
            fileSelector = true;
        }
        // Username
        BeginScissorMode(1460, 100, 120, 36);
        DrawTextEx(font, TextFormat("%s", config.userName), (Vector2){1460, 100}, 32, 1.0f, mainColor);
        EndScissorMode();
        DrawLine(1460, 136, 1580, 136, mainColor);
        // Description
        if (GuiTextBox((Rectangle){1320, 270, 260, 400}, newDesc, MAX_DESC, activeField==4)) {
            activeField = (activeField == 4) ? -1 : 4;
        } else {
            DrawTextBoxed(font, config.profileDescription, (Rectangle){ 1326, 278, 248, 388 }, 20, 1.0f, mainColor);
        }
        // Copy friend invite code
        GuiSetStyle(DEFAULT, TEXT_SIZE, 16);
        if (GuiButton((Rectangle){1320, 230, 250, 30}, "скопировать код дружбы")) {
            char copyToClipboard[13];
            snprintf(copyToClipboard, 12, "%ld", config.userId);
            SetClipboardText(copyToClipboard);
        }
        // Refresh profile button
        GuiSetStyle(DEFAULT, TEXT_SIZE, 24);
        if (GuiButton((Rectangle){1320, 690, 200, 50}, "Обновить")) {
            if (newDesc[0] != 0) {
                newDesc[1024]='\0';
                strcpy(config.profileDescription, newDesc);
                memset(newDesc, 0, sizeof(newDesc));
            }
            SaveEncryptedConfig(&config, masterPassword);
        }
        // Manual avatar path (will be deprecated in next version)
        DrawTextEx(font, "Путь к аватарке:", (Vector2){1320, 760}, 20, 2, mainColor);
        if (path2 == NULL && CheckCollisionPointRec(GetMousePosition(), (Rectangle){1320, 790, 260, 40})) {
            path2 = malloc(255*sizeof(char));
            if (path2 == NULL) {
                printf(cRED "[FATAL]" RESET " Failed to allocate memory for self avatar path, exiting.");
                exit(6);
            }
            memset(path2, 0, 255);
        }
        if (GuiTextBox((Rectangle){1320, 790, 260, 40}, path2, 255, activeField == 7)) {
            activeField = (activeField == 7) ? -1 : 7;
        }
        // Upload avatar button
        if (GuiButton((Rectangle){1320, 840, 200, 50}, "Загрузить")) {
            if (path2 == NULL) {
                path2 = malloc(255*sizeof(char));
                if (path2 == NULL) {
                    printf(cRED "[FATAL]" RESET " Failed to allocate memory for self avatar path, exiting.");
                    free(path2);
                    path2=nullptr;
                    exit(6);
                }
                memset(path2, 0, 255);
            }
            // Checking if path contains atleast
            // one symbol before file extension
            if (strlen(path2) > 5) {
                Image img = LoadImage(path2);

                if (img.data != NULL) {
                    // square 128 by 128
                    int side = (img.width < img.height) ? img.width : img.height;   // taking smallest side

                    // crop to square
                    Rectangle cropRect = {
                        (float)(img.width - side) / 2.0f,      // x
                        (float)(img.height - side) / 2.0f,     // y
                        (float)side,                           // width
                        (float)side                            // height
                    };

                    ImageCrop(&img, cropRect);
                    ImageResize(&img, 128, 128);

                    // saving near config file
                    const char *savePath = TextFormat("avatars/%ld.png", config.userId);

                    // in case folder doesnt exist
                    system("mkdir -p avatars");

                    if (ExportImage(img, savePath)) {
                        printf("[SAVE SELF AVATAR] Avatar was cropped and saved: %s\n", savePath);

                        // updating config
                        snprintf(config.avatarUrl, MAX_AVATAR, "avatars/%ld.png", config.userId);

                        // refreshing texture
                        if (userAvatarTexture.id != 0) UnloadTexture(userAvatarTexture);
                        userAvatarTexture = LoadTextureFromImage(img);

                        SaveEncryptedConfig(&config, masterPassword);        // save and pull to server

                        // Uploading avatar to server
                        // TODO: перенести загрузку в обновление профиля
                        FILE *f = fopen(savePath, "rb");
                        if (f) {
                            fseek(f, 0, SEEK_END);
                            int fileSize = (int)ftell(f);
                            fseek(f, 0, SEEK_SET);

                            unsigned char *pngData = malloc(fileSize);
                            fread(pngData, 1, fileSize, f);
                            fclose(f);

                            char *b64 = Base64Encode(pngData, fileSize);
                            free(pngData);

                            if (b64) {
                                char response1[PACKET_SIZE];
                                snprintf(response1, sizeof(response1), "saveAvatar/%ld\x1E%s", config.userId, b64);
                                sendMessage(response1);
                                free(b64);
                            }
                        }
                    } else {
                        printf("[SAVE SELF AVATAR] Failed to save avatar\n");
                    }

                    UnloadImage(img);
                } else {
                    printf("[SAVE SELF AVATAR] Failed to load image: %s\n", path2);
                }
            }
            memset(path2, 0, 255);
        }
    }

    // Profile status code informer
    if (profileUpdateCode == 0) {
        // Successfully updated

        if (warningTimer > 1) {
            Rectangle warningRec = {1352, 16, 232, 40};
            Color accentPlateColor = {79, 255, 79, 255};
            Color backgroundPlateColor = {157, 255, 157, 255};

            DrawRectangleRec(warningRec, backgroundPlateColor);
            DrawRectangleLinesEx(warningRec, 2, accentPlateColor);

            // Hiding alert manually
            if (CheckCollisionPointRec(GetMousePosition(), warningRec)) {
                if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON) || IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
                    warningTimer=5000;
                    profileUpdateCode=-1;
                }
            }
            DrawTextEx(font, "Успешно обновлен", (Vector2){warningRec.x+14, warningRec.y+8}, 24, 2, RED);
            warningTimer-=1;
        } else {
            // Hiding alert automatically
            profileUpdateCode = -1;
            warningTimer = 5000;
        }

    } else if (profileUpdateCode == 1) {
        // Server got an error

        if (warningTimer > 1) {
            Rectangle warningRec = {1352, 16, 232, 40};
            Color accentPlateColor = {255, 79, 79, 255};
            Color backgroundPlateColor = {255, 157, 157, 255};

            DrawRectangleRec(warningRec, backgroundPlateColor);
            DrawRectangleLinesEx(warningRec, 2, accentPlateColor);

            // Hiding alert manually
            if (CheckCollisionPointRec(GetMousePosition(), warningRec)) {
                if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON) || IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
                    warningTimer=5000;
                    profileUpdateCode=-1;
                }
            }
            DrawTextEx(font, "Ошибка сервера", (Vector2){warningRec.x+14, warningRec.y+8}, 24, 2, RED);
            warningTimer-=1;
        } else {
            // Hiding alert automatically
            profileUpdateCode = -1;
            warningTimer = 5000;
        }

    } else if (profileUpdateCode == 2) {
        // Bad profile syntax

        if (warningTimer > 1) {
            Rectangle warningRec = {1352, 16, 268, 40};
            Color accentPlateColor = {255, 79, 79, 255};
            Color backgroundPlateColor = {255, 157, 157, 255};

            DrawRectangleRec(warningRec, backgroundPlateColor);
            DrawRectangleLinesEx(warningRec, 2, accentPlateColor);

            // Hiding alert manually
            if (CheckCollisionPointRec(GetMousePosition(), warningRec)) {
                if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON) || IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
                    warningTimer=5000;
                    profileUpdateCode=-1;
                }
            }
            DrawTextEx(font, "Плохой синтаксис", (Vector2){warningRec.x+14, warningRec.y+8}, 24, 2, RED);
            warningTimer-=1;
        } else {
            // Hiding alert automatically
            profileUpdateCode = -1;
            warningTimer = 5000;
        }
    }

    // Server error informer
    if (serverErrorCode == 1) { // Server is busy
        if (warningTimer > 1) {
            Rectangle warningRec = {1352, 16, 232, 40};
            Color accentPlateColor = {255, 79, 79, 255};
            Color backgroundPlateColor = {255, 157, 157, 255};

            DrawRectangleRec(warningRec, backgroundPlateColor);
            DrawRectangleLinesEx(warningRec, 2, accentPlateColor);

            // Hiding alert manually
            if (CheckCollisionPointRec(GetMousePosition(), warningRec)) {
                if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON) || IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
                    warningTimer=5000;
                    serverErrorCode=-1;
                }
            }
            DrawTextEx(font, "Сервер занят", (Vector2){warningRec.x+14, warningRec.y+8}, 24, 2, RED);
            warningTimer-=1;
        } else {
            // Hiding alert automatically
            serverErrorCode = -1;
            warningTimer = 5000;
        }
    } else if (serverErrorCode == 2) { // Server got an error
        if (warningTimer > 1) {
            Rectangle warningRec = {1352, 16, 268, 40};
            Color accentPlateColor = {255, 79, 79, 255};
            Color backgroundPlateColor = {255, 157, 157, 255};

            DrawRectangleRec(warningRec, backgroundPlateColor);
            DrawRectangleLinesEx(warningRec, 2, accentPlateColor);

            // Hiding alert manually
            if (CheckCollisionPointRec(GetMousePosition(), warningRec)) {
                if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON) || IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
                    warningTimer=5000;
                    serverErrorCode=-1;
                }
            }
            DrawTextEx(font, "Ошибка сервера", (Vector2){warningRec.x+14, warningRec.y+8}, 24, 2, RED);
            warningTimer-=1;
        } else {
            // Hiding alert automatically
            serverErrorCode = -1;
            warningTimer = 5000;
        }
    }

    // Friend section
    if (friendsCount >= 0) { // Draw if there is atleast one friend
        isUpdatedFriends = false;
        float friendStartY = 90.0f;

        for (int i=0; i<=friendsCount && i<100 && friends[i].userId != 0; i++) {
            Rectangle friendRect = { 6, friendStartY, 280, 70 };
            // Highlighting targeted profile
            if (CheckCollisionPointRec(GetMousePosition(), friendRect) && isAddingFriend==false && fileSelector==false) {
                DrawRectangleRec(friendRect, secondary2Color);
                // Open DM
                if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON) || IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
                    currentFriendId = friends[i].userId;
                    friends[i].newMessageCount = 0;

                    char req[96];
                    snprintf(req, sizeof(req), "getChatHistory/%ld\x1E%ld", config.userId, friends[i].userId);
                    sendMessage(req);

                    chatAutoScrollAllowed=true;
                }
            } else {
                DrawRectangleRec(friendRect, plateColor);
            }

            // friend avatar
            Rectangle avatarRect2 = { 12, friendStartY + 8, 56, 56 };
            // Draw avatar if friend has it,
            // draw black mirror if doesnt
            if (friendAvatarArr[i].format != 0) {
                DrawTexturePro(friendAvatarArr[i], (Rectangle){0, 0, 128, 128}, avatarRect2, (Vector2){0, 0}, 0.0f, WHITE);
            } else {
                // 1 Deep glass base
                DrawRectangleRec(avatarRect2, (Color){ 15, 15, 18, 240 });

                // 2 The Rotated Mirror Sheen (Confined strictly to the avatar square)
                BeginScissorMode((int)avatarRect2.x, (int)avatarRect2.y, (int)avatarRect2.width, (int)avatarRect2.height);

                // We draw a thick, semi-transparent white line rotated at -20 degrees
                // Placing it slightly offset to catch the top-left section like a mirror reflection
                Vector2 startPos = { avatarRect2.x - 10, avatarRect2.y + 10 };
                Vector2 endPos   = { avatarRect2.x + 70, avatarRect2.y + 40 };
                Color glassGlow  = (Color){ 255, 255, 255, 40 }; // Sharp white glare

                // Draw a thick angled reflection streak across the glass
                DrawLineEx(startPos, endPos, 22.0f, glassGlow);

                EndScissorMode();

                // 3 Crisp Glass Border (Crucial at small scales to make it look like a physical object)
                Color glassBorder = (Color){ 255, 255, 255, 30 };
                DrawRectangleLinesEx(avatarRect2, 1.0f, glassBorder);
            }

            // Displaying friend name on card
            DrawTextEx(font, friends[i].name, (Vector2){76, friendStartY + 12}, 24, 2, mainColor);

            // Unread message counter for other chats
            if (friends[i].newMessageCount > 0) {
                if (friends[i].userId != currentFriendId) {
                    char badge[16] = {0};
                    snprintf(badge, sizeof(badge), "%d", friends[i].newMessageCount);
                    int textW = MeasureText(badge, 20);
                    Rectangle badgeRect = {240, friendStartY + 12, (float)textW + 12, 24};

                    DrawRectangleRec(badgeRect, RED);
                    DrawText(badge, (int)badgeRect.x + 6, (int)badgeRect.y + 4, 20, mainColor);
                }
                chatAutoScrollAllowed=true;
            }

            // Displaying friend description on card
            if (strlen(friends[i].profileDescription) > 0) {
                char shortDesc[71] = {0};
                strncpy(shortDesc, friends[i].profileDescription, 70);
                shortDesc[70] = '\0';
                // Cutting long text
                if (strlen(friends[i].profileDescription) > 30) {
                    // looking for last UTF-8 symbol before 30th slot
                    int pos = 30;
                    while (pos > 0 && (shortDesc[pos] & 0xC0) == 0x80) {
                        pos--;  // rolling back to the start of UTF-8 symbol
                    }

                    shortDesc[pos] = '\0';
                    snprintf(shortDesc + strlen(shortDesc), sizeof(shortDesc) - strlen(shortDesc), "...");
                }
                DrawTextEx(font, shortDesc, (Vector2){76, friendStartY + 42}, 18, 2, secondaryColor);
            }

            friendStartY += 80.0f;

            // Drawing friend's full profile page
            if (profilePage == 2 && currentFriendId==friends[i].userId) {
                DrawTextEx(font, "Профиль друга", (Vector2){1350, 50}, 24, 2.0f, mainColor);
                Rectangle avatarRect = {1320, 90, 128, 128};
                DrawRectangleRec(avatarRect, background2Color);

                // Has avatar -> draw avatar
                // Doesnt have -> draw black mirror
                if (friendAvatarArr[i].format != 0) {
                    DrawTexturePro(friendAvatarArr[i], (Rectangle){0, 0, 128, 128}, avatarRect, (Vector2){0, 0}, 0.0f, WHITE);
                } else {
                    // 1 Deep glass base
                    DrawRectangleRec(avatarRect, (Color){ 15, 15, 18, 240 });

                    // 2 The Rotated Mirror Sheen (Confined strictly to the avatar square)
                    BeginScissorMode((int)avatarRect.x, (int)avatarRect.y, (int)avatarRect.width, (int)avatarRect.height);

                    // We draw a thick, semi-transparent white line rotated at -20 degrees
                    // Placing it slightly offset to catch the top-left section like a mirror reflection
                    Vector2 startPos = { avatarRect.x - 10, avatarRect.y + 10 };
                    Vector2 endPos   = { avatarRect.x + 70, avatarRect.y + 40 };
                    Color glassGlow  = (Color){ 255, 255, 255, 40 }; // Sharp white glare

                    // Draw a thick angled reflection streak across the glass
                    DrawLineEx(startPos, endPos, 22.0f, glassGlow);

                    EndScissorMode();

                    // 3 Crisp Glass Border (Crucial at small scales to make it look like a physical object)
                    Color glassBorder = (Color){ 255, 255, 255, 30 };
                    DrawRectangleLinesEx(avatarRect, 1.0f, glassBorder);
                }

                // Friend name
                BeginScissorMode(1460, 100, 120, 36);
                DrawTextEx(font, TextFormat("%s", friends[i].name), (Vector2){1460, 100}, 32, 1.0f, mainColor);
                EndScissorMode();

                // Profile description
                DrawLine(1460, 136, 1580, 136, mainColor);
                DrawRectangleLines(1320, 270, 260, 400, plateColor);
                DrawTextBoxed(font, friends[i].profileDescription, (Rectangle){ 1326, 278, 248, 388 }, 20, 1.0f, mainColor);

                // Friend code copy button
                GuiSetStyle(DEFAULT, TEXT_SIZE, 16);
                if (GuiButton((Rectangle){1320, 230, 250, 30}, "скопировать код дружбы")) {
                    char copyToClipboard[13];
                    snprintf(copyToClipboard, 12, "%ld", friends[i].userId);
                    SetClipboardText(copyToClipboard);
                }
                GuiSetStyle(DEFAULT, TEXT_SIZE, 24);
            }
        }
    } else if (friendsCount == 0) {
        // Empty set

        Vector2 result = MeasureTextEx(font, "--пусто--", 20, 2);
        DrawTextEx(font, "--пусто--", (Vector2){(301.0f/2-result.x/2), 120}, 20, 2, secondaryColor);

    } else if (friendsCount == -1) {
        // Reading error (bad packet / client bug)

        Vector2 result = MeasureTextEx(font, "--ошибка чтения--", 20, 2);
        DrawTextEx(font, "--ошибка чтения--", (Vector2){(301.0f/2-result.x/2), 120}, 20, 2, secondaryColor);
    }

    // Update friend avatars
    if (requestedAvatarUpdate==true) {
        for (int i = 0; i < 100 && friends[i].userId != 0; i++) {
            // Clearing previous data
            if (friendAvatarArr[i].id != 0) {
                UnloadTexture(friendAvatarArr[i]);
                friendAvatarArr[i].id = 0;
            }
            char avatarPath[256] = {0};
            snprintf(avatarPath, sizeof(avatarPath), "avatars/%ld.png", friends[i].userId);

            // If avatar exists - we load it
            // if not - request for current user
            if (FileExists(avatarPath)) {
                Image img = LoadImage(avatarPath);
                if (img.data == NULL) {
                    printf("[LOAD FRIEND AVATAR] Couldnt load %ld's avatar with %s path\n", friends[i].userId, avatarPath);
                } else {
                    // Copy image as texture into array
                    ImageResize(&img, 128, 128);
                    friendAvatarArr[i] = LoadTextureFromImage(img);
                    UnloadImage(img);
                }
            } else if (friends[i].triedLoadAvatar==false) {

                // Per-friend retrying
                char req[64] = {0};
                snprintf(req, sizeof(req), "getAvatar/%ld", friends[i].userId);
                sendMessage(req);
                printf("[AVATAR] Requested avatar for %ld\n", friends[i].userId);
                friends[i].triedLoadAvatar=true;
            }
        }
        requestedAvatarUpdate=false;
    }

    // Message box
    if (GuiTextBox((Rectangle){361, 839, 880, 60}, message, MAX_MESS, activeField==5)) {
        activeField = (activeField == 5) ? -1 : 5;
    }
    // Add file button
    GuiSetStyle(DEFAULT, TEXT_SIZE, 40);
    if (GuiButton((Rectangle){301, 839, 60, 60}, "+")) {
        fileSelector=true;
    }
    // Send message button
    if (GuiButton((Rectangle){1241, 839, 60, 60}, "^") || IsKeyPressed(KEY_ENTER)) {
        // If message is not empty and we selected friend
        if (strlen(message)!=0 && currentFriendId>0) {
            // Request new message id
            sendMessage("createId/message");
            // Actually send message
            sendsMessage=true;
        }
    }
    if (sendsMessage == true) {
        // Preparing buffers
        message[2048]='\0';
        char parsed[BUFFER_SIZE] = {0};

        // Initializing new message array
        if (messagesCount < 0) messagesCount = 0;

        // If buffer is not overloaded
        // and we have new message if
        if (messagesCount < 1000000 && randomMessageId!=-1) {

            // Add message to display array
            messages[messagesCount].messageId = randomMessageId;
            messages[messagesCount].senderId = config.userId;
            messages[messagesCount].receiverId = currentFriendId;
            strncpy(messages[messagesCount].message, message, 2048);
            messagesCount++;

            // Send message
            snprintf(parsed, sizeof(parsed), "receive-message/%ld\x1E%ld\x1E%ld\x1E%s", randomMessageId, config.userId, currentFriendId, message);
            sendMessage(parsed);
            randomMessageId=-1;
            sendsMessage=false;

            // Clear after trying
            memset(message, 0, sizeof(message));
            memset(parsed, 0, strlen(parsed));
            chatAutoScrollAllowed=true;
            activeField=5;
        }
    }

    // Add friend button
    GuiSetStyle(DEFAULT, TEXT_SIZE, 24);
    if (GuiButton((Rectangle){13, 45, 100, 30}, "+ Друг")) {
        isAddingFriend=true;
    }
    if (hasFriendRequests==true) {
        // New friend requests badge
        DrawCircle(111, 44, 6, RED);
    }

    // Create a group
    if (GuiButton((Rectangle){127, 45, 120, 30}, "+ Группа")) {
        // TODO версия 3.0
    }

    // Reload friends and groups
    if (GuiButton((Rectangle){260, 45, 30, 30}, "R")) {

        // Cleanup
        memset(friends, 0, sizeof(friends));

        // Update friend list again
        char req[96] = {0};
        snprintf(req, 96, "getFriendsList/%ld", config.userId);
        sendMessage(req);

        // Update incoming friend requests again
        memset(req, 0, 96);
        snprintf(req, 96, "requestPendingFriends/%ld", config.userId);
        sendMessage(req);

        requestedAvatarUpdate=true;
    }


    // Chat section
    Rectangle chatArea = {300, 80, 980, 700};

    // chat header
    if (currentFriendId != 0) {
        // Getting friend name
        char *friendName = "НН";
        for (int k=0; k<100; k++) {
            if (friends[k].userId == currentFriendId) {
                friendName = friends[k].name;
                break;
            }
        }

        // Drawing friend name
        DrawTextEx(font, TextFormat("Чат с %s", friendName), (Vector2){321, 48}, 28, 2, mainColor);

        // Audio call button
        GuiButton((Rectangle){1189, 42, 36, 36}, "");
        GuiDrawIcon(122, 1192, 44, 2, mainColor);

        // Video call button
        GuiButton((Rectangle){1243, 42, 36, 36}, "");
        GuiDrawIcon(169, 1246, 44, 2, mainColor);
        // TODO: аудио и видео звонок
        // TODO: версия 3.0
    }

    // Message section
    if (messagesCount > 0) {
        // FAST CACHE
        // calculating only messages that doesnt have cachedHeight value
        for (int i = 0; i < messagesCount; i++) {

            Message *m = &messages[i];

            if (m->cachedHeight == 0) {
                // Message and bubble width
                int maxBubbleWidth = (int)chatArea.width - 220;
                int maxTextWidth = maxBubbleWidth - 40;

                // Get wrapped text height
                char dummy[2048] = {0};
                int textHeight = WrapText(m->message, dummy, sizeof(dummy), maxTextWidth, font, 22, 2);
                Vector2 tMeasure = MeasureTextEx(font, dummy, 22.0f, 2.0f);

                // Store values
                m->cachedBubbleWidth = (int)tMeasure.x + 40;
                m->cachedHeight = textHeight + 25;
            }
        }

        // calculating main height for scrollbar
        chatContentHeight = 0.0f;
        for (int i = 0; i < messagesCount; i++) {

            chatContentHeight += (float)messages[i].cachedHeight + 18;
        }

        // Do we need scroll with chat size?
        if (chatContentHeight < 680) chatScrollOffset = 0;
        float maxScroll = fmaxf(0.0f, chatContentHeight - 680.0f);
        chatScrollOffset = clamp(chatScrollOffset, 0.0f, maxScroll);
        if (chatAutoScrollAllowed == true && messagesCount > 0) {
            chatScrollOffset = maxScroll;
        }

        // Rendering messages
        float currentY = 100 - chatScrollOffset;

        for (int i = 0; i < messagesCount; i++) {
            Message *m = &messages[i];
            bool isMine = (m->senderId == config.userId);

            int bubbleHeight = m->cachedHeight;
            int bubbleWidth = m->cachedBubbleWidth;

            // CULLING
            // draw only visible messages
            if (currentY > 80 && currentY < 780) {

                // Get bubble
                Rectangle bubble = {
                                 isMine ? (chatArea.x + chatArea.width - (float)bubbleWidth - 10) : (chatArea.x + 30),
                                    currentY,
                                    (float)bubbleWidth,
                                    (float)bubbleHeight
                };
                Color bubbleColor = isMine ? (Color){158, 105, 32, 255} : (Color){70, 70, 60, 255};

                // Draw bubble
                DrawRectangleRec(bubble, bubbleColor);
                DrawRectangleLinesEx(bubble, 2, secondary2Color);

                // Draw text in bubble
                int maxTextWidth = ((int)chatArea.width - 220) - 40;
                char wrapped[2048] = {0};
                WrapText(m->message, wrapped, sizeof(wrapped), maxTextWidth, font, 22, 2);
                DrawWrappedText(wrapped, (Vector2){bubble.x + 20, bubble.y + 12}, font, 22, 2, mainColor);
            }

            // Move future messages down
            currentY += (float)bubbleHeight + 18;
        }

        // If chat is higher than visible part
        // calculate and add a scrollbar
        if (chatContentHeight > 680) {
            float scrollbarTrackHeight = 680;
            float scrollbarHeight = (680 / chatContentHeight) * scrollbarTrackHeight;
            float scrollbarY = 100 + (chatScrollOffset / chatContentHeight) * scrollbarTrackHeight;

            Rectangle scrollbarRect = {
                chatArea.x + chatArea.width,
                scrollbarY,
                10,
                scrollbarHeight
            };

            DrawRectangle((int)chatArea.x + (int)chatArea.width, 100, 10, 680, Fade(BLACK, 0.3f));

            Color sbColor = chatIsDraggingScrollbar ? WHITE : GRAY;
            DrawRectangleRec(scrollbarRect, Fade(sbColor, 0.85f));

            Vector2 mouse = GetMousePosition();

            // Moving by held mouse button
            if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON)) {
                if (CheckCollisionPointRec(mouse, scrollbarRect)) {
                    chatIsDraggingScrollbar = true;
                    chatAutoScrollAllowed=false;
                }
            }

            // Released button
            if (IsMouseButtonReleased(MOUSE_LEFT_BUTTON)) {
                chatIsDraggingScrollbar = false;
                chatAutoScrollAllowed=false;
            }

            // Moving by scroll wheel
            if (chatIsDraggingScrollbar) {
                chatAutoScrollAllowed=false;
                float mouseRelative = mouse.y - scrollbarHeight/2 - 100;
                chatScrollOffset = (mouseRelative / 680) * chatContentHeight;
            }
        }
    } else if (messagesCount == 0 && currentFriendId != 0) {
        // No messages in this chat yet

        Vector2 result = MeasureTextEx(font, "--пусто--", 32, 2);
        DrawTextEx(font, "--пусто--", (Vector2){(1001.0f/2-result.x/2)+300, 600}, 32, 2, secondaryColor);

    } else if (messagesCount == -1) {
        // Reading error (bad packet / client bug)

        Vector2 result = MeasureTextEx(font, "--ошибка чтения--", 32, 2);
        DrawTextEx(font, "--ошибка чтения--", (Vector2){(1301.0f/2-result.x/2), 600}, 32, 2, secondaryColor);

    }

    // Adding friend window
    if (isAddingFriend == true && fileSelector==false) {

        // Closing window on ESC
        if (IsKeyPressed(KEY_ESCAPE)) isAddingFriend=false;

        // Base
        DrawRectangle(1600/2-200, 900/2-200, 400, 400, secondaryColor);
        DrawRectangleLines(1600/2-200, 900/2-200, 400, 400, mainColor);
        DrawRectangleLines(1600/2-190, 900/2-140, 381, 61, mainColor);

        // Friend code input box
        DrawTextEx(font, "Введи код дружбы:", (Vector2){1600.0f/2-190, 900.0f/2-180}, 20, 2, mainColor);
        if (GuiTextBox((Rectangle){1600.0f/2-190, 900.0f/2-140, 380, 60}, userId, 14, activeField==6)) {
            activeField = (activeField == 6) ? -1 : 6;
        }

        // Send friend request
        if (GuiButton((Rectangle){1600.0f/2+66, 900.0f/2+156, 130, 40}, "Отправить")) {
            // Empty id?
            if (strlen(userId) == 0) return 1;

            char parsed[37] = {0};
            snprintf(parsed, sizeof(parsed), "addFriend/%ld\x1E%s", config.userId, userId);
            sendMessage(parsed);
            printf("[SEND FRIEND REQUEST] Sent request for %s: %s\n", userId, parsed);
            hasFriendRequests=false;
        }

        // Accept friend request
        if (GuiButton((Rectangle){1600.0f/2-196, 900.0f/2+156, 130, 40}, "Принять")) {
            // Empty id?
            if (strlen(userId) > 0) {
                // Reloading friend list

                long targetId = strtol(userId, nullptr, 10);
                if (targetId == 0) return 1; // Empty id?

                // Accepting friend request
                char packet[100];
                snprintf(packet, sizeof(packet), "acceptFriend/%ld\x1E%ld", config.userId, targetId);
                sendMessage(packet);
                printf("[ACCEPT FRIEND] Accepted friend request from %ld\n", targetId);

                // Appending current friend to friends array
                for (int i=0; i<100 && pendingFriends[i].userId!=0; i++) {

                    // Finding current friend
                    char id[15] = {0};
                    snprintf(id, 14, "%ld", pendingFriends[i].userId);

                    // Is this a person we need?
                    if (strncmp(userId, id, 14) == 0) {

                        // Appending to array
                        pendingFriends[i].userId = 0L;
                        memset(pendingFriends[i].avatarUrl, 0, sizeof(pendingFriends[i].avatarUrl));
                        memset(pendingFriends[i].name, 0, sizeof(pendingFriends[i].name));
                        memset(pendingFriends[i].profileDescription, 0, sizeof(pendingFriends[i].profileDescription));
                        memset(userId, 0, 15);
                    }
                }
            }
            hasFriendRequests=false;
        }

        // Pending friends list
        float startY = 900/2.0f -70;
        for (int i=0; i<100 && pendingFriends[i].userId!=0; i++) {

            // Card base
            Rectangle friendRect = {1600.0f/2-190, startY, 380, 68};
            DrawRectangleLines(1600/2-189, (int)startY+1, 378, 66, secondaryColor);
            Rectangle avatarRect2 = { 1600.0f/2-184, startY + 8, 54, 54 };

            // Choosing who to accept
            if (CheckCollisionPointRec(GetMousePosition(), friendRect)) {

                DrawRectangleRec(friendRect, (Color){60, 60, 70, 255});

                // Sending to add queue
                if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON)) {
                    snprintf(userId, 14, "%ld", pendingFriends[i].userId);
                }

            } else {
                DrawRectangleRec(friendRect, (Color){50, 50, 60, 255});
            }

            // Mini avatar
            if (pendingFriendAvatarArr[i].id != 0) {
                DrawTexturePro(pendingFriendAvatarArr[i],
                               (Rectangle){0, 0, 54, 54},
                               avatarRect2,
                               (Vector2){0, 0}, 0.0f, WHITE);
            } else {
                DrawRectangleRec(avatarRect2, GRAY);
            }

            // Name
            DrawTextEx(font, pendingFriends[i].name, (Vector2){1600.0f/2-190 + 70, startY + 12}, 24, 2, mainColor);

            // Profile description
            if (strlen(pendingFriends[i].profileDescription) > 0) {

                char shortDesc[80];
                strncpy(shortDesc, pendingFriends[i].profileDescription, 70);
                shortDesc[70] = '\0';

                // Cutting long text
                if (strlen(pendingFriends[i].profileDescription) > 70) {
                    snprintf(shortDesc + strlen(shortDesc), sizeof(shortDesc) - strlen(shortDesc), "...");
                }
                DrawTextEx(font, shortDesc, (Vector2){1600.0f/2-190 + 70, startY + 42}, 18, 2, secondaryColor);
            }

            startY += 80;
        }
    }

    // Closing current chat
    if (IsKeyPressed(KEY_ESCAPE) && currentFriendId>0 && fileSelector==false && isAddingFriend==false) {
        currentFriendId=0;
    }

    // Custom gui file selector
    if (fileSelector == true && isAddingFriend==false) {

        // Closing window
        if (IsKeyPressed(KEY_ESCAPE)) {fileSelector=false;}

        Rectangle bounds = {100, 100, 800, 600};
        path2 = GuiFileSelector(bounds, "Выбор файла:", font, mainColor, secondaryColor, mainColor);

        // Got selected path
        if (path2!=NULL && strlen(path2)>1) {
            fileSelector=false;
            printf("\nend filename: %s", path2);
        }
    }

    // Bad network state
    if (initedNetwork == false || connected == false) {

        Rectangle networkErrorRec = {1, 900.0f/2-100, 1600, 200};
        Color accentPlateColor = {255, 79, 79, 255};
        Color backgroundPlateColor = {255, 157, 157, 255};

        // Full-screen warning line
        DrawRectangleRec(networkErrorRec, backgroundPlateColor);
        DrawRectangleLinesEx(networkErrorRec, 2, accentPlateColor);
        DrawTextEx(font, "Потеряно соединение с сервером!", (Vector2){1600.0f/2-470, 900.0f/2-20}, 60, 2, RED);
    }

    return 0;
}


#define RGBA_TO_HEX(r, g, b, a) (((r) << 24) | ((g) << 16) | ((b) << 8) | (a))
int main(void) {
    // Window setup
    printf("\n");
    InitWindow(1600, 900, "SecureTTY - BETA 2.0");
    SetTargetFPS(140);
    SetTraceLogLevel(LOG_WARNING);
    SetExitKey(KEY_NULL);

    // Font measuring
    int codepoints[1024] = {0};
    int count = 0;
    for (int i = 32; i < 128; i++) codepoints[count++] = i;
    for (int i = 0x0400; i <= 0x04FF; i++) codepoints[count++] = i;
    // Font setup
    font = LoadFontEx("Pixellari.ttf", 64, codepoints, count);
    GenTextureMipmaps(&font.texture);
    SetTextureFilter(font.texture, TEXTURE_FILTER_BILINEAR);
    GuiSetFont(font);
    GuiSetStyle(DEFAULT, TEXT_SIZE, 24);

    // Audio setup
    InitAudioDevice();

    // Changing raygui components to yellow color theme
    GuiSetStyle(BUTTON, BORDER_COLOR_NORMAL, RGBA_TO_HEX(0, 0, 0, 0));
    GuiSetStyle(BUTTON, BORDER_COLOR_FOCUSED, RGBA_TO_HEX(0, 0, 0, 0));
    GuiSetStyle(BUTTON, BORDER_COLOR_DISABLED, RGBA_TO_HEX(0, 0, 0, 0));
    GuiSetStyle(BUTTON, BORDER_COLOR_PRESSED, RGBA_TO_HEX(0, 0, 0, 0));
    GuiSetStyle(BUTTON, BASE_COLOR_NORMAL, RGBA_TO_HEX(70, 70, 60, 255));
    GuiSetStyle(BUTTON, BASE_COLOR_FOCUSED, RGBA_TO_HEX(218, 165, 32, 255));
    GuiSetStyle(BUTTON, BASE_COLOR_DISABLED, RGBA_TO_HEX(70, 70, 60, 255));
    GuiSetStyle(BUTTON, BASE_COLOR_PRESSED, RGBA_TO_HEX(218, 165, 32, 255));
    GuiSetStyle(BUTTON, TEXT_COLOR_NORMAL, RGBA_TO_HEX(255, 255, 255, 255));
    GuiSetStyle(BUTTON, TEXT_COLOR_FOCUSED, RGBA_TO_HEX(255, 255, 255, 255));
    GuiSetStyle(BUTTON, TEXT_COLOR_DISABLED, RGBA_TO_HEX(255, 255, 255, 255));
    GuiSetStyle(BUTTON, TEXT_COLOR_PRESSED, RGBA_TO_HEX(255, 255, 255, 255));
    GuiSetStyle(TEXTBOX, BORDER_COLOR_NORMAL, RGBA_TO_HEX(70, 70, 60, 255));
    GuiSetStyle(TEXTBOX, BORDER_COLOR_FOCUSED, RGBA_TO_HEX(218, 165, 32, 255));
    GuiSetStyle(TEXTBOX, BORDER_COLOR_DISABLED, RGBA_TO_HEX(70, 70, 60, 255));
    GuiSetStyle(TEXTBOX, BORDER_COLOR_PRESSED, RGBA_TO_HEX(218, 165, 32, 255));
    GuiSetStyle(TEXTBOX, BASE_COLOR_NORMAL, RGBA_TO_HEX(0, 0, 0, 0));
    GuiSetStyle(TEXTBOX, BASE_COLOR_FOCUSED, RGBA_TO_HEX(70, 70, 60, 255));
    GuiSetStyle(TEXTBOX, BASE_COLOR_DISABLED, RGBA_TO_HEX(0, 0, 0, 0));
    GuiSetStyle(TEXTBOX, BASE_COLOR_PRESSED, RGBA_TO_HEX(70, 70, 60, 255));
    GuiSetStyle(TEXTBOX, TEXT_COLOR_NORMAL, RGBA_TO_HEX(255, 255, 255, 255));
    GuiSetStyle(TEXTBOX, TEXT_COLOR_FOCUSED, RGBA_TO_HEX(255, 255, 255, 255));
    GuiSetStyle(TEXTBOX, TEXT_COLOR_DISABLED, RGBA_TO_HEX(255, 255, 255, 255));
    GuiSetStyle(TEXTBOX, TEXT_COLOR_PRESSED, RGBA_TO_HEX(255, 255, 255, 255));

    while (!WindowShouldClose()) {
        pthread_mutex_lock(&clientStateMutex);

        // Scroll
        float wheel = GetMouseWheelMove();
        if (wheel != 0.0f) {

            chatScrollVelocity -= wheel * 15.0f;        // bigger number = faster scroll
            friendScrollVelocity -= wheel * 15.0f;
            chatAutoScrollAllowed=false;
        }

        if (!chatIsDraggingScrollbar) {

            // regular scroollo with inertion
            chatScrollOffset += chatScrollVelocity;
            chatScrollVelocity *= chatSrollFriction;    // fadeout

            // if the speed is too slow -> resetting to zero
            if (fabsf(chatScrollVelocity) < 0.5f) {
                chatScrollVelocity = 0.0f;
            }
        }

        if (!friendIsDraggingScrollbar) {

            // regular scroollo with inertion
            friendScrollOffset += friendScrollVelocity;
            friendScrollVelocity *= friendSrollFriction;       // fadeout

            // if the speed is too slow -> resetting to zero
            if (fabsf(friendScrollVelocity) < 0.5f) {
                friendScrollVelocity = 0.0f;
            }
        }


        BeginDrawing();
        ClearBackground((Color){ 40, 40, 40, 255 });
        DrawRectangleGradientEx((Rectangle){0, 0, 1600, 900}, backgroundColor, background2Color, background2Color, backgroundColor);

        switch (currentState) {
            case STATE_MASTER_PASSWORD:

                // Untill user enters the right password
                // we keep app from changing its state
                if (MasterPasswordState() == 1) goto next;

                break;

            case STATE_FIRST_SETUP:

                // Here users inputs his profile data
                // and program registers it on server
                if (FirstSetupState() == 1) goto next;

                break;

            case STATE_MAIN_CHAT:

                if (MainState() == 1) goto next;

                break;
        }

        next:
        EndDrawing();
        pthread_mutex_unlock(&clientStateMutex);
    }

    // Close connection
    close(sock);
    free(path2);

    UnloadTexture(userAvatarTexture);
    UnloadFont(font);
    CloseAudioDevice();
    CloseWindow();
    return 0;
}
