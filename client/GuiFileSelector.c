//
// Created by unnamedfurry on 8/28/26.
//

#include <dirent.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#include "raygui.h"
#include "raylib.h"

extern float clamp(float val, float min, float max);

static void appendPath(char *dst, size_t cap, const char *part) {
    size_t used = strlen(dst);
    if (used < cap - 1) snprintf(dst + used, cap - used, "%s", part);
}

/**
 * ## GuiFileSelector by @unnamed_furry
 *
 * This method helps the user easily select a file through a simple TUI interface.
 *
 * How it works:
 *
 * Step 1. The method attempts to read the root directory.
 *         If it fails, it falls back to the current working directory.
 *         If successful, it proceeds to step 2.
 *
 * Step 2. It scans all subfolders using scandir(), sorts them alphabetically
 *         and stores the result in the long-lived `rootFolders` array.
 *
 * Step 3. It scans all files using the same utility and stores the result
 *         in the long-lived `rootFiles` array.
 *
 * Step 4. The interface is rendered: path bar, folders panel and files panel.
 *
 * Step 5. Each panel listens for input events:
 *         - Left panel (folders): back arrow, mouse back, Delete key — go to parent directory.
 *         - Right panel (files): double-click or Enter — select the file and proceed to step 6.
 *
 * Step 6. When a file is selected (or Escape is pressed), the method enters
 *         the cleanup phase: frees all temporary memory and returns a pointer
 *         to the allocated full path string.
 *
 * Graphical explanation:
 *
 * @mermaid
 * flowchart TD
 *     A[Start: Allocate Memory] --> B[Draw UI Base and Headers]
 *     B --> C{Try to read root folder?}
 *     C -->|Success| D[Save folders to rootFolders]
 *     C -->|Failure| E[Read current directory]
 *     E --> D
 *     D --> F[Save files to rootFiles]
 *     F --> G[Render folders panel + input handling]
 *     G --> H[Render files panel + input handling]
 *     H --> I{File selected or Escape?}
 *     I -->|Yes| J[Cleanup and return path]
 *     I -->|No| G
 * @endmermaid
 */
char *path;
char *rootFolders[256] = {0};
typedef struct {
    char name[256];
    char dateTime[24];
    char size[24];
} RootFiles;
RootFiles *rootFiles[5120];
bool initialized = false;
float contentHeight = 0.0f;
float scrollOffset = 0.0f;
bool isDraggingScrollbar = false;
float scrollOffset2 = 0.0f;
bool isDraggingScrollbar2 = false;
float scrollVelocity = 0.0f;
float scrollFriction = 0.92f;
float scrollVelocity2 = 0.0f;
float scrollFriction2 = 0.92f;
bool readDirFiles = false;
int rootFoldersAmount = 0;
int rootFilesAmount = 0;
float filenameOffset = 0.0f;
int offsetedFileId = -1;
int selectedOnce = 0;
int offsetedPath = 0;
bool manualPath = false;
void format_size_pretty(uint64_t bytes, char *buf, size_t size){
    const char *units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    int unit = 0;
    double value = (double)bytes;

    while (value >= 1024.0 && unit < 4) {
        value /= 1024.0;
        unit++;
    }

    if (unit == 0)
        snprintf(buf, size, "%llu B", (unsigned long long)bytes);
    else if (value >= 100.0)
        snprintf(buf, size, "%.1f %s", value, units[unit]);
    else
        snprintf(buf, size, "%.2f %s", value, units[unit]);
}
void format_date_short(time_t timestamp, char *buffer, size_t bufsize){
    struct tm *tm_info = localtime(&timestamp);
    if (tm_info == NULL) {
        snprintf(buffer, bufsize, "unknown");
        return;
    }

    strftime(buffer, bufsize, "%d.%m.%Y %H:%M", tm_info);
}
char* GuiFileSelector(Rectangle bounds, char *text, Font font, Color primaryColor, Color secondaryColor, Color textColor) {
    // Defining window's size, can't be less than 400 by 600 pixels
    const int minWidth = 800;
    const int minHeight = 600;
    int width = ((int)bounds.width > minWidth) ? (int)bounds.width : minWidth;
    int height = ((int)bounds.height > minHeight) ? (int)bounds.height : minHeight;
    // Defining variables for left chunk that will display file tree
    if (initialized==false) {path = malloc(512 * sizeof(char)); manualPath=false;}

    // Drawing window base and moving header
    DrawRectangle((int)bounds.x, (int)bounds.y, width, height, secondaryColor);
    DrawRectangleLines((int)bounds.x, (int)bounds.y, width, height, primaryColor);
    int field2Width = width/3;
    int field2Height = height-78;
    DrawRectangleLines((int)bounds.x+4, (int)bounds.y+74, field2Width, field2Height, primaryColor);
    int field3Width = width-(width/3);
    int field3Height = height-78;
    DrawRectangleLines((int)bounds.x+field2Width, (int)bounds.y+74, field3Width-4, field3Height, primaryColor);
    DrawLine((int)bounds.x, (int)bounds.y+70, (int)bounds.x+width, (int)bounds.y+70, primaryColor);
    DrawLine((int)bounds.x, (int)bounds.y+30, (int)bounds.x+width, (int)bounds.y+30, primaryColor);
    DrawTextEx(font,text,(Vector2){bounds.x+2, bounds.y+4},28,2,textColor);
    if (!manualPath) {
        Vector2 measure = MeasureTextEx(font, path, (float)18, 2.0f);
        BeginScissorMode((int)bounds.x+8, (int)bounds.y+38, (int)bounds.width-8, 30);
        DrawTextEx(font,path,(Vector2){bounds.x+8-(float)offsetedPath, bounds.y+38},26,2,textColor);
        EndScissorMode();
        if (CheckCollisionPointRec(GetMousePosition(), (Rectangle){bounds.x+8, bounds.y+38, bounds.width-8, 30})) {
            offsetedPath = (int)((float)offsetedPath + 0.2f) * ((float)offsetedPath<measure.x);
        }
    } else {
        GuiTextBox((Rectangle){bounds.x+8, bounds.y+38, bounds.width-8, 30}, path, 512*sizeof(char), manualPath);
    }
    if (CheckCollisionPointRec(GetMousePosition(), (Rectangle){bounds.x+8, bounds.y+38, bounds.width-8, 30.0f})) manualPath=true;
    else manualPath=false;

    // ------------------------
    //
    // PRINT ERRORS USING PRINTF?
    //
    // ------------------------

    // Opening root folder
    static char lastPath[512] = {0};
    struct dirent **dir;
    if (path == NULL) {printf("\nError: not enough memory for directory listing.\n"); return nullptr;}
    if (initialized==false) { snprintf(path, 512, "/"); }

    if (initialized==false) { // allocating memory if called firstly
        for (int i=0; i<256; i++) {rootFolders[i] = malloc(256 * sizeof(char)); if (rootFolders[i] == NULL) {printf("\nError: not enough memory for file listing.\n"); return nullptr;}}
        for (int i=0; i<5120; i++) {rootFiles[i] = malloc(sizeof(RootFiles)); if (rootFiles[i] == NULL) {printf("\nError: not enough memory for file listing.\n"); return nullptr;}}
        initialized=true;
    }

    // Trying ro read root folder: if succeeded - store files, if not - work with current program's directory
    if (!initialized || readDirFiles == false || strcmp(path, lastPath) != 0) {
        rootFoldersAmount = 0;
        rootFilesAmount = 0;
        int n = scandir(path, &dir, nullptr, alphasort);

        if (n < 0) {
            printf("scandir error on %s\n", path);
        }
        else if (n > 0) {
            for (int i=0; i<n; i++) {
                if (strcmp(dir[i]->d_name, ".") == 0 || strcmp(dir[i]->d_name, "..") == 0) continue; // skipping sub-files and sub-folders

                char fullpath[512] = {0};
                snprintf(fullpath, sizeof(fullpath), "%s%s", path, dir[i]->d_name);
                struct stat st;
                if (stat(fullpath, &st) != 0)
                    continue;

                if (S_ISDIR(st.st_mode)) {
                    // folder
                    if (rootFoldersAmount < 256) {
                        strncpy(rootFolders[rootFoldersAmount], dir[i]->d_name, 255);
                        rootFolders[rootFoldersAmount][255] = '\0';
                        rootFoldersAmount++;
                    }
                } else if (S_ISREG(st.st_mode)) {
                    // regular file
                    if (rootFilesAmount < 5120) {
                        strncpy(rootFiles[rootFilesAmount]->name, dir[i]->d_name, 255);
                        rootFiles[rootFilesAmount]->name[255] = '\0';
                        format_size_pretty(st.st_size, rootFiles[rootFilesAmount]->size, 23);
                        format_date_short(st.st_ctime, rootFiles[rootFilesAmount]->dateTime, 23);
                        rootFilesAmount++;
                    }
                }
            }
            for (int i = 0; i < n; i++) free(dir[i]);
            free(dir);
            dir = NULL;
        }
    }

    readDirFiles=true;
    // -------- Left Chunk (Folder List) --------
    {
        // Scroll settings
        float visibleHeight = (float)field2Height;
        float contentHeight2 = (float)rootFoldersAmount * 34.0f;
        float wheel = 0.0f;
        if (CheckCollisionPointRec(GetMousePosition(), (Rectangle){bounds.x+4, bounds.y+82, (float)field2Width, (float)field2Height})) wheel = GetMouseWheelMove();
        if (wheel != 0.0f) {
            scrollVelocity -= wheel * 15.0f;
        }
        scrollOffset += scrollVelocity;
        scrollVelocity *= scrollFriction;
        if (fabsf(scrollVelocity) < 0.5f) {
            scrollVelocity = 0.0f;
        }
        float maxScroll = fmax(0.0f, contentHeight2 - visibleHeight);
        scrollOffset = clamp(scrollOffset, 0.0f, maxScroll);
        // Setting up variables
        int x = (int)bounds.x + 8;
        int startY = (int)bounds.y + 82;
        float currentY = (float)startY - scrollOffset;
        for (int i = 0; i < rootFoldersAmount; i++) {
            Rectangle directoryRectangle = {
                (float)x,
                currentY,
                (float)field2Width - 26,
                30
            };

            // Rendering left chunk (only visible)
            if (currentY > (float)startY - 10 &&
                currentY < (float)startY + (float)field2Height - 34) {

                BeginScissorMode((int)directoryRectangle.x, (int)directoryRectangle.y, (int)directoryRectangle.width, (int)directoryRectangle.height);
                DrawRectangleLines(x, (int)currentY, field2Width - 26, 30, primaryColor);
                DrawTextEx(font, rootFolders[i],
                           (Vector2){(float)x + 4, currentY + 4}, 18, 2, textColor);
                EndScissorMode();

                if (CheckCollisionPointRec(GetMousePosition(), directoryRectangle)) {
                    DrawRectangleLines(x, (int)currentY, field2Width - 26, 30, SKYBLUE);

                    // Entering path clicked
                    if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON)) {
                        appendPath(path, 512, rootFolders[i]);
                        appendPath(path, 512, "/");
                        readDirFiles=false;
                        rootFoldersAmount = 0;
                        rootFilesAmount = 0;
                        selectedOnce=0;
                    }
                }
            }

            currentY += 34.0f;
        }
        if (IsKeyPressed(KEY_BACKSPACE) || IsKeyPressed(KEY_BACK) || IsMouseButtonPressed(MOUSE_BUTTON_BACK) || IsMouseButtonPressed(MOUSE_BUTTON_SIDE)) {
            char *last = nullptr;
            char *pre_last = nullptr;
            char *current = path;
            int k=0;
            while ((current = strstr(current, "/")) != NULL) {
                pre_last = last;
                last = current;
                current++;
                k++;
            }
            if (k>2) {
                int index = pre_last ? (int)(pre_last - path) : -1;
                path[index+1] = '\0';
            } else if (k==2) {
                snprintf(path, 512, "/");
            }
            readDirFiles=false;
            rootFoldersAmount = 0;
            rootFilesAmount = 0;
            selectedOnce=0;
        }
        // Rendering scrollbar
        if (contentHeight2 > (float)field2Height) {
            float scrollbarTrackHeight = (float)field2Height-14;
            float scrollbarHeight = ((float)field2Height / contentHeight2) * scrollbarTrackHeight;
            float scrollbarY = (float)startY + (scrollOffset / contentHeight2) * scrollbarTrackHeight;

            DrawRectangle(x + field2Width - 22, startY, 10, field2Height-14, Fade(BLACK, 0.3f));

            Color sbColor = isDraggingScrollbar ? WHITE : LIGHTGRAY;
            Rectangle scrollbarRect = {
                (float)(x + field2Width - 22),
                scrollbarY,
                10,
                scrollbarHeight
            };

            DrawRectangleRec(scrollbarRect, Fade(sbColor, 0.85f));

            Vector2 mouse = GetMousePosition();

            if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON)) {
                if (CheckCollisionPointRec(mouse, scrollbarRect)) {
                    isDraggingScrollbar = true;
                }
            }
            if (IsMouseButtonReleased(MOUSE_LEFT_BUTTON)) {
                isDraggingScrollbar = false;
            }
            if (isDraggingScrollbar) {
                float mouseRelative = mouse.y - scrollbarHeight / 2.0f - (float)startY;
                scrollOffset = (mouseRelative / (float)field2Height) * contentHeight2;
            }
        }
    }

    // -------- Right Chunk (File List) --------
    {
        // Scroll settings
        float visibleHeight = (float)field3Height;
        float contentHeight2 = (float)rootFilesAmount * 34.0f;
        float wheel = 0.0f;
        if (CheckCollisionPointRec(GetMousePosition(), (Rectangle){bounds.x+(float)field2Width+4, bounds.y+82, (float)field3Width, (float)field3Height})) wheel = GetMouseWheelMove();
        if (wheel != 0.0f) {
            scrollVelocity2 -= wheel * 15.0f;
        }
        scrollOffset2 += scrollVelocity2;
        scrollVelocity2 *= scrollFriction2;
        if (fabsf(scrollVelocity2) < 0.5f) {
            scrollVelocity2 = 0.0f;
        }
        float maxScroll = fmaxf(0.0f, contentHeight2 - visibleHeight);
        scrollOffset2 = clamp(scrollOffset2, 0.0f, maxScroll);
        // Setting up variables
        int x = (int)bounds.x + field2Width+8;
        int startY = (int)bounds.y + 82;
        float currentY = (float)startY - scrollOffset2;
        for (int i = 0; i < rootFilesAmount; i++) {
            Rectangle fileRectangle = {
                (float)x,
                currentY,
                (float)field3Width - 32,
                30
            };

            // Rendering right chunk (only visible)
            if (currentY > (float)startY - 10 &&
                currentY < (float)startY + (float)field3Height - 34) {

                // Date-Time and Size
                Vector2 tMeasure = MeasureTextEx(font, rootFiles[i]->name, (float)18, 2.0f);
                float maxTextLength = (35.4f*(fileRectangle.width/100));
                DrawRectangleLines(x, (int)currentY, field3Width - 32, 30, primaryColor);
                BeginScissorMode((int)fileRectangle.x, (int)fileRectangle.y, (int)fileRectangle.width, (int)fileRectangle.height);
                DrawTextEx(font, rootFiles[i]->dateTime,
                              (Vector2){(float)x + 1.2f*fileRectangle.width/3, currentY + 6}, 18, 2, textColor);
                DrawTextEx(font, rootFiles[i]->size,
                           (Vector2){(float)x + 2.34f*fileRectangle.width/3, currentY + 6}, 18, 2, textColor);
                EndScissorMode();

                // Cutting and moving FileName leftwards if name could collide with date-time text
                if (tMeasure.x >= maxTextLength) {
                    BeginScissorMode((int)fileRectangle.x+4, (int)fileRectangle.y, (int)maxTextLength, (int)fileRectangle.height);
                    DrawTextEx(font, rootFiles[i]->name,
                               (Vector2){(float)x + 4 - (float)(i==offsetedFileId)*filenameOffset, currentY + 6}, 18, 2, textColor);
                    EndScissorMode();
                } else {
                    DrawTextEx(font, rootFiles[i]->name,
                               (Vector2){(float)x + 4, currentY + 6}, 18, 2, textColor);
                }

                // Marking current file slot as wanted
                // Double-Click selects the wanted file and exits the window
                if (CheckCollisionPointRec(GetMousePosition(), fileRectangle)) {
                    filenameOffset = (filenameOffset + 0.2f) * (float)(filenameOffset<tMeasure.x);
                    DrawRectangleLines(x, (int)currentY, field3Width - 32, 30, SKYBLUE);

                    if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON)) { selectedOnce++; }
                    if (selectedOnce>=2 && offsetedFileId==i) {
                        appendPath(path, 512, rootFiles[i]->name);
                        goto exit;
                    } else if (i!=offsetedFileId) {
                        selectedOnce=0;
                    }
                    offsetedFileId=i;
                }
            }

            currentY += 34.0f;
        }
        if (IsKeyPressed(KEY_ENTER)) { goto exit; }
        // Rendering scrollbar
        if (contentHeight2 > (float)field3Height) {
            float scrollbarTrackHeight = (float)field3Height-14;
            float scrollbarHeight = ((float)field3Height / contentHeight2) * scrollbarTrackHeight;
            float scrollbarY = (float)startY + (scrollOffset2 / contentHeight2) * scrollbarTrackHeight;

            DrawRectangle(x + field3Width - 28, startY, 10, field3Height-14, Fade(BLACK, 0.3f));

            Color sbColor = isDraggingScrollbar2 ? WHITE : LIGHTGRAY;
            Rectangle scrollbarRect = {
                (float)(x + field3Width - 28),
                scrollbarY,
                10,
                scrollbarHeight
            };

            DrawRectangleRec(scrollbarRect, Fade(sbColor, 0.85f));

            Vector2 mouse = GetMousePosition();

            if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON)) {
                if (CheckCollisionPointRec(mouse, scrollbarRect)) {
                    isDraggingScrollbar2 = true;
                }
            }
            if (IsMouseButtonReleased(MOUSE_LEFT_BUTTON)) {
                isDraggingScrollbar2 = false;
            }
            if (isDraggingScrollbar2) {
                float mouseRelative = mouse.y - scrollbarHeight / 2.0f - (float)startY;
                scrollOffset2 = (mouseRelative / (float)field3Height) * contentHeight2;
            }
        }
    }

    if (IsKeyPressed(KEY_ESCAPE)) {
        exit:
        initialized=false;
        readDirFiles=false;
        rootFoldersAmount = 0;
        rootFilesAmount = 0;
        contentHeight = 0.0f;
        scrollOffset = 0.0f;
        isDraggingScrollbar = false;
        scrollOffset2 = 0.0f;
        isDraggingScrollbar2 = false;
        scrollVelocity = 0.0f;
        scrollFriction = 0.92f;
        scrollVelocity2 = 0.0f;
        scrollFriction2 = 0.92f;
        for (int k=0; k<256; k++) {free(rootFolders[k]);}
        for (int k=0; k<5120; k++) {free(rootFiles[k]);}
        return path;
    }
    return nullptr;
}