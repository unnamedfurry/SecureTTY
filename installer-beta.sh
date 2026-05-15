#!/bin/bash
# =============================================
# UnChat Client Installer
# =============================================

# ==================== НАСТРОЙКИ (поменяй здесь) ====================
GITHUB_USER="unnamedfurry"          # твой ник на GitHub
GITHUB_REPO="UnChat"

# Выбери одну из двух строк ниже:

# Вариант A — из Release (рекомендуется)
VERSION="BETA"                    # или "v1.2.3", или оставь latest
BRANCH_OR_TAG="${VERSION}"

# Вариант B — напрямую из ветки (develop/main)
# BRANCH="main"                     # ← раскомментируй и укажи ветку
# BRANCH_OR_TAG="${BRANCH}"

# =================================================================

APP_NAME="unchat-client"
INSTALL_DIR="$HOME/.local/bin"
DESKTOP_FILE="$HOME/.local/share/applications/unchat.desktop"

echo "=== UnChat Client Installer ==="

# Создаём папки
mkdir -p "$INSTALL_DIR"
mkdir -p "$HOME/.local/share/applications"

# Определяем архитектуру
ARCH=$(uname -m)
case $ARCH in
    x86_64)  ARCH="x86_64" ;;
    aarch64) ARCH="aarch64" ;;
    armv7l)  ARCH="armv7" ;;
    *)       echo "Неизвестная архитектура: $ARCH"; exit 1 ;;
esac

echo "Архитектура: $ARCH"

# ==================== Скачивание ====================

if [ "$VERSION" = "latest" ]; then
    DOWNLOAD_URL="https://github.com/${GITHUB_USER}/${GITHUB_REPO}/releases/latest/download/${APP_NAME}-linux-${ARCH}"
else
    DOWNLOAD_URL="https://github.com/${GITHUB_USER}/${GITHUB_REPO}/releases/download/${BRANCH_OR_TAG}/${APP_NAME}-linux-${ARCH}"
fi

echo "Скачиваем с: $DOWNLOAD_URL"

curl -L -o "$INSTALL_DIR/$APP_NAME" "$DOWNLOAD_URL" || {
    echo "Ошибка скачивания. Проверь, существует ли файл в Releases."
    exit 1
}

chmod +x "$INSTALL_DIR/$APP_NAME"

# ==================== .desktop файл ====================
cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Name=UnChat
Comment=Клиент UnChat
Exec=$INSTALL_DIR/$APP_NAME
Icon=application-x-executable
Type=Application
Categories=Network;InstantMessaging;Chat;
Terminal=false
StartupNotify=true
EOF

# ==================== Финал ====================
echo "========================================"
echo "✅ UnChat Client успешно установлен!"
echo "   Команда для запуска: $APP_NAME"
echo "   Или найди UnChat в меню приложений."
echo "========================================"

# Добавляем в PATH, если нужно
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo "export PATH=\"\$PATH:$INSTALL_DIR\"" >> "$HOME/.bashrc"
    echo "export PATH=\"\$PATH:$INSTALL_DIR\"" >> "$HOME/.zshrc" 2>/dev/null || true
    echo "PATH обновлён (перезапустите терминал)"
fi
