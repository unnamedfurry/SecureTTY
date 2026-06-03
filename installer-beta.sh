#!/bin/bash
set -e

# 0. MAKE SURE WE ARE ROOT!
if [ "$EUID" -ne 0 ]; then
    echo "Please run this installer script with sudo or as root."
    exit 1
fi

# 1. Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
fi

# 2. Install native dependencies with non-interactive flags
if [ "$ID" = "ubuntu" ] || [ "$ID" = "debian" ] || [ "$ID" = "linuxmint" ] || [ "$ID" = "pop" ]; then
    echo "Building natively for Debian-based..."
    sudo apt-get update
    sudo apt-get install -y libraylib-dev libssl-dev pkgconf default-mysql-client libxrandr-dev libxinerama-dev libxi-dev libxcursor-dev mesa-common-dev
elif [ "$ID" = "centos" ] || [ "$ID" = "rhel" ] || [ "$ID" = "fedora" ] || [ "$ID" = "rocky" ] || [ "$ID" = "almalinux" ]; then
    echo "Building natively for Red Hat-based..."
    sudo dnf install -y raylib-devel openssl-devel pkgconf community-mysql libXrandr-devel libXinerama-devel libXi-devel libXcursor-devel
elif [ "$ID" = "alpine" ]; then
    echo "Building natively for Alpine..."
    sudo apk add raylib-dev openssl-dev pkgconf mysql-client libxrandr-dev libxinerama-dev libxi-dev libxcursor-dev mesa-dev
elif [ "$ID" = "arch" ] || [ "$ID" = "manjaro" ]; then
    echo "Building natively for Arch..."
    sudo pacman -S --noconfirm raylib openssl pkgconf mariadb-clients
else
    echo "Unknown distribution: $ID"
    exit 1
fi

# 3. Download and Compile
echo "Fetching githubusercontent..."
mkdir -p unchat
cd unchat
wget -O client.c https://raw.githubusercontent.com/unnamedfurry/UnChat/refs/heads/main/client.c
echo "Compiling the .c file..."
gcc client.c -o client -lraylib -lssl -lcrypto -lGL -lm -lpthread -ldl -lrt -lX11 -lXrandr -lXinerama -lXi -lXcursor
install -m 755 client /usr/local/bin/unchat

echo "Application installed with no troubles, enjoy!"
echo "(launch with unchat command in terminal)"