# SecureTTY
This is yet another chat project made for practide and fun. 
This project uses: 
- raylib as graphical engine
- native linux network library for communication
- openssl and sodium as network and client config encryptor
- mysql as server’s memory
**Maaaaybeeee** sometimes it will grow to serious, big, enterprise-level project. All you can do now is just use it and report bugs to improve whatever its called or contribute if you’re a C developer (i will personally say “thaaaank you :3 *purrrrrr*” to you). Enjoy

---

### Server setup:
You will need:
- Any VPS/VDS on Debian-based or Arch-based linux distro
- MySQL package
- Root privilegies (strongly recommended for installer)

You should do:
1. Download server binary to folder (e.g. "securetty") and chmod is (`chmod +x server`)
2. Create mysql table named `securetty`:
    ```bash
    mysql -u root -p
    CREATE DATABASE securetty;
    exit;
    ```
3. Configure your server network in **server.h**
4. Run the binary:
    ```bash
    cd securetty
    ./server
    ```
    P.S. its recommended to use screen package to not lose process and its tty console: `sudo apt install screen`, and then run with command:
    ```bach
    cd securetty
    screen -s securetty -dm ./server
    ```
---
### Client setup
You should do:
1. Download **installer-beta.sh** or **installer-stable.sh**
2. Configure your client network in **client.h**
3. Execute it. Installer will automatically download all needed libraries and chat binary

I'll update this later
