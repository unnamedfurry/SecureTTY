# UnChat
This is yet another chat project made for practide and fun. **Maaaaybeeee** sometimes it will grow to serious, big, enterprise-level project. All you can do now is just use it and report bugs to improve whatever its called. Enjoy :3

---

### Server setup:
You will need:
- Any VPS/VDS on Ubuntu/Debian
- MySQL package
- Root privilegies (strongly recommended for installer)

You should do:
1. Download server binary to folder (e.g. "unchat") and chmod is (`chmod +x server`)
2. Create mysql table named `unchat`:
    ```bash
    mysql -u root -p
    CREATE DATABASE unchat;
    exit;
    ```
3. Configure your server network in **server.h**
4. Run the binary:
    ```bash
    cd unchat
    ./server
    ```
    P.S. its recommended to use screen package to not lose process and its tty console: `sudo apt install screen`, and then run with command:
    ```bach
    cd unchat
    screen -s unchat -dm ./server
    ```
---
### Client setup
You should do:
1. Download **installer-beta.sh** or **installer-stable.sh**
2. Configure your client network in **client.h**
3. Execute it. Installer will automatically download all needed libraries and chat binary

I'll update this later
