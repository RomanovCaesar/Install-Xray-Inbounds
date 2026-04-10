[中文](/README.md) | [English](/README_en_US.md) | [日本語](/README_ja_JP.md) 

# Caesar's Special Xray One-Click Installation & Management Toolkit (Install-Xray-Inbounds)

This is a powerful, highly modular, and extremely compatible collection of Xray node installation and management scripts. It supports the perfect coexistence of multiple mainstream protocols (VLESS-Reality, VLESS-Encryption, Shadowsocks 2022, etc.) deployed on a single server, and provides convenient configuration backup, routing management, and Geo data update features.

## ✨ Core Features

* **Smart Multi-Protocol Coexistence**: Utilizes underlying `jq` parsing to intelligently append JSON configurations. Install multiple different protocols or multi-port nodes as you wish, **absolutely without overwriting** original node configurations.
* **Extreme System Compatibility**: Not only perfectly supports mainstream systems based on Systemd like Debian/Ubuntu, but also features **deep compatibility with Alpine Linux (OpenRC)**, making it highly friendly to extremely stripped-down lightweight systems.
* **NAT / DDNS Friendly**: Built-in independent connection address customization. Whether you are using a NAT VPS with dynamic ports or DDNS domain resolution, it can generate the correct share links with one click. Say goodbye to the hassle of manually modifying addresses.
* **Cutting-Edge Protocol Support**: Supports the latest VLESS Encryption (Post-Quantum pure encryption) and VLESS-Reality (Vision), automatically converting native keys to more highly-compatible random keys.
* **One-Stop Management**: Provides a unified global management menu (`xray-manager`), a routing configuration tool (`xray-routing`), and a configuration backup/restore tool (`xray-restore`).
* **Safe & Precise Deletion**: Supports precise identification and deletion of specific node configurations by port and protocol, ensuring innocent configurations are never accidentally damaged.

---

## 🚀 Quick Start (Recommended)

If you want to experience the most complete management features, it is highly recommended to directly install the **Unified Management Center (Xray Manager)**.

Execute the following command to download and bring up the global management menu:

```bash
curl -L https://raw.githubusercontent.com/RomanovCaesar/Install-Xray-Inbounds/main/xray_manager.sh -o xray_manager.sh && chmod +x xray_manager.sh && sudo ./xray_manager.sh
```

**💡 Pro Tip:**
After the unified management tool is installed, it automatically registers a global command. You can quickly wake up the main menu anytime by entering the following command in the terminal:
```bash
xray-manager
```

In the `xray-manager` menu, you can invoke all the independent features below with one click, without needing to download scripts separately.

---

## 📦 Independent Module Installation Guide

If you only want to use a specific feature of this project, you can also use the following independent installation commands directly.

### 1. VLESS-Reality (Vision) Node Management
Supports auto-generation of X25519 key pairs, defaults to `xtls-rprx-vision` flow control, stable and stealthy.
```bash
curl -L https://raw.githubusercontent.com/RomanovCaesar/Install-Xray-Inbounds/main/install_vless_reality.sh -o install_vless_reality.sh && chmod +x install_vless_reality.sh && sudo ./install_vless_reality.sh
```

### 2. VLESS-Encryption (Post-Quantum) Node Management
Deploys the latest post-quantum encryption protocol (ML-KEM-768), automatically generates and optimizes random keys, escorting future network security.
```bash
curl -L https://raw.githubusercontent.com/RomanovCaesar/Install-Xray-Inbounds/main/install_vless_encryption.sh -o install_vless_encryption.sh && chmod +x install_vless_encryption.sh && sudo ./install_vless_encryption.sh
```

### 3. Shadowsocks 2022 & Legacy SS Node Management
Supports the lightning-fast new generation encryption protocols like 2022-blake3-aes, and is backward compatible with traditional aes-gcm encryption, automatically generating strong random passwords.
```bash
curl -L https://raw.githubusercontent.com/RomanovCaesar/Install-Xray-Inbounds/main/install_ss2022.sh -o install_ss2022.sh && chmod +x install_ss2022.sh && sudo ./install_ss2022.sh
```

### 4. Server-Side Routing Tool (Xray Routing)
A powerful server-side outbound routing control panel. Supports importing external config links, parsing multiple parameters in ss and vless config links (currently only supporting ss, ss2022, vless vision reality and vless encryption), and visually configuring IP/domain routing rules from Inbounds to Outbounds.
```bash
curl -L https://raw.githubusercontent.com/RomanovCaesar/Install-Xray-Inbounds/main/xray_routing.sh -o xray_routing.sh && chmod +x xray_routing.sh && sudo ./xray_routing.sh
```
*Available anytime via the `xray-routing` command after installation.*

### 5. Backup & Restore Tool (Xray Restore)
Accidentally messed up your config? Want to migrate configurations? Use this tool to import `config.json` via a direct URL, or manually paste it in the console. Comes with built-in safety tests to prevent crash errors.
```bash
curl -L https://raw.githubusercontent.com/RomanovCaesar/Install-Xray-Inbounds/main/xray_restore.sh -o xray_restore.sh && chmod +x xray_restore.sh && sudo ./xray_restore.sh
```
*Available anytime via the `xray-restore` command after installation.*

### 6. Complete Uninstallation Tool
If you encounter unresolvable severe issues or want to completely clean your server, you can use this script. It cleanly removes system services (Systemd/OpenRC), binaries, logs, and residual configurations.
```bash
curl -L https://raw.githubusercontent.com/RomanovCaesar/Install-Xray-Inbounds/main/uninstall_xray.sh -o uninstall_xray.sh && chmod +x uninstall_xray.sh && sudo ./uninstall_xray.sh
```

---

## 🛠️ Frequently Asked Questions (FAQ)

**Q: My server is a NAT VPS, or the inbound IP is different from the outbound IP, and the generated node doesn't connect. What should I do?**

**A:** Please select the **"Set Connection Address (NAT/DDNS)"** option in any installation menu (or the main management menu). Enter the actual IP address or DDNS domain name you use for external connections. Once set, the share links automatically generated by the script will use your specified address, perfectly solving direct connection issues in NAT environments.

**Q: How do I view Xray's running logs?**

**A:** In the menus of all installation/management scripts, there is a **"View Xray Log"** option. Select it to view real-time running logs. Press `Ctrl + C` to stop viewing and return to the menu.

**Q: How do I update the GeoIP and GeoSite routing rule files?**

**A:** If you use `xray-routing` (the server-side routing tool), it includes a one-click automatic scheduled task configuration that updates them automatically every day at dawn. You can also manually trigger an instant update in the main management tool (`xray-manager`).
