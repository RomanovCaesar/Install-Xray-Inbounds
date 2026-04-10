[中文](/README.md) | [English](/README_en_US.md) | [日本語](/README_ja_JP.md) | [Русский](/README_ru_RU.md) 

# Caesar 蜜汁 Xray 一键安装与管理工具箱 (Install-Xray-Inbounds)

这是一个功能强大、高度模块化且极具兼容性的 Xray 节点安装与管理脚本集合。支持在一台服务器上完美共存部署多种主流协议（VLESS-Reality、VLESS-Encryption、Shadowsocks 2022 等），并提供便捷的配置备份、路由分流管理以及 Geo 数据更新功能。

## ✨ 核心特性

* **多协议智能共存**：采用底层 `jq` 解析并智能追加 JSON 配置，随心所欲安装多个不同协议或多端口节点，**绝对不会覆盖**原有节点配置。
* **极致的系统兼容**：不仅完美支持 Debian / Ubuntu 等基于 Systemd 的主流系统，更**深度兼容 Alpine Linux (OpenRC)**，对极其精简的轻量级系统同样友好。
* **NAT / DDNS 友好**：内置独立连接地址自定义功能，无论你是使用 NAT 动态端口机，还是通过 DDNS 域名解析，都能一键生成正确的分享链接，告别手动改地址的烦恼。
* **前沿协议支持**：支持最新的 VLESS Encryption (Post-Quantum 纯净抗量子加密) 和 VLESS-Reality (Vision)，并自动将原生密钥转换为兼容性更强的随机密钥。
* **一站式管理**：提供全局统一的管理菜单 (`xray-manager`)、路由分流配置工具 (`xray-routing`) 以及配置备份还原工具 (`xray-restore`)。
* **安全精准删除**：支持按端口和协议精准识别并删除特定节点配置，绝不误伤无辜配置。

---

## 🚀 快速开始（推荐）

如果你想体验最完整的管理功能，推荐直接安装**统一管理中心（Xray Manager）**。

执行以下命令即可下载并唤出全局管理菜单：

```bash
curl -L https://raw.githubusercontent.com/RomanovCaesar/Install-Xray-Inbounds/main/xray_manager.sh -o xray_manager.sh && chmod +x xray_manager.sh && sudo ./xray_manager.sh
```

**💡 贴心提示：**
统一管理工具安装完成后，会自动注册全局命令。以后你随时可以通过在终端输入以下命令来快速唤醒主菜单：
```bash
xray-manager
```

在 `xray-manager` 菜单中，你可以直接一键调用以下所有独立功能，无需再单独下载脚本。

---

## 📦 各功能模块独立安装指南

如果你只想使用本项目的某一个特定功能，也可以直接使用以下独立安装命令。

### 1. VLESS-Reality (Vision) 节点管理
支持自动生成 X25519 密钥对，默认使用 `xtls-rprx-vision` 流控，稳定且隐蔽。
```bash
curl -L https://raw.githubusercontent.com/RomanovCaesar/Install-Xray-Inbounds/main/install_vless_reality.sh -o install_vless_reality.sh && chmod +x install_vless_reality.sh && sudo ./install_vless_reality.sh
```

### 2. VLESS-Encryption (Post-Quantum) 节点管理
部署最新的抗量子加密协议 (ML-KEM-768)，自动生成并优化随机密钥，为未来网络安全保驾护航。
```bash
curl -L https://raw.githubusercontent.com/RomanovCaesar/Install-Xray-Inbounds/main/install_vless_encryption.sh -o install_vless_encryption.sh && chmod +x install_vless_encryption.sh && sudo ./install_vless_encryption.sh
```

### 3. Shadowsocks 2022 & 传统 SS 节点管理
支持极速的 2022-blake3-aes 等新一代加密协议，并向下兼容传统的 aes-gcm 加密，自动生成强随机密码。
```bash
curl -L https://raw.githubusercontent.com/RomanovCaesar/Install-Xray-Inbounds/main/install_ss2022.sh -o install_ss2022.sh && chmod +x install_ss2022.sh && sudo ./install_ss2022.sh
```

### 4. 服务端路由分流工具 (Xray Routing)
强大的服务端出口分流控制面板。支持引入外部配置链接、支持解析ss和vless分享链接中各种参数（目前只支持ss、ss2022、vless vision reality和vless encryption）、可视化配置 Inbounds 到 Outbounds 的 IP/域名分流规则。
```bash
curl -L https://raw.githubusercontent.com/RomanovCaesar/Install-Xray-Inbounds/main/xray_routing.sh -o xray_routing.sh && chmod +x xray_routing.sh && sudo ./xray_routing.sh
```
*安装后随时可用 `xray-routing` 命令唤起。*

### 5. 备份与还原工具 (Xray Restore)
不小心改错了配置？想要迁移配置？使用此工具可以通过直链 URL 导入配置文件，或者打开控制台手动粘贴 `config.json`，自带安全测试防报错功能。
```bash
curl -L https://raw.githubusercontent.com/RomanovCaesar/Install-Xray-Inbounds/main/xray_restore.sh -o xray_restore.sh && chmod +x xray_restore.sh && sudo ./xray_restore.sh
```
*安装后随时可用 `xray-restore` 命令唤起。*

### 6. 完全卸载工具
如果你遇到无法解决的严重问题，或者想要完全清理服务器，可以使用此脚本。它会极其干净地清理系统服务（Systemd/OpenRC）、二进制文件、日志以及残留配置。
```bash
curl -L https://raw.githubusercontent.com/RomanovCaesar/Install-Xray-Inbounds/main/uninstall_xray.sh -o uninstall_xray.sh && chmod +x uninstall_xray.sh && sudo ./uninstall_xray.sh
```

---

## 🛠️ 常见问题 (FAQ)

**Q: 我的服务器是 NAT VPS，或者入口 IP 跟出口 IP 不一样，生成的节点不通怎么办？**

**A:** 请在任意安装菜单（或主管理菜单）中选择 **“设置连接地址 (NAT/DDNS)”** 选项。填入你实际用于外部连接的 IP 地址或 DDNS 域名。设置完成后，脚本自动生成的分享链接将会使用你指定的地址，完美解决 NAT 环境下的直连问题。

**Q: 如何查看 Xray 的运行日志？**

**A:** 在各个安装管理脚本的菜单中，都有 **“查看 Xray 日志”** 选项。选择后即可实时查看运行日志，按 `Ctrl + C` 即可停止查看并返回菜单。

**Q: 如何更新 GeoIP 和 GeoSite 路由规则文件？**

**A:** 如果你使用了 `xray-routing` (服务端分流工具)，里面包含了一键自动配置定时任务的功能，会每天凌晨自动更新。你也可以在主管理工具 (`xray-manager`) 中手动执行即时更新。
