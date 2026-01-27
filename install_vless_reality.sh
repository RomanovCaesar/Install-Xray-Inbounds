#!/bin/bash

# ==============================================================================
# Xray VLESS-Reality 一键安装管理脚本
# 此脚本Fork自https://github.com/yahuisme/xray-vless-reality, 感谢@yahuisme
# 版本: V-Fork-Caesar-2.2
# 更新日志 (V-Fork-Caesar-2.2):
# - [改进] 默认Outbounds domainStrategy改为AsIs
# - [改进] 默认Reality sni改为hk.art.museum
# - [改进] 新增 Alpine 系统识别与兼容（apk 依赖安装、OpenRC 服务管理与日志查看）
# ==============================================================================

# --- Shell 严格模式 ---
set -euo pipefail

# --- 全局常量 ---
readonly SCRIPT_VERSION="V-Final-2.1"
readonly xray_config_path="/usr/local/etc/xray/config.json"
readonly xray_binary_path="/usr/local/bin/xray"
readonly xray_install_script_url="https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh"

# --- 颜色定义 ---
readonly red='\e[91m' green='\e[92m' yellow='\e[93m'
readonly magenta='\e[95m' cyan='\e[96m' none='\e[0m'

# --- 全局变量 ---
xray_status_info=""
is_quiet=false
OS_ID=""
INIT_SYSTEM=""

# --- 辅助函数 ---
error() { echo -e "\n${red}[✖] $1${none}\n" >&2; }
info()  { [[ "$is_quiet" = false ]] && echo -e "\n${yellow}[!] $1${none}\n"; }
success(){ [[ "$is_quiet" = false ]] && echo -e "\n${green}[✔] $1${none}\n"; }

spinner() {
    local pid=$1; local spinstr='|/-\\'
    if [[ "$is_quiet" = true ]]; then
        wait "$pid"
        return
    fi
    while ps -p "$pid" > /dev/null 2>&1; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep 0.1
        printf "\r"
    done
    printf "    \r"
}

get_public_ip() {
    local ip
    for cmd in "curl -4s --max-time 5" "wget -4qO- --timeout=5"; do
        for url in "https://api.ipify.org" "https://ip.sb" "https://checkip.amazonaws.com"; do
            ip=$($cmd "$url" 2>/dev/null) && [[ -n "$ip" ]] && echo "$ip" && return
        done
    done
    for cmd in "curl -6s --max-time 5" "wget -6qO- --timeout=5"; do
        for url in "https://api64.ipify.org" "https://ip.sb"; do
            ip=$($cmd "$url" 2>/dev/null) && [[ -n "$ip" ]] && echo "$ip" && return
        done
    done
    error "无法获取公网 IP 地址。" && return 1
}

execute_official_script() {
    local action="$1"
    local install_dir="/usr/local/bin"
    local version url tmpdir arch

    # 判断是否有 systemctl（Debian/Ubuntu）
    if command -v systemctl >/dev/null 2>&1; then
        info "检测到 systemd 系统，使用官方 Xray 安装脚本..."
        if [[ "$is_quiet" = true ]]; then
            curl -fsSL "$xray_install_script_url" | bash -s -- "$action" >/dev/null 2>&1
        else
            curl -fsSL "$xray_install_script_url" | bash -s -- "$action"
        fi
        return
    fi

    # 否则走手动安装（Alpine/OpenRC）
    info "检测到非 systemd 系统（如 Alpine / OpenRC），使用手动安装逻辑..."

    case "$action" in
        install)
            # 获取最新版本号
            version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name | sed 's/^v//')
            [[ -z "$version" ]] && { error "获取 Xray 版本号失败"; return 1; }

            info "正在下载 Xray-core $version ..."
            tmpdir=$(mktemp -d)
            arch=$(uname -m)
            case "$arch" in
                x86_64)  arch="64" ;;
                aarch64) arch="arm64-v8a" ;;
                armv7l)  arch="arm32-v7a" ;;
                *) error "不支持的架构: $arch"; rm -rf "$tmpdir"; return 1 ;;
            esac

            url="https://github.com/XTLS/Xray-core/releases/download/v${version}/Xray-linux-${arch}.zip"
            curl -L -o "$tmpdir/xray.zip" "$url" || { error "下载失败"; rm -rf "$tmpdir"; return 1; }

            unzip -qo "$tmpdir/xray.zip" -d "$tmpdir" || { error "解压失败"; rm -rf "$tmpdir"; return 1; }
            install -m 755 "$tmpdir/xray" "$install_dir/xray"

            mkdir -p /usr/local/etc/xray /usr/local/share/xray
            rm -rf "$tmpdir"

            success "Xray 核心已安装到 $install_dir/xray"
            ;;

        install-geodata)
            info "下载最新 GeoIP / GeoSite 数据文件..."
            mkdir -p /usr/local/share/xray
            curl -fsSL -o /usr/local/share/xray/geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
            curl -fsSL -o /usr/local/share/xray/geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
            success "Geo 数据文件已更新"
            ;;

        remove|--purge)
            info "卸载 Xray..."
            rm -f /usr/local/bin/xray /usr/local/etc/xray/config.json
            rm -rf /usr/local/share/xray
            success "Xray 已卸载完成"
            ;;

        *)
            error "未知操作: $action"
            return 1
            ;;
    esac
}

# --- 改进的验证函数 ---
is_valid_port() {
    local port=$1
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

# 新增：检查端口是否被占用（兼容多系统）
is_port_in_use() {
    local port=$1
    if command -v ss &>/dev/null; then
        ss -tuln 2>/dev/null | grep -q ":$port "
    elif command -v netstat &>/dev/null; then
        netstat -tuln 2>/dev/null | grep -q ":$port "
    elif command -v lsof &>/dev/null; then
        lsof -i ":$port" &>/dev/null
    elif command -v nc &>/dev/null; then
        nc -z 127.0.0.1 "$port" 2>/dev/null
    else
        # /dev/tcp 方案（需要 bash 支持）
        (echo > "/dev/tcp/127.0.0.1/$port") >/dev/null 2>&1
    fi
}

# 增强的UUID验证函数
is_valid_uuid() {
    local uuid=$1
    [[ "$uuid" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]
}

is_valid_domain() {
    local domain=$1
    [[ "$domain" =~ ^[a-zA-Z0-9-]{1,63}(\.[a-zA-Z0-9-]{1,63})+$ ]] && [[ "$domain" != *--* ]]
}

# --- 初始化系统识别 ---
detect_system() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID=${ID:-}
    fi
    if command -v systemctl >/dev/null 2>&1; then
        INIT_SYSTEM="systemd"
    elif command -v rc-service >/dev/null 2>&1; then
        INIT_SYSTEM="openrc"
    else
        INIT_SYSTEM="unknown"
    fi
}

# --- OpenRC 服务编排（仅 Alpine 等 OpenRC 环境） ---
ensure_openrc_service() {
    # 如果是 systemd 则不处理
    [[ "$INIT_SYSTEM" != "openrc" ]] && return 0

    # 若已存在 init 脚本直接返回
    if [[ -x /etc/init.d/xray ]]; then
        return 0
    fi

    info "检测到 OpenRC，正在创建 /etc/init.d/xray 服务脚本…"
    install -d -m 0755 /var/log/xray || true

    cat >/etc/init.d/xray <<'EOF'
#!/sbin/openrc-run
name="Xray"
description="Xray (XTLS) service"

command="/usr/local/bin/xray"
command_args="run -config /usr/local/etc/xray/config.json"
command_background=true
pidfile="/run/xray.pid"
output_log="/var/log/xray/access.log"
error_log="/var/log/xray/error.log"

depend() {
    need net
    use dns logger
}
EOF

    chmod +x /etc/init.d/xray
    rc-update add xray default || true
    success "OpenRC 服务已创建并加入开机自启。"
}

service_restart() {
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        systemctl restart xray
    elif [[ "$INIT_SYSTEM" == "openrc" ]]; then
        rc-service xray restart
    else
        error "无法确定服务管理器，请手动重启 Xray。"
        return 1
    fi
}

service_is_active() {
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        systemctl is-active --quiet xray
    elif [[ "$INIT_SYSTEM" == "openrc" ]]; then
        rc-service xray status >/dev/null 2>&1 && rc-service xray status 2>/dev/null | grep -qi started
    else
        return 1
    fi
}

# --- 改进的系统兼容性检查（加入 Alpine） ---
check_system_compatibility() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        error "错误: 此脚本仅支持 Linux 系统。"
        return 1
    fi

    detect_system

    # 支持发行版
    local supported_distros=("ubuntu" "debian" "kali" "raspbian" "deepin" "mint" "elementary" "alpine")
    local distro_detected=false

    for s in "${supported_distros[@]}"; do
        if [[ "${OS_ID}" == "$s" ]]; then
            distro_detected=true
            break
        fi
    done

    # APT 兼容作为兜底
    if [[ "$distro_detected" == false ]]; then
        if command -v apt &>/dev/null && command -v dpkg &>/dev/null; then
            distro_detected=true
            OS_ID="debian-compatible"
            info "检测到基于 APT 的包管理系统，假定为 Debian 兼容系统。"
        fi
    fi

    if [[ "$distro_detected" == false ]]; then
        error "错误: 未检测到支持的 Linux 发行版。"
        error "支持的系统: Ubuntu, Debian, Kali, Raspbian, Deepin, Linux Mint, elementary OS, Alpine"
        error "当前系统信息: $(uname -a)"
        return 1
    fi

    if [[ "$is_quiet" == false ]]; then
        info "系统兼容性检查通过"
        info "检测到系统: ${OS_ID} | init: ${INIT_SYSTEM}"
    fi

    # 关键命令：不再强制 systemctl；按需检查基础工具
    local required_commands=("awk" "grep" "sed")
    local missing_commands=()
    for cmd in "${required_commands[@]}"; do
        command -v "$cmd" >/dev/null 2>&1 || missing_commands+=("$cmd")
    done
    if [[ ${#missing_commands[@]} -gt 0 ]]; then
        error "错误: 缺少必要的系统命令: ${missing_commands[*]}"
        return 1
    fi
    return 0
}

# --- 预检查与环境设置 ---
pre_check() {
    [[ $(id -u) != 0 ]] && error "错误: 您必须以root用户身份运行此脚本" && exit 1

    if ! check_system_compatibility; then
        exit 1
    fi

    # 依赖安装：根据不同包管理器处理
    if ! command -v jq &>/dev/null || ! command -v curl &>/dev/null; then
        info "检测到缺失的依赖 (jq/curl)，正在尝试自动安装…"
        if [[ "$OS_ID" == "alpine" ]]; then
            (apk update && apk add --no-cache jq curl bash iproute2 coreutils netcat-openbsd) &> /dev/null &
            spinner $!
            # Alpine 默认 /bin/sh 为 ash，但本脚本用 bash，确保安装了 bash
        else
            (DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y jq curl) &> /dev/null &
            spinner $!
        fi
        if ! command -v jq &>/dev/null || ! command -v curl &>/dev/null; then
            if [[ "$OS_ID" == "alpine" ]]; then
                error "依赖 (jq/curl) 自动安装失败。请手动运行 'apk add --no-cache jq curl' 后重试。"
            else
                error "依赖 (jq/curl) 自动安装失败。请手动运行 'apt update && apt install -y jq curl' 后重试。"
            fi
            exit 1
        fi
        success "依赖已成功安装。"
    fi
}

check_xray_status() {
    if [[ ! -f "$xray_binary_path" ]]; then xray_status_info="  Xray 状态: ${red}未安装${none}"; return; fi
    local xray_version=$($xray_binary_path version 2>/dev/null | head -n 1 | awk '{print $2}' || echo "未知")
    local service_status
    if service_is_active; then service_status="${green}运行中${none}"; else service_status="${yellow}未运行${none}"; fi
    xray_status_info="  Xray 状态: ${green}已安装${none} | ${service_status} | 版本: ${cyan}${xray_version}${none}"
}

# --- 菜单功能函数 ---
install_xray() {
    if [[ -f "$xray_binary_path" ]]; then
        info "检测到 Xray 已安装。继续操作将覆盖现有配置。"
        read -p "是否继续？[y/N]: " confirm
        if [[ ! $confirm =~ ^[yY]$ ]]; then info "操作已取消。"; return; fi
    fi
    info "开始配置 Xray..."
    local port uuid domain

    while true; do
        read -p "$(echo -e "请输入端口 [1-65535] (默认: ${cyan}443${none}): ")" port
        [ -z "$port" ] && port=443
        if ! is_valid_port "$port"; then
            error "端口无效，请输入一个1-65535之间的数字。"
            continue
        fi
        if is_port_in_use "$port"; then
            error "端口 $port 已被占用，请选择其他端口。"
            continue
        fi
        break
    done

    while true; do
        read -p "$(echo -e "请输入UUID (留空将默认生成随机UUID): ")" uuid
        if [[ -z "$uuid" ]]; then 
            uuid=$(cat /proc/sys/kernel/random/uuid)
            info "已为您生成随机UUID: ${cyan}${uuid}${none}"
            break
        elif is_valid_uuid "$uuid"; then
            break
        else
            error "UUID格式无效，请输入标准UUID格式 (如: 550e8400-e29b-41d4-a716-446655440000) 或留空自动生成。"
        fi
    done

    while true; do
        read -p "$(echo -e "请输入SNI域名 (默认: ${cyan}hk.art.museum${none}): ")" domain
        [ -z "$domain" ] && domain="hk.art.museum"
        if is_valid_domain "$domain"; then break; else error "域名格式无效，请重新输入。"; fi
    done

    run_install "$port" "$uuid" "$domain"
}

update_xray() {
    if [[ ! -f "$xray_binary_path" ]]; then error "错误: Xray 未安装，无法执行更新。请先选择安装选项。" && return; fi
    info "正在检查最新版本..."
    local current_version=$($xray_binary_path version | head -n 1 | awk '{print $2}')
    local latest_version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.tag_name' | sed 's/v//' || echo "")
    if [[ -z "$latest_version" ]]; then error "获取最新版本号失败，请检查网络或稍后再试。" && return; fi
    info "当前版本: ${cyan}${current_version}${none}，最新版本: ${cyan}${latest_version}${none}"
    if [[ "$current_version" == "$latest_version" ]]; then success "您的 Xray 已是最新版本，无需更新。" && return; fi
    info "发现新版本，开始更新..."
    if ! execute_official_script "install"; then error "Xray 核心更新失败！" && return; fi
    info "正在更新 GeoIP 和 GeoSite 数据文件..."
    execute_official_script "install-geodata"

    if ! restart_xray; then return; fi
    success "Xray 更新成功！"
}

restart_xray() {
    if [[ ! -f "$xray_binary_path" ]]; then error "错误: Xray 未安装，无法重启。" && return 1; fi
    info "正在重启 Xray 服务..."
    if ! service_restart; then
        error "错误: Xray 服务重启失败, 请使用菜单 5 查看日志检查具体原因。"
        return 1
    fi
    sleep 1
    if ! service_is_active; then
        error "错误: Xray 服务启动失败, 请使用菜单 5 查看日志检查具体原因。"
        return 1
    fi
    success "Xray 服务已成功重启！"
}

uninstall_xray() {
    if [[ ! -f "$xray_binary_path" ]]; then error "错误: Xray 未安装，无需卸载。" && return; fi
    read -p "您确定要卸载 Xray 吗？这将删除所有相关文件。[Y/n]: " confirm
    if [[ "$confirm" =~ ^[nN]$ ]]; then
        info "卸载操作已取消。"
        return
    fi
    info "正在卸载 Xray..."
    if execute_official_script "remove --purge"; then
        rm -f ~/xray_vless_reality_link.txt || true
        # OpenRC 清理
        if [[ "$INIT_SYSTEM" == "openrc" ]]; then
            rc-update del xray default >/dev/null 2>&1 || true
            rm -f /etc/init.d/xray || true
        fi
        success "Xray 已成功卸载。"
    else
        error "Xray 卸载失败！"
        return 1
    fi
}

view_xray_log() {
    if [[ ! -f "$xray_binary_path" ]]; then error "错误: Xray 未安装，无法查看日志。" && return; fi
    info "正在显示 Xray 实时日志... 按 Ctrl+C 退出。"
    if command -v journalctl >/dev/null 2>&1; then
        journalctl -u xray -f --no-pager
    elif command -v logread >/dev/null 2>&1; then
        # BusyBox syslog
        logread -f | grep -i xray
    elif [[ -d /var/log/xray ]]; then
        tail -n 200 -F /var/log/xray/*.log 2>/dev/null || tail -n 200 -F /var/log/*.log | grep -i xray
    else
        error "无法找到日志来源，请检查系统日志或 /var/log/xray。"
    fi
}

modify_config() {
    if [[ ! -f "$xray_config_path" ]]; then error "错误: Xray 未安装，无法修改配置。" && return; fi
    info "读取当前配置..."
    local current_port=$(jq -r '.inbounds[0].port' "$xray_config_path")
    local current_uuid=$(jq -r '.inbounds[0].settings.clients[0].id' "$xray_config_path")
    local current_domain=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' "$xray_config_path")
    local private_key=$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey' "$xray_config_path")
    local public_key=$(jq -r '.inbounds[0].streamSettings.realitySettings.publicKey' "$xray_config_path")

    info "请输入新配置，直接回车则保留当前值。"
    local port uuid domain
    
    while true; do
        read -p "$(echo -e "端口 (当前: ${cyan}${current_port}${none}): ")" port
        [ -z "$port" ] && port=$current_port
        if ! is_valid_port "$port"; then
            error "端口无效，请输入一个1-65535之间的数字。"
            continue
        fi
        if [[ "$port" != "$current_port" ]] && is_port_in_use "$port"; then
            error "端口 $port 已被占用，请选择其他端口。"
            continue
        fi
        break
    done
    
    while true; do
        read -p "$(echo -e "UUID (当前: ${cyan}${current_uuid}${none}): ")" uuid
        [ -z "$uuid" ] && uuid=$current_uuid
        if is_valid_uuid "$uuid"; then
            break
        else
            error "UUID格式无效，请输入标准UUID格式。"
        fi
    done
    
    while true; do
        read -p "$(echo -e "SNI域名 (当前: ${cyan}${current_domain}${none}): ")" domain
        [ -z "$domain" ] && domain=$current_domain
        if is_valid_domain "$domain"; then break; else error "域名格式无效，请重新输入。"; fi
    done

    write_config "$port" "$uuid" "$domain" "$private_key" "$public_key"
    if ! restart_xray; then return; fi

    success "配置修改成功！"
    view_subscription_info
}

view_subscription_info() {
    if [ ! -f "$xray_config_path" ]; then error "错误: 配置文件不存在, 请先安装。" && return; fi
    
    local ip
    if ! ip=$(get_public_ip); then return 1; fi

    local uuid=$(jq -r '.inbounds[0].settings.clients[0].id' "$xray_config_path")
    local port=$(jq -r '.inbounds[0].port' "$xray_config_path")
    local domain=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' "$xray_config_path")
    local public_key=$(jq -r '.inbounds[0].streamSettings.realitySettings.publicKey' "$xray_config_path")
    local shortid=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0]' "$xray_config_path")
    if [[ -z "$public_key" ]]; then error "配置文件中缺少公钥信息,可能是旧版配置,请重新安装以修复。" && return; fi

    local display_ip=$ip && [[ $ip =~ ":" ]] && display_ip="[$ip]"
    local link_name="$(hostname) X-reality"
    local link_name_encoded=$(echo "$link_name" | sed 's/ /%20/g')
    local vless_url="vless://${uuid}@${display_ip}:${port}?flow=xtls-rprx-vision&encryption=none&type=tcp&security=reality&sni=${domain}&fp=chrome&pbk=${public_key}&sid=${shortid}#${link_name_encoded}"

    if [[ "$is_quiet" = true ]]; then
        echo "${vless_url}"
    else
        echo "${vless_url}" > ~/xray_vless_reality_link.txt
        echo "----------------------------------------------------------------"
        echo -e "${green} --- Xray VLESS-Reality 订阅信息 --- ${none}"
        echo -e "${yellow} 名称: ${cyan}$link_name${none}"
        echo -e "${yellow} 地址: ${cyan}$ip${none}"
        echo -e "${yellow} 端口: ${cyan}$port${none}"
        echo -e "${yellow} UUID: ${cyan}$uuid${none}"
        echo -e "${yellow} 流控: ${cyan}"xtls-rprx-vision"${none}"
        echo -e "${yellow} 指纹: ${cyan}"chrome"${none}"
        echo -e "${yellow} SNI: ${cyan}$domain${none}"
        echo -e "${yellow} 公钥: ${cyan}$public_key${none}"
        echo -e "${yellow} ShortId: ${cyan}$shortid${none}"
        echo "----------------------------------------------------------------"
        echo -e "${green} 订阅链接 (已保存到 ~/xray_vless_reality_link.txt): ${none}\n"; echo -e "${cyan}${vless_url}${none}"
        echo "----------------------------------------------------------------"
    fi
}

# --- 核心逻辑函数 ---
write_config() {
    local port=$1 uuid=$2 domain=$3 private_key=$4 public_key=$5 shortid="20220701"
    mkdir -p "$(dirname "$xray_config_path")"
    jq -n \
        --argjson port "$port" \
        --arg uuid "$uuid" \
        --arg domain "$domain" \
        --arg private_key "$private_key" \
        --arg public_key "$public_key" \
        --arg shortid "$shortid" \
    '{
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "0.0.0.0",
            "port": $port,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": $uuid, "flow": "xtls-rprx-vision"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": ($domain + ":443"),
                    "xver": 0,
                    "serverNames": [$domain],
                    "privateKey": $private_key,
                    "publicKey": $public_key,
                    "shortIds": [$shortid]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"]
            }
        }],
        "outbounds": [{
            "protocol": "freedom",
            "settings": {
                "domainStrategy": "AsIs"
            }
        }]
    }' > "$xray_config_path"
}

run_install() {
    local port=$1 uuid=$2 domain=$3
    info "正在下载并安装 Xray 核心..."
    if ! execute_official_script "install"; then
        error "Xray 核心安装失败！请检查网络连接。"
        exit 1
    fi

    info "正在安装/更新 GeoIP 和 GeoSite 数据文件..."
    if ! execute_official_script "install-geodata"; then
        error "Geo-data 更新失败！"
        info "这通常不影响核心功能，您可以稍后通过更新选项(2)来重试。"
    fi

    info "正在生成 Reality 密钥对..."
    local key_pair=$($xray_binary_path x25519)
    local private_key=$(echo "$key_pair" | awk '/PrivateKey:/ {print $2}')
    local public_key=$(echo "$key_pair" | awk '/Password:/ {print $2}')
    if [[ -z "$private_key" || -z "$public_key" ]]; then
        error "生成 Reality 密钥对失败！请检查 Xray 核心是否正常。"
        exit 1
    fi

    info "正在写入 Xray 配置文件..."
    write_config "$port" "$uuid" "$domain" "$private_key" "$public_key"

    # OpenRC 环境下确保服务单位存在
    ensure_openrc_service

    if ! restart_xray; then exit 1; fi

    success "Xray 安装/配置成功！"
    view_subscription_info
}

press_any_key_to_continue() {
    echo ""
    read -n 1 -s -r -p "按任意键返回主菜单..." || true
}

main_menu() {
    while true; do
        clear
        echo -e "${cyan} Xray VLESS-Reality 一键安装管理脚本${none}"
        echo "---------------------------------------------"
        check_xray_status
        echo -e "${xray_status_info}"
        echo "---------------------------------------------"
        printf "  ${green}%-2s${none} %-35s\n" "1." "安装/重装 Xray"
        printf "  ${cyan}%-2s${none} %-35s\n" "2." "更新 Xray"
        printf "  ${yellow}%-2s${none} %-35s\n" "3." "重启 Xray"
        printf "  ${red}%-2s${none} %-35s\n" "4." "卸载 Xray"
        printf "  ${magenta}%-2s${none} %-35s\n" "5." "查看 Xray 日志"
        printf "  ${cyan}%-2s${none} %-35s\n" "6." "修改节点配置"
        printf "  ${green}%-2s${none} %-35s\n" "7." "查看订阅信息"
        echo "---------------------------------------------"
        printf "  ${yellow}%-2s${none} %-35s\n" "0." "退出脚本"
        echo "---------------------------------------------"
        read -p "请输入选项 [0-7]: " choice

        local needs_pause=true
        case $choice in
            1) install_xray ;;
            2) update_xray ;;
            3) restart_xray ;;
            4) uninstall_xray ;;
            5) view_xray_log; needs_pause=false ;;
            6) modify_config ;;
            7) view_subscription_info ;;
            0) success "感谢使用！"; exit 0 ;;
            *) error "无效选项，请输入 0-7 之间的数字。" ;;
        esac

        if [ "$needs_pause" = true ]; then
            press_any_key_to_continue
        fi
    done
}

# --- 脚本主入口 ---
main() {
    pre_check
    if [[ $# -gt 0 && "$1" == "install" ]]; then
        shift
        local port="" uuid="" domain=""
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --port) port="$2"; shift 2 ;;
                --uuid) uuid="$2"; shift 2 ;;
                --sni) domain="$2"; shift 2 ;;
                --quiet|-q) is_quiet=true; shift ;;
                *) error "未知参数: $1"; exit 1 ;;
            esac
        done
        [[ -z "$port" ]] && port=443
        [[ -z "$uuid" ]] && uuid=$(cat /proc/sys/kernel/random/uuid)
        [[ -z "$domain" ]] && domain="hk.art.museum"
        if ! is_valid_port "$port" || ! is_valid_domain "$domain"; then
            error "参数无效。请检查端口或SNI域名格式。" && exit 1
        fi
        if [[ -n "$uuid" ]] && ! is_valid_uuid "$uuid"; then
            error "UUID格式无效。请提供标准UUID格式或留空自动生成。" && exit 1
        fi
        if is_port_in_use "$port"; then
            error "端口 $port 已被占用，请选择其他端口。" && exit 1
        fi
        run_install "$port" "$uuid" "$domain"
    else
        main_menu
    fi
}

main "$@"
