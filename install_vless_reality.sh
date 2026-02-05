#!/bin/bash

# ==============================================================================
# Xray VLESS-Reality 一键安装管理脚本
# 此脚本Fork自https://github.com/yahuisme/xray-vless-reality, 感谢@yahuisme
# 自从Fork之后，本脚本已经过大量修改重构，感谢ChatGPT和Gemini
# 版本: V-Fork-Caesar-3.3 (NAT/DDNS 增强版)
# 更新日志: 新增自定义连接地址支持
# ==============================================================================

# --- Shell 严格模式 ---
set -euo pipefail

# --- 全局常量 ---
readonly SCRIPT_VERSION="V-Final-2.1"
readonly xray_config_path="/usr/local/etc/xray/config.json"
readonly xray_binary_path="/usr/local/bin/xray"
readonly address_file="/root/inbound_address.txt" # 自定义地址保存路径

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

# --- 手动安装核心 ---
install_xray_core() {
    info "开始安装 Xray 核心..."
    
    # 架构检测
    local arch machine
    machine="$(uname -m)"
    case "$machine" in
        x86_64|amd64) arch="64" ;;
        aarch64|arm64) arch="arm64-v8a" ;;
        *) error "不支持的 CPU 架构: $machine"; return 1 ;;
    esac

    # 获取最新版本
    local api="https://api.github.com/repos/XTLS/Xray-core/releases/latest"
    info "获取 Xray 最新版本信息..."
    local tag
    tag="$(curl -fsSL "$api" | grep -oE '"tag_name":\s*"[^"]+"' | head -n1 | cut -d'"' -f4)" || true
    
    local version_str="${tag:-latest}"
    info "目标版本: $version_str"

    local tmpdir; tmpdir="$(mktemp -d)"
    local zipname="Xray-linux-${arch}.zip"
    local url_main="https://github.com/XTLS/Xray-core/releases/latest/download/${zipname}"
    local url_tag="https://github.com/XTLS/Xray-core/releases/download/${tag}/${zipname}"

    info "正在下载 Xray ($zipname)..."
    if [[ -n "${tag:-}" ]] && curl -fL "$url_tag" -o "$tmpdir/xray.zip"; then :;
    elif curl -fL "$url_main" -o "$tmpdir/xray.zip"; then :;
    else 
        rm -rf "$tmpdir"
        error "下载 Xray 失败"
        return 1
    fi

    info "解压并安装到 /usr/local/bin ..."
    unzip -qo "$tmpdir/xray.zip" -d "$tmpdir"
    install -m 0755 "$tmpdir/xray" "$xray_binary_path"
    
    # 确保目录存在
    mkdir -p /usr/local/etc/xray /usr/local/share/xray
    
    rm -rf "$tmpdir"
    success "Xray 核心安装完成"
}

install_geodata() {
    info "正在安装/更新 GeoIP 和 GeoSite 数据文件..."
    curl -fsSL -o /usr/local/bin/geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
    curl -fsSL -o /usr/local/bin/geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
    cp -f /usr/local/bin/geoip.dat /usr/local/share/xray/geoip.dat
    cp -f /usr/local/bin/geosite.dat /usr/local/share/xray/geosite.dat
    success "Geo 数据文件已更新"
}

# --- Systemd 服务安装 ---
install_service_systemd() {
    info "安装 Systemd 服务 (User=root)..."
    cat >/etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=Xray Service
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
User=root
Group=root
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=false
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now xray
    success "Systemd 服务已安装并启动"
}

# --- OpenRC 服务安装 ---
install_service_openrc() {
    info "安装 OpenRC 服务..."
    install -d -m 0755 /var/log/xray || true

    cat >/etc/init.d/xray <<'EOF'
#!/sbin/openrc-run
name="xray"
description="Xray Service"
command="/usr/local/bin/xray"
command_args="run -config /usr/local/etc/xray/config.json"
command_background=true
pidfile="/run/xray.pid"
start_stop_daemon_args="--make-pidfile --background"

depend() {
  need net
  use dns
}
EOF
    chmod +x /etc/init.d/xray
    rc-update add xray default
    rc-service xray restart || rc-service xray start
    success "OpenRC 服务已安装并启动"
}

setup_service() {
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        install_service_systemd
    elif [[ "$INIT_SYSTEM" == "openrc" ]]; then
        install_service_openrc
    else
        error "无法确定服务管理器，请手动配置自启动。"
    fi
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

# --- 系统兼容性检查（加入 Alpine） ---
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
            error "UUID格式无效，请输入标准UUID格式或留空自动生成。"
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
    if ! install_xray_core; then error "Xray 核心更新失败！" && return; fi
    install_geodata

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
    
    # 停止服务
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        systemctl stop xray || true
        systemctl disable xray || true
        rm -f /etc/systemd/system/xray.service
        systemctl daemon-reload
    elif [[ "$INIT_SYSTEM" == "openrc" ]]; then
        rc-service xray stop || true
        rc-update del xray default || true
        rm -f /etc/init.d/xray
    fi

    # 删除文件
    rm -f "$xray_binary_path"
    rm -rf /usr/local/etc/xray
    rm -rf /usr/local/share/xray
    rm -f ~/xray_vless_reality_link.txt || true
    rm -f /root/inbound_address.txt # 同时清理地址配置文件
    
    success "Xray 已成功卸载。"
}

view_xray_log() {
    if [[ ! -f "$xray_binary_path" ]]; then error "错误: Xray 未安装，无法查看日志。" && return; fi
    
    info "正在显示 Xray 实时日志... 按 Ctrl+C 停止查看。"

    # 捕获 SIGINT (Ctrl+C) 信号，打印换行
    trap 'echo -e "\n日志查看已停止。"' SIGINT

    # 执行日志命令
    if command -v journalctl >/dev/null 2>&1; then
        journalctl -u xray -f --no-pager || true
    elif command -v logread >/dev/null 2>&1; then
        (logread -f | grep -i xray) || true
    elif [[ -d /var/log/xray ]]; then
        (tail -n 200 -F /var/log/xray/*.log 2>/dev/null || tail -n 200 -F /var/log/*.log | grep -i xray) || true
    else
        error "无法找到日志来源，请检查系统日志或 /var/log/xray。"
    fi

    # 解除捕获，恢复 Ctrl+C 的默认行为
    trap - SIGINT

    # 手动添加返回提示
    echo ""
    read -n 1 -s -r -p "按任意键返回主菜单..." || true
}

modify_config() {
    if [[ ! -f "$xray_config_path" ]]; then error "错误: Xray 未安装，无法修改配置。" && return; fi
    
    # 1. 查找所有 Reality 节点的端口
    echo "当前 VLESS-Reality 节点:"
    local ports
    ports=$(jq -r '.inbounds[] | select(.streamSettings.security == "reality") | .port' "$xray_config_path")
    
    if [[ -z "$ports" ]]; then error "未找到 Reality 节点配置。"; return; fi
    
    for p in $ports; do echo " - 端口: $p"; done
    echo ""
    read -p "请输入要修改的端口 (输入上述端口之一): " target_port
    
    # 验证端口是否存在于 reality 节点中
    if ! echo "$ports" | grep -q "^$target_port$"; then error "端口未找到或不是 Reality 节点"; return; fi

    info "读取当前配置..."
    # 精准读取：只选择端口匹配且是 reality 的节点
    local node_json
    node_json=$(jq --argjson p "$target_port" '.inbounds[] | select(.port == $p and .streamSettings.security == "reality")' "$xray_config_path")
    
    local current_uuid=$(echo "$node_json" | jq -r '.settings.clients[0].id')
    local current_domain=$(echo "$node_json" | jq -r '.streamSettings.realitySettings.serverNames[0]')
    local private_key=$(echo "$node_json" | jq -r '.streamSettings.realitySettings.privateKey')
    local public_key=$(echo "$node_json" | jq -r '.streamSettings.realitySettings.publicKey')

    info "请输入新配置，直接回车则保留当前值。"
    local port uuid domain
    
    while true; do
        read -p "$(echo -e "端口 (当前: ${cyan}${target_port}${none}): ")" port
        [ -z "$port" ] && port=$target_port
        if ! is_valid_port "$port"; then error "端口无效"; continue; fi
        # 如果改了端口，需要检查新端口是否被占用
        if [[ "$port" != "$target_port" ]] && is_port_in_use "$port"; then error "端口已被占用"; continue; fi
        break
    done
    
    while true; do
        read -p "$(echo -e "UUID (当前: ${cyan}${current_uuid}${none}): ")" uuid
        [ -z "$uuid" ] && uuid=$current_uuid
        if is_valid_uuid "$uuid"; then break; else error "UUID格式无效"; fi
    done
    
    while true; do
        read -p "$(echo -e "SNI域名 (当前: ${cyan}${current_domain}${none}): ")" domain
        [ -z "$domain" ] && domain=$current_domain
        if is_valid_domain "$domain"; then break; else error "域名格式无效"; fi
    done

    info "正在更新配置..."
    
    # 2. 删除旧节点 (精准删除)
    local tmp_file; tmp_file=$(mktemp)
    jq --argjson p "$target_port" 'del(.inbounds[] | select(.port == $p and .streamSettings.security == "reality"))' "$xray_config_path" > "$tmp_file" && mv "$tmp_file" "$xray_config_path"

    # 3. 写入新节点 (复用追加逻辑)
    write_config "$port" "$uuid" "$domain" "$private_key" "$public_key"
    
    if ! restart_xray; then return; fi

    success "配置修改成功！"
    view_subscription_info "$port" # 传入端口以精确显示
}

# --- 自定义连接地址管理 ---
set_connection_address() {
    echo ""
    echo "================================================="
    echo "         自定义连接地址 (NAT/DDNS 模式)"
    echo "================================================="
    echo "说明: 如果您使用的是 NAT VPS 或拥有动态 IP 的机器，"
    echo "请在此输入外部可访问的 IP 地址或 DDNS 域名。"
    echo "脚本生成分享链接时将优先使用此地址。"
    echo "-------------------------------------------------"
    
    if [[ -f "$address_file" ]]; then
        local current_addr=$(cat "$address_file")
        echo -e "当前已设置: ${cyan}${current_addr}${none}"
    else
        echo -e "当前状态: ${yellow}自动获取公网 IP${none}"
    fi
    echo ""
    read -p "请输入新的连接地址 (留空并回车则恢复自动获取): " new_addr
    
    if [[ -z "$new_addr" ]]; then
        rm -f "$address_file"
        success "已恢复为自动获取公网 IP 模式。"
    else
        echo "$new_addr" > "$address_file"
        success "连接地址已更新为: $new_addr"
    fi
}

view_subscription_info() {
    if [ ! -f "$xray_config_path" ]; then error "错误: 配置文件不存在, 请先安装。" && return; fi
    
    # 1. 扫描所有 Reality 节点
    local ports
    ports=$(jq -r '.inbounds[] | select(.streamSettings.security == "reality") | .port' "$xray_config_path")

    if [[ -z "$ports" ]]; then
        error "未找到任何 VLESS-Reality 节点配置。"
        return
    fi

    local target_port=""
    local port_count=$(echo "$ports" | wc -l)

    # 2. 智能选择逻辑
    if [[ "$port_count" -eq 1 ]]; then
        # 只有一个节点，自动选择
        target_port=$(echo "$ports" | tr -d ' \n')
    else
        # 多个节点，列出并让用户选择
        echo "发现多个 Reality 节点:"
        for p in $ports; do echo " - 端口: $p"; done
        echo ""
        
        while true; do
            read -p "请输入要查看的端口: " input_p
            # 验证输入是否在列表里
            if echo "$ports" | grep -q "^$input_p$"; then
                target_port=$input_p
                break
            else
                error "无效端口，请从列表中选择。"
            fi
        done
    fi

    # 3. 精准读取选中节点的配置
    local node_json
    node_json=$(jq --argjson p "$target_port" '.inbounds[] | select(.port == $p and .streamSettings.security == "reality")' "$xray_config_path")
    
    if [[ -z "$node_json" ]]; then error "读取配置失败"; return; fi

    local uuid=$(echo "$node_json" | jq -r '.settings.clients[0].id')
    local domain=$(echo "$node_json" | jq -r '.streamSettings.realitySettings.serverNames[0]')
    local public_key=$(echo "$node_json" | jq -r '.streamSettings.realitySettings.publicKey')
    local shortid=$(echo "$node_json" | jq -r '.streamSettings.realitySettings.shortIds[0]')
    local spiderx=$(echo "$node_json" | jq -r '.streamSettings.realitySettings.spiderX // "/"')

    if [[ -z "$public_key" || "$public_key" == "null" ]]; then 
        error "端口 $target_port 的配置缺少公钥信息。"
        return 
    fi

    # 4. 确定连接地址 (NAT/DDNS 支持)
    local ip
    if [[ -f "$address_file" && -s "$address_file" ]]; then
        ip=$(cat "$address_file")
        if [[ -z "$ip" ]]; then if ! ip=$(get_public_ip); then return 1; fi; fi
    else
        if ! ip=$(get_public_ip); then return 1; fi
    fi
    local display_ip=$ip && [[ $ip =~ ":" ]] && display_ip="[$ip]"

    # URL 编码处理
    local spiderx_encoded=$(echo "$spiderx" | sed 's/\//%2F/g')
    local link_name="$(hostname)-${target_port}"
    local link_name_encoded=$(echo "$link_name" | sed 's/ /%20/g')
    
    local vless_url="vless://${uuid}@${display_ip}:${target_port}?flow=xtls-rprx-vision&encryption=none&type=tcp&security=reality&sni=${domain}&fp=chrome&pbk=${public_key}&sid=${shortid}&spx=${spiderx_encoded}#${link_name_encoded}"

    # 5. 独立文件保存逻辑
    local save_file=~/xray_vless_reality_link_${target_port}.txt

    if [[ "$is_quiet" = true ]]; then
        echo "${vless_url}"
    else
        echo "${vless_url}" > "$save_file"
        
        echo "----------------------------------------------------------------"
        echo -e "${green} --- Xray VLESS-Reality 订阅信息 --- ${none}"
        echo -e "${yellow} 名称: ${cyan}$link_name${none}"
        echo -e "${yellow} 地址: ${cyan}$ip${none}"
        echo -e "${yellow} 端口: ${cyan}$target_port${none}"
        echo -e "${yellow} UUID: ${cyan}$uuid${none}"
        echo -e "${yellow} 流控: ${cyan}"xtls-rprx-vision"${none}"
        echo -e "${yellow} SNI: ${cyan}$domain${none}"
        echo -e "${yellow} SpiderX: ${cyan}$spiderx${none}"
        echo "----------------------------------------------------------------"
        echo -e "${green} 订阅链接 (已保存到 $save_file): ${none}\n"
        echo -e "${cyan}${vless_url}${none}"
        echo "----------------------------------------------------------------"
    fi
}

# --- 核心逻辑函数 ---
write_config() {
    local port=$1 uuid=$2 domain=$3 private_key=$4 public_key=$5 shortid="20220701" spiderx="/"
    local tag="vless-reality-in-$port"

    # 构造单个 Inbound 的 JSON 对象
    local inbound_json=$(jq -n \
        --argjson port "$port" \
        --arg uuid "$uuid" \
        --arg domain "$domain" \
        --arg private_key "$private_key" \
        --arg public_key "$public_key" \
        --arg shortid "$shortid" \
        --arg spiderx "$spiderx" \
        --arg tag "$tag" \
    '{
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
                "shortIds": [$shortid],
                "spiderX": $spiderx
            }
        },
        "sniffing": {
            "enabled": false
        },
        "tag": $tag
    }')

    # 1. 如果配置不存在，初始化基础结构
    if [[ ! -f "$xray_config_path" ]]; then
        mkdir -p "$(dirname "$xray_config_path")"
        echo '{ "log": { "loglevel": "warning" }, "inbounds": [], "outbounds": [{ "protocol": "freedom", "settings": {"domainStrategy": "AsIs"}, "tag": "direct" }, { "protocol": "blackhole", "tag": "blocked" }] }' > "$xray_config_path"
    fi

    # 2. 备份当前配置
    cp "$xray_config_path" "${xray_config_path}.bak.$(date +%s)"

    # 3. 使用 jq 追加新的 inbound 到数组末尾
    local tmp_file; tmp_file=$(mktemp)
    jq --argjson new "$inbound_json" '
        if .inbounds == null then .inbounds = [] else . end |
        .inbounds += [$new]
    ' "$xray_config_path" > "$tmp_file" && mv "$tmp_file" "$xray_config_path"

    chmod 644 "$xray_config_path" || true
    # 不再打印整个路径，保持清爽，外层函数会提示成功
}

run_install() {
    local port=$1 uuid=$2 domain=$3
    
    # 替换为新的手动安装逻辑
    if ! install_xray_core; then
        error "Xray 核心安装失败！请检查网络连接。"
        exit 1
    fi

    # 替换为新的 Geodata 安装逻辑
    install_geodata

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

    # 安装服务（包含强制 root 逻辑）
    setup_service

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
        printf "  ${magenta}%-2s${none} %-35s\n" "8." "设置连接地址 (NAT/DDNS)"
        printf "  ${yellow}%-2s${none} %-35s\n" "0." "退出脚本"
        echo "---------------------------------------------"
        read -p "请输入选项 [0-8]: " choice

        local needs_pause=true
        case $choice in
            1) install_xray ;;
            2) update_xray ;;
            3) restart_xray ;;
            4) uninstall_xray ;;
            5) view_xray_log; needs_pause=false ;;
            6) modify_config ;;
            7) view_subscription_info ;;
            8) set_connection_address ;;
            0) success "感谢使用！"; exit 0 ;;
            *) error "无效选项，请输入 0-8 之间的数字。" ;;
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
