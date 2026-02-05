#!/bin/bash

# ==============================================================================
# Xray VLESS Encryption (Post-Quantum) 一键安装管理脚本
# 架构重构版：模仿 Reality 脚本体验，支持多协议共存
# 版本: V-PQ-Reborn-1.0
# 功能:
# - 安装/管理 VLESS Encryption (ML-KEM-768)
# - 自动生成并替换抗量子密钥 (.native. -> .random.)
# - 智能追加配置 (不覆盖 Reality/SS 节点)
# - 多端口/多节点管理
# - 支持自定义连接地址 (NAT/DDNS)
# ==============================================================================

# --- Shell 严格模式 ---
set -euo pipefail

# --- 全局常量 ---
readonly SCRIPT_VERSION="V-PQ-Reborn-1.0"
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
    error "无法获取公网 IP 地址。" && return 1
}

# --- 核心安装逻辑 ---
install_xray_core() {
    info "开始安装 Xray 核心..."
    
    local arch machine
    machine="$(uname -m)"
    case "$machine" in
        x86_64|amd64) arch="64" ;;
        aarch64|arm64) arch="arm64-v8a" ;;
        *) error "不支持的 CPU 架构: $machine"; return 1 ;;
    esac

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

# --- Systemd 服务安装 (User=root) ---
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

# --- 验证函数 ---
is_valid_port() {
    local port=$1
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

is_port_in_use() {
    local port=$1
    # 检查系统监听
    if command -v ss &>/dev/null; then
        ss -tuln 2>/dev/null | grep -q ":$port " && return 0
    elif command -v netstat &>/dev/null; then
        netstat -tuln 2>/dev/null | grep -q ":$port " && return 0
    elif command -v lsof &>/dev/null; then
        lsof -i ":$port" &>/dev/null
    else
        (echo > "/dev/tcp/127.0.0.1/$port") >/dev/null 2>&1 && return 0
    fi
    
    # 检查 Config 文件中是否已经占用了该端口 (防止 Xray 内部冲突)
    if [[ -f "$xray_config_path" ]]; then
         if jq -e --argjson p "$port" '.inbounds[]? | select(.port == $p)' "$xray_config_path" >/dev/null 2>&1; then
             return 0
         fi
    fi
    return 1
}

is_valid_uuid() {
    local uuid=$1
    [[ "$uuid" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]
}

# --- 系统检测 ---
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

check_system_compatibility() {
    if [[ "$(uname -s)" != "Linux" ]]; then error "仅支持 Linux"; return 1; fi
    detect_system
    
    local required_commands=("awk" "grep" "sed" "jq" "curl" "openssl")
    local missing_commands=()
    for cmd in "${required_commands[@]}"; do
        command -v "$cmd" >/dev/null 2>&1 || missing_commands+=("$cmd")
    done
    if [[ ${#missing_commands[@]} -gt 0 ]]; then
        info "正在安装缺失依赖: ${missing_commands[*]} ..."
        if [[ "$OS_ID" == "alpine" ]]; then
            apk add --no-cache "${missing_commands[@]}" bash iproute2 coreutils netcat-openbsd unzip
        elif command -v apt-get >/dev/null; then
            DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing_commands[@]}" unzip
        fi
    fi
    return 0
}

pre_check() {
    [[ $(id -u) != 0 ]] && error "必须以 root 运行" && exit 1
    check_system_compatibility
}

check_xray_status() {
    if [[ ! -f "$xray_binary_path" ]]; then xray_status_info="  Xray 状态: ${red}未安装${none}"; return; fi
    local xray_version=$($xray_binary_path version 2>/dev/null | head -n 1 | awk '{print $2}' || echo "未知")
    local service_status
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        systemctl is-active --quiet xray && service_status="${green}运行中${none}" || service_status="${yellow}未运行${none}"
    elif [[ "$INIT_SYSTEM" == "openrc" ]]; then
        rc-service xray status 2>/dev/null | grep -qi started && service_status="${green}运行中${none}" || service_status="${yellow}未运行${none}"
    fi
    xray_status_info="  Xray 状态: ${green}已安装${none} | ${service_status} | 版本: ${cyan}${xray_version}${none}"
}

# --- 核心 VLESS Encryption 逻辑 ---

generate_vless_tokens() {
    info "生成 VLESS Encryption (ML-KEM-768) 密钥..."
    
    if ! command -v "$xray_binary_path" >/dev/null 2>&1; then
        error "未找到 Xray 程序，无法生成密钥。请先安装 Xray。"
        return 1
    fi

    local out dec enc
    out="$($xray_binary_path vlessenc 2>&1 || true)"

    dec="$(printf '%s\n' "$out" | awk '/Authentication: ML-KEM-768/ {p=1; next} p && /"decryption":/ {gsub(/^.*"decryption": *"/,""); gsub(/".*/,""); print; exit}')"
    enc="$(printf '%s\n' "$out" | awk '/Authentication: ML-KEM-768/ {p=1; next} p && /"encryption":/ {gsub(/^.*"encryption": *"/,""); gsub(/".*/,""); print; exit}')"

    if [[ -z "$dec" || -z "$enc" ]]; then
        error "密钥生成失败。'xray vlessenc' 输出异常。"
        return 1
    fi

    # 关键步骤：替换 native 为 random，提高兼容性
    VLESS_DECRYPTION="${dec/.native./.random.}"
    VLESS_ENCRYPTION="${enc/.native./.random.}"
    info "密钥生成成功 (native -> random 已转换)。"
}

# --- 智能追加配置函数 (不覆盖) ---
append_vless_config() {
    local port=$1 uuid=$2
    local tag="vless-pq-in-${port}"
    
    # 构造 Inbound JSON
    local inbound_json
    inbound_json=$(jq -n \
        --argjson port "$port" \
        --arg uuid "$uuid" \
        --arg dec "$VLESS_DECRYPTION" \
        --arg enc "$VLESS_ENCRYPTION" \
        --arg tag "$tag" \
        '{
            port: $port,
            protocol: "vless",
            settings: {
                clients: [{ id: $uuid }],
                decryption: $dec,
                encryption: $enc,
                selectedAuth: "ML-KEM-768, Post-Quantum"
            },
            streamSettings: {
                network: "tcp"
            },
            tag: $tag
        }')

    # 1. 如果文件不存在，初始化
    if [[ ! -f "$xray_config_path" ]]; then
        info "配置文件不存在，创建新配置..."
        mkdir -p "$(dirname "$xray_config_path")"
        echo '{ "log": { "loglevel": "warning" }, "inbounds": [], "outbounds": [{ "protocol": "freedom", "tag": "direct" }, { "protocol": "blackhole", "tag": "blocked" }] }' > "$xray_config_path"
    fi

    # 2. 备份
    cp "$xray_config_path" "${xray_config_path}.bak.$(date +%s)"

    # 3. 使用 jq 智能追加到数组末尾
    local temp_file; temp_file=$(mktemp)
    jq --argjson new "$inbound_json" '
        if .inbounds == null then .inbounds = [] else . end |
        .inbounds += [$new]
    ' "$xray_config_path" > "$temp_file" && mv "$temp_file" "$xray_config_path"
    
    chmod 644 "$xray_config_path"
    success "配置已安全追加到: $xray_config_path"
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

# --- 菜单操作函数 ---

install_vless_pq() {
    info "开始配置 VLESS Encryption (Post-Quantum)..."
    
    local port uuid
    while true; do
        read -p "$(echo -e "请输入端口 [1-65535] (默认: ${cyan}40000${none}): ")" port
        [ -z "$port" ] && port=40000
        if ! is_valid_port "$port"; then error "端口无效"; continue; fi
        if is_port_in_use "$port"; then error "端口 $port 已被占用"; continue; fi
        break
    done

    while true; do
        read -p "$(echo -e "请输入 UUID (留空随机生成): ")" uuid
        if [[ -z "$uuid" ]]; then 
            uuid=$(cat /proc/sys/kernel/random/uuid || openssl rand -hex 16 | sed 's/^\(........\)\(....\)\(....\)\(....\)\(............\)$/\1-\2-\3-\4-\5/')
            info "已生成 UUID: ${cyan}${uuid}${none}"
            break
        elif is_valid_uuid "$uuid"; then
            break
        else
            error "UUID 格式无效"
        fi
    done

    # 安装核心 & GeoData
    if ! install_xray_core; then return 1; fi
    install_geodata
    
    # 生成密钥
    if ! generate_vless_tokens; then return 1; fi

    # 写入配置
    append_vless_config "$port" "$uuid"
    
    # 设置并重启服务
    setup_service
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then systemctl restart xray; else rc-service xray restart; fi
    
    success "安装配置完成！"
    view_subscription_info "$port"
}

view_subscription_info() {
    if [[ ! -f "$xray_config_path" ]]; then error "配置不存在"; return; fi
    
    # 1. 扫描所有 VLESS Encryption 节点 (特征: selectedAuth 包含 Post-Quantum)
    local ports
    ports=$(jq -r '.inbounds[] | select(.protocol=="vless" and (.settings.selectedAuth | tostring | contains("Post-Quantum"))) | .port' "$xray_config_path")
    
    if [[ -z "$ports" ]]; then error "未找到 VLESS Encryption 节点配置。"; return; fi

    local target_port=""
    local port_count=$(echo "$ports" | wc -l)

    # 2. 智能选择逻辑
    if [[ -n "$1" ]]; then
        target_port=$1
    elif [[ "$port_count" -eq 1 ]]; then
        target_port=$(echo "$ports" | tr -d ' \n')
    else
        echo "发现多个 VLESS Encryption 节点:"
        for p in $ports; do echo " - 端口: $p"; done
        echo ""
        
        while true; do
            read -p "请输入要查看的端口: " input_p
            if echo "$ports" | grep -q "^$input_p$"; then
                target_port=$input_p
                break
            else
                error "无效端口，请从列表中选择。"
            fi
        done
    fi

    # 3. 读取详细信息
    local node_json
    node_json=$(jq -r --argjson p "$target_port" '.inbounds[] | select(.port==$p)' "$xray_config_path")
    
    if [[ -z "$node_json" ]]; then error "读取配置失败"; return; fi

    local uuid=$(echo "$node_json" | jq -r '.settings.clients[0].id')
    local enc_key=$(echo "$node_json" | jq -r '.settings.encryption')
    local tag=$(echo "$node_json" | jq -r '.tag')
    
    # 4. 确定连接地址 (NAT/DDNS 支持)
    local ip
    if [[ -f "$address_file" && -s "$address_file" ]]; then
        ip=$(cat "$address_file")
        if [[ -z "$ip" ]]; then ip=$(get_public_ip); fi
    else
        ip=$(get_public_ip)
    fi
    local display_ip=$ip
    [[ $ip =~ ":" ]] && display_ip="[$ip]" # IPv6 wrap
    
    # 5. 生成链接 (VLESS)
    # 格式: vless://uuid@ip:port?encryption=key&type=tcp&security=none#tag
    local tag_enc=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$tag'))")
    local link="vless://${uuid}@${display_ip}:${target_port}?encryption=${enc_key}&type=tcp&security=none#${tag_enc}"

    # 6. 独立文件保存
    local save_file="/root/xray_vless_encryption_link_${target_port}.txt"

    if [[ "$is_quiet" = true ]]; then
        echo "$link"
    else
        echo "----------------------------------------------------------------"
        echo -e "${green} --- VLESS Encryption (Post-Quantum) 配置信息 --- ${none}"
        echo -e "${yellow} 端口: ${cyan}${target_port}${none}"
        echo -e "${yellow} UUID: ${cyan}${uuid}${none}"
        echo -e "${yellow} 地址: ${cyan}${ip}${none}"
        echo -e "${yellow} Encryption (公钥): ${cyan}${enc_key}${none}"
        echo -e "${yellow} 备注: ${cyan}${tag}${none}"
        echo "----------------------------------------------------------------"
        echo -e "${green} 分享链接 (已保存到 $save_file):${none}\n"
        echo -e "${cyan}${link}${none}"
        echo "----------------------------------------------------------------"
        echo "$link" > "$save_file"
    fi
}

update_xray() {
    info "检查更新..."
    install_xray_core
    install_geodata
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then systemctl restart xray; else rc-service xray restart; fi
    success "Xray 已更新"
}

restart_xray() {
    info "正在重启 Xray..."
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then systemctl restart xray; else rc-service xray restart; fi
    success "服务已重启"
}

uninstall_xray() {
    read -p "确定卸载 Xray 吗？(删除程序文件，保留配置文件可选) [y/N]: " confirm
    if [[ ! $confirm =~ ^[yY]$ ]]; then return; fi
    
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        systemctl stop xray || true
        systemctl disable xray || true
        rm -f /etc/systemd/system/xray.service
        systemctl daemon-reload
    else
        rc-service xray stop || true
        rc-update del xray default || true
        rm -f /etc/init.d/xray
    fi
    
    rm -f "$xray_binary_path"
    read -p "是否删除配置文件和日志？[y/N]: " del_conf
    if [[ $del_conf =~ ^[yY]$ ]]; then
        rm -rf /usr/local/etc/xray /usr/local/share/xray /var/log/xray
        rm -f /root/inbound_address.txt
        success "Xray 及配置已完全卸载"
    else
        success "Xray 程序已卸载，配置保留"
    fi
}

view_xray_log() {
    info "显示日志... 按 Ctrl+C 停止查看"
    trap 'echo -e "\n日志查看已停止。"' SIGINT
    
    if command -v journalctl >/dev/null 2>&1; then
        journalctl -u xray -f --no-pager || true
    elif [[ -d /var/log/xray ]]; then
        (tail -n 200 -F /var/log/xray/*.log 2>/dev/null || tail -n 200 -F /var/log/*.log | grep -i xray) || true
    else
        error "无法找到日志"
    fi
    
    trap - SIGINT
    echo ""
    read -n 1 -s -r -p "按任意键返回主菜单..." || true
}

modify_config() {
    if [[ ! -f "$xray_config_path" ]]; then error "配置不存在"; return; fi
    
    echo "当前 VLESS Encryption 节点:"
    local ports
    ports=$(jq -r '.inbounds[] | select(.protocol=="vless" and (.settings.selectedAuth | tostring | contains("Post-Quantum"))) | .port' "$xray_config_path")
    
    if [[ -z "$ports" ]]; then error "未找到相关节点"; return; fi
    
    for p in $ports; do echo " - 端口: $p"; done
    echo ""
    
    local target_p
    while true; do
        read -p "请输入要修改的端口: " target_p
        if echo "$ports" | grep -q "^$target_p$"; then break; else error "端口未找到"; fi
    done
    
    info "注意：修改将删除旧端口配置并重新生成密钥对。"
    
    local new_uuid
    while true; do
        read -p "$(echo -e "请输入新 UUID (留空随机生成): ")" new_uuid
        if [[ -z "$new_uuid" ]]; then 
            new_uuid=$(cat /proc/sys/kernel/random/uuid || openssl rand -hex 16 | sed 's/^\(........\)\(....\)\(....\)\(....\)\(............\)$/\1-\2-\3-\4-\5/')
            break
        elif is_valid_uuid "$new_uuid"; then
            break
        else
            error "UUID 格式无效"
        fi
    done

    # 重新生成密钥
    if ! generate_vless_tokens; then return 1; fi
    
    # 删除旧配置 (精准删除)
    local tmp; tmp=$(mktemp)
    jq --argjson p "$target_p" 'del(.inbounds[] | select(.port == $p))' "$xray_config_path" > "$tmp" && mv "$tmp" "$xray_config_path"
    
    # 追加新配置
    append_vless_config "$target_p" "$new_uuid"
    
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then systemctl restart xray; else rc-service xray restart; fi
    success "修改完成"
    view_subscription_info "$target_p"
}

press_any_key_to_continue() {
    echo ""
    read -n 1 -s -r -p "按任意键返回主菜单..." || true
}

main_menu() {
    while true; do
        clear
        echo -e "${cyan} Xray VLESS Encryption (Post-Quantum) 管理脚本${none}"
        echo "---------------------------------------------"
        check_xray_status
        echo -e "${xray_status_info}"
        echo "---------------------------------------------"
        printf "  ${green}%-2s${none} %-35s\n" "1." "新增/安装 VLESS PQ 节点"
        printf "  ${cyan}%-2s${none} %-35s\n" "2." "更新 Xray 核心"
        printf "  ${yellow}%-2s${none} %-35s\n" "3." "重启 Xray 服务"
        printf "  ${red}%-2s${none} %-35s\n" "4." "卸载 Xray"
        printf "  ${magenta}%-2s${none} %-35s\n" "5." "查看日志"
        printf "  ${cyan}%-2s${none} %-35s\n" "6." "修改/重置节点配置"
        printf "  ${green}%-2s${none} %-35s\n" "7." "查看节点链接"
        echo "---------------------------------------------"
        printf "  ${magenta}%-2s${none} %-35s\n" "8." "设置连接地址 (NAT/DDNS)"
        printf "  ${yellow}%-2s${none} %-35s\n" "0." "退出"
        echo "---------------------------------------------"
        read -p "请输入选项 [0-8]: " choice

        local needs_pause=true
        case $choice in
            1) install_vless_pq ;;
            2) update_xray ;;
            3) restart_xray ;;
            4) uninstall_xray ;;
            5) view_xray_log; needs_pause=false ;;
            6) modify_config ;;
            7) view_subscription_info "" ;;
            8) set_connection_address ;;
            0) success "再见！"; exit 0 ;;
            *) error "无效选项" ;;
        esac

        if [ "$needs_pause" = true ]; then
            press_any_key_to_continue
        fi
    done
}

main() {
    pre_check
    if [[ $# -gt 0 && "$1" == "install" ]]; then
        install_vless_pq
    else
        main_menu
    fi
}

main "$@"
