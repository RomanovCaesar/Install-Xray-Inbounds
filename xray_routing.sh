#!/bin/bash
# ==============================================================================
# Caesar 蜜汁 xray 服务端分流脚本 v2.0
# 适配环境：Debian/Ubuntu/Alpine
# 依赖：jq, curl, python3, openssl
# 功能：安装Geo数据、添加Outbounds(Socks/SS/VLESS)、添加Routing、查询配置
# ==============================================================================

# --- 全局设置 ---
set -euo pipefail
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
CYAN='\033[96m'
PLAIN='\033[0m'

CONFIG_FILE="/usr/local/etc/xray/config.json"
SCRIPT_PATH="/usr/bin/xray-routing"
GEO_DIR="/usr/local/bin" # 根据要求下载到此目录
GEO_SHARE_DIR="/usr/local/share/xray" # 兼容标准路径

# --- 基础函数 ---
die() { echo -e "${RED}[ERROR] $*${PLAIN}" >&2; exit 1; }
info() { echo -e "${GREEN}[INFO] $*${PLAIN}"; }
warn() { echo -e "${YELLOW}[WARN] $*${PLAIN}"; }

# --- 权限与依赖检测 ---
pre_check() {
    [[ ${EUID:-$(id -u)} -ne 0 ]] && die "请以 root 身份运行此脚本。"
    
    # 检测系统
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID="${ID,,}"
    else
        die "无法检测系统版本。"
    fi

    # 依赖安装
    local deps=("jq" "curl" "python3" "openssl")
    local install_cmd=""
    
    if [[ "$OS_ID" == "alpine" ]]; then
        install_cmd="apk add --no-cache"
    elif [[ "$OS_ID" =~ debian|ubuntu ]]; then
        install_cmd="apt-get update && apt-get install -y"
    fi

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            info "正在安装依赖: $dep ..."
            $install_cmd "$dep" >/dev/null 2>&1 || die "安装依赖 $dep 失败。"
        fi
    done
}

# --- 自我安装 ---
install_self() {
    local current_path
    current_path="$(realpath "$0")"
    
    if [[ "$current_path" != "$SCRIPT_PATH" ]]; then
        info "正在安装脚本到 $SCRIPT_PATH ..."
        cp "$current_path" "$SCRIPT_PATH"
        chmod +x "$SCRIPT_PATH"
        info "脚本安装完成，请在命令行直接输入 xray-routing 使用。"
        sleep 1
        exec "$SCRIPT_PATH" "$@"
    fi
}

# --- 重启 Xray ---
restart_xray() {
    info "正在重启 Xray 服务..."
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart xray || warn "Xray 重启失败，请检查日志 (systemctl status xray)"
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service xray restart || warn "Xray 重启失败，请检查日志 (rc-service xray status)"
    else
        warn "未检测到服务管理工具，请手动重启 Xray。"
    fi
}

# --- 辅助：按任意键继续 ---
pause() {
    echo
    read -n 1 -s -r -p "按任意键回到主菜单..." || true
    echo
}

# --- 功能 1: 安装 Geo 文件与定时任务 (脚本版) ---
install_geo_assets() {
    local updater_script="/root/update_geo.sh"
    # 这里填写你存放 update_geo.sh 的真实 Github 链接
    local updater_url="https://raw.githubusercontent.com/RomanovCaesar/Install-Xray-Inbounds/main/update_geo.sh"

    info "正在拉取自动更新脚本 update_geo.sh ..."
    
    # 下载更新脚本
    if curl -fsSL -o "$updater_script" "$updater_url"; then
        chmod +x "$updater_script"
        info "脚本下载成功: $updater_script"
    else
        die "无法从 Github 下载更新脚本，请检查网络或 URL。"
    fi

    info "正在执行第一次 Geo 文件下载与安装..."
    # 立即执行一次，确保文件就位
    if "$updater_script"; then
        info "初始化下载成功！"
    else
        die "初始化下载失败，请检查上方错误信息。"
    fi
    
    info "设置 Crontab 定时任务 (每天凌晨 3:00 执行 /root/update_geo.sh)..."
    
    # 定义简单的 Cron 任务 (追加日志记录，方便排错)
    local cron_job="0 3 * * * $updater_script >> /var/log/update_geo.log 2>&1"
    
    # 写入 Crontab
    local tmp_cron
    tmp_cron=$(mktemp)
    crontab -l 2>/dev/null > "$tmp_cron" || true
    
    # 移除旧的 v2ray-rules-dat 任务 或 旧的 update_geo.sh 任务，防止重复
    sed -i '/v2ray-rules-dat/d' "$tmp_cron"
    sed -i '/update_geo.sh/d' "$tmp_cron"
    
    # 追加新任务
    echo "$cron_job" >> "$tmp_cron"
    crontab "$tmp_cron"
    rm -f "$tmp_cron"
    
    info "Geo 文件自动更新已配置完成！"
    info "日志将保存在: /var/log/update_geo.log"
    pause
}

# --- Python 解析脚本 (嵌入) ---
# 用于解析 SS 和 VLESS 链接
parse_link_py() {
    python3 -c '
import sys, urllib.parse, json, base64, re

link = sys.argv[1]
result = {}

def b64decode(s):
    s = s.strip()
    missing_padding = len(s) % 4
    if missing_padding:
        s += "=" * (4 - missing_padding)
    try:
        return base64.urlsafe_b64decode(s).decode("utf-8")
    except:
        return base64.b64decode(s).decode("utf-8")

try:
    if link.startswith("ss://"):
        result["protocol"] = "shadowsocks"
        # 移除 ss://
        body = link[5:]
        tag = ""
        if "#" in body:
            body, tag = body.split("#", 1)
            result["tag_comment"] = urllib.parse.unquote(tag)
        
        if "@" in body:
            # format: user:pass@host:port (base64 encoded user:pass potentially)
            userpass_part, hostport = body.split("@", 1)
            # 尝试解码 userpass
            try:
                decoded_up = b64decode(userpass_part)
                if ":" in decoded_up:
                    method, password = decoded_up.split(":", 1)
                else:
                    method, password = userpass_part.split(":", 1) # legacy plain
            except:
                # 可能是明文 method:pass
                if ":" in userpass_part:
                    method, password = userpass_part.split(":", 1)
                else:
                    raise Exception("Invalid SS format")
            
            host, port = hostport.split(":")
            result["address"] = host
            result["port"] = int(port)
            result["method"] = method
            result["password"] = password
        else:
            # format: base64(method:pass@host:port)
            decoded = b64decode(body)
            # method:pass@host:port
            if "@" in decoded:
                method_pass, host_port = decoded.split("@", 1)
                method, password = method_pass.split(":", 1)
                host, port = host_port.split(":")
                result["address"] = host
                result["port"] = int(port)
                result["method"] = method
                result["password"] = password
            else:
                 raise Exception("Invalid SS Base64")

    elif link.startswith("vless://"):
        result["protocol"] = "vless"
        parsed = urllib.parse.urlparse(link)
        result["uuid"] = parsed.username
        result["address"] = parsed.hostname
        result["port"] = parsed.port
        result["tag_comment"] = urllib.parse.unquote(parsed.fragment)
        
        params = urllib.parse.parse_qs(parsed.query)
        
        result["encryption"] = params.get("encryption", ["none"])[0]
        result["security"] = params.get("security", ["none"])[0]
        result["flow"] = params.get("flow", [""])[0]
        result["sni"] = params.get("sni", [""])[0]
        result["pbk"] = params.get("pbk", [""])[0]
        result["sid"] = params.get("sid", [""])[0]
        result["fp"] = params.get("fp", [""])[0]
        result["type"] = params.get("type", ["tcp"])[0]
        
    else:
        result["error"] = "Unsupported scheme"

    print(json.dumps(result))

except Exception as e:
    print(json.dumps({"error": str(e)}))
' "$1"
}

# --- 功能 2: 添加 Outbounds ---
add_outbound() {
    if [[ ! -f "$CONFIG_FILE" ]]; then die "配置文件不存在: $CONFIG_FILE"; fi

    echo "================ 添加 Outbound 节点 ================"
    
    # 1. Unique Tag
    local tag
    while true; do
        read -rp "请输入节点唯一 Tag: " tag
        if [[ -z "$tag" ]]; then continue; fi
        if jq -e --arg t "$tag" '.outbounds[] | select(.tag == $t)' "$CONFIG_FILE" >/dev/null 2>&1; then
            echo -e "${RED}Tag '$tag' 已存在，请使用其他 Tag。${PLAIN}"
        else
            break
        fi
    done

    # 2. Type Selection
    echo "请选择节点类型:"
    echo "  1) Socks"
    echo "  2) Shadowsocks (SS)"
    echo "  3) VLESS"
    read -rp "选择 (1-3): " type_choice

    local outbound_json=""

    case "$type_choice" in
        1) # Socks
            read -rp "地址 (Address): " addr
            read -rp "端口 (Port): " port
            read -rp "用户名 (User, 可留空): " user
            read -rp "密码 (Pass, 可留空): " pass
            
            # 构建 JSON
            outbound_json=$(jq -n \
                --arg tag "$tag" \
                --arg addr "$addr" \
                --argjson port "$port" \
                --arg user "$user" \
                --arg pass "$pass" \
                '{
                    tag: $tag,
                    protocol: "socks",
                    settings: {
                        servers: [{
                            address: $addr,
                            port: $port,
                            users: (if $user != "" then [{user: $user, pass: $pass}] else [] end)
                        }]
                    }
                }')
            ;;
            
        2) # SS
            echo "添加方式: 1) 粘贴链接  2) 手动输入"
            read -rp "选择 (1/2): " ss_method_choice
            if [[ "$ss_method_choice" == "1" ]]; then
                read -rp "请输入 SS 分享链接: " link
                local parsed
                parsed=$(parse_link_py "$link")
                if echo "$parsed" | grep -q '"error"'; then
                    die "解析失败: $(echo "$parsed" | jq -r '.error')"
                fi
                
                local addr method pass port
                addr=$(echo "$parsed" | jq -r '.address')
                port=$(echo "$parsed" | jq -r '.port')
                method=$(echo "$parsed" | jq -r '.method')
                pass=$(echo "$parsed" | jq -r '.password')
                
                info "解析成功: $method:$pass@$addr:$port"
                
                outbound_json=$(jq -n \
                    --arg tag "$tag" \
                    --arg addr "$addr" \
                    --argjson port "$port" \
                    --arg method "$method" \
                    --arg pass "$pass" \
                    '{
                        tag: $tag,
                        protocol: "shadowsocks",
                        settings: {
                            servers: [{
                                address: $addr,
                                port: $port,
                                method: $method,
                                password: $pass,
                                level: 1
                            }]
                        }
                    }')
            else
                read -rp "地址 (Address): " addr
                read -rp "端口 (Port): " port
                echo "加密方式 (1-6):"
                echo "1) aes-128-gcm  2) aes-256-gcm  3) chacha20-ietf-poly1305"
                echo "4) 2022-blake3-aes-128-gcm  5) 2022-blake3-aes-256-gcm  6) 2022-blake3-chacha20-poly1305"
                read -rp "选择: " m_idx
                local methods=("aes-128-gcm" "aes-256-gcm" "chacha20-ietf-poly1305" "2022-blake3-aes-128-gcm" "2022-blake3-aes-256-gcm" "2022-blake3-chacha20-poly1305")
                local method="${methods[$((m_idx-1))]}"
                if [[ -z "$method" ]]; then die "无效选择"; fi
                read -rp "密码: " pass
                
                outbound_json=$(jq -n \
                    --arg tag "$tag" \
                    --arg addr "$addr" \
                    --argjson port "$port" \
                    --arg method "$method" \
                    --arg pass "$pass" \
                    '{
                        tag: $tag,
                        protocol: "shadowsocks",
                        settings: {
                            servers: [{
                                address: $addr,
                                port: $port,
                                method: $method,
                                password: $pass
                            }]
                        },
                        streamSettings: { network: "tcp" }
                    }')
            fi
            ;;
            
        3) # VLESS
            read -rp "请输入 VLESS 分享链接: " link
            local parsed
            parsed=$(parse_link_py "$link")
            if echo "$parsed" | grep -q '"error"'; then
                die "解析失败: $(echo "$parsed" | jq -r '.error')"
            fi
            
            # 提取所有需要的字段
            local addr port uuid encryption security flow sni pbk sid fp type
            addr=$(echo "$parsed" | jq -r '.address')
            port=$(echo "$parsed" | jq -r '.port')
            uuid=$(echo "$parsed" | jq -r '.uuid')
            encryption=$(echo "$parsed" | jq -r '.encryption') # Important for VLESS Encryption inbound compatibility
            security=$(echo "$parsed" | jq -r '.security')
            flow=$(echo "$parsed" | jq -r '.flow')
            sni=$(echo "$parsed" | jq -r '.sni')
            pbk=$(echo "$parsed" | jq -r '.pbk')
            sid=$(echo "$parsed" | jq -r '.sid')
            fp=$(echo "$parsed" | jq -r '.fp')
            type=$(echo "$parsed" | jq -r '.type')
            
            info "解析成功: VLESS $uuid@$addr:$port (Sec: $security, Enc: $encryption)"

            # 构建 VLESS JSON
            # 注意：VLESS Encryption 场景下，Share Link 里的 encryption 参数对应 Outbound User 中的 encryption 字段
            outbound_json=$(jq -n \
                --arg tag "$tag" \
                --arg addr "$addr" \
                --argjson port "$port" \
                --arg uuid "$uuid" \
                --arg encryption "$encryption" \
                --arg security "$security" \
                --arg flow "$flow" \
                --arg sni "$sni" \
                --arg pbk "$pbk" \
                --arg sid "$sid" \
                --arg fp "$fp" \
                --arg type "$type" \
                '{
                    tag: $tag,
                    protocol: "vless",
                    settings: {
                        vnext: [{
                            address: $addr,
                            port: $port,
                            users: [{
                                id: $uuid,
                                encryption: $encryption,
                                flow: (if $flow == "" then null else $flow end)
                            }]
                        }]
                    },
                    streamSettings: {
                        network: $type,
                        security: (if $security == "none" then null else $security end),
                        realitySettings: (if $security == "reality" then {
                            serverName: $sni,
                            publicKey: $pbk,
                            shortId: $sid,
                            fingerprint: $fp
                        } else null end),
                        tlsSettings: (if $security == "tls" then {
                            serverName: $sni
                        } else null end)
                    }
                } | del(.streamSettings.realitySettings | select(. == null)) | del(.streamSettings.tlsSettings | select(. == null)) | del(.streamSettings.security | select(. == null))')
            ;;
        *) die "无效选择" ;;
    esac

    # 写入 Config
    local tmp_conf
    tmp_conf=$(mktemp)
    jq --argjson new "$outbound_json" '.outbounds += [$new]' "$CONFIG_FILE" > "$tmp_conf" && mv "$tmp_conf" "$CONFIG_FILE"
    
    info "已添加 Outbound: $tag"
    restart_xray
    pause
}

# --- 功能 3: 添加 Routing ---
add_routing() {
    if [[ ! -f "$CONFIG_FILE" ]]; then die "配置文件不存在"; fi
    
    echo "================ 添加分流规则 (Routing) ================"

    # 1. Select Inbounds
    echo "当前 Inbounds:"
    jq -r '.inbounds[] | " - " + .tag' "$CONFIG_FILE"
    echo
    read -rp "请输入 Inbound Tags (英文逗号分隔，留空表示所有 Inbounds): " in_tags_raw
    
    local in_tags_json="null"
    if [[ -n "$in_tags_raw" ]]; then
        # split by comma -> json array
        in_tags_json=$(echo "$in_tags_raw" | jq -R 'split(",") | map(gsub(" "; ""))')
    fi

    # 2. Conditions
    echo "请输入分流条件 (回车跳过):"
    read -rp "1) IP/CIDR (如 8.8.8.8, 192.168.1.0/24, geoip:cn): " ip_cond
    read -rp "2) Domain/GeoSite (如 google.com, geosite:cn): " domain_cond

    if [[ -z "$ip_cond" && -z "$domain_cond" ]]; then
        die "必须至少输入一个条件 (IP 或 Domain)。"
    fi

    # 3. Select Outbound
    echo "当前 Outbounds:"
    jq -r '.outbounds[] | " - " + .tag' "$CONFIG_FILE"
    echo
    local out_tag
    while true; do
        read -rp "请输入目标 Outbound Tag: " out_tag
        if jq -e --arg t "$out_tag" '.outbounds[] | select(.tag == $t)' "$CONFIG_FILE" >/dev/null 2>&1; then
            break
        else
            echo -e "${RED}Tag '$out_tag' 不存在，请重新输入。${PLAIN}"
        fi
    done

    # 4. Construct Rule
    local rule_json
    rule_json=$(jq -n \
        --argjson inbounds "$in_tags_json" \
        --arg outbound "$out_tag" \
        --arg ip "$ip_cond" \
        --arg domain "$domain_cond" \
        '{
            type: "field",
            inboundTag: $inbounds,
            outboundTag: $outbound,
            ip: (if $ip != "" then [$ip] else null end),
            domain: (if $domain != "" then [$domain] else null end)
        } | del(.ip | select(. == null)) | del(.domain | select(. == null))')

    # 5. Write to Config
    local tmp_conf
    tmp_conf=$(mktemp)
    
    # 确保 routing 对象存在，如果不存在则创建，然后追加规则
    jq --argjson rule "$rule_json" '
        if .routing == null then .routing = {rules: []} else . end |
        if .routing.rules == null then .routing.rules = [] else . end |
        .routing.rules += [$rule]
    ' "$CONFIG_FILE" > "$tmp_conf" && mv "$tmp_conf" "$CONFIG_FILE"

    info "分流规则添加成功！"
    restart_xray
    pause
}

# --- 功能 4: 查询 Inbounds ---
query_inbounds() {
    echo "================ Inbounds 列表 ================"
    printf "%-20s %-15s %-10s\n" "Tag" "Protocol" "Port"
    echo "------------------------------------------------"
    jq -r '.inbounds[] | "\(.tag)\t\(.protocol)\t\(.port)"' "$CONFIG_FILE" | while IFS=$'\t' read -r tag proto port; do
        printf "%-20s %-15s %-10s\n" "$tag" "$proto" "$port"
    done
    pause
}

# --- 功能 5: 查询 Outbounds ---
query_outbounds() {
    echo "================ Outbounds 列表 ================"
    printf "%-20s %-15s %-25s %-10s\n" "Tag" "Protocol" "Address" "Port"
    echo "----------------------------------------------------------------------"
    jq -r '.outbounds[] | 
        "\(.tag)\t\(.protocol)\t\(if .settings.servers then .settings.servers[0].address else (.settings.vnext[0].address // "N/A") end)\t\(if .settings.servers then .settings.servers[0].port else (.settings.vnext[0].port // "N/A") end)"' "$CONFIG_FILE" | \
    while IFS=$'\t' read -r tag proto addr port; do
        printf "%-20s %-15s %-25s %-10s\n" "$tag" "$proto" "$addr" "$port"
    done
    pause
}

# --- 功能 6: 查询 Routing ---
query_routing() {
    echo "================ Routing 规则 ================"
    # 使用 jq 格式化输出，如果 jq 表达式过于复杂，简化显示
    echo "ID | Source(Inbounds) | IP Rules | Domain Rules | -> Target(Outbound)"
    echo "---------------------------------------------------------------------"
    jq -r '.routing.rules[]? | 
        "\(.inboundTag // ["ALL"] | join(",")) | \(.ip // [] | join(",")) | \(.domain // [] | join(",")) | \(.outboundTag)"' "$CONFIG_FILE" | nl -w 2 -s " | "
    pause
}

# --- 功能 7: 更新脚本 ---
update_script() {
    info "正在拉取最新版本脚本..."
    local update_url="https://raw.githubusercontent.com/RomanovCaesar/Install-Xray-Inbounds/main/xray_routing.sh"
    if curl -fsSL "$update_url" -o "$SCRIPT_PATH"; then
        chmod +x "$SCRIPT_PATH"
        info "脚本更新成功，即将退出，请重新运行。"
        exit 0
    else
        die "脚本更新失败，请检查网络连接。"
    fi
}

# --- 主菜单 ---
show_menu() {
    clear
    echo "================================================="
    echo "       Caesar 蜜汁 xray 服务端分流脚本 v1.0       "
    echo "================================================="
    echo "  1. 安装 Geo 文件 (配置每日自动更新)"
    echo "  2. 添加 Outbounds (Socks / SS / VLESS)"
    echo "  3. 添加 Routing (配置分流规则)"
    echo "  4. 查询已有 Inbounds"
    echo "  5. 查询已有 Outbounds"
    echo "  6. 查询已有 Routing"
    echo "  7. 更新脚本"
    echo "  0. 退出脚本"
    echo "================================================="
    read -rp " 请输入选项 [0-7]: " num
    
    case "$num" in
        1) install_geo_assets ;;
        2) add_outbound ;;
        3) add_routing ;;
        4) query_inbounds ;;
        5) query_outbounds ;;
        6) query_routing ;;
        7) update_script ;;
        0) echo -e "${GREEN}感谢使用此脚本，再见！${PLAIN}"; exit 0 ;;
        *) echo -e "${RED}无效输入，请重新选择。${PLAIN}"; sleep 1 ;;
    esac
}

# --- 主程序入口 ---
main() {
    pre_check
    install_self "$@"
    
    while true; do
        show_menu
    done
}

main "$@"
