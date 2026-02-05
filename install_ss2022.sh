#!/usr/bin/env bash
# install_ss2022_xray.sh
# 安装/追加 Xray 的 Shadowsocks 入站（aes-128/256-gcm 或 chacha20-ietf-poly1305 或 2022-blake3-aes-128/256-gcm 或 2022-blake3-chacha20-poly1305）
# 适配 Debian/Ubuntu/Alpine（OpenRC 后台运行）；支持可选域名；支持自定义密码
# 检测旧配置则追加 inbound；检测端口冲突（配置内&系统监听）；自动生成唯一 tag
set -euo pipefail

die() { echo -e "\e[31m[ERROR]\e[0m $*" >&2; exit 1; }
info(){ echo -e "\e[32m[INFO]\e[0m $*"; }
warn(){ echo -e "\e[33m[WARN]\e[0m $*"; }

require_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    die "请以 root 身份运行（使用 sudo）"
  fi
}

detect_os() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS_ID="${ID,,}"
  else
    die "无法检测系统类型（缺少 /etc/os-release）"
  fi
  case "$OS_ID" in
    debian|ubuntu) OS_FAMILY="debian" ;;
    alpine)        OS_FAMILY="alpine" ;;
    *)             die "当前系统不受支持：$OS_ID（仅支持 Debian/Ubuntu/Alpine）" ;;
  esac
  info "检测到系统：$PRETTY_NAME"
}

ensure_packages() {
  case "$OS_FAMILY" in
    debian)
      apt-get update -y
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates curl unzip xz-utils openssl python3 jq net-tools iproute2
      ;;
    alpine)
      apk add --no-cache ca-certificates curl unzip xz openssl python3 jq iproute2 net-tools
      ;;
  esac
}

prompt_domain() {
  local input
  read -rp "请输入要使用的 IP 或者域名（留空则使用公网 IP）： " input || true
  input="$(echo -n "$input" | awk '{$1=$1;print}')"  # trim
  if [[ -z "$input" ]]; then
    SERVER_DOMAIN=""
    info "未输入 IP 或域名，将在稍后使用公网 IP。"
  else
    input="${input,,}"
    SERVER_DOMAIN="$input"
    info "将使用 IP 或域名：$SERVER_DOMAIN"
  fi
}

# ===== 端口输入与冲突检测 =====
read_port_once() {
  local input
  read -rp "请输入 Shadowsocks 2022 入站端口（1-65535，默认 40000）： " input || true
  input="${input:-40000}"
  [[ "$input" =~ ^[0-9]+$ ]] && (( input>=1 && input<=65535 )) || die "端口无效：$input"
  echo "$input"
}

port_in_config_inuse() {
  local cfg="/usr/local/etc/xray/config.json" p="$1"
  [[ -s "$cfg" ]] || return 1
  jq -e --argjson p "$p" '
    try (
      if .inbounds == null then
        false
      elif (.inbounds|type)!="array" then
        (.inbounds.port? // empty) == $p
      else
        any(.inbounds[]?; (.port? // empty) == $p)
      end
    ) catch false
  ' "$cfg" >/dev/null 2>&1
}

port_in_system_inuse() {
  local p="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${p}([[:space:]]|$)" && return 0
    ss -H -lun 2>/dev/null | awk '{print $5}' | grep -Eq "[:.]${p}([[:space:]]|$)" && return 0
    return 1
  elif command -v netstat >/dev/null 2>&1; then
    netstat -tuln 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${p}([[:space:]]|$)"
    return $?
  else
    return 1
  fi
}

prompt_port_until_free() {
  while :; do
    local p; p="$(read_port_once)"
    if port_in_config_inuse "$p"; then
      warn "端口 $p 已在 Xray 现有配置的 inbounds 中使用，请换一个。"
      continue
    fi
    if port_in_system_inuse "$p"; then
      warn "端口 $p 已被系统中其它进程监听（TCP/UDP），请换一个。"
      continue
    fi
    SS_PORT="$p"
    info "将使用端口：$SS_PORT"
    break
  done
}

install_xray() {
  # --- 架构检测修复 ---
  local arch
  local machine
  machine="$(uname -m)"
  case "$machine" in
    x86_64|amd64) arch="64" ;;
    aarch64|arm64) arch="arm64-v8a" ;;
    *) die "不支持的 CPU 架构: $machine" ;;
  esac
  # ------------------

  local api="https://api.github.com/repos/XTLS/Xray-core/releases/latest"
  info "获取 Xray 最新版本信息..."
  local tag
  tag="$(curl -fsSL "$api" | grep -oE '"tag_name":\s*"[^"]+"' | head -n1 | cut -d'"' -f4)" || true
  [[ -n "${tag:-}" ]] && info "最新版本：$tag" || warn "无法从 GitHub API 获取最新版本，使用 latest 直链"

  local tmpdir=""; trap 'test -n "${tmpdir:-}" && rm -rf "$tmpdir"' EXIT; tmpdir="$(mktemp -d)"
  
  # 使用动态架构名称
  local zipname="Xray-linux-${arch}.zip"
  
  local url_main="https://github.com/XTLS/Xray-core/releases/latest/download/${zipname}"
  local url_tag="https://github.com/XTLS/Xray-core/releases/download/${tag}/${zipname}"

  info "下载 Xray ($zipname)..."
  if [[ -n "${tag:-}" ]] && curl -fL "$url_tag" -o "$tmpdir/xray.zip"; then :; \
  elif curl -fL "$url_main" -o "$tmpdir/xray.zip"; then :; else die "下载 Xray 失败"; fi

  info "解压并安装到 /usr/local/bin ..."
  unzip -q -o "$tmpdir/xray.zip" -d "$tmpdir"
  install -m 0755 "$tmpdir/xray" /usr/local/bin/xray
}

select_protocol() {
  echo
  echo "================ 请选择协议类型 ================"
  echo "  1) Shadowsocks (ss)"
  echo "  2) Shadowsocks 2022 (ss2022)"
  echo "================================================"
  read -rp "请输入编号（1/2）： " PROTO_SELECT || true

  case "$PROTO_SELECT" in
    1)
      PROTOCOL="ss"
      info "已选择：Shadowsocks (ss)"
      ;;
    2)
      PROTOCOL="ss2022"
      info "已选择：Shadowsocks 2022 (ss2022)"
      ;;
    *)
      die "输入无效：必须是 1 或 2"
      ;;
  esac
}

generate_key() {

  if [[ "$PROTOCOL" = "ss" ]]; then

    echo
    echo "================ Shadowsocks 加密方式选择 ================"
    echo "  1) aes-128-gcm  （16 字节密钥）"
    echo "  2) aes-256-gcm  （32 字节密钥）"
    echo "  3) chacha20-ietf-poly1305  （32 字节密钥）"
    echo "=========================================================="
    read -rp "请输入加密方式编号（1/2/3，默认选2）： " msel || true
    msel="${msel:-2}"

    case "$msel" in
      1)
        SS_METHOD="aes-128-gcm"
        KEY_BYTES=16
        ;;
      2)
        SS_METHOD="aes-256-gcm"
        KEY_BYTES=32
        ;;
      3)
        SS_METHOD="chacha20-ietf-poly1305"
        KEY_BYTES=32
        ;;
      *)
        die "无效选择，请输入 1，2 或 3"
        ;;
    esac

  else  # ss2022

    echo
    echo "================ Shadowsocks 2022 加密方式选择 ================"
    echo "  1) 2022-blake3-aes-128-gcm  （16 字节密钥）"
    echo "  2) 2022-blake3-aes-256-gcm  （32 字节密钥）"
    echo "  3) 2022-blake3-chacha20-poly1305  （32 字节密钥）"
    echo "=============================================================="
    read -rp "请输入加密方式编号（1/2/3，默认选2）： " msel || true
    msel="${msel:-2}"

    case "$msel" in
      1)
        SS_METHOD="2022-blake3-aes-128-gcm"
        KEY_BYTES=16
        ;;
      2)
        SS_METHOD="2022-blake3-aes-256-gcm"
        KEY_BYTES=32
        ;;
      3)
        SS_METHOD="2022-blake3-chacha20-poly1305"
        KEY_BYTES=32
        ;;
      *)
        die "无效选择，请输入 1，2 或 3"
        ;;
    esac
  fi

  echo
  echo "================ 密码设置 ================"
  read -rp "请输入密码（留空则自动生成随机密码，注意自己输入密码需要格式正确，本脚本不做检查）： " input || true
  input="$(echo -n "$input" | awk '{$1=$1;print}')"

  if [[ -n "$input" ]]; then
    SS_KEY_B64="$input"
    info "使用用户自定义密码。"
  else
    SS_KEY_B64="$(openssl rand -base64 $KEY_BYTES | tr -d '\n')"
    [[ -n "$SS_KEY_B64" ]] || die "密码生成失败"
    info "未输入密码，已自动生成随机密码（${KEY_BYTES} 字节）"
  fi
}

backup_config_if_exists() {
  local cfg="/usr/local/etc/xray/config.json"
  if [[ -s "$cfg" ]]; then
    local ts; ts="$(date +%Y%m%d-%H%M%S)"
    local backup="/root/xray-config-backup-${ts}.json"
    cp -a "$cfg" "$backup"
    info "已备份现有配置到：$backup"
  fi
}

# ===== 生成唯一 inbound tag =====
generate_unique_tag() {
  local cfg="/usr/local/etc/xray/config.json"
  local base="ss-2022-in-${SS_PORT}"
  SS_TAG="$base"

  if [[ -s "$cfg" ]] && jq empty "$cfg" >/dev/null 2>&1; then
    # 如果已存在相同 tag，则追加 -2、-3...
    if jq -e --arg t "$SS_TAG" '((.inbounds // []) | map(.tag // "") | index($t)) != null' "$cfg" >/dev/null; then
      local n=2
      while :; do
        SS_TAG="${base}-${n}"
        jq -e --arg t "$SS_TAG" '((.inbounds // []) | map(.tag // "") | index($t)) == null' "$cfg" >/dev/null && break
        n=$((n+1))
      done
    fi
  fi
  info "将使用 inbound tag：$SS_TAG"
}

append_or_create_config() {
  local cfg="/usr/local/etc/xray/config.json"

  # 生成将要追加的新 inbound（不启用 sniffing）
  local new_inbound
  new_inbound="$(cat <<EOF
{
  "port": $SS_PORT,
  "protocol": "shadowsocks",
  "settings": {
    "method": "$SS_METHOD",
    "password": "$SS_KEY_B64",
    "network": "tcp,udp"
  },
  "tag": "$SS_TAG"
}
EOF
)"

  if [[ -s "$cfg" ]]; then
    info "检测到已有 Xray 配置，尝试追加一个 ss-2022 inbound ..."
    if ! jq empty "$cfg" >/dev/null 2>&1; then
      die "现有配置不是有效 JSON，请手动检查：$cfg"
    fi
    local tmp; tmp="$(mktemp)"
    jq --argjson inbound "$new_inbound" '
      if .inbounds == null then
        .inbounds = [$inbound]
      elif (.inbounds|type) != "array" then
        .inbounds = [ .inbounds, $inbound ]
      else
        .inbounds += [ $inbound ]
      end
    ' "$cfg" > "$tmp"
    mv "$tmp" "$cfg"
    info "已在原有配置中追加 inbound。"
  else
    info "未检测到现有配置，生成新的配置文件 ..."
    cat > "$cfg" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [ $new_inbound ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "blocked" }
  ]
}
EOF
  fi

  chown xray:xray "$cfg"
  chmod 0644 "$cfg"
  info "配置已更新：$cfg"
}

install_service_systemd() {
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
}

install_service_openrc() {
  cat >/etc/init.d/xray <<'EOF'
#!/sbin/openrc-run
name="xray"
description="Xray Service"
command="/usr/local/bin/xray"
command_args="run -config /usr/local/etc/xray/config.json"
# 后台运行并写入 pidfile，避免安装流程卡在前台
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
}

setup_service() {
  if command -v systemctl >/dev/null 2>&1; then
    install_service_systemd
  elif command -v rc-update >/dev/null 2>&1; then
    install_service_openrc
  else
    die "未检测到 systemd 或 OpenRC，无法安装服务"
  fi
}

detect_address() {
  if [[ -n "${SERVER_DOMAIN:-}" ]]; then
    SERVER_ADDR="$SERVER_DOMAIN"; return
  fi
  local ipv4=""
  ipv4="$(curl -fsSL http://api.ipify.org || true)"
  [[ -n "$ipv4" ]] || ipv4="$(curl -fsSL http://ip.sb || true)"
  [[ -n "$ipv4" ]] || ipv4="$(curl -fsSL http://ifconfig.me || true)"
  [[ -n "$ipv4" ]] || ipv4="$(hostname -I 2>/dev/null | awk '{print $1}')" || true
  SERVER_ADDR="${ipv4:-<SERVER_IP>}"
  if [[ "$SERVER_ADDR" = "<SERVER_IP>" ]]; then
    warn "无法自动探测公网 IP，请手动替换分享链接中的 <SERVER_IP>"
  fi
}

print_ss_uri() {
  local enc_pw tag_enc
  enc_pw="$(python3 - <<'PY'
import urllib.parse, os
print(urllib.parse.quote(os.environ.get("PW",""), safe=''))
PY
)"
  tag_enc="$(python3 - <<'PY'
import urllib.parse
print(urllib.parse.quote("xray-ss2022", safe=''))
PY
)"
  local uri="ss://${SS_METHOD}:${enc_pw}@${SERVER_ADDR}:${SS_PORT}#${tag_enc}"

  echo
  echo "================ Shadowsocks 2022 配置信息 ================"
  echo "Method : $SS_METHOD"
  echo "Port   : $SS_PORT"
  echo "Tag    : $SS_TAG"
  echo "Key(B64): $SS_KEY_B64"
  echo "Server : $SERVER_ADDR"
  echo
  echo "SS 分享链接（SIP002）："
  echo "$uri"
  echo "==========================================================="

  # 新增部分：保存分享链接到文件
  local link_file="/root/xray_ss2022_link.txt"
  {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')]"
    echo "$uri"
    echo
  } >> "$link_file"

  info "已将分享链接保存到：$link_file"
}

restart_service() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart xray || true
    systemctl status xray --no-pager -l || true
  else
    rc-service xray restart || true
    rc-service xray status || true
  fi
}

main() {
  require_root
  detect_os
  ensure_packages
  prompt_domain
  prompt_port_until_free
  install_xray
  select_protocol
  generate_key
  backup_config_if_exists
  generate_unique_tag      # <- 这里生成不会冲突的 tag
  append_or_create_config
  setup_service
  detect_address
  PW="$SS_KEY_B64" print_ss_uri
  restart_service

  info "完成。常用命令："
  if command -v systemctl >/dev/null 2>&1; then
    echo "  systemctl status xray      # 查看状态"
    echo "  journalctl -u xray -e      # 查看日志"
  else
    echo "  rc-service xray status     # 查看状态（OpenRC）"
    echo "  rc-service xray restart    # 重启服务（OpenRC）"
  fi
}

main "$@"
