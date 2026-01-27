#!/usr/bin/env bash
# install_vless_pq_xray_autoenc.sh
# 安装 Xray 并追加一个 VLESS (VLESS Encryption, ML-KEM-768) inbound（无 TLS）
# 通过 `xray vlessenc` 获取 ML-KEM-768 字段，并将 .native. -> .random.
# 追加不覆盖、端口冲突检测、唯一 tag、OpenRC 后台、可选域名；新增：生成 UUID 并输出 vless 分享链接
set -euo pipefail

die(){ echo -e "\e[31m[ERROR]\e[0m $*" >&2; exit 1; }
info(){ echo -e "\e[32m[INFO]\e[0m $*"; }
warn(){ echo -e "\e[33m[WARN]\e[0m $*"; }

require_root(){ if [[ ${EUID:-$(id -u)} -ne 0 ]]; then die "请以 root 身份运行（sudo）"; fi; }

detect_os(){
  if [[ -f /etc/os-release ]]; then . /etc/os-release; OS_ID="${ID,,}"; else die "无法检测 /etc/os-release"; fi
  case "$OS_ID" in
    debian|ubuntu) OS_FAMILY="debian" ;;
    alpine)        OS_FAMILY="alpine" ;;
    *) die "仅支持 Debian/Ubuntu/Alpine，检测到：$OS_ID" ;;
  esac
  info "检测到系统：${PRETTY_NAME:-$OS_ID}"
}

ensure_packages(){
  case "$OS_FAMILY" in
    debian)
      apt-get update -y
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates curl unzip xz-utils openssl python3 jq iproute2 net-tools
      ;;
    alpine)
      apk add --no-cache ca-certificates curl unzip xz openssl python3 jq iproute2 net-tools
      ;;
  esac
}

create_xray_user(){
  if id -u xray >/dev/null 2>&1; then return; fi
  case "$OS_FAMILY" in
    debian) adduser --system --no-create-home --shell /usr/sbin/nologin --group xray || true ;;
    alpine) addgroup -S xray || true; adduser -S -H -s /sbin/nologin -G xray xray || true ;;
  esac
}

prompt_domain(){
  read -rp "请输入要使用的域名或IP（留空则使用公网 IP）： " input || true
  input="$(echo -n "$input" | awk '{$1=$1;print}')"
  if [[ -z "$input" ]]; then 
    SERVER_DOMAIN=""
    info "未输入域名或IP，将使用公网 IP"
  else
    input="${input,,}"
    SERVER_DOMAIN="$input"
    info "将使用域名：$SERVER_DOMAIN"
  fi
}

read_port_once(){
  read -rp "请输入 VLESS 入站端口（1-65535，默认 40000）： " input || true
  input="${input:-40000}"
  [[ "$input" =~ ^[0-9]+$ ]] && (( input>=1 && input<=65535 )) || die "端口无效：$input"
  echo "$input"
}

port_in_config_inuse(){
  local cfg="/usr/local/etc/xray/config.json" p="$1"
  [[ -s "$cfg" ]] || return 1
  jq -e --argjson p "$p" '
    try (if .inbounds == null then false
      elif (.inbounds|type)!="array" then (.inbounds.port? // empty) == $p
      else any(.inbounds[]?; (.port? // empty) == $p) end) catch false
  ' "$cfg" >/dev/null 2>&1
}

port_in_system_inuse(){
  local p="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${p}([[:space:]]|$)" && return 0
    ss -H -lun 2>/dev/null | awk '{print $5}' | grep -Eq "[:.]${p}([[:space:]]|$)" && return 0
    return 1
  elif command -v netstat >/dev/null 2>&1; then
    netstat -tuln 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${p}([[:space:]]|$)" && return 0
    return 1
  else
    return 1
  fi
}

prompt_port_until_free(){
  while :; do
    local p; p="$(read_port_once)"
    if port_in_config_inuse "$p"; then warn "端口 $p 已在 Xray 配置中使用，请换一个"; continue; fi
    if port_in_system_inuse "$p"; then warn "端口 $p 已被系统监听（TCP/UDP），请换一个"; continue; fi
    SS_PORT="$p"; info "将使用端口：$SS_PORT"; break
  done
}

install_xray(){
  # 架构检测
  local arch
  local machine
  machine="$(uname -m)"
  case "$machine" in
    x86_64|amd64) arch="64" ;;       # 常规 Intel/AMD 64位 CPU
    aarch64|arm64) arch="arm64-v8a" ;; # ARM 64位 CPU
    *) die "不支持的 CPU 架构: $machine" ;;
  esac
  
  local api="https://api.github.com/repos/XTLS/Xray-core/releases/latest"
  info "获取 Xray 最新版本信息..."
  local tag; tag="$(curl -fsSL "$api" | grep -oE '\"tag_name\":\s*\"[^\"]+\"' | head -n1 | cut -d\" -f4)" || true
  [[ -n "${tag:-}" ]] && info "最新版本：$tag" || warn "无法获取最新 tag，使用 latest 直链"

  local tmpdir=""; trap 'test -n "${tmpdir:-}" && rm -rf "$tmpdir"' EXIT; tmpdir="$(mktemp -d)"
  
  # 使用动态生成的 zip 名称
  local zipname="Xray-linux-${arch}.zip"
  
  local url_main="https://github.com/XTLS/Xray-core/releases/latest/download/${zipname}"
  local url_tag="https://github.com/XTLS/Xray-core/releases/download/${tag}/${zipname}"

  info "下载 Xray ($zipname)..."
  if [[ -n "${tag:-}" ]] && curl -fL "$url_tag" -o "$tmpdir/xray.zip"; then :;
  elif curl -fL "$url_main" -o "$tmpdir/xray.zip"; then :;
  else die "下载 Xray 失败"; fi

  info "解压并安装 /usr/local/bin/xray ..."
  unzip -q -o "$tmpdir/xray.zip" -d "$tmpdir"
  install -m 0755 "$tmpdir/xray" /usr/local/bin/xray || die "安装 xray 失败"

  create_xray_user
  mkdir -p /usr/local/etc/xray
  chown -R xray:xray /usr/local/etc/xray || true
}

generate_vless_tokens_from_xray(){
  command -v xray >/dev/null 2>&1 || die "'xray' 未找到（需要运行 'xray vlessenc'）"
  info "调用 'xray vlessenc' 生成 ML-KEM-768 的 decryption/encryption ..."
  local out dec enc
  out="$(xray vlessenc 2>&1 || true)"

  dec="$(printf '%s\n' "$out" | awk '/Authentication: ML-KEM-768/ {p=1; next} p && /"decryption":/ {gsub(/^.*"decryption": *"/,""); gsub(/".*/,""); print; exit}')"
  enc="$(printf '%s\n' "$out" | awk '/Authentication: ML-KEM-768/ {p=1; next} p && /"encryption":/ {gsub(/^.*"encryption": *"/,""); gsub(/".*/,""); print; exit}')"

  if [[ -z "$dec" || -z "$enc" ]]; then
    warn "无法提取 ML-KEM-768 字段，'xray vlessenc' 输出为："
    printf '%s\n' "$out" | sed -n '1,200p'
    die "请确认 xray 版本支持 vlessenc 且输出包含 ML-KEM-768。"
  fi

  # 按你的要求：native -> random
  VLESS_DECRYPTION="${dec/.native./.random.}"
  VLESS_ENCRYPTION="${enc/.native./.random.}"
  info "已获取并转换字段：native -> random"
}

# ---------------- UUID ----------------
generate_uuid(){
  if [[ -r /proc/sys/kernel/random/uuid ]]; then
    CLIENT_ID="$(cat /proc/sys/kernel/random/uuid)"
  elif command -v uuidgen >/dev/null 2>&1; then
    CLIENT_ID="$(uuidgen)"
  else
    # 退路：用 openssl 生成 16 字节随机并格式化成 UUID 样式（不保证版本位）
    CLIENT_ID="$(openssl rand -hex 16 | sed 's/^\(........\)\(....\)\(....\)\(....\)\(............\)$/\1-\2-\3-\4-\5/')"
  fi
  info "已生成 UUID：$CLIENT_ID"
}

# ---------------- backup existing config ----------------
backup_config_if_exists(){
  local cfg="/usr/local/etc/xray/config.json"
  if [[ -s "$cfg" ]]; then
    local ts; ts="$(date +%Y%m%d-%H%M%S)"
    cp -a "$cfg" "/root/xray-config-backup-${ts}.json"
    info "已备份现有配置到 /root/xray-config-backup-${ts}.json"
  fi
}

# ---------------- unique tag ----------------
generate_unique_tag(){
  local cfg="/usr/local/etc/xray/config.json"
  local base="vless-pq-in-${SS_PORT}"
  VLESS_TAG="$base"
  if [[ -s "$cfg" ]] && jq empty "$cfg" >/dev/null 2>&1; then
    if jq -e --arg t "$VLESS_TAG" '((.inbounds // []) | map(.tag // "") | index($t)) != null' "$cfg" >/dev/null; then
      local n=2
      while :; do
        VLESS_TAG="${base}-${n}"
        jq -e --arg t "$VLESS_TAG" '((.inbounds // []) | map(.tag // "") | index($t)) == null' "$cfg" >/dev/null && break
        n=$((n+1))
      done
    fi
  fi
  info "将使用 inbound tag：$VLESS_TAG"
}

# ---------------- append or create config ----------------
append_or_create_config(){
  local cfg="/usr/local/etc/xray/config.json"

  # 仅 TCP，按你分享链接的参数
  local new_inbound
  new_inbound="$(cat <<EOF
{
  "port": $SS_PORT,
  "protocol": "vless",
  "settings": {
    "clients": [ { "id": "$CLIENT_ID" } ],
    "decryption": "$VLESS_DECRYPTION",
    "encryption": "$VLESS_ENCRYPTION",
    "selectedAuth": "ML-KEM-768, Post-Quantum"
  },
  "tag": "$VLESS_TAG",
  "streamSettings": { "network": "tcp" }
}
EOF
)"

  if [[ -s "$cfg" ]]; then
    info "检测已有 Xray 配置，追加 VLESS PQ inbound ..."
    if ! jq empty "$cfg" >/dev/null 2>&1; then die "现有配置不是有效 JSON，请手动检查 $cfg"; fi
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
    info "追加完成。"
  else
    info "未检测到配置，生成新配置文件 ..."
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

  chown xray:xray "$cfg" || true
  chmod 0644 "$cfg" || true
  info "已写入配置：$cfg"
}

install_service_systemd(){
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

install_service_openrc(){
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
}

setup_service(){
  if command -v systemctl >/dev/null 2>&1; then install_service_systemd
  elif command -v rc-update >/dev/null 2>&1; then install_service_openrc
  else die "未检测到 systemd 或 OpenRC"
  fi
}

detect_address(){
  if [[ -n "${SERVER_DOMAIN:-}" ]]; then SERVER_ADDR="$SERVER_DOMAIN"; return; fi
  local ipv4=""
  ipv4="$(curl -fsSL https://api.ipify.org || true)"
  [[ -n "$ipv4" ]] || ipv4="$(curl -fsSL http://ifconfig.me || true)"
  [[ -n "$ipv4" ]] || ipv4="$(hostname -I 2>/dev/null | awk '{print $1}')" || true
  SERVER_ADDR="${ipv4:-<SERVER_IP>}"
  if [[ "$SERVER_ADDR" = "<SERVER_IP>" ]]; then warn "无法自动探测公网 IP，请手动替换分享链接中的 <SERVER_IP>"; fi
}

print_share_uri(){
  # 只需 URL 编码 remark/tag
  local tag_enc
  tag_enc="$(python3 - <<'PY'
import urllib.parse, os
print(urllib.parse.quote(os.environ.get("TAG",""), safe=''))
PY
)"
  local uri="vless://${CLIENT_ID}@${SERVER_ADDR}:${SS_PORT}?type=tcp&encryption=${VLESS_ENCRYPTION}&security=none#${tag_enc}"

  echo
  echo "================ VLESS PQ 配置信息 ================"
  echo "ID (UUID) : $CLIENT_ID"
  echo "Port      : $SS_PORT"
  echo "Tag       : $VLESS_TAG"
  echo "Auth      : ML-KEM-768"
  echo "Decryption: $VLESS_DECRYPTION"
  echo "Encryption: $VLESS_ENCRYPTION"
  echo "Server    : ${SERVER_ADDR:-<SERVER_IP>}"
  echo
  echo "VLESS 分享链接："
  echo "$uri"
  echo "==================================================="

  # 保存分享链接到文件 (与 ss 脚本逻辑一致) 
  local link_file="/root/xray_vless_encryption_link.txt"
  {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')]"
    echo "$uri"
    echo
  } >> "$link_file"

  info "已将分享链接保存到：$link_file"
}

restart_service(){
  if command -v systemctl >/dev/null 2>&1; then systemctl restart xray || true; systemctl status xray --no-pager -l || true
  else rc-service xray restart || true; rc-service xray status || true; fi
}

main(){
  require_root
  detect_os
  ensure_packages
  prompt_domain
  prompt_port_until_free
  install_xray
  generate_vless_tokens_from_xray
  generate_uuid
  backup_config_if_exists
  generate_unique_tag
  append_or_create_config
  setup_service
  detect_address
  TAG="$VLESS_TAG" print_share_uri
  restart_service

  info "完成。常用命令："
  if command -v systemctl >/dev/null 2>&1; then
    echo "  systemctl status xray"
    echo "  journalctl -u xray -e"
  else
    echo "  rc-service xray status"
  fi
}

main "$@"
