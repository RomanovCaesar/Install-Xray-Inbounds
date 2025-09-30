#!/usr/bin/env bash
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
        ca-certificates curl unzip xz-utils openssl python3
      ;;
    alpine)
      apk add --no-cache ca-certificates curl unzip xz openssl python3
      ;;
  esac
}

create_xray_user() {
  if id -u xray >/dev/null 2>&1; then
    return
  fi
  case "$OS_FAMILY" in
    debian)
      adduser --system --no-create-home --shell /usr/sbin/nologin --group xray
      ;;
    alpine)
      addgroup -S xray || true
      adduser  -S -H -s /sbin/nologin -G xray xray
      ;;
  esac
}

prompt_port() {
  local input
  read -rp "请输入 Shadowsocks 2022 入站端口（1-65535，默认 40000）： " input || true
  input="${input:-40000}"
  if ! [[ "$input" =~ ^[0-9]+$ ]] || (( input < 1 || input > 65535 )); then
    die "端口无效：$input"
  fi
  SS_PORT="$input"
}

install_xray() {
  local api="https://api.github.com/repos/XTLS/Xray-core/releases/latest"
  info "获取 Xray 最新版本信息..."
  local tag
  tag="$(curl -fsSL "$api" | grep -oE '"tag_name":\s*"[^"]+"' | head -n1 | cut -d'"' -f4)" || true
  [[ -n "${tag:-}" ]] && info "最新版本：$tag" || warn "无法从 GitHub API 获取最新版本，使用 latest 直链"

  local tmpdir=""
  trap 'test -n "${tmpdir:-}" && rm -rf "$tmpdir"' EXIT
  tmpdir="$(mktemp -d)"

  local zipname="Xray-linux-64.zip"
  local url_main="https://github.com/XTLS/Xray-core/releases/latest/download/${zipname}"
  local url_tag="https://github.com/XTLS/Xray-core/releases/download/${tag}/${zipname}"

  info "下载 Xray..."
  if [[ -n "${tag:-}" ]] && curl -fL "$url_tag" -o "$tmpdir/xray.zip"; then
    :
  elif curl -fL "$url_main" -o "$tmpdir/xray.zip"; then
    :
  else
    die "下载 Xray 失败"
  fi

  info "解压并安装到 /usr/local/bin ..."
  unzip -q -o "$tmpdir/xray.zip" -d "$tmpdir"
  install -m 0755 "$tmpdir/xray" /usr/local/bin/xray

  create_xray_user
  mkdir -p /usr/local/etc/xray
  chown -R xray:xray /usr/local/etc/xray
}

generate_key() {
  SS_METHOD="2022-blake3-aes-256-gcm"
  SS_KEY_B64="$(openssl rand -base64 32 | tr -d '\n')"
  [[ -n "$SS_KEY_B64" ]] || die "密钥生成失败（openssl rand）"
}

write_config() {
  local cfg=/usr/local/etc/xray/config.json
  cat > "$cfg" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": $SS_PORT,
      "protocol": "shadowsocks",
      "settings": {
        "method": "$SS_METHOD",
        "password": "$SS_KEY_B64",
        "network": "tcp,udp"
      },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls"] },
      "tag": "ss-2022-in"
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "blocked" }
  ]
}
EOF
  chown xray:xray "$cfg"
  chmod 0644 "$cfg"
  info "已写入配置：$cfg"
}

install_service_systemd() {
  cat >/etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=Xray Service
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
User=xray
Group=xray
ExecStart=/usr/local/bin/xray -config /usr/local/etc/xray/config.json
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
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
command_args="-config /usr/local/etc/xray/config.json"
command_user="xray:xray"
pidfile="/run/xray.pid"

depend() {
  need net
  use dns
}

start_pre() {
  checkpath --directory --owner ${command_user} /run
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

detect_public_ip() {
  local ipv4=""
  ipv4="$(curl -fsSL https://api.ipify.org || true)"
  [[ -n "$ipv4" ]] || ipv4="$(curl -fsSL http://ifconfig.me || true)"
  [[ -n "$ipv4" ]] || ipv4="$(hostname -I 2>/dev/null | awk '{print $1}')" || true
  SERVER_IP="${ipv4:-<SERVER_IP>}"
  if [[ "$SERVER_IP" = "<SERVER_IP>" ]]; then
    warn "无法自动探测公网 IP，请手动替换分享链接中的 <SERVER_IP>"
  fi
}

print_ss_uri() {
  # 使用 python3 做 URL 编码，兼容 Alpine
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
  local uri="ss://${SS_METHOD}:${enc_pw}@${SERVER_IP}:${SS_PORT}#${tag_enc}"

  echo
  echo "================ Shadowsocks 2022 配置信息 ================"
  echo "Method : $SS_METHOD"
  echo "Port   : $SS_PORT"
  echo "Key(B64): $SS_KEY_B64"
  echo "Server : $SERVER_IP"
  echo
  echo "SS 分享链接（SIP002）："
  echo "$uri"
  echo "==========================================================="
}

main() {
  require_root
  detect_os
  ensure_packages
  prompt_port
  install_xray
  generate_key
  write_config
  setup_service
  detect_public_ip
  PW="$SS_KEY_B64" print_ss_uri

  info "完成。可用命令："
  if command -v systemctl >/dev/null 2>&1; then
    echo "  systemctl status xray   # 查看运行状态"
    echo "  journalctl -u xray -e   # 查看日志"
  else
    echo "  rc-service xray status  # 查看运行状态（OpenRC）"
    echo "  rc-service xray restart # 重启服务"
  fi
}

main "$@"
