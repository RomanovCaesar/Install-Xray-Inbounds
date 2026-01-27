#!/bin/bash
# update_geo.sh
# 用于自动更新 Xray 的 Geo 文件并重启服务
# 适配 Debian/Ubuntu (systemd) 和 Alpine (OpenRC)

# --- 环境变量设置 ---
# 确保在 Cron 环境下能找到命令
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# --- 配置路径 ---
GEO_DIR="/usr/local/bin"
GEO_SHARE_DIR="/usr/local/share/xray"
DOWNLOAD_URL_GEOIP="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
DOWNLOAD_URL_GEOSITE="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"

# --- 日志函数 ---
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# --- 1. 下载文件 ---
log "开始下载 Geo 文件..."
mkdir -p "$GEO_DIR"

if curl -fsSL -o "$GEO_DIR/geoip.dat" "$DOWNLOAD_URL_GEOIP"; then
    log "geoip.dat 下载成功"
else
    log "Error: geoip.dat 下载失败"
    exit 1
fi

if curl -fsSL -o "$GEO_DIR/geosite.dat" "$DOWNLOAD_URL_GEOSITE"; then
    log "geosite.dat 下载成功"
else
    log "Error: geosite.dat 下载失败"
    exit 1
fi

# --- 2. 复制到 Share 目录 ---
if [[ -d "$GEO_SHARE_DIR" ]]; then
    log "正在复制文件到 $GEO_SHARE_DIR ..."
    cp -f "$GEO_DIR/geoip.dat" "$GEO_SHARE_DIR/"
    cp -f "$GEO_DIR/geosite.dat" "$GEO_SHARE_DIR/"
fi

# --- 3. 重启 Xray 服务 ---
log "正在重启 Xray 服务..."

# 检测服务管理器并执行重启
if command -v systemctl >/dev/null 2>&1; then
    systemctl restart xray
    if systemctl is-active --quiet xray; then
        log "Xray (systemd) 重启成功"
    else
        log "Error: Xray 重启失败，请检查日志"
    fi
elif command -v rc-service >/dev/null 2>&1; then
    rc-service xray restart
    if rc-service xray status | grep -q "started"; then
        log "Xray (OpenRC) 重启成功"
    else
        log "Error: Xray 重启失败"
    fi
else
    log "Warning: 未找到 systemctl 或 rc-service，无法重启 Xray"
fi

log "更新流程结束"
