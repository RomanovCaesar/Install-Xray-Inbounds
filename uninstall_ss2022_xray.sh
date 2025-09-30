#!/usr/bin/env bash
# uninstall_ss2022_xray.sh
# 卸载并清理 Xray + ss-2022 配置（Debian/Ubuntu/Alpine）
set -euo pipefail

PURGE=false
[[ "${1:-}" == "--purge" ]] && PURGE=true

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
    OS_ID="unknown"
  fi
  case "$OS_ID" in
    debian|ubuntu) OS_FAMILY="debian" ;;
    alpine)        OS_FAMILY="alpine" ;;
    *)             OS_FAMILY="other" ;;
  esac
  info "系统：${PRETTY_NAME:-$OS_ID}"
}

stop_disable_service() {
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q '^xray\.service'; then
    info "检测到 systemd 服务，停止并禁用 xray.service ..."
    systemctl stop xray.service || true
    systemctl disable xray.service || true
    systemctl daemon-reload || true
  elif command -v rc-update >/dev/null 2>&1 && [[ -f /etc/init.d/xray ]]; then
    info "检测到 OpenRC 服务，停止并移出开机自启 ..."
    rc-service xray stop || true
    rc-update del xray default || true
  else
    warn "未检测到已注册的 Xray 服务（systemd/OpenRC）。"
  fi
}

remove_service_files() {
  # systemd
  if [[ -f /etc/systemd/system/xray.service ]]; then
    info "删除 systemd 单元文件 /etc/systemd/system/xray.service"
    rm -f /etc/systemd/system/xray.service
    command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload || true
  fi
  # OpenRC
  if [[ -f /etc/init.d/xray ]]; then
    info "删除 OpenRC 脚本 /etc/init.d/xray"
    rm -f /etc/init.d/xray
  fi
  # 可能遗留的 pid
  [[ -f /run/xray.pid ]] && rm -f /run/xray.pid || true
}

backup_and_remove_config() {
  local cfg_dir="/usr/local/etc/xray"
  if [[ -d "$cfg_dir" ]]; then
    local ts
    ts="$(date +%Y%m%d-%H%M%S)"
    local backup="/root/xray-config-backup-${ts}.tar.gz"
    info "备份配置目录到 $backup"
    tar -czf "$backup" -C "$(dirname "$cfg_dir")" "$(basename "$cfg_dir")"
    info "删除配置目录 $cfg_dir"
    rm -rf "$cfg_dir"
    echo -e "\e[34m[NOTE]\e[0m 备份已保存：$backup"
  else
    warn "未找到配置目录：$cfg_dir"
  fi
}

remove_binary_and_misc() {
  local bin="/usr/local/bin/xray"
  if [[ -f "$bin" ]]; then
    info "删除二进制文件 $bin"
    rm -f "$bin"
  else
    warn "未找到二进制文件：$bin"
  fi

  # 可选：删除可能存在的 geo 数据目录（如果曾自行下载）
  for d in /usr/local/share/xray /usr/share/xray /var/lib/xray; do
    [[ -d "$d" ]] && { info "删除数据目录 $d"; rm -rf "$d"; }
  done

  # 可选：日志位置（脚本默认没创建专门日志）
  for f in /var/log/xray.log /var/log/xray/xray.log; do
    [[ -f "$f" ]] && { info "删除日志文件 $f"; rm -f "$f"; }
  done
  [[ -d /var/log/xray ]] && { info "删除日志目录 /var/log/xray"; rm -rf /var/log/xray; }
}

remove_user_group_if_purge() {
  $PURGE || { info "保留用户/组 xray（未使用 --purge）。"; return; }

  info "执行 --purge：尝试删除 xray 用户与组 ..."
  # 结束残留进程（保险）
  pkill -u xray 2>/dev/null || true

  # Alpine: deluser/delgroup；Debian: userdel/groupdel
  if command -v deluser >/dev/null 2>&1; then
    deluser xray 2>/dev/null || true
  elif command -v userdel >/dev/null 2>&1; then
    userdel xray 2>/dev/null || true
  fi

  if command -v delgroup >/dev/null 2>&1; then
    delgroup xray 2>/dev/null || true
  elif command -v groupdel >/dev/null 2>&1; then
    groupdel xray 2>/dev/null || true
  fi

  # 移除家目录（通常不存在，因为是 system/no-home）
  [[ -d /home/xray ]] && rm -rf /home/xray || true
}

summary() {
  echo
  echo "====== 卸载完成 ======"
  echo "已停止并移除服务、删除二进制与配置（配置已备份到 /root/xray-config-backup-*.tar.gz）。"
  if $PURGE; then
    echo "已尝试删除 xray 用户与组。"
  else
    echo "保留了 xray 用户与组（如需同时删除，请加 --purge 重新执行）。"
  fi
  echo
  echo "如需恢复，可解压备份："
  echo "  tar -xzf /root/xray-config-backup-YYYYMMDD-HHMMSS.tar.gz -C /"
  echo
}

main() {
  require_root
  detect_os
  stop_disable_service
  remove_service_files
  backup_and_remove_config
  remove_binary_and_misc
  remove_user_group_if_purge
  summary
}

main "$@"
