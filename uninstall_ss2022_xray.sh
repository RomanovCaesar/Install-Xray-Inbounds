#!/usr/bin/env bash
# uninstall_ss2022_xray.sh
# 更严格地卸载并清理 Xray（Debian/Ubuntu/Alpine）
set -euo pipefail

PURGE=false
[[ "${1:-}" == "--purge" ]] && PURGE=true

die()  { echo -e "\e[31m[ERROR]\e[0m $*" >&2; exit 1; }
info() { echo -e "\e[32m[INFO]\e[0m $*"; }
warn() { echo -e "\e[33m[WARN]\e[0m $*"; }

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

has_systemd() { command -v systemctl >/dev/null 2>&1; }

# 收集所有可能存在的 xray systemd 单元（xray.service / xray@.service 实例）
collect_xray_units() {
  local units=()

  # 1) 从 unit-files 列表搜
  if has_systemd; then
    while read -r u; do [[ -n "$u" ]] && units+=("$u"); done < <(
      systemctl list-unit-files --type=service 2>/dev/null | awk '/^xray(@.*)?\.service/ {print $1}'
    )
    # 2) 从已加载单元（包含inactive/failed）搜
    while read -r u; do [[ -n "$u" ]] && units+=("$u"); done < <(
      systemctl list-units --type=service --all 2>/dev/null | awk '/xray(@.*)?\.service/ {print $1}'
    )
  fi

  # 3) 如果上述都没抓到，但单元文件存在，也将 xray.service 加进去
  [[ -f /etc/systemd/system/xray.service || -f /lib/systemd/system/xray.service || -f /usr/lib/systemd/system/xray.service ]] && units+=("xray.service")

  # 去重
  if ((${#units[@]})); then
    printf "%s\n" "${units[@]}" | awk '!seen[$0]++'
  fi
}

stop_disable_systemd_units() {
  has_systemd || return 0
  local units
  units="$(collect_xray_units || true)"
  if [[ -z "$units" ]]; then
    warn "未检测到已注册的 Xray 服务（systemd）。"
    return 0
  fi

  info "检测到以下 systemd 单元将被停止并禁用："
  echo "$units" | sed 's/^/  - /'

  # 逐个停止/禁用，并清理失败状态
  while read -r u; do
    [[ -z "$u" ]] && continue
    systemctl stop "$u" 2>/dev/null || true
    systemctl disable "$u" 2>/dev/null || true
    systemctl reset-failed "$u" 2>/dev/null || true
  done <<< "$units"

  # 清理常见 wants 软链，防止重启后又被拉起
  for wants in \
    /etc/systemd/system/multi-user.target.wants/xray.service \
    /etc/systemd/system/*/xray.service
  do
    [[ -L "$wants" || -f "$wants" ]] && { info "移除残留链接/文件：$wants"; rm -f "$wants"; }
  done
}

remove_systemd_files() {
  has_systemd || return 0
  local removed=false
  for f in \
    /etc/systemd/system/xray.service \
    /lib/systemd/system/xray.service \
    /usr/lib/systemd/system/xray.service
  do
    if [[ -f "$f" ]]; then
      info "删除 systemd 单元文件：$f"
      rm -f "$f"
      removed=true
    fi
  done
  # 彻底移除后 reload
  if $removed; then
    systemctl daemon-reload || true
  fi
}

stop_disable_openrc() {
  if command -v rc-update >/dev/null 2>&1 && [[ -f /etc/init.d/xray ]]; then
    info "检测到 OpenRC 服务，停止并移出开机自启 ..."
    rc-service xray stop || true
    rc-update del xray default || true
  else
    warn "未检测到已注册的 Xray 服务（OpenRC）。"
  fi
}

remove_openrc_files() {
  if [[ -f /etc/init.d/xray ]]; then
    info "删除 OpenRC 脚本 /etc/init.d/xray"
    rm -f /etc/init.d/xray
  fi
  [[ -f /run/xray.pid ]] && rm -f /run/xray.pid || true
}

backup_and_remove_config() {
  local cfg_dir="/usr/local/etc/xray"
  if [[ -d "$cfg_dir" ]]; then
    local ts backup
    ts="$(date +%Y%m%d-%H%M%S)"
    backup="/root/xray-config-backup-${ts}.tar.gz"
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

  for d in /usr/local/share/xray /usr/share/xray /var/lib/xray; do
    [[ -d "$d" ]] && { info "删除数据目录 $d"; rm -rf "$d"; }
  done

  for f in /var/log/xray.log /var/log/xray/xray.log; do
    [[ -f "$f" ]] && { info "删除日志文件 $f"; rm -f "$f"; }
  done
  [[ -d /var/log/xray ]] && { info "删除日志目录 /var/log/xray"; rm -rf /var/log/xray; }
}

remove_user_group_if_purge() {
  $PURGE || { info "保留用户/组 xray（未使用 --purge）。"; return; }

  info "执行 --purge：尝试删除 xray 用户与组 ..."
  pkill -u xray 2>/dev/null || true

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

  [[ -d /home/xray ]] && rm -rf /home/xray || true
}

summary() {
  echo
  echo "====== 卸载完成 ======"
  echo "已停止并移除服务、删除单元文件、二进制与配置（配置已备份到 /root/xray-config-backup-*.tar.gz）。"
  if $PURGE; then
    echo "已尝试删除 xray 用户与组。"
  else
    echo "保留了 xray 用户与组（如需同时删除，请加 --purge 重新执行）。"
  fi
  echo
  if has_systemd; then
    echo "检查残留（可选）："
    echo "  systemctl list-units --type=service | grep -i xray || true"
    echo "  systemctl list-unit-files | grep -i xray || true"
  fi
}

main() {
  require_root
  detect_os

  # 优先处理 systemd（Debian 12 属于此分支）
  stop_disable_systemd_units
  remove_systemd_files

  # 同时处理 OpenRC（以防用户自己装过 OpenRC 版本）
  stop_disable_openrc
  remove_openrc_files

  backup_and_remove_config
  remove_binary_and_misc
  remove_user_group_if_purge

  summary
}

main "$@"
