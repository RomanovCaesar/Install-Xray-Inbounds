#!/bin/bash
# ==============================================================================
# Caesar 蜜汁 xray 配置还原工具
# 功能：从 URL 下载或手动粘贴 config.json，并提供测试功能
# ==============================================================================

# --- 全局设置 ---
set -u
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
CYAN='\033[96m'
PLAIN='\033[0m'

# --- 路径配置 ---
SCRIPT_PATH="/usr/bin/xray-restore"
CONFIG_DIR="/usr/local/etc/xray"
CONFIG_FILE="${CONFIG_DIR}/config.json"
XRAY_BIN="/usr/local/bin/xray"

# --- Github 更新地址 ---
# 请确保此文件名为 xray_restore.sh 并存在于您的仓库中
GITHUB_USER="RomanovCaesar"
GITHUB_REPO="Install-Xray-Inbounds"
GITHUB_BRANCH="main"
UPDATE_URL="https://raw.githubusercontent.com/${GITHUB_USER}/${GITHUB_REPO}/${GITHUB_BRANCH}/xray_restore.sh"

# --- 基础函数 ---
die() { echo -e "${RED}[ERROR] $*${PLAIN}" >&2; exit 1; }
info() { echo -e "${GREEN}[INFO] $*${PLAIN}"; }
warn() { echo -e "${YELLOW}[WARN] $*${PLAIN}"; }

# --- 权限与依赖检测 ---
pre_check() {
    [[ ${EUID:-$(id -u)} -ne 0 ]] && die "请以 root 身份运行此脚本。"
    
    # 确保目录存在
    if [[ ! -d "$CONFIG_DIR" ]]; then
        mkdir -p "$CONFIG_DIR"
    fi

    # 依赖检测 (nano 和 curl)
    local deps=("curl" "nano")
    local install_cmd=""
    local missing_deps=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing_deps+=("$dep")
        fi
    done

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        info "正在安装缺失依赖: ${missing_deps[*]} ..."
        if [[ -f /etc/alpine-release ]]; then
            apk update && apk add --no-cache "${missing_deps[@]}"
        elif [[ -f /etc/os-release ]]; then
            apt-get update && apt-get install -y "${missing_deps[@]}"
        else
            die "无法检测系统包管理器，请手动安装: ${missing_deps[*]}"
        fi
    fi
}

# --- 自我安装 ---
install_self() {
    local current_path
    current_path="$(realpath "$0")"
    
    if [[ "$current_path" != "$SCRIPT_PATH" ]]; then
        info "正在安装脚本到 $SCRIPT_PATH ..."
        cp "$current_path" "$SCRIPT_PATH"
        chmod +x "$SCRIPT_PATH"
        info "安装完成！以后可以在终端直接输入 ${CYAN}xray-restore${PLAIN} 使用。"
        sleep 1
        exec "$SCRIPT_PATH" "$@"
    fi
}

# --- 功能 1: 从 URL 还原 (优化版：带自动备份) ---
restore_from_url() {
    echo "================ 从 URL 还原配置 ================"
    echo "请输入 config.json 的直链下载地址 (例如: https://example.com/backup.json)"
    read -rp "地址: " url
    
    if [[ -z "$url" ]]; then
        warn "地址不能为空。"
        return
    fi

    info "正在下载配置文件..."
    # 先下载到临时文件，防止损坏现有配置
    local tmp_file
    tmp_file="$(mktemp)"
    
    if curl -fsSL -o "$tmp_file" "$url"; then
        # 简单检查是否是 JSON (检查是否以 { 开头)
        if grep -q "^[[:space:]]*{" "$tmp_file"; then
            
            # --- 新增：备份逻辑 ---
            if [[ -f "$CONFIG_FILE" ]]; then
                local backup_file="${CONFIG_FILE}.bak.$(date +%Y%m%d%H%M%S)"
                cp "$CONFIG_FILE" "$backup_file"
                info "检测到旧配置，已自动备份为: $backup_file"
            fi
            # --------------------

            mv "$tmp_file" "$CONFIG_FILE"
            chmod 644 "$CONFIG_FILE"
            info "新配置文件已成功下载并保存到: $CONFIG_FILE"
            info "建议使用选项 3 测试配置文件有效性。"
        else
            warn "下载的文件似乎不是有效的 JSON 格式，已取消覆盖。"
            rm -f "$tmp_file"
        fi
    else
        die "下载失败，请检查 URL 或网络连接。"
    fi
    
    echo
    read -n 1 -s -r -p "按任意键返回主菜单..." || true
}

# --- 功能 2: 手动粘贴 (优化版：带自动备份) ---
restore_manual() {
    echo "================ 手动粘贴配置 ================"
    
    # --- 新增：备份逻辑 ---
    if [[ -f "$CONFIG_FILE" ]]; then
        # 为了安全起见，这里直接强制备份旧配置
        local backup_file="${CONFIG_FILE}.bak.$(date +%Y%m%d%H%M%S)"
        cp "$CONFIG_FILE" "$backup_file"
        info "检测到旧配置，已自动备份为: $backup_file"
    fi
    # --------------------

    info "即将打开 nano 编辑器..."
    info "请将您的 config.json 内容粘贴进去 (这会覆盖当前 config.json)。"
    info "操作提示: 粘贴后按 Ctrl+O 保存 (回车确认)，然后 Ctrl+X 退出。"
    echo
    read -n 1 -s -r -p "按任意键开始编辑..." || true
    
    nano "$CONFIG_FILE"
    
    if [[ -s "$CONFIG_FILE" ]]; then
        info "编辑完成，文件已保存。"
        info "建议使用选项 3 测试配置文件有效性。"
    else
        warn "文件为空或未保存 (如果之前有旧文件，内容可能已被清空或未变)。"
    fi
    
    echo
    read -n 1 -s -r -p "按任意键返回主菜单..." || true
}

# --- 功能 3: 试运行测试 ---
test_config() {
    echo "================ 测试配置文件 ================"
    
    if [[ ! -f "$CONFIG_FILE" ]]; then
        die "配置文件不存在: $CONFIG_FILE"
    fi
    
    if [[ ! -f "$XRAY_BIN" ]]; then
        die "Xray 核心未找到: $XRAY_BIN，无法测试。"
    fi

    info "正在执行: xray -config ... -test"
    echo "------------------------------------------------"
    
    # 捕获输出并显示
    "$XRAY_BIN" -config "$CONFIG_FILE" -test
    local ret=$?
    
    echo "------------------------------------------------"
    if [[ $ret -eq 0 ]]; then
        echo -e "${GREEN}✔ 配置文件测试通过！Xray 可以正常启动。${PLAIN}"
        echo -e "提示: 如果需要立即应用，请手动重启 Xray (systemctl restart xray 或 rc-service xray restart)"
    else
        echo -e "${RED}✖ 配置文件有错误！请检查上方报错信息。${PLAIN}"
    fi
    
    echo
    echo "将在 30 秒后自动返回主菜单，或按任意键立即返回..."
    read -t 30 -n 1 -s -r || true
}

# --- 功能 4: 更新脚本 ---
update_script() {
    info "正在检查更新..."
    
    if curl -fsSL -o "$SCRIPT_PATH" "$UPDATE_URL"; then
        chmod +x "$SCRIPT_PATH"
        info "脚本更新成功！正在重新加载..."
        sleep 1
        exec "$SCRIPT_PATH"
    else
        die "更新失败，请检查网络或 Github 仓库地址。"
    fi
}

# --- 主菜单 ---
show_menu() {
    clear
    echo -e "${CYAN}=================================================${PLAIN}"
    echo -e "${CYAN}       Caesar 蜜汁 xray 配置还原工具             ${PLAIN}"
    echo -e "${CYAN}=================================================${PLAIN}"
    echo -e "  ${GREEN}1.${PLAIN} 从 URL 下载 config.json"
    echo -e "  ${GREEN}2.${PLAIN} 手动粘贴 config.json (Nano)"
    echo -e "  ${YELLOW}3.${PLAIN} 试运行测试配置文件 (Debug)"
    echo -e "  ${CYAN}4.${PLAIN} 更新此还原脚本"
    echo -e "  ${RED}0.${PLAIN} 退出脚本"
    echo -e "${CYAN}=================================================${PLAIN}"
    
    read -rp " 请输入选项 [0-4]: " choice
    
    case "$choice" in
        1) restore_from_url ;;
        2) restore_manual ;;
        3) test_config ;;
        4) update_script ;;
        0) echo -e "${GREEN}感谢使用本脚本，再见！${PLAIN}"; exit 0 ;;
        *) echo -e "${RED}无效输入，请重新选择。${PLAIN}"; sleep 1 ;;
    esac
}

# --- 主程序入口 ---
main() {
    pre_check
    install_self
    
    while true; do
        show_menu
    done
}

main "$@"
