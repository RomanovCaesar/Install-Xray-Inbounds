#!/bin/bash

# --- 启动前提示：优先推荐 Mihomo 实现 ---
offer_mihomo_alternative() {
    local mihomo_script="$1"
    shift
    local red='\033[1;31m' yellow='\033[1;33m' cyan='\033[1;36m' green='\033[1;32m' plain='\033[0m'
    local answer="" temp_file="" download_url="" saved_preference=""
    local preference_file="/etc/xray-inbounds-core-preference"
    local is_uzumaru=false

    if [[ "${XRAY_SKIP_MIHOMO_PROMPT_ONCE:-0}" == "1" ]]; then
        unset XRAY_SKIP_MIHOMO_PROMPT_ONCE
        return 0
    fi

    [[ -d /etc/uzmaru ]] && is_uzumaru=true

    if [[ -r "$preference_file" ]]; then
        IFS= read -r saved_preference <"$preference_file" || saved_preference=""
        case "$saved_preference" in
            mihomo)
                printf '%b已读取保存的内核偏好：Mihomo，将自动运行对应脚本。%b\n' "$green" "$plain"
                answer="y"
                ;;
            xray)
                if [[ "$is_uzumaru" == false ]]; then
                    printf '%b已读取保存的内核偏好：Xray，将继续运行当前脚本。%b\n' "$yellow" "$plain"
                    return 0
                fi
                ;;
        esac
    fi

    if [[ "$answer" != "y" ]]; then
        printf '\n%b============================================================%b\n' "$yellow" "$plain"
        printf '%b  Xray 内核风险提示%b\n' "$red" "$plain"
        printf '%b============================================================%b\n' "$yellow" "$plain"
        printf '%bXray 内核在部分环境下可能出现内存占用持续增长、OOM，%b\n' "$yellow" "$plain"
        printf '%b以及 TCP 连接数异常爆炸等问题；在低配置、低性能机器，%b\n' "$yellow" "$plain"
        printf '%b尤其是 Uzumaru 等平台的 NAT 容器上，风险会更加明显。%b\n\n' "$yellow" "$plain"
        printf '建议改用资源占用更低的 Mihomo 脚本项目：\n'
        printf '%bhttps://github.com/RomanovCaesar/Install-Mihomo-Inbounds%b\n\n' "$cyan" "$plain"
        if [[ "$is_uzumaru" == true ]]; then
            printf '%b已检测到 /etc/uzmaru：选择 Xray 仅本次有效，下次仍会询问。%b\n\n' "$red" "$plain"
        else
            printf '%b本次选择将保存在此机器上，供这五个 Xray 脚本共同使用。%b\n\n' "$green" "$plain"
        fi
    fi

    while true; do
        if [[ "$answer" != "y" ]]; then
            printf '%b是否改用 Mihomo 对应脚本？[Y/n]：%b' "$green" "$plain"
            if [[ -r /dev/tty ]]; then
                IFS= read -r answer </dev/tty 2>/dev/null || answer=""
            else
                IFS= read -r answer || answer=""
            fi
        fi

        case "$answer" in
            ""|y|Y|yes|YES|Yes)
                if [[ "$saved_preference" != "mihomo" ]]; then
                    if printf '%s\n' "mihomo" >"$preference_file"; then
                        printf '%b已保存 Mihomo 偏好；以后将自动运行对应的 Mihomo 脚本。%b\n' "$green" "$plain"
                    else
                        printf '%b[警告] 无法写入偏好文件 %s，本次仍将运行 Mihomo。%b\n' "$yellow" "$preference_file" "$plain" >&2
                    fi
                fi
                download_url="https://raw.githubusercontent.com/RomanovCaesar/Install-Mihomo-Inbounds/main/${mihomo_script}"
                temp_file="$(mktemp "/tmp/${mihomo_script}.XXXXXX")" || {
                    printf '%b[错误] 无法创建临时文件。%b\n' "$red" "$plain" >&2
                    exit 1
                }
                trap 'rm -f -- "$temp_file"' EXIT

                printf '%b正在下载并执行 Mihomo 脚本：%s%b\n' "$green" "$mihomo_script" "$plain"
                if command -v curl >/dev/null 2>&1; then
                    if ! curl -fsSL "$download_url" -o "$temp_file"; then
                        printf '%b[错误] Mihomo 脚本下载失败：%s%b\n' "$red" "$download_url" "$plain" >&2
                        exit 1
                    fi
                elif command -v wget >/dev/null 2>&1; then
                    if ! wget -qO "$temp_file" "$download_url"; then
                        printf '%b[错误] Mihomo 脚本下载失败：%s%b\n' "$red" "$download_url" "$plain" >&2
                        exit 1
                    fi
                else
                    printf '%b[错误] 未找到 curl 或 wget，无法下载 Mihomo 脚本。%b\n' "$red" "$plain" >&2
                    exit 1
                fi

                if [[ ! -s "$temp_file" ]]; then
                    printf '%b[错误] Mihomo 脚本下载失败或内容为空。%b\n' "$red" "$plain" >&2
                    exit 1
                fi

                bash "$temp_file" "$@"
                local mihomo_status=$?
                exit "$mihomo_status"
                ;;
            n|N|no|NO|No)
                if [[ "$is_uzumaru" == true ]]; then
                    rm -f -- "$preference_file" 2>/dev/null || true
                    printf '%b已选择继续运行 Xray 脚本。%b\n\n' "$yellow" "$plain"
                else
                    if printf '%s\n' "xray" >"$preference_file"; then
                        printf '%b已保存 Xray 偏好；以后将直接运行 Xray 脚本。%b\n\n' "$yellow" "$plain"
                    else
                        printf '%b[警告] 无法写入偏好文件 %s，本次继续运行 Xray。%b\n\n' "$yellow" "$preference_file" "$plain" >&2
                    fi
                fi
                return 0
                ;;
            *)
                printf '%b请输入 y、n，或直接按 Enter 使用默认选项 Y。%b\n' "$red" "$plain"
                ;;
        esac
    done
}

offer_mihomo_alternative "mihomo_manager.sh" "$@"
# ==============================================================================
# Caesar 蜜汁 xray 管理工具
# 统一管理安装、分流、卸载及Geo文件更新等脚本
# ==============================================================================

# --- 全局设置 ---
set -u # 遇到未定义变量报错，但不使用 set -e 以免子脚本退出导致主菜单崩溃
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
CYAN='\033[96m'
PLAIN='\033[0m'

# --- 仓库配置 ---
GITHUB_USER="RomanovCaesar"
GITHUB_REPO="Install-Xray-Inbounds"
GITHUB_BRANCH="main"
BASE_URL="https://raw.githubusercontent.com/${GITHUB_USER}/${GITHUB_REPO}/${GITHUB_BRANCH}"

# --- 本地路径 ---
MANAGER_PATH="/usr/bin/xray-manager"
WORK_DIR="/root"

# --- 基础函数 ---
die() { echo -e "${RED}[ERROR] $*${PLAIN}" >&2; exit 1; }
info() { echo -e "${GREEN}[INFO] $*${PLAIN}"; }
warn() { echo -e "${YELLOW}[WARN] $*${PLAIN}"; }

# --- 权限检测 ---
check_root() {
    [[ ${EUID:-$(id -u)} -ne 0 ]] && die "请以 root 身份运行此脚本。"
}

# --- 依赖检测 ---
check_deps() {
    if ! command -v curl >/dev/null 2>&1; then
        info "正在安装 curl..."
        if [ -f /etc/alpine-release ]; then
            apk add --no-cache curl
        else
            apt-get update && apt-get install -y curl
        fi
    fi
}

# --- 自我安装 ---
install_self() {
    local current_path
    current_path="$(realpath "$0")"
    
    if [[ "$current_path" != "$MANAGER_PATH" ]]; then
        info "正在安装管理脚本到 $MANAGER_PATH ..."
        cp "$current_path" "$MANAGER_PATH"
        chmod +x "$MANAGER_PATH"
        info "安装完成！以后可以直接在终端输入 ${CYAN}xray-manager${PLAIN} 唤醒此菜单。"
        sleep 1
        export XRAY_SKIP_MIHOMO_PROMPT_ONCE=1
        exec "$MANAGER_PATH" "$@"
    fi
}

# --- 核心：拉取并运行脚本 ---
# 参数 $1: 脚本文件名
# 参数 $2: (可选) 描述信息
pull_and_run() {
    local script_name="$1"
    local desc="${2:-运行脚本}"
    local target_file="${WORK_DIR}/${script_name}"
    local download_url="${BASE_URL}/${script_name}"

    info "正在拉取: $script_name ..."
    
    if curl -fsSL -o "$target_file" "$download_url"; then
        chmod +x "$target_file"
        info "拉取成功，正在$desc..."
        echo "----------------------------------------------------------------"
        # 切换到工作目录执行
        cd "$WORK_DIR" || die "无法进入 $WORK_DIR"
        ./"$script_name"
        
        # 执行完子脚本后，提示按键返回主菜单
        echo "----------------------------------------------------------------"
        read -n 1 -s -r -p "子脚本执行结束，按任意键返回主菜单..." || true
    else
        echo -e "${RED}[ERROR] 无法下载脚本: $script_name${PLAIN}"
        echo -e "${RED}请检查网络连接或 Github 仓库地址是否正确。${PLAIN}"
        read -n 1 -s -r -p "按任意键返回主菜单..." || true
    fi
}

# --- 功能 8: 更新自身 ---
update_self() {
    info "正在检查更新..."
    local download_url="${BASE_URL}/xray_manager.sh" # 假设你在仓库里把这个脚本命名为 xray_manager.sh
    
    if curl -fsSL -o "$MANAGER_PATH" "$download_url"; then
        chmod +x "$MANAGER_PATH"
        info "脚本更新成功！正在重新加载..."
        sleep 1
        exec "$MANAGER_PATH"
    else
        die "更新失败，请检查网络。"
    fi
}

# --- 主菜单 ---
show_menu() {
    clear
    echo -e "${CYAN}=================================================${PLAIN}"
    echo -e "${CYAN}          Caesar 蜜汁 xray 管理工具              ${PLAIN}"
    echo -e "${CYAN}=================================================${PLAIN}"
    echo -e "  ${GREEN}1.${PLAIN} Geo文件更新 (立即执行，不设定时任务)"
    echo -e "  ${GREEN}2.${PLAIN} 安装/管理 Shadowsocks (2022)"
    echo -e "  ${GREEN}3.${PLAIN} 安装/管理 VLESS Reality"
    echo -e "  ${GREEN}4.${PLAIN} 安装/管理 VLESS Encryption (Post-Quantum)"
    echo -e "  ${YELLOW}5.${PLAIN} Xray 服务端分流配置 (Routing)"
    echo -e "  ${RED}6.${PLAIN} 卸载 Xray 及相关文件"
    echo -e "  ${CYAN}7.${PLAIN} 还原 Xray 配置 (Restore)"
    echo "-------------------------------------------------"
    echo -e "  ${CYAN}8.${PLAIN} 更新此管理脚本"
    echo -e "  ${CYAN}0.${PLAIN} 退出脚本"
    echo -e "${CYAN}=================================================${PLAIN}"
    
    read -rp " 请输入选项 [0-7]: " choice
    
    case "$choice" in
        1) pull_and_run "update_geo.sh" "更新 GeoIP/GeoSite" ;;
        2) pull_and_run "install_ss2022.sh" "执行 SS2022 安装向导" ;;
        3) pull_and_run "install_vless_reality.sh" "执行 VLESS Reality 安装向导" ;;
        4) pull_and_run "install_vless_encryption.sh" "执行 VLESS Encryption 安装向导" ;;
        5) pull_and_run "xray_routing.sh" "进入分流配置工具" ;;
        6) pull_and_run "uninstall_xray.sh" "执行卸载程序" ;;
        7) pull_and_run "xray_restore.sh" "执行配置还原工具" ;;
        8) update_self ;;
        0) echo -e "${GREEN}感谢使用此脚本，再见！${PLAIN}"; exit 0 ;;
        *) echo -e "${RED}无效输入，请重新选择。${PLAIN}"; sleep 1 ;;
    esac
}

# --- 入口逻辑 ---
main() {
    check_root
    check_deps
    install_self
    
    while true; do
        show_menu
    done
}

main "$@"
