#!/bin/bash
# shadowbridge_motd.sh — ShadowBridge Terminal Banner
#
# Source ezt a .bashrc-ben:
#   source /opt/shadowbridge/shadowbridge_motd.sh
#
# Gép szerepe (env var vagy auto-detect):
#   SHADOW_ROLE=server|attack|monitor|assistant|mesh
#
# Példa .bashrc hozzáadás:
#   export SHADOW_ROLE=server
#   source /opt/shadowbridge/shadowbridge_motd.sh

# ── Színek ────────────────────────────────────────────────────────────────────
_C_RED='\033[0;31m'
_C_GRN='\033[0;32m'
_C_YLW='\033[0;33m'
_C_CYN='\033[0;36m'
_C_MAG='\033[0;35m'
_C_BLD='\033[1m'
_C_DIM='\033[2m'
_C_RST='\033[0m'

# ── Terminál szélesség ────────────────────────────────────────────────────────
_COLS=$(tput cols 2>/dev/null || echo 80)

_line() {
    # Teljes szélességű vonal adott karakterrel
    local char="${1:─}"
    local color="${2:-$_C_RED}"
    printf "${color}"
    printf '%*s' "$_COLS" '' | tr ' ' "$char"
    printf "${_C_RST}\n"
}

_center() {
    local text="$1"
    local color="${2:-$_C_GRN}"
    local clean="${text//$'\033'[*m/}"   # ANSI strip a hosszhoz
    local textlen=${#clean}
    local pad=$(( (_COLS - textlen) / 2 ))
    printf "%*s${color}%s${_C_RST}\n" "$pad" "" "$text"
}

# ── Szerepkör detektálás ──────────────────────────────────────────────────────
_detect_role() {
    if [[ -n "${SHADOW_ROLE:-}" ]]; then
        echo "$SHADOW_ROLE"
        return
    fi
    local h
    h=$(hostname -s 2>/dev/null | tr '[:upper:]' '[:lower:]')
    case "$h" in
        *attack*)  echo "attack"    ;;
        *monitor*) echo "monitor"   ;;
        *assist*)  echo "assistant" ;;
        *mesh*)    echo "mesh"      ;;
        *)         echo "server"    ;;
    esac
}

_role_label() {
    case "$1" in
        attack)    echo "⚔  ATTACK NODE"   ;;
        monitor)   echo "📡  MONITOR"       ;;
        assistant) echo "🤖  AI ASSISTANT"  ;;
        mesh)      echo "🕸  MESH NODE"     ;;
        *)         echo "🖥  SERVER"        ;;
    esac
}

_role_color() {
    case "$1" in
        attack)    echo "$_C_RED"  ;;
        monitor)   echo "$_C_CYN"  ;;
        assistant) echo "$_C_MAG"  ;;
        mesh)      echo "$_C_YLW"  ;;
        *)         echo "$_C_GRN"  ;;
    esac
}

# ── Státusz ellenőrzések ──────────────────────────────────────────────────────
_svc_status() {
    local svc="$1"
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo -e "${_C_GRN}● ONLINE${_C_RST}"
    else
        echo -e "${_C_RED}○ OFFLINE${_C_RST}"
    fi
}

_ollama_status() {
    if curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
        local models
        models=$(curl -sf http://localhost:11434/api/tags | python3 -c \
            "import json,sys; d=json.load(sys.stdin); print(len(d.get('models',[])))" 2>/dev/null || echo "?")
        echo -e "${_C_GRN}● ONLINE${_C_RST} ${_C_DIM}(${models} model)${_C_RST}"
    else
        echo -e "${_C_RED}○ OFFLINE${_C_RST}"
    fi
}

# ── ASCII Banner (dinamikus szélesség) ────────────────────────────────────────
_print_banner() {
    local role="$1"
    local rcolor
    rcolor=$(_role_color "$role")

    # figlet ha van, fallback ha nincs
    if command -v figlet &>/dev/null; then
        local font="banner"
        command -v toilet &>/dev/null && font="term"
        local art
        art=$(figlet -w "$_COLS" -f "$font" "ShadowBridge" 2>/dev/null \
              || figlet -w "$_COLS" "ShadowBridge" 2>/dev/null)
        while IFS= read -r artline; do
            printf "${rcolor}%s${_C_RST}\n" "$artline"
        done <<< "$art"
    else
        # Fallback: szöveges banner teljes szélességgel
        _line "═" "$rcolor"
        _center "S H A D O W B R I D G E" "$rcolor"
        _line "═" "$rcolor"
    fi
}

# ── Fő banner megjelenítő ─────────────────────────────────────────────────────
shadowbridge_banner() {
    local role
    role=$(_detect_role)
    local rcolor
    rcolor=$(_role_color "$role")
    local rlabel
    rlabel=$(_role_label "$role")

    clear

    # Banner
    _print_banner "$role"

    # Vonal
    _line "─" "$rcolor"

    # Szerepkör + mottó (centred)
    _center "${_C_BLD}${rlabel}${_C_RST}" "$rcolor"
    _center "${_C_DIM}[ ShadowBridge Secure Infrastructure ]${_C_RST}" "$_C_DIM"

    _line "─" "$rcolor"
    echo ""

    # Gép infó — 2 oszlopban ha elég széles
    local agent kernel date_str uptime_str ip_str
    agent=$(whoami)@$(hostname -s)
    kernel=$(uname -r)
    date_str=$(date '+%Y-%m-%d %H:%M:%S')
    uptime_str=$(uptime -p 2>/dev/null | sed 's/up //')
    ip_str=$(hostname -I 2>/dev/null | awk '{print $1}')

    printf "  ${rcolor}%-10s${_C_RST}: ${_C_BLD}%s${_C_RST}\n" "NODE"   "$agent"
    printf "  ${rcolor}%-10s${_C_RST}: %s\n"                    "KERNEL" "$kernel"
    printf "  ${rcolor}%-10s${_C_RST}: %s\n"                    "DATE"   "$date_str"
    printf "  ${rcolor}%-10s${_C_RST}: %s\n"                    "UPTIME" "$uptime_str"
    printf "  ${rcolor}%-10s${_C_RST}: %s\n"                    "IP"     "$ip_str"
    echo ""

    # Szerepkör-specifikus státuszok
    _line "─" "$rcolor"
    case "$role" in
        server)
            printf "  ${rcolor}%-10s${_C_RST}: %b\n" "AGENT"    "$(_svc_status shadowbridge-agent)"
            printf "  ${rcolor}%-10s${_C_RST}: %b\n" "MESH"     "$(_svc_status shadowmesh)"
            printf "  ${rcolor}%-10s${_C_RST}: %b\n" "HONEYPOT" "$(_svc_status shadowbridge-honeypot)"
            ;;
        attack)
            printf "  ${rcolor}%-10s${_C_RST}: %b\n" "NOX AGENT" "$(_svc_status nox-attack-agent)"
            printf "  ${rcolor}%-10s${_C_RST}: %b\n" "OLLAMA"    "$(_ollama_status)"
            printf "  ${rcolor}%-10s${_C_RST}: %b\n" "MESH"      "$(_svc_status shadowmesh)"
            ;;
        monitor)
            printf "  ${rcolor}%-10s${_C_RST}: %b\n" "DASHBOARD" "$(_svc_status nox-dashboard)"
            printf "  ${rcolor}%-10s${_C_RST}: %b\n" "MESH"      "$(_svc_status shadowmesh)"
            ;;
        assistant)
            printf "  ${rcolor}%-10s${_C_RST}: %b\n" "OLLAMA"  "$(_ollama_status)"
            printf "  ${rcolor}%-10s${_C_RST}: %b\n" "AGENT"   "$(_svc_status shadowbridge-agent)"
            ;;
        mesh)
            printf "  ${rcolor}%-10s${_C_RST}: %b\n" "MESH"    "$(_svc_status shadowmesh)"
            printf "  ${rcolor}%-10s${_C_RST}: %b\n" "TOR"     "$(_svc_status tor)"
            ;;
    esac
    _line "─" "$rcolor"
    echo ""
}

# ── Prompt beállítás ──────────────────────────────────────────────────────────
_set_prompt() {
    local role
    role=$(_detect_role)
    local rcolor
    rcolor=$(_role_color "$role")
    local rlabel
    rlabel=$(_role_label "$role" | sed 's/[^A-Z ]//g' | xargs)  # csak szöveg

    # Kétszintű prompt (mint az X-FILES-nél)
    PS1="\[${rcolor}\][SB·${rlabel}]\[${_C_RST}\]}\[${_C_YLW}\]]\[${_C_RST}\]}-\[\033[38;5;39m\][\[${_C_BLD}\]\u\[${_C_RST}\]\[\033[38;5;39m\]@\[\033[38;5;39m\]\h\[${_C_RST}\]]-[\[${_C_CYN}\]\w\[${_C_RST}\]]\n\[${rcolor}\][>]\[${_C_RST}\]\\$ "
}

# ── Futtatás ──────────────────────────────────────────────────────────────────
# Csak interaktív shellben jelenítse meg
if [[ $- == *i* ]]; then
    shadowbridge_banner
    _set_prompt
fi
