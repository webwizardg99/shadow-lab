#!/bin/bash
# github_tools_manager.sh — GitHub-alapú eszközök kezelője az attack node-on
#
# Futtatandó AZ ATTACK GÉPEN (nem a deploy gépről):
#   bash github_tools_manager.sh install <repo_url>   # új tool hozzáadása
#   bash github_tools_manager.sh update               # minden tool frissítése
#   bash github_tools_manager.sh list                 # telepített toolok listája
#   bash github_tools_manager.sh remove <name>        # eltávolítás
#
# Példák:
#   bash github_tools_manager.sh install https://github.com/webwizardg99/hexstrike-ai
#   bash github_tools_manager.sh update hexstrike-ai
#   bash github_tools_manager.sh list

set -euo pipefail

GITHUB_TOOLS_DIR="${GITHUB_TOOLS_DIR:-/opt/github-tools}"
REGISTRY_FILE="$GITHUB_TOOLS_DIR/.registry.json"

# ── Colour ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'
CYN='\033[0;36m'; BLD='\033[1m'; RST='\033[0m'
ok()   { echo -e "${GRN}[✓]${RST} $*"; }
warn() { echo -e "${YLW}[!]${RST} $*"; }
err()  { echo -e "${RED}[✗]${RST} $*"; exit 1; }
info() { echo -e "${CYN}[*]${RST} $*"; }

# ── Registry helpers ──────────────────────────────────────────────────────────
_reg_read() {
    [[ -f "$REGISTRY_FILE" ]] || echo '{"tools":[]}' > "$REGISTRY_FILE"
    cat "$REGISTRY_FILE"
}

_reg_add() {
    local name="$1" url="$2" path="$3"
    python3 - "$name" "$url" "$path" "$REGISTRY_FILE" << 'PYEOF'
import json, sys, time
name, url, path, reg = sys.argv[1:]
data = json.loads(open(reg).read())
data["tools"] = [t for t in data["tools"] if t["name"] != name]
data["tools"].append({"name": name, "url": url, "path": path, "installed": int(time.time())})
open(reg, "w").write(json.dumps(data, indent=2))
PYEOF
}

_reg_remove() {
    local name="$1"
    python3 - "$name" "$REGISTRY_FILE" << 'PYEOF'
import json, sys
name, reg = sys.argv[1:]
data = json.loads(open(reg).read())
data["tools"] = [t for t in data["tools"] if t["name"] != name]
open(reg, "w").write(json.dumps(data, indent=2))
PYEOF
}

# ── Install ───────────────────────────────────────────────────────────────────
cmd_install() {
    local repo_url="${1:?Megadandó: repo URL}"
    local name
    name=$(basename "$repo_url" .git)
    local dest="$GITHUB_TOOLS_DIR/$name"

    info "Telepítés: $name ($repo_url)"
    info "Cél: $dest"

    # Kategória választás
    echo ""
    echo "  Kategória: ai-tools / pentest / recon / exploit / wordlists / (enter = gyökér)"
    read -rp "  Kategória [enter=gyökér]: " category
    if [[ -n "$category" ]]; then
        dest="$GITHUB_TOOLS_DIR/$category/$name"
    fi

    # Clone vagy update
    if [[ -d "$dest" ]]; then
        warn "$name már létezik → frissítés"
        git -C "$dest" pull --ff-only
    else
        git clone "$repo_url" "$dest"
    fi

    # Auto-setup
    _auto_setup "$dest"

    # Registry
    _reg_add "$name" "$repo_url" "$dest"
    ok "Telepítve: $name → $dest"

    # Wrapper script
    _make_wrapper "$name" "$dest"
}

# ── Auto-setup (Python/Node/Go/Rust detekció) ─────────────────────────────────
_auto_setup() {
    local dir="$1"
    local name
    name=$(basename "$dir")

    info "Auto-setup futtatása ($name)..."

    cd "$dir"

    # Python
    if [[ -f requirements.txt ]] || [[ -f setup.py ]] || [[ -f pyproject.toml ]]; then
        info "Python projekt észlelve — venv létrehozása"
        python3 -m venv .venv
        # shellcheck disable=SC1091
        source .venv/bin/activate
        [[ -f requirements.txt ]] && pip install -q -r requirements.txt
        [[ -f setup.py ]]         && pip install -q -e . || true
        [[ -f pyproject.toml ]]   && pip install -q -e . || true
        # AI alap deps
        pip install -q anthropic openai requests httpx rich 2>/dev/null || true
        deactivate
        ok "Python venv kész: $dir/.venv"
    fi

    # Node.js
    if [[ -f package.json ]]; then
        info "Node.js projekt észlelve"
        if command -v npm &>/dev/null; then
            npm install --silent 2>/dev/null || true
            ok "npm install kész"
        else
            warn "npm nem található — kihagyva"
        fi
    fi

    # Go
    if [[ -f go.mod ]]; then
        info "Go projekt észlelve"
        if command -v go &>/dev/null; then
            go build ./... 2>/dev/null && ok "go build kész" || warn "go build hiba (kézzel ellenőrizd)"
        else
            warn "Go nem található"
        fi
    fi

    # Makefile
    if [[ -f Makefile ]] && ! [[ -f setup.py ]] && ! [[ -f go.mod ]]; then
        info "Makefile észlelve"
        make install 2>/dev/null || make build 2>/dev/null || true
    fi

    # README figyelmeztetés
    if [[ -f README.md ]]; then
        info "README.md elérhető: $dir/README.md"
    fi
}

# ── Wrapper script ────────────────────────────────────────────────────────────
_make_wrapper() {
    local name="$1"
    local dir="$2"

    # Megkeresi a belépési pontot
    local entry=""
    for f in main.py cli.py "${name}.py" __main__.py app.py run.py; do
        [[ -f "$dir/$f" ]] && entry="$f" && break
    done

    local wrapper="/usr/local/bin/$name"
    sudo tee "$wrapper" > /dev/null << WEOF
#!/bin/bash
# Auto-generated wrapper for $name
DIR="$dir"
SHADOWBRIDGE_URL="${DASHBOARD_URL:-http://100.75.31.41:8888}"

if [[ -d "\$DIR/.venv" ]]; then
    source "\$DIR/.venv/bin/activate"
fi

export SHADOWBRIDGE_URL
export ANTHROPIC_API_KEY="\${ANTHROPIC_API_KEY:-}"

WEOF

    if [[ -n "$entry" ]]; then
        echo "python3 \"\$DIR/$entry\" \"\$@\"" | sudo tee -a "$wrapper" > /dev/null
    elif [[ -f "$dir/package.json" ]]; then
        echo "cd \"\$DIR\" && node . \"\$@\"" | sudo tee -a "$wrapper" > /dev/null
    else
        echo "echo 'Nem találtam belépési pontot — futtasd manuálisan: cd $dir'" \
            | sudo tee -a "$wrapper" > /dev/null
    fi

    sudo chmod +x "$wrapper"
    ok "Wrapper: $wrapper"
}

# ── Update ────────────────────────────────────────────────────────────────────
cmd_update() {
    local target="${1:-}"
    local reg
    reg=$(_reg_read)

    if [[ -n "$target" ]]; then
        local dir
        dir=$(echo "$reg" | python3 -c "
import json,sys
d=json.load(sys.stdin)
t=[x['path'] for x in d['tools'] if x['name']=='$target']
print(t[0] if t else '')
")
        [[ -z "$dir" ]] && err "Nem található: $target"
        info "Frissítés: $target"
        git -C "$dir" pull --ff-only
        _auto_setup "$dir"
        ok "Frissítve: $target"
    else
        info "Minden tool frissítése..."
        echo "$reg" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for t in d['tools']:
    print(t['path'])
" | while read -r path; do
            name=$(basename "$path")
            if [[ -d "$path/.git" ]]; then
                info "  → $name"
                git -C "$path" pull --ff-only 2>&1 | tail -1
                _auto_setup "$path" 2>/dev/null || true
            fi
        done
        ok "Minden tool frissítve"
    fi
}

# ── List ──────────────────────────────────────────────────────────────────────
cmd_list() {
    info "Telepített GitHub tools ($GITHUB_TOOLS_DIR):"
    echo ""

    # Könyvtárakból
    echo -e "  ${BLD}Kategóriák:${RST}"
    find "$GITHUB_TOOLS_DIR" -maxdepth 2 -name ".git" -type d | while read -r gitdir; do
        local repo_dir
        repo_dir=$(dirname "$gitdir")
        local name
        name=$(basename "$repo_dir")
        local url
        url=$(git -C "$repo_dir" remote get-url origin 2>/dev/null || echo "?")
        local branch
        branch=$(git -C "$repo_dir" branch --show-current 2>/dev/null || echo "?")
        local commits
        commits=$(git -C "$repo_dir" rev-list --count HEAD 2>/dev/null || echo "?")
        local rel_path="${repo_dir#$GITHUB_TOOLS_DIR/}"
        echo -e "  ${GRN}•${RST} ${BLD}${name}${RST}"
        echo -e "    path   : $repo_dir"
        echo -e "    url    : $url"
        echo -e "    branch : $branch  ($commits commits)"
        [[ -d "$repo_dir/.venv" ]] && echo -e "    venv   : ${GRN}✓${RST}" || true
        echo ""
    done

    echo -e "  ${BLD}Könyvtárstruktúra:${RST}"
    ls -la "$GITHUB_TOOLS_DIR/" 2>/dev/null || echo "  (üres)"
}

# ── Remove ────────────────────────────────────────────────────────────────────
cmd_remove() {
    local name="${1:?Megadandó: tool neve}"
    local reg
    reg=$(_reg_read)
    local dir
    dir=$(echo "$reg" | python3 -c "
import json,sys
d=json.load(sys.stdin)
t=[x['path'] for x in d['tools'] if x['name']=='$name']
print(t[0] if t else '')
")
    [[ -z "$dir" ]] && err "Nem található: $name"
    read -rp "Törli: $dir ? [y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { echo "Megszakítva."; exit 0; }
    rm -rf "$dir"
    _reg_remove "$name"
    sudo rm -f "/usr/local/bin/$name"
    ok "Törölve: $name"
}

# ── Sync hexstrike-ai (shortcut) ──────────────────────────────────────────────
cmd_sync_hexstrike() {
    info "hexstrike-ai szinkronizálása..."
    local dest="$GITHUB_TOOLS_DIR/hexstrike-ai"
    if [[ ! -d "$dest" ]]; then
        cmd_install "https://github.com/webwizardg99/hexstrike-ai"
    else
        git -C "$dest" pull --ff-only
        _auto_setup "$dest"
        ok "hexstrike-ai frissítve: $(git -C "$dest" log --oneline -1)"
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
CMD="${1:-list}"
shift || true

case "$CMD" in
    install)       cmd_install "$@" ;;
    update)        cmd_update  "$@" ;;
    list|ls)       cmd_list ;;
    remove|rm)     cmd_remove  "$@" ;;
    sync-hexstrike) cmd_sync_hexstrike ;;
    *)
        echo "Használat: $0 <install|update|list|remove|sync-hexstrike> [args]"
        echo ""
        echo "  install <url>     — GitHub repo klónozása + setup"
        echo "  update [name]     — frissítés (vagy minden)"
        echo "  list              — telepített toolok"
        echo "  remove <name>     — eltávolítás"
        echo "  sync-hexstrike    — hexstrike-ai gyors szinkron"
        exit 1
        ;;
esac
