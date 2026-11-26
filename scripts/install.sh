#!/usr/bin/env bash
# =====================================================================
# install.sh - copy-install claude-blueteam into Claude Code (macOS / Linux)
#
#   bash scripts/install.sh              # skills + commands + agents -> ~/.claude/
#   bash scripts/install.sh --uninstall  # remove what this script installed
#
# Prefer the plugin install when you can:
#   /plugin marketplace add Bizaza-devs/Claude-BlueTeam
#   /plugin install claude-blueteam@bizaza-devs
# =====================================================================
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
claude="${CLAUDE_HOME:-$HOME/.claude}"
mandir="$claude/.skill-manifests"
manifest="$mandir/claude-blueteam.txt"

if [ "${1:-}" = "--uninstall" ]; then
  [ -f "$manifest" ] || { echo "Nothing to uninstall (no manifest)."; exit 0; }
  while IFS= read -r rel; do
    [ -n "$rel" ] && [ -e "$claude/$rel" ] && rm -rf "${claude:?}/$rel" && echo "removed $rel"
  done < "$manifest"
  rm -f "$manifest"
  echo "claude-blueteam uninstalled."
  exit 0
fi

backup="$claude/install-backups/claude-blueteam-$(date +%Y%m%d-%H%M%S)"
tmp_manifest="$(mktemp)"

install_item() {  # $1 = source, $2 = path relative to ~/.claude
  local dest="$claude/$2"
  if [ -e "$dest" ]; then
    mkdir -p "$(dirname "$backup/$2")"
    mv "$dest" "$backup/$2"
  fi
  mkdir -p "$(dirname "$dest")"
  cp -R "$1" "$dest"
  echo "$2" >> "$tmp_manifest"
}

for d in "$repo"/skills/*/; do
  name="$(basename "$d")"
  install_item "${d%/}" "skills/$name"
done
for kind in commands agents; do
  for f in "$repo/$kind"/*.md; do
    [ -e "$f" ] && install_item "$f" "$kind/$(basename "$f")"
  done
done
install_item "$repo/scripts/new-case.sh"  "scripts/claude-blueteam/new-case.sh"
install_item "$repo/scripts/new-case.ps1" "scripts/claude-blueteam/new-case.ps1"
chmod +x "$claude/scripts/claude-blueteam/new-case.sh"

mkdir -p "$mandir"
mv "$tmp_manifest" "$manifest"
echo "Installed $(wc -l < "$manifest" | tr -d ' ') items into $claude"
[ -d "$backup" ] && echo "Backups of replaced items: $backup"
echo "Restart Claude Code, then try: /triage  /ir  /hunt  /detect"
