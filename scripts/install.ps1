# =====================================================================
# install.ps1 - copy-install claude-blueteam into Claude Code (Windows)
#
#   pwsh ./scripts/install.ps1             # skills + commands + agents -> ~\.claude\
#   pwsh ./scripts/install.ps1 -Uninstall  # remove what this script installed
#
# Prefer the plugin install when you can:
#   /plugin marketplace add Bizaza-devs/Claude-BlueTeam
#   /plugin install claude-blueteam@bizaza-devs
#
# Existing items with the same name are backed up to
# ~\.claude\install-backups\claude-blueteam-<timestamp>\ (outside the loading path).
# A manifest of installed items is kept in ~\.claude\.skill-manifests\claude-blueteam.txt
# =====================================================================
[CmdletBinding()]
param([switch] $Uninstall)

$ErrorActionPreference = 'Stop'
$repo     = Split-Path -Parent $PSScriptRoot
$claude   = Join-Path $HOME '.claude'
$manDir   = Join-Path $claude '.skill-manifests'
$manifest = Join-Path $manDir 'claude-blueteam.txt'

if ($Uninstall) {
    if (-not (Test-Path $manifest)) { Write-Host 'Nothing to uninstall (no manifest).'; return }
    foreach ($rel in Get-Content $manifest) {
        $p = Join-Path $claude $rel
        if (Test-Path $p) { Remove-Item -Recurse -Force $p; Write-Host "removed $rel" }
    }
    Remove-Item -Force $manifest
    Write-Host 'claude-blueteam uninstalled.'
    return
}

$ts     = Get-Date -Format 'yyyyMMdd-HHmmss'
$backup = Join-Path $claude "install-backups\claude-blueteam-$ts"
$installed = New-Object System.Collections.Generic.List[string]

function Install-Item([string] $src, [string] $rel) {
    $dest = Join-Path $claude $rel
    if (Test-Path $dest) {
        $b = Join-Path $backup $rel
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $b) | Out-Null
        Move-Item -Force $dest $b
    }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null
    Copy-Item -Recurse -Force $src $dest
    $installed.Add($rel)
}

Get-ChildItem -Directory (Join-Path $repo 'skills') | ForEach-Object {
    Install-Item $_.FullName ("skills\" + $_.Name)
}
foreach ($kind in 'commands', 'agents') {
    Get-ChildItem -File (Join-Path $repo $kind) -Filter *.md | ForEach-Object {
        Install-Item $_.FullName ("$kind\" + $_.Name)
    }
}
Install-Item (Join-Path $repo 'scripts\new-case.ps1') 'scripts\claude-blueteam\new-case.ps1'
Install-Item (Join-Path $repo 'scripts\new-case.sh')  'scripts\claude-blueteam\new-case.sh'

New-Item -ItemType Directory -Force -Path $manDir | Out-Null
$installed | Set-Content -Encoding utf8 $manifest

Write-Host ("Installed {0} items into {1}" -f $installed.Count, $claude)
if (Test-Path $backup) { Write-Host "Backups of replaced items: $backup" }
Write-Host 'Restart Claude Code, then try: /triage  /ir  /hunt  /detect'
