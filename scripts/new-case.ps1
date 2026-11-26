# =====================================================================
# new-case.ps1 - scaffold an incident case folder (Windows / PowerShell)
#
#   .\scripts\new-case.ps1 -Name phish-finance-0425
#   .\scripts\new-case.ps1 -Name ransomware-fs01 -Root D:\IR\cases -Severity SEV1
#
# Creates <Root>\<YYYY-MM-DD>-<slug>\ with:
#   notes.md  timeline.csv  iocs.csv  evidence-log.csv  actions.md  report.md  evidence\
# Default Root: .\cases (relative to the current directory).
# Never overwrites an existing case folder.
# =====================================================================
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $Name,
    [string] $Root = (Join-Path (Get-Location) 'cases'),
    [ValidateSet('SEV1', 'SEV2', 'SEV3', 'SEV4')] [string] $Severity = 'SEV3',
    [string] $Analyst = $env:USERNAME
)

$ErrorActionPreference = 'Stop'

$slug = ($Name.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')
if (-not $slug) { throw "Name '$Name' has no usable characters." }

$nowUtc = (Get-Date).ToUniversalTime()
$date   = $nowUtc.ToString('yyyy-MM-dd')
$stamp  = $nowUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
$caseId = "$date-$slug"
$dir    = Join-Path $Root $caseId

if (Test-Path $dir) { throw "Case folder already exists: $dir" }
New-Item -ItemType Directory -Force -Path (Join-Path $dir 'evidence') | Out-Null

$utf8 = New-Object System.Text.UTF8Encoding($false)
function Write-CaseFile([string] $file, [string] $text) {
    [System.IO.File]::WriteAllText((Join-Path $dir $file), $text.Replace("`r`n", "`n"), $utf8)
}

Write-CaseFile 'timeline.csv'     "timestamp_utc,host,source,event,detail,analyst,confidence`n"
Write-CaseFile 'iocs.csv'         "type,value_defanged,first_seen_utc,last_seen_utc,source,confidence,tlp,notes`n"
Write-CaseFile 'evidence-log.csv' "item_id,description,source_host,acquired_utc,acquired_by,method,sha256,storage_location,notes`n"

Write-CaseFile 'notes.md' @"
# Case $caseId

| Field | Value |
|---|---|
| Opened (UTC) | $stamp |
| Opened by | $Analyst |
| Severity | $Severity |
| Status | Open - Identification |
| Incident commander | |
| TLP | AMBER |

## Summary (one paragraph, keep current)

## Scope
- Affected hosts:
- Affected identities:
- Affected data:

## Hypotheses
| # | Hypothesis | Evidence for | Evidence against | Status |
|---|---|---|---|---|

## Working notes (newest at the bottom, UTC timestamps)
- $stamp - case opened
"@

Write-CaseFile 'actions.md' @"
# Actions & decisions - $caseId

Every containment / eradication action needs an approver before it runs.

| Time (UTC) | Action | Target | Blast radius | Approved by | Executed by | Result | Reversible? |
|---|---|---|---|---|---|---|---|

## Decisions
| Time (UTC) | Decision | Made by | Rationale |
|---|---|---|---|
"@

Write-CaseFile 'report.md' @"
# Incident report - $caseId

> Draft. Fill with ``/report`` once the timeline and scope are stable.

## Executive summary
## Impact
## Timeline (UTC)
## Root cause & initial access
## Scope
## Actions taken
## Recommendations (owner, due date)
## Appendix A - IOCs
## Appendix B - ATT&CK mapping
"@

Write-Host "Case created: $dir"
