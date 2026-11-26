#!/usr/bin/env bash
# =====================================================================
# new-case.sh - scaffold an incident case folder (macOS / Linux / Git Bash)
#
#   scripts/new-case.sh phish-finance-0425
#   CASE_ROOT=/srv/ir/cases SEVERITY=SEV1 scripts/new-case.sh ransomware-fs01
#
# Creates $CASE_ROOT/<YYYY-MM-DD>-<slug>/ (default ./cases) with:
#   notes.md  timeline.csv  iocs.csv  evidence-log.csv  actions.md  report.md  evidence/
# Never overwrites an existing case folder.
# =====================================================================
set -euo pipefail

if [ $# -lt 1 ] || [ -z "${1:-}" ]; then
  echo "usage: $0 <case-name>" >&2
  exit 2
fi

slug=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//')
[ -n "$slug" ] || { echo "case name has no usable characters" >&2; exit 2; }

root="${CASE_ROOT:-$(pwd)/cases}"
severity="${SEVERITY:-SEV3}"
analyst="${ANALYST:-${USER:-${USERNAME:-unknown}}}"
date_utc=$(date -u +%Y-%m-%d)
stamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
case_id="$date_utc-$slug"
dir="$root/$case_id"

if [ -e "$dir" ]; then echo "case folder already exists: $dir" >&2; exit 1; fi
mkdir -p "$dir/evidence"

printf 'timestamp_utc,host,source,event,detail,analyst,confidence\n' > "$dir/timeline.csv"
printf 'type,value_defanged,first_seen_utc,last_seen_utc,source,confidence,tlp,notes\n' > "$dir/iocs.csv"
printf 'item_id,description,source_host,acquired_utc,acquired_by,method,sha256,storage_location,notes\n' > "$dir/evidence-log.csv"

cat > "$dir/notes.md" <<EOF
# Case $case_id

| Field | Value |
|---|---|
| Opened (UTC) | $stamp |
| Opened by | $analyst |
| Severity | $severity |
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
EOF

cat > "$dir/actions.md" <<EOF
# Actions & decisions - $case_id

Every containment / eradication action needs an approver before it runs.

| Time (UTC) | Action | Target | Blast radius | Approved by | Executed by | Result | Reversible? |
|---|---|---|---|---|---|---|---|

## Decisions
| Time (UTC) | Decision | Made by | Rationale |
|---|---|---|---|
EOF

cat > "$dir/report.md" <<EOF
# Incident report - $case_id

> Draft. Fill with \`/report\` once the timeline and scope are stable.

## Executive summary
## Impact
## Timeline (UTC)
## Root cause & initial access
## Scope
## Actions taken
## Recommendations (owner, due date)
## Appendix A - IOCs
## Appendix B - ATT&CK mapping
EOF

echo "Case created: $dir"
