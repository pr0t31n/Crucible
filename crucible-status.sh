#!/usr/bin/env bash
# crucible-status.sh — CLI engagement summary for Crucible v2
# Usage: ./crucible-status.sh [PROJECT_ID]
#   If no PROJECT_ID given, lists all projects and lets you pick one.

set -euo pipefail
PORT="${CRUCIBLE_PORT:-5100}"
BASE="http://localhost:${PORT}"
BOLD='\033[1m'
DIM='\033[2m'
RED='\033[0;31m'
YEL='\033[0;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
MAG='\033[0;35m'
WHT='\033[0;37m'
RST='\033[0m'

_risk_color() {
    case "$1" in
        CRITICAL) echo -ne "$RED" ;;
        HIGH)     echo -ne "$YEL" ;;
        MEDIUM)   echo -ne "$MAG" ;;
        LOW)      echo -ne "$CYN" ;;
        INFO)     echo -ne "$DIM" ;;
        *)        echo -ne "$RST" ;;
    esac
}

_status_color() {
    case "$1" in
        running)  echo -ne "$GRN" ;;
        complete) echo -ne "$CYN" ;;
        failed)   echo -ne "$RED" ;;
        idle)     echo -ne "$DIM" ;;
        *)        echo -ne "$RST" ;;
    esac
}

if ! command -v jq &>/dev/null; then
    echo "Error: jq is required. Install with: apt install jq" >&2
    exit 1
fi

if ! curl -sf "${BASE}/api/health" &>/dev/null; then
    echo "Error: Crucible is not reachable at ${BASE}" >&2
    exit 1
fi

PID="${1:-}"

if [ -z "$PID" ]; then
    echo -e "${BOLD}Available Projects${RST}"
    echo "─────────────────────────────────────────────────────────"
    PROJECTS=$(curl -sf "${BASE}/api/projects")
    echo "$PROJECTS" | jq -r '.projects[] | "\(.id)  \(.client_name // "—")  \(.name // "—")"' | while read -r line; do
        echo "  $line"
    done
    echo ""
    echo -e "${DIM}Usage: $0 <PROJECT_ID>${RST}"
    exit 0
fi

DATA=$(curl -sf "${BASE}/api/engagement-summary/${PID}")
if [ -z "$DATA" ] || echo "$DATA" | jq -e '.error' &>/dev/null; then
    echo "Error: Could not load project ${PID}" >&2
    exit 1
fi

CLIENT=$(echo "$DATA" | jq -r '.client // "—"')
ENGAGEMENT=$(echo "$DATA" | jq -r '.engagement // "—"')
TOTAL=$(echo "$DATA" | jq -r '.findings.total')

echo ""
echo -e "${BOLD}Crucible Engagement Summary${RST}"
echo "═══════════════════════════════════════════════════════════"
echo -e "  Client:     ${BOLD}${CLIENT}${RST}"
echo -e "  Engagement: ${BOLD}${ENGAGEMENT}${RST}"
echo -e "  Project ID: ${DIM}${PID}${RST}"
echo ""

echo -e "${BOLD}Scopes${RST}"
echo "───────────────────────────────────────────────────────────"
echo "$DATA" | jq -r '.scopes | to_entries[] | .key' | while read -r scope; do
    STATUS=$(echo "$DATA" | jq -r ".scopes.\"${scope}\".status")
    _status_color "$STATUS"
    printf "  %-16s %s\n" "$scope" "[$STATUS]"
    echo -ne "$RST"

    echo "$DATA" | jq -r ".scopes.\"${scope}\".tools | to_entries[] | \"\(.value.name)|\(.value.status)\"" | while IFS='|' read -r tname tstatus; do
        _status_color "$tstatus"
        printf "    %-20s %s\n" "$tname" "$tstatus"
        echo -ne "$RST"
    done
done
echo ""

echo -e "${BOLD}Findings${RST}  (${TOTAL} total)"
echo "───────────────────────────────────────────────────────────"
for risk in CRITICAL HIGH MEDIUM LOW INFO; do
    COUNT=$(echo "$DATA" | jq -r ".findings.by_risk.${risk}")
    if [ "$COUNT" -gt 0 ]; then
        _risk_color "$risk"
        printf "  %-12s %s\n" "$risk" "$COUNT"
        echo -ne "$RST"
    else
        echo -e "  ${DIM}${risk}$(printf '%*s' $((12 - ${#risk})) '')${COUNT}${RST}"
    fi
done
echo ""
