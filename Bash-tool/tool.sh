#!/usr/bin/env bash
# =============================================================
# Tool Name : FIM - File Integrity Checker (Bash)
# Purpose   : Create a SHA-256 baseline of a directory and later
#             verify it to detect modified, new, or deleted files.
# Usage     : ./tool.sh -h
# =============================================================

set -u

VERSION="1.0"

# ---------- Colors (disabled if output is not a terminal) ----------
if [[ -t 1 ]]; then
    RED=$'\e[31m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; BLUE=$'\e[34m'; RESET=$'\e[0m'
else
    RED=""; GREEN=""; YELLOW=""; BLUE=""; RESET=""
fi

# ---------- Help / usage ----------
usage() {
    cat <<EOF
File Integrity Checker v$VERSION

Usage:
  $0 -c <directory> -b <baseline_file>   Create a baseline
  $0 -v <directory> -b <baseline_file>   Verify against a baseline
  $0 -h                                  Show this help

Options:
  -c <dir>    Create baseline of all files in <dir> (recursive)
  -v <dir>    Verify <dir> against an existing baseline
  -b <file>   Baseline file path (default: baseline.sha256)
  -h          Show this help message

Examples:
  $0 -c /etc/ssh -b ssh.baseline
  $0 -v /etc/ssh -b ssh.baseline
EOF
}

# ---------- Helper: print error and exit ----------
die() {
    echo "${RED}[ERROR]${RESET} $1" >&2
    exit "${2:-1}"
}

# ---------- Check required commands exist ----------
check_dependencies() {
    command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found. Install coreutils."
    command -v find >/dev/null 2>&1 || die "find not found."
}

# ---------- Create baseline ----------
create_baseline() {
    local dir="$1" baseline="$2"
    [[ -d "$dir" ]] || die "Directory '$dir' does not exist."
    [[ -r "$dir" ]] || die "Directory '$dir' is not readable."

    echo "${BLUE}[*]${RESET} Creating baseline for: $dir"
    # Hash every regular file; unreadable files are skipped with a warning
    : > "$baseline" 2>/dev/null || die "Cannot write baseline file '$baseline'."
    local count=0 skipped=0
    while IFS= read -r -d '' f; do
        if [[ -r "$f" ]]; then
            sha256sum "$f" >> "$baseline"
            ((count++))
        else
            echo "${YELLOW}[WARN]${RESET} Skipped unreadable file: $f"
            ((skipped++))
        fi
    done < <(find "$dir" -type f -print0 | sort -z)

    echo "${GREEN}[+]${RESET} Baseline saved to '$baseline'"
    echo "    Files hashed : $count"
    echo "    Files skipped: $skipped"
}

# ---------- Verify against baseline ----------
verify_baseline() {
    local dir="$1" baseline="$2"
    [[ -d "$dir" ]] || die "Directory '$dir' does not exist."
    [[ -f "$baseline" ]] || die "Baseline file '$baseline' not found. Create one with -c."

    echo "${BLUE}[*]${RESET} Verifying '$dir' against '$baseline'"
    echo "----------------------------------------------"

    local modified=0 deleted=0 added=0 ok=0
    declare -A known

    # Check files recorded in the baseline
    while read -r hash path; do
        [[ -z "$hash" ]] && continue
        known["$path"]=1
        if [[ ! -f "$path" ]]; then
            echo "${RED}[DELETED ]${RESET} $path"
            ((deleted++))
        else
            current=$(sha256sum "$path" 2>/dev/null | awk '{print $1}')
            if [[ "$current" != "$hash" ]]; then
                echo "${RED}[MODIFIED]${RESET} $path"
                ((modified++))
            else
                ((ok++))
            fi
        fi
    done < "$baseline"

    # Look for new files not present in the baseline
    while IFS= read -r -d '' f; do
        if [[ -z "${known[$f]:-}" ]]; then
            echo "${YELLOW}[NEW     ]${RESET} $f"
            ((added++))
        fi
    done < <(find "$dir" -type f -print0)

    echo "----------------------------------------------"
    echo "Unchanged: $ok | Modified: $modified | Deleted: $deleted | New: $added"

    if (( modified + deleted + added == 0 )); then
        echo "${GREEN}[OK]${RESET} Integrity verified. No changes detected."
        exit 0
    else
        echo "${RED}[ALERT]${RESET} Changes detected!"
        exit 2
    fi
}

# ---------- Main: parse arguments ----------
main() {
    local mode="" dir="" baseline="baseline.sha256"

    [[ $# -eq 0 ]] && { usage; exit 1; }

    while getopts ":c:v:b:h" opt; do
        case "$opt" in
            c) mode="create"; dir="$OPTARG" ;;
            v) mode="verify"; dir="$OPTARG" ;;
            b) baseline="$OPTARG" ;;
            h) usage; exit 0 ;;
            :) die "Option -$OPTARG requires an argument." ;;
            \?) die "Invalid option: -$OPTARG (use -h for help)" ;;
        esac
    done

    [[ -z "$mode" ]] && die "Specify -c (create) or -v (verify). Use -h for help."

    check_dependencies

    case "$mode" in
        create) create_baseline "$dir" "$baseline" ;;
        verify) verify_baseline "$dir" "$baseline" ;;
    esac
}

main "$@"
