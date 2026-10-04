#!/usr/bin/env python3
"""
Tool Name : Log Analyzer (Python)
Purpose   : Analyze SSH/auth logs to find failed logins, top attacking IPs,
            targeted usernames, and possible brute-force activity.
Usage     : python3 tool.py -h
"""

import argparse
import re
import sys
from collections import Counter

# Regex patterns for common sshd auth.log lines
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
INVALID_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
SUCCESS_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def read_log(path):
    """Read a log file and return its lines. Handles common errors."""
    try:
        with open(path, "r", errors="ignore") as f:
            return f.readlines()
    except FileNotFoundError:
        sys.exit(f"[ERROR] File not found: {path}")
    except PermissionError:
        sys.exit(f"[ERROR] Permission denied: {path} (try sudo)")
    except IsADirectoryError:
        sys.exit(f"[ERROR] '{path}' is a directory, not a file.")


def analyze(lines):
    """Parse log lines and return counters of interesting events."""
    failed_ips, failed_users, success = Counter(), Counter(), []
    for line in lines:
        m = FAILED_RE.search(line) or INVALID_RE.search(line)
        if m:
            failed_ips[m.group("ip")] += 1
            failed_users[m.group("user")] += 1
            continue
        s = SUCCESS_RE.search(line)
        if s:
            success.append((s.group("user"), s.group("ip")))
    return failed_ips, failed_users, success


def print_table(title, counter, top):
    """Print the top N items of a Counter as a simple table."""
    print(f"\n=== {title} ===")
    if not counter:
        print("  (none found)")
        return
    for item, count in counter.most_common(top):
        print(f"  {item:<25} {count}")


def detect_bruteforce(failed_ips, threshold):
    """Return IPs whose failed attempts meet or exceed the threshold."""
    return {ip: c for ip, c in failed_ips.items() if c >= threshold}


def save_report(path, failed_ips, failed_users, suspects, total):
    """Write a simple text report to disk."""
    try:
        with open(path, "w") as f:
            f.write(f"Total failed attempts: {total}\n\nTop IPs:\n")
            for ip, c in failed_ips.most_common(10):
                f.write(f"  {ip} - {c}\n")
            f.write("\nTop usernames:\n")
            for u, c in failed_users.most_common(10):
                f.write(f"  {u} - {c}\n")
            f.write("\nPossible brute-force IPs:\n")
            for ip, c in suspects.items():
                f.write(f"  {ip} - {c}\n")
        print(f"\n[+] Report saved to {path}")
    except OSError as e:
        print(f"[ERROR] Could not write report: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Log Analyzer - detect failed SSH logins and brute-force attempts"
    )
    parser.add_argument("logfile", help="Path to log file (e.g. /var/log/auth.log)")
    parser.add_argument("-t", "--threshold", type=int, default=5,
                        help="Failed attempts to flag an IP as suspicious (default: 5)")
    parser.add_argument("-n", "--top", type=int, default=5,
                        help="Number of top results to display (default: 5)")
    parser.add_argument("-o", "--output", help="Save report to this file")
    args = parser.parse_args()

    if args.threshold < 1 or args.top < 1:
        sys.exit("[ERROR] --threshold and --top must be positive numbers.")

    lines = read_log(args.logfile)
    failed_ips, failed_users, success = analyze(lines)
    total = sum(failed_ips.values())
    suspects = detect_bruteforce(failed_ips, args.threshold)

    print(f"[*] Analyzed {len(lines)} lines from {args.logfile}")
    print(f"[*] Total failed login attempts: {total}")
    print(f"[*] Successful logins: {len(success)}")

    print_table("Top Source IPs (failed)", failed_ips, args.top)
    print_table("Top Targeted Usernames", failed_users, args.top)

    print(f"\n=== Possible Brute-Force (>= {args.threshold} failures) ===")
    if suspects:
        for ip, c in sorted(suspects.items(), key=lambda x: -x[1]):
            print(f"  [!] {ip} - {c} failed attempts")
    else:
        print("  No suspicious IPs detected.")

    if args.output:
        save_report(args.output, failed_ips, failed_users, suspects, total)


if __name__ == "__main__":
    main()
