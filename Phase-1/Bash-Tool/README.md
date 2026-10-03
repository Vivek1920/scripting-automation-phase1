# Log Analyzer (Python)

## Objective
Parse SSH authentication logs (e.g. `/var/log/auth.log`) to identify failed logins, the most active source IPs, targeted usernames, and possible brute-force attacks.

## Features
- Extracts failed password and invalid-user attempts using regex
- Top attacking IPs and most targeted usernames
- Configurable brute-force threshold
- Counts successful logins
- Optional text report export
- Modular functions, error handling, and `--help`

## Requirements
- Python 3.6+
- No external libraries (standard library only)

## How to Run
```bash
python3 tool.py -h
python3 tool.py /var/log/auth.log
```

| Option | Description |
|--------|-------------|
| `logfile` | Path to the log file |
| `-t, --threshold N` | Failures needed to flag an IP (default 5) |
| `-n, --top N` | Number of top results shown (default 5) |
| `-o, --output FILE` | Save a report to FILE |

## Example Usage
```bash
python3 tool.py auth.log
python3 tool.py auth.log -t 3 -n 10 -o report.txt
sudo python3 tool.py /var/log/auth.log
```

## Example Output
```
[*] Analyzed 7 lines from auth.log
[*] Total failed login attempts: 6
[*] Successful logins: 1

=== Top Source IPs (failed) ===
  192.168.1.50              5
  10.0.0.7                  1

=== Top Targeted Usernames ===
  root                      3
  admin                     1
  test                      1
  ubuntu                    1

=== Possible Brute-Force (>= 5 failures) ===
  [!] 192.168.1.50 - 5 failed attempts
```

Screenshots are in the `screenshots/` folder.

## Challenges Faced
- Writing regex that matches both "Failed password" and "invalid user" log formats
- Handling missing files, permission errors, and directories gracefully
- Keeping logic split into small reusable functions

## Future Improvements
- Support more log formats (Apache, nginx, Windows events)
- GeoIP lookup of attacking IPs
- Time-window detection (e.g. 5 failures in 1 minute)
- CSV/JSON export and automatic IP blocklist generation
