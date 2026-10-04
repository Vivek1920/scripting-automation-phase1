# File Integrity Checker (Bash)

## Objective
Detect unauthorized or accidental changes to files by comparing SHA-256 hashes against a saved baseline. File integrity monitoring is a core defensive security technique.

## Features
- Creates a SHA-256 baseline of every file in a directory (recursive)
- Verifies a directory against the baseline
- Reports **MODIFIED**, **DELETED**, and **NEW** files
- Colored output (auto-disabled when piped)
- Exit codes: `0` = clean, `2` = changes detected, `1` = error
- Basic error handling (missing directory, missing baseline, unreadable files, invalid options)
- Built-in help (`-h`)

## Requirements
- Linux / macOS / WSL with Bash 4+ (uses associative arrays)
- `sha256sum`, `find`, `awk` (standard coreutils)

## How to Run
```bash
chmod +x tool.sh
./tool.sh -h
```

| Option | Description |
|--------|-------------|
| `-c <dir>` | Create a baseline for `<dir>` |
| `-v <dir>` | Verify `<dir>` against the baseline |
| `-b <file>` | Baseline file (default `baseline.sha256`) |
| `-h` | Show help |

## Example Usage
```bash
./tool.sh -c /etc/ssh -b ssh.baseline    # create baseline
./tool.sh -v /etc/ssh -b ssh.baseline    # verify later
```

## Example Output
```
$ ./tool.sh -c d -b base.sha
[*] Creating baseline for: d
[+] Baseline saved to 'base.sha'
    Files hashed : 2
    Files skipped: 0

$ ./tool.sh -v d -b base.sha
[*] Verifying 'd' against 'base.sha'
----------------------------------------------
[MODIFIED] d/a.txt
[DELETED ] d/b.txt
[NEW     ] d/c.txt
----------------------------------------------
Unchanged: 0 | Modified: 1 | Deleted: 1 | New: 1
[ALERT] Changes detected!
```

Screenshots are in the `screenshots/` folder.

## Challenges Faced
- Handling filenames with spaces/special characters (solved with `find -print0` and `read -d ''`)
- Detecting *new* files, not just changed ones (solved with an associative array of known paths)
- Making colors work in both terminals and piped output

## Future Improvements
- Support excluding paths/patterns
- Store hashes with timestamps and file permissions
- Email/log alerts and scheduled runs via cron
- Optional SHA-512 / algorithm selection
