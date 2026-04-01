# RULES
Current rule file is meant to help scanning for the AXIOS 1.14.1 and 0.30.4 vulnerabilities as well as the PLAIN-CRYPTO-JS malware package.
Also checks for active connections to `sfrclak.com` 

Feel free to extend it.


# vscan

`vscan.py` scans a directory tree for rule-matched files and also checks live network connections defined in a JSON rules file.

This tool has only been tested on macOS.

## Run

```bash
python3 vscan.py --rules vscan_rules.json --path ../
```

Options:

- `--path`: root directory to scan recursively
- `--rules`: JSON rules file
- `--threads`: worker thread count, default `3`
- `--match-timeout-seconds`: per file-rule text match timeout, default `15`

See the current CLI help with:

```bash
python3 vscan.py --help
```

## How It Works

- Only regular files are eligible for text scanning.
- A file is only queued if it matches at least one rule's `include_globs`.
- `exclude_globs` are optional and only apply after `include_globs` matched.
- Network checks are separate from file scanning and are evaluated from live `lsof -i` output.

## Rules File

The rules file must contain a top-level `rules` array.

Supported rule types:

- `text_pattern`
- `network_connection`
- `path_exists`

### `text_pattern`

Use this to search matching files with a regex pattern.

Required fields:

- `id`
- `type`
- `label`
- `pattern`
- `include_globs`

Optional fields:

- `exclude_globs`

Example:

```json
{
  "id": "package-lock-axios-version",
  "type": "text_pattern",
  "label": "axios 1.14.1 or 0.30.4 in package-lock.json",
  "pattern": "\"axios\"\\s*:\\s*\\{[\\s\\S]*?\"version\"\\s*:\\s*\"(?:1\\.14\\.1|0\\.30\\.4)\"",
  "include_globs": ["package-lock.json"],
  "exclude_globs": []
}
```

### `network_connection`

Use this to search active network connections from `lsof -i`.

Required fields:

- `id`
- `type`
- `label`
- `pattern`

Example:

```json
{
  "id": "network-sfrclak-ip-port",
  "type": "network_connection",
  "label": "active connection to 142.11.206.73:8000",
  "pattern": "142\\.11\\.206\\.73:8000"
}
```

### `path_exists`

Use this to check whether an exact filesystem path currently exists.

Required fields:

- `id`
- `type`
- `label`
- `target_path`

Example:

```json
{
  "id": "macos-act-cache-path",
  "type": "path_exists",
  "label": "filesystem path /Library/Caches/com.apple.act.mond exists",
  "target_path": "/Library/Caches/com.apple.act.mond"
}
```

## Output

The scanner prints:

- live progress in the terminal status line
- immediate `FOUND` records as matches are discovered
- a final summary with checked counts per rule

Sections are derived automatically from rule type:

- `text_pattern` -> `Package Files`
- `network_connection` -> `Active Network Connections`
- `path_exists` -> `Filesystem Paths`

## Current Example Rules

The bundled [vscan_rules.json](/Users/ivan/code/vscan/vscan_rules.json) currently checks:

- `package.json` for `axios 1.14.1` or `0.30.4`
- `package-lock.json` for `axios 1.14.1` or `0.30.4`
- `yarn.lock` for `axios 1.14.1` or `0.30.4`
- `bun.lock` for `axios 1.14.1` or `0.30.4`
- `bun.lock` for `plain-crypto-js`
- active connections to `sfrclak.com`
- active connections to `142.11.206.73:8000`
- filesystem path `/Library/Caches/com.apple.act.mond`

## Notes

- `Ctrl+C` should stop the scan and exit with an error message.
- `network_connection` rules require `lsof`.
- `path_exists` rules check exact paths and do not depend on `--path`.
- `text_pattern` rules currently use regex matching with a per file-rule timeout.
