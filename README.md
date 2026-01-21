# SentinelGuard — Ransomware Protection System (Detailed)

> A practical, code-accurate README describing modules, CLI, config keys, and operational behavior.

---

## Overview
SentinelGuard is a modular Python prototype for ransomware detection and response. It combines multiple detectors (FIM, process monitoring, YARA scanning, PE analysis, and optional network sniffing) with a centralized SQLite event store and a correlation engine to surface likely ransomware attacks and support rollback remediation.

This README documents the exact behavior implemented in the codebase, CLI usage, configuration, and operational recommendations.

---

## Quick facts (code-accurate)
- Default config file: `config.json` (CLI flag `--config` changes this)
- Default DB file: `firewall.db` (CLI flag `--db` changes this)
- Main CLI: `ransomware_protection_system.py` (with `CLIHandler`)
- Coordinator/utility wrapper: `firewall.py` (interactive operations, PE/YARA manual scans)
- Central logger: `utils/logging_utils.RansomwareLogger`
- Default network interface constant: `NETWORK_INTERFACE` set to `ens33` in `utils/constants.py` (used when a configured interface is not provided)

---

## Modules & behavior (precise)
- ConfigurationManager (`ransomware_protection_system.ConfigurationManager`)
  - Loads `config.json` and populates module enable flags. Required sections flagged if missing (logs a CONFIG_MISSING_SECTION).
  - Module enable defaults are: `crypto` (True), `fim` (False initially in code but interpreted from config), `process_monitor` (False initially), `network_sniffer` (False by default), `pe_analyzer` (True), `yara_scanner` (True).

- SystemManager (`ransomware_protection_system.SystemManager`)
  - Owns the lifecycle, lazy-loads components (FIM, process monitor, network sniffer, YARA, PE analyzer) only when needed and when the config enables them.
  - Core methods:
    - `start_protection()` — Starts enabled modules and correlation engine in daemon threads (returns boolean success).
    - `stop_protection()` — Signals modules to stop, stops correlation engine, waits for threads.
    - `encrypt_file(file, key)` / `decrypt_file(file, key)` — Convenience methods using `CryptoManager` for manual ops and logging events to the DB.
    - `attempt_rollback(file, backup=None)` — Calls `Database.attempt_rollback` to restore files from backups tracked in the DB.
    - `cleanup_system(days=30)` — Calls DB cleanup to purge old events.
    - `create_test_files(directory)` — Writes demo files used for encryption/rollback testing (NOTE: current implementations write text in the test files in Russian; see 'Known caveats' below).

- FIM (`fim.FIM`)
  - Monitors configured paths, computes hashes/entropy, inserts FIM events into the DB. Uses chunked hashing with `FIM_HASH_CHUNK_SIZE` for large files.

- Process monitor (`process_monitor.ProcessMonitor`)
  - Samples processes at configured intervals, records process start/stop events, command lines, and heuristics for suspicious imports/names.

- Network components (`network_sniffer`, `network_capture`, `network_monitor`)
  - Capture traffic, analyze for C2 patterns, DDoS heuristics and beaconing. Network sniffer initialization uses the configured interface if present, otherwise falls back to `NETWORK_INTERFACE` constant.

- YARA scanner (`yara_scanner.YARAScanner`)
  - Compiles rules from `config.json` `yara.rules_files` and can scan single files or directories. Matches are recorded to DB and used for correlation.

- PE analyzer (`pe_analyzer.PEAnalyzer`)
  - Examines PE headers, computes section entropy, collects imports, and flags anomalies and suspicious imports.

- Database (`database.Database`)
  - Tables include `fim_events`, `process_events`, `network_events`, `netsec_alerts`, `yara_events`, `pe_files`, `pe_sections`, `pe_imports`, and `ransomware_attacks`.
  - Provides `query_events`, attack correlation helpers, `attempt_rollback`, and cleanup routines.

---

## CLI reference (exact commands and behavior)
Primary entry: `python3 firewall.py <command>` (run `python3 firewall.py --help` for full usage). `ransomware_protection_system.py` is deprecated and will delegate to `firewall.py` when executed.

To view the CLI help and available commands, run:

```bash
python3 firewall.py --help
```

Example output (trimmed):

```
usage: firewall.py [-h] [--config CONFIG] [--db DB] [--version]
                   {start,stop,logs,reload,netsec-scan,baseline,compare,start-sniffer,start-fim,start-process,start-netsec,start-ransomware,interactive,scan,rules,pe-analyze,pe-reports}

Firewall / SentinelGuard command-line interface (primary project entry)

optional arguments:
  -h, --help            show this help message and exit
  --config CONFIG, -c CONFIG
                        Path to configuration file (default: config.json)
  --db DB, -d DB        Database file (default: firewall.db)
  --version             show program's version number and exit

Commands:
  start                 Start protection system
  stop                  Stop protection system
  logs                  View logged events
  ... (other commands)
```

This is the recommended way to start and control the system.

Available subcommands (implemented exactly as shown in `CLIHandler`):
- `start` — starts the protection system via `SystemManager.start_protection()` (spawns threads for modules and the correlation engine).
- `stop` — stops the system `SystemManager.stop_protection()`.
- `status` — prints a human-readable status via `StatusReporter.display_system_status()`.
- `encrypt <file> [--key <keyfile>]` — triggers `SystemManager.encrypt_file()` and logs an FIM event when successful.
- `decrypt <file> [--key <keyfile>]` — triggers `SystemManager.decrypt_file()` and logs an FIM event when successful.
- `alerts [--limit N]` — displays most recent N alerts (`status_reporter.display_alerts`).
- `attacks [--hours N]` — shows correlated attacks observed in the last N hours (`status_reporter.display_ransomware_attacks`).
- `rollback <file> [--backup path]` — attempts a rollback using DB-stored backup information.
- `cleanup <days>` — removes DB events older than `<days>` (defaults to 30).
- `test [--dir ./test_files]` — creates test files used for encryption/rollback tests.

Wrapper coordinator (`firewall.py`):
- Offers helper commands and interactive convenience (manual YARA scans, PE analysis). Example methods exposed:
  - `manual_scan(path)` — runs YARA on a file/directory.
  - `manual_pe_analysis(path)` — runs PE analysis with YARA integration.

---

## Where logs & data live
- Default log file: `logs/ransomware_protection.log` (configured via `config.json`).
- Database file: `firewall.db` (or path you supply via `--db`).
- Demo and test files: created under `./test_files` by default when `test` subcommand is used.

---

## Known caveats & recommended fixes (practical)
- Some user-facing strings and test file contents were in Russian; these have been translated in the README but code-level localization remains (e.g., `create_test_files()` may still produce Russian strings). The system logic is correct; full localization is recommended for consistent English UX.
- `NetworkSniffer` default interface is `ens33` — update the `config.json` or `NetworkSniffer` initialization if your environment uses `eth0`, `wlp3s0`, etc.
- `network_sniffer` does not always provide a `stop()` method; stopping relies on the thread ending naturally — consider adding a controlled shutdown method for immediate stops.
- Duplicate event logging: the system previously could produce duplicate log entries when modules were started independently; recent changes centralize startup via `firewall.py` (SystemManager) and add short-window deduplication for rapid identical events (FIM and process events) and logging configuration now prevents handler propagation duplication.

---

## Operational checklist
- Enable `fim`, `process_monitor`, and `yara_scanner` in `config.json` for a good starting point.
- If enabling `network_sniffer`, set a correct `interface` in `config.json`.
- Run `python3 tests/run_tests_manual.py` after making changes.
- Back up `firewall.db` and `logs/` before experiments that change persistent state.

---

## Quick operations cheat sheet
- Start: `python3 ransomware_protection_system.py start`
- Stop: `python3 ransomware_protection_system.py stop`
- Status: `python3 ransomware_protection_system.py status`
- Alerts: `python3 ransomware_protection_system.py alerts --limit 50`
- Attacks: `python3 ransomware_protection_system.py attacks --hours 48`
- Encrypt: `python3 ransomware_protection_system.py encrypt ./document.txt`
- Decrypt: `python3 ransomware_protection_system.py decrypt ./document.txt.encrypted`
- Rollback: `python3 ransomware_protection_system.py rollback ./document.txt`
- Cleanup: `python3 ransomware_protection_system.py cleanup 30`
- Test files generation: `python3 ransomware_protection_system.py test --dir ./test_files`

---

## Development & tests
- Run the manual test runner: `python3 tests/run_tests_manual.py`.
- Use `demos/demo_runner.py` for demo scenarios.
- Before merging changes, run linters and the manual test suite.

---

License: MIT

