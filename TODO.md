# TODO List for Software Firewall Prototype

- [x] Install required dependencies (scapy, psutil) using pip.
- [x] Create database.py: Define SQLite database schema with tables for network events, FIM events, and process events. Include functions to insert and query events.
- [x] Create rules.json: Sample JSON file with rules including conditions (source/dest IP, port, protocol) and actions (ACCEPT/DROP).
- [x] Create rules_manager.py: Functions to load rules from JSON, validate packets against rules, return action (ACCEPT/DROP).
- [x] Create network_capture.py: Use Scapy to capture packets in real-time, apply rule-based filtering, log events to database.
- [x] Create fim.py: Monitor rules.json for changes using file hashing (e.g., SHA256), log integrity violations to database.
- [x] Create process_monitor.py: Use psutil to monitor running processes, detect anomalous network-related activity (e.g., high network usage), log to database.
- [x] Create firewall.py: Main script with CLI interface for starting/stopping firewall, viewing logs, managing rules. Integrate all modules.
- [x] Integrate logging across modules with timestamps, event types, and criticality levels.
- [x] Run the firewall prototype to test packet capture, filtering, FIM, process monitoring.
- [x] Verify database storage and CLI functionality.
- [x] Handle any runtime errors or missing features.
