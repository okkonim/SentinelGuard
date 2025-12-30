# Commands to Demonstrate All Protection System Modules

## 🎯 Basic Commands for Testing the System

### 1. Run the full demonstration of all modules
```bash
cd /home/userss/Downloads/Software-Firewall-Prototype
python3 demos/demo_runner.py
```

**Result:** Automatic test of the main modules with a summary report

### 2. Interactive firewall testing
```bash
cd /home/userss/Downloads/Software-Firewall-Prototype
python3 firewall.py interactive
```

**Menu options:**
- `1` - Start all modules
- `2` - Start the hybrid network sniffer
- `3` - Start the FIM module
- `4` - Start the process monitoring module
- `5` - Start the network monitoring module
- `6` - Start the ransomware protection system
- `7` - View logs
- `8` - Reload rules
- `9` - Scan network threats
- `10` - Create baseline
- `11` - Compare to baseline
- `12` - Manual YARA scan
- `13` - List YARA rules
- `14` - PE file analysis
- `15` - View PE reports
- `0` - Exit

### 3. Test the ransomware protection system
```bash
cd /home/userss/Downloads/Software-Firewall-Prototype
python3 ransomware_protection_system.py start
```

**To stop:** Press `Ctrl+C`

### 4. Create test files for demonstration
```bash
cd /home/userss/Downloads/Software-Firewall-Prototype
python3 ransomware_protection_system.py test --dir ./test_files_demo
```

### 5. View event statistics
```bash
# View FIM events
python3 firewall.py logs --table fim_events --limit 10

# View process events
python3 firewall.py logs --table process_events --limit 10

# View network security alerts
python3 firewall.py logs --table netsec_alerts --limit 10

# View YARA events
python3 firewall.py logs --table yara_events --limit 10
```

### 6. Manual file scans
```bash
# YARA scan
python3 firewall.py scan --path /etc/passwd

# PE analysis
python3 firewall.py pe-analyze --path /bin/ls

# View PE reports
python3 firewall.py pe-reports --limit 5
```

### 7. Check configuration and rules
```bash
# List loaded YARA rules
python3 firewall.py rules

# Reload configuration
python3 firewall.py reload
```

## 🔍 Module Overview (based on the specification)

### Integration modules:
```bash
# Integration and auto-response module
python3 ransomware_protection_system.py start &

# Firewall <-> FIM integration
python3 firewall.py interactive
# Choose option 1 (Start all modules)

# Firewall <-> Process monitor integration
python3 firewall.py interactive
# Choose option 1 (Start all modules)
```

### Specialized modules:
```bash
# YARA scanner and rule management
python3 firewall.py rules
python3 firewall.py scan --path ./test_files_demo

# PE static analysis and anomaly detection
python3 firewall.py pe-analyze --path /bin/bash
python3 firewall.py pe-reports --limit 10
```

### Monitoring modules:
```bash
# FIM monitoring
python3 firewall.py interactive
# Choose option 3 (Start FIM)

# Process monitoring
python3 firewall.py interactive  
# Choose option 4 (Start process monitoring)

# Network monitoring
python3 firewall.py interactive
# Choose option 5 (Start network monitoring)
```

## 📊 Quick Functionality Summary

**Working modules (from the demo):**
- ✅ **Firewall Module** - Central management system
- ✅ **YARA Scanner Module** - Signature-based detection
- ✅ **PE Analyzer Module** - Static analysis of executables
- ✅ **Anomaly Detection Module** - PE anomaly detection
- ✅ **Integration System** - Event correlation and response

**Needs improvement:**
- ⚠️ **FIM Module** - File integrity monitoring
- ⚠️ **Process Monitor Module** - Process monitoring

## 🎯 Log Commands
```bash
# View logs in real time
tail -f ransomware_protection.log

# Show the last 50 lines of logs
tail -50 ransomware_protection.log

# Search for errors in logs
grep -i error ransomware_protection.log
```

## 🚀 Quick Demo (recommended sequence)
```bash
# 1. Run the full demo
python3 demos/demo_runner.py

# 2. Interactive testing  
python3 firewall.py interactive
# Choose: 6, 12, 14, 15

# 3. Check logs
python3 firewall.py logs --table netsec_alerts --limit 5
```

**Demo result summary:** 5 out of 7 modules functioning correctly (71.4% success rate)
