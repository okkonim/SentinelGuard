#!/usr/bin/env python3
"""E2E test: create baseline, run notepad.exe to generate outbound connection, verify detection."""
import os
import time
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from network_monitor import NetworkMonitor


def compile_notepad():
    src = Path(__file__).resolve().parents[0] / 'notepad.c'
    bin_path = Path(__file__).resolve().parents[0] / 'notepad.exe'
    if not bin_path.exists():
        subprocess.check_call(['gcc', '-o', str(bin_path), str(src)])
    return str(bin_path)


def run():
    monitor = NetworkMonitor()

    # 1) create baseline
    monitor.generate_baseline()

    # 2) start server
    srv_proc = subprocess.Popen([sys.executable, str(Path(__file__).resolve().parents[0] / 'server.py')])
    # Give the server more time to start and bind the port
    time.sleep(1.0)

    # 3) compile and start fake notepad.exe
    bin_path = compile_notepad()
    note_proc = subprocess.Popen([bin_path, '9001'])
    print(f"Started fake notepad.exe with PID {note_proc.pid}")

    # wait for connection to happen and be visible to the monitor
    # wait for connection to happen (poll / wait up to 4s for the server/client to establish connection)
    start = time.time()
    connected = False
    while time.time() - start < 4.0:
        conns = monitor.get_network_connections()
        for c in conns:
            la = c.get('laddr')
            ra = c.get('raddr')

            def addr_str(a):
                if not a:
                    return ''
                if isinstance(a, tuple) and len(a) >= 2:
                    return f"{a[0]}:{a[1]}"
                return str(a)

            if '127.0.0.1:9001' in (addr_str(la), addr_str(ra)):
                connected = True
                break
        if connected:
            break
        time.sleep(0.25)

    # 4) check for anomalies / new connections
    anomalies = monitor.compare_with_baseline()
    print("Anomalies from compare_with_baseline():", anomalies)

    # Quick-win: if compare_with_baseline already attributed the new connection to our PID,
    # accept that as a match to avoid race issues with very short-lived sockets.
    matched = []
    for a in anomalies:
        if a.get('type') != 'new_connection':
            continue
        conn = a.get('connection', {})
        # Debug print to see what compare_with_baseline returned
        print(f"[DEBUG-ANOMALY] conn={conn!r} note_pid={note_proc.pid}")

        # Robust PID match: handle strings, ints, and None
        try:
            an_pid = int(conn.get('pid')) if conn.get('pid') not in (None, '', 'None') else 0
        except (ValueError, TypeError):
            an_pid = 0

        if an_pid and an_pid == note_proc.pid:
            # create a normalized connection dict similar to get_network_connections()
            matched.append({
                'laddr': conn.get('laddr'),
                'raddr': conn.get('raddr'),
                'status': conn.get('status'),
                'pid': note_proc.pid,
                'inferred_from': 'anomaly'
            })

    # If we already matched by anomaly, skip active polling to avoid race overwrites
    if matched:
        print(f"Matched from anomaly: {matched}")
    else:
        # 5) enumerate current connections and find the one from our PID
        # The connection can be short-lived; poll for a longer period to avoid race conditions
        timeout = 10.0
        interval = 0.25
        end_time = time.time() + timeout
        while time.time() < end_time:
            conns = monitor.get_network_connections()

            # direct pid match
            matched = [c for c in conns if c.get('pid') == note_proc.pid]

            # Helper: normalize an addr (tuple or psutil object) into 'ip:port' string
            def norm_addr(a):
                if not a:
                    return ''
                # If it's a tuple like (ip, port)
                if isinstance(a, tuple) and len(a) >= 2:
                    return f"{a[0]}:{a[1]}"
                # psutil's addr objects stringify like "addr(ip='127.0.0.1', port=12345)";
                # try to extract numbers
                s = f"{a}"
                if ':' in s and s.count('.') >= 1:
                    # likely 'ip:port' already
                    return s
                # fallback
                return s

            # If compare_with_baseline reported a new connection but without pid, try matching by addr pair
            if not matched:
                for a in anomalies:
                    if a.get('type') != 'new_connection':
                        continue
                    conn = a.get('connection', {})
                    l = conn.get('laddr') or ''
                    r = conn.get('raddr') or ''

                    for c in conns:
                        l_c = norm_addr(c.get('laddr'))
                        r_c = norm_addr(c.get('raddr'))

                        # match direct or reversed (local/remote may be reported in different order)
                        if ((l_c == l and r_c == r) or (l_c == r and r_c == l)) and c.get('pid'):
                            matched.append(c)
                            break
                    if matched:
                        break
            if matched:
                break
            # If nothing matched, print a short debug snapshot of current connections to help
            # diagnose races / pid attribution issues (limited output to avoid noise)
            if not matched:
                sample = []
                for c in conns[:20]:
                    sample.append({
                        'pid': c.get('pid'),
                        'laddr': f"{c.get('laddr')}",
                        'raddr': f"{c.get('raddr')}",
                        'inode': c.get('inode')
                    })
                print(f"[DEBUG] current connections snapshot (len={len(conns)}):", sample)
            time.sleep(interval)

    # (Polling and matching handled above in conditional block)

    print(f"Connections for fake notepad.exe (pid {note_proc.pid}):", matched)

    # Cleanup
    try:
        note_proc.terminate()
    except Exception:
        pass
    try:
        srv_proc.terminate()
    except Exception:
        pass

    # Evaluate
    if not anomalies:
        print("Test failed: no anomalies detected by compare_with_baseline().")
        return 2
    if not matched:
        print("Test failed: could not find connection attributed to fake notepad.exe.")
        return 3

    print("Test passed: new connection detected and attributed to notepad.exe")
    return 0


if __name__ == '__main__':
    sys.exit(run())
