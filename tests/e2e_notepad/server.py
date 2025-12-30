#!/usr/bin/env python3
import socket
import threading

def run_server(port=9001):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port))
    srv.listen(1)
    conn, addr = srv.accept()
    data = conn.recv(1024)
    # echo and close
    conn.sendall(data)
    # Keep the connection open longer so the monitor can detect it
    try:
        import time
        time.sleep(8)
    except Exception:
        pass
    conn.close()
    srv.close()

if __name__ == '__main__':
    run_server()
