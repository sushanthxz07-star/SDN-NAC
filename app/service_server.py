#!/usr/bin/env python3
"""
service_server.py - a protected TCP service (e.g. web portal on 10.0.0.201:8080,
grades DB on 10.0.0.202:9090).

The service itself does NOT check passwords: access control is enforced by the
network. A packet from an unauthenticated host never reaches this server
because the SDN controller has no flow rule allowing it.

Text protocol (one command per line):
    <any text>     -> "ECHO <text>"
    WHOAMI         -> the client address as seen by the server
    BULK <bytes>   -> server streams <bytes> bytes then closes (throughput test)
    QUIT           -> close
"""
import argparse
import os
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import EventLog  # noqa: E402

CHUNK = b"x" * 65536


def handle(conn, addr, name, log):
    log.log("CONNECT", service=name, client=f"{addr[0]}:{addr[1]}")
    try:
        conn.settimeout(60)
        conn.sendall(f"WELCOME to {name} (protected service) - hello {addr[0]}\n".encode())
        f = conn.makefile("rb")
        for raw in f:
            line = raw.decode(errors="replace").strip()
            if not line:
                continue
            cmd = line.split()
            if cmd[0].upper() == "QUIT":
                break
            if cmd[0].upper() == "WHOAMI":
                conn.sendall(f"YOU ARE {addr[0]}\n".encode())
            elif cmd[0].upper() == "BULK" and len(cmd) == 2 and cmd[1].isdigit():
                remaining = min(int(cmd[1]), 1 << 30)
                log.log("BULK", service=name, client=addr[0], bytes=remaining)
                while remaining > 0:
                    n = min(remaining, len(CHUNK))
                    conn.sendall(CHUNK[:n])
                    remaining -= n
                break
            else:
                conn.sendall(f"ECHO {line}\n".encode())
    except OSError:
        pass
    finally:
        conn.close()
        log.log("DISCONNECT", service=name, client=addr[0])


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--name", default="service")
    a = p.parse_args()
    log = EventLog(f"service_{a.name}.log")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", a.port))
    srv.listen(128)
    log.log("SERVICE_START", service=a.name, port=a.port)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr, a.name, log), daemon=True).start()


if __name__ == "__main__":
    main()
