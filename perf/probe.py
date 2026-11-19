#!/usr/bin/env python3
"""probe.py IP PORT OUTFILE - keep an open TCP session to a service and send an
echo every 10 ms. Exits at the first echo that gets no reply (connection cut by
the SDN controller) and writes timing to OUTFILE as JSON."""
import json
import socket
import sys
import time

ip, port, outfile = sys.argv[1], int(sys.argv[2]), sys.argv[3]
max_seconds = float(sys.argv[4]) if len(sys.argv) > 4 else 30
s = socket.create_connection((ip, port), timeout=3)
f = s.makefile("rb")
f.readline()
s.settimeout(0.3)
last_ok, n_ok, t_start = None, 0, time.time()
result = {"cut": False}
while time.time() - t_start < max_seconds:
    t_send = time.time()
    try:
        s.sendall(b"probe\n")
        if not f.readline():
            raise OSError("closed")
        last_ok = t_send
        n_ok += 1
    except OSError:
        result = {"cut": True, "first_fail_send": t_send, "last_ok": last_ok, "n_ok": n_ok}
        break
    time.sleep(0.01)
json.dump(result, open(outfile, "w"))
