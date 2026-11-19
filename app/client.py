#!/usr/bin/env python3
"""
client.py - TCP client for the SDN Authentication & Network Access Control system.

Run it on a Mininet host, e.g.  mininet> h1 python3 app/client.py login alice alice123

Commands
  login USER PASS [--keepalive]   authenticate; --keepalive keeps renewing the session
  status | renew | logout         act on the saved session of this host
  access IP PORT [--msg TEXT]     try to use a protected service (exit 0 = reachable)
  bench IP PORT --bytes N         download N bytes from a service, report throughput
  admin list|stats|revoke USER|block IP [SECS]|unblock IP   (admin role only)
  bruteforce USER [--attempts N]  (attack demo) guess wrong passwords
  scan IP --ports A-B             (attack demo) probe many ports without logging in

Add --json for machine-readable output (used by the automated tests).
"""
import argparse
import json
import os
import secrets
import signal
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (AUTH_IP, AUTH_PORT, TOKEN_DIR, LineReader, ProtocolError,  # noqa: E402
                    client_proof, send_msg)

OUT_JSON = False


def out(text=None, **data):
    if OUT_JSON:
        print(json.dumps(data), flush=True)
    elif text:
        print(text, flush=True)


def local_ip(server=AUTH_IP):
    """Find this host's IP on the path to the server (no packet is sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((server, AUTH_PORT))
        return s.getsockname()[0]
    finally:
        s.close()


def session_path(ip):
    os.makedirs(TOKEN_DIR, exist_ok=True)
    return os.path.join(TOKEN_DIR, f"{ip}.json")


def load_session(args):
    if getattr(args, "token", None):
        return {"token": args.token, "server": args.server}
    try:
        with open(session_path(local_ip(args.server))) as f:
            return json.load(f)
    except FileNotFoundError:
        out("No saved session on this host - run 'login' first", ok=False,
            error="no-session")
        sys.exit(2)


class AuthConnection:
    def __init__(self, server, port=AUTH_PORT, timeout=5):
        self.sock = socket.create_connection((server, port), timeout=timeout)
        self.reader = LineReader(self.sock)

    def call(self, obj):
        send_msg(self.sock, obj)
        reply = self.reader.read_msg()
        if reply is None:
            raise ConnectionError("server closed the connection")
        return reply

    def close(self):
        self.sock.close()


def do_login(server, user, password, timeout=5):
    """SCRAM-style login. Returns (reply_dict, elapsed_ms)."""
    t0 = time.time()
    c = AuthConnection(server, timeout=timeout)
    try:
        cnonce = secrets.token_hex(16)
        ch = c.call({"type": "HELLO", "user": user, "cnonce": cnonce})
        if ch.get("type") != "CHALLENGE":
            return ch, (time.time() - t0) * 1000
        proof, expected_sig = client_proof(password, ch["salt"], ch["iters"], user,
                                           cnonce, ch["snonce"])
        r = c.call({"type": "AUTH", "proof": proof})
        if r.get("type") == "AUTH_OK" and r.get("server_sig") != expected_sig:
            # mutual authentication: the server proved it knows our credentials
            return {"type": "AUTH_FAIL", "reason": "server failed mutual authentication"}, 0
        return r, (time.time() - t0) * 1000
    finally:
        c.close()


# ------------------------------------------------------------------ commands
def cmd_login(args):
    try:
        r, ms = do_login(args.server, args.user, args.password, timeout=args.timeout)
    except (OSError, ProtocolError, ConnectionError) as e:
        out(f"[!] cannot reach auth server {args.server}:{AUTH_PORT} ({e})",
            ok=False, error=str(e))
        return 1
    if r.get("type") != "AUTH_OK":
        out(f"[-] login failed: {r.get('type')} {r.get('reason', '')} "
            f"{'attempts_left=%s' % r['attempts_left'] if 'attempts_left' in r else ''}"
            f"{'blocked_for=%ss' % r['seconds'] if 'seconds' in r else ''}",
            ok=False, reply=r, ms=round(ms, 2))
        return 1
    ip = local_ip(args.server)
    sess = {"token": r["token"], "user": args.user, "role": r["role"], "ttl": r["ttl"],
            "server": args.server, "ip": ip, "services": r["services"]}
    with open(session_path(ip), "w") as f:
        json.dump(sess, f)
    svc = ", ".join(f"{s['name']}={s['ip']}:{s['port']}" for s in r["services"]) or "none"
    out(f"[+] logged in as {args.user} (role={r['role']}) from {ip} in {ms:.1f} ms\n"
        f"    session ttl={r['ttl']}s   allowed services: {svc}",
        ok=True, ms=round(ms, 2), role=r["role"], token=r["token"], ttl=r["ttl"],
        services=r["services"])
    if args.keepalive:
        keepalive(args.server, sess)
    return 0


def keepalive(server, sess):
    """Renew the session every ttl/3 seconds until it is revoked or we are killed."""
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    period = max(1.0, sess["ttl"] / 3)
    while True:
        time.sleep(period)
        try:
            c = AuthConnection(server)
            r = c.call({"type": "RENEW", "token": sess["token"]})
            c.close()
        except (OSError, ProtocolError, ConnectionError) as e:
            print(f"[keepalive] renew failed: {e}", flush=True)
            continue
        if r.get("type") != "RENEW_OK":
            print(f"[keepalive] session ended: {r.get('reason')}", flush=True)
            return
        print(f"[keepalive] renewed ({time.strftime('%H:%M:%S')})", flush=True)


def simple_call(args, mtype, **extra):
    sess = load_session(args)
    try:
        c = AuthConnection(sess["server"], timeout=args.timeout)
        r = c.call(dict(type=mtype, token=sess["token"], **extra))
        c.close()
    except (OSError, ProtocolError, ConnectionError) as e:
        out(f"[!] cannot reach auth server ({e})", ok=False, error=str(e))
        return None
    return r


def cmd_status(args):
    r = simple_call(args, "STATUS")
    if not r:
        return 1
    if r.get("type") != "STATUS":
        out(f"[-] {r.get('reason')}", ok=False, reply=r)
        return 1
    out(f"[+] {r['user']} ({r['role']}) @ {r['ip']}  {r['remaining']}s left; services: "
        + ", ".join(f"{s['name']}={s['ip']}:{s['port']}" for s in r["services"]),
        ok=True, reply=r)
    return 0


def cmd_renew(args):
    r = simple_call(args, "RENEW")
    ok = bool(r and r.get("type") == "RENEW_OK")
    out(f"[{'+' if ok else '-'}] {r}", ok=ok, reply=r)
    return 0 if ok else 1


def cmd_logout(args):
    r = simple_call(args, "LOGOUT")
    ok = bool(r and r.get("type") == "BYE")
    if ok and not getattr(args, "token", None):
        try:
            os.remove(session_path(local_ip(args.server)))
        except FileNotFoundError:
            pass
    out("[+] logged out - network access revoked" if ok else f"[-] logout failed: {r}",
        ok=ok, reply=r)
    return 0 if ok else 1


def cmd_admin(args):
    extra = {"action": args.action.upper()}
    if args.action in ("revoke",):
        extra["user"] = args.target
    elif args.action in ("block", "unblock"):
        extra["ip"] = args.target
        extra["seconds"] = args.seconds
    r = simple_call(args, "ADMIN", **extra)
    ok = bool(r and r.get("type") == "ADMIN_OK")
    out(json.dumps(r, indent=2), ok=ok, reply=r)
    return 0 if ok else 1


def cmd_access(args):
    t0 = time.time()
    try:
        s = socket.create_connection((args.ip, args.port), timeout=args.timeout)
        s.settimeout(args.timeout)
        f = s.makefile("rb")
        banner = f.readline().decode().strip()
        s.sendall((args.msg + "\n").encode())
        reply = f.readline().decode().strip()
        s.close()
        ms = (time.time() - t0) * 1000
        out(f"[+] ACCESS GRANTED to {args.ip}:{args.port} ({ms:.1f} ms)\n    {banner}\n    {reply}",
            ok=True, ms=round(ms, 2), banner=banner, reply=reply)
        return 0
    except (OSError, socket.timeout) as e:
        ms = (time.time() - t0) * 1000
        out(f"[-] ACCESS DENIED to {args.ip}:{args.port} - no route through the network "
            f"({type(e).__name__} after {ms:.0f} ms)", ok=False, ms=round(ms, 2),
            error=type(e).__name__)
        return 1


def cmd_bench(args):
    try:
        s = socket.create_connection((args.ip, args.port), timeout=args.timeout)
        s.settimeout(max(args.timeout, 30))
        f = s.makefile("rb")
        f.readline()
        t0 = time.time()
        s.sendall(f"BULK {args.bytes}\n".encode())
        got = 0
        while True:
            chunk = f.read1(65536)
            if not chunk:
                break
            got += len(chunk)
        dt = time.time() - t0
        s.close()
        mbps = got * 8 / dt / 1e6 if dt > 0 else 0
        out(f"[+] received {got} bytes in {dt:.2f}s = {mbps:.2f} Mbit/s",
            ok=got == args.bytes, bytes=got, seconds=round(dt, 3), mbps=round(mbps, 2))
        return 0 if got == args.bytes else 1
    except (OSError, socket.timeout) as e:
        out(f"[-] bench failed: {e}", ok=False, error=str(e))
        return 1


def cmd_bruteforce(args):
    """Attack demo: keep guessing passwords until the network blocks us."""
    results = []
    for i in range(1, args.attempts + 1):
        t0 = time.time()
        try:
            r, _ = do_login(args.server, args.user, f"guess{i:03d}", timeout=2)
            res = r.get("type")
        except (OSError, ProtocolError, ConnectionError) as e:
            res = f"NO-RESPONSE({type(e).__name__})"
        results.append(res)
        out(f"  attempt {i:2d}: password=guess{i:03d} -> {res}")
        time.sleep(args.delay)
    out(None, ok=True, results=results)
    return 0


def cmd_scan(args):
    """Attack demo: probe a range of TCP ports without being logged in."""
    a, b = (int(x) for x in args.ports.split("-"))
    opened = []
    for port in range(a, b + 1):
        s = socket.socket()
        s.settimeout(args.timeout)
        try:
            s.connect((args.ip, port))
            opened.append(port)
        except OSError:
            pass
        finally:
            s.close()
    out(f"[scan] {args.ip} ports {a}-{b}: open={opened or 'none'}", ok=True, open=opened)
    return 0


def main():
    global OUT_JSON
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--server", default=AUTH_IP)
    p.add_argument("--timeout", type=float, default=3.0)
    p.add_argument("--json", action="store_true")
    p.add_argument("--token", help="use this token instead of the saved session (replay tests)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("login")
    s.add_argument("user")
    s.add_argument("password")
    s.add_argument("--keepalive", action="store_true")
    s.set_defaults(fn=cmd_login)
    for name, fn in (("status", cmd_status), ("renew", cmd_renew), ("logout", cmd_logout)):
        sub.add_parser(name).set_defaults(fn=fn)
    s = sub.add_parser("access")
    s.add_argument("ip")
    s.add_argument("port", type=int)
    s.add_argument("--msg", default="hello")
    s.set_defaults(fn=cmd_access)
    s = sub.add_parser("bench")
    s.add_argument("ip")
    s.add_argument("port", type=int)
    s.add_argument("--bytes", type=int, default=10_000_000)
    s.set_defaults(fn=cmd_bench)
    s = sub.add_parser("admin")
    s.add_argument("action", choices=["list", "stats", "revoke", "block", "unblock"])
    s.add_argument("target", nargs="?")
    s.add_argument("seconds", nargs="?", type=int, default=30)
    s.set_defaults(fn=cmd_admin)
    s = sub.add_parser("bruteforce")
    s.add_argument("user")
    s.add_argument("--attempts", type=int, default=7)
    s.add_argument("--delay", type=float, default=0.2)
    s.set_defaults(fn=cmd_bruteforce)
    s = sub.add_parser("scan")
    s.add_argument("ip")
    s.add_argument("--ports", default="8070-8090")
    s.set_defaults(fn=cmd_scan)

    args = p.parse_args()
    OUT_JSON = args.json
    if args.cmd == "scan" and args.timeout == 3.0:
        args.timeout = 0.3
    sys.exit(args.fn(args))


if __name__ == "__main__":
    main()
