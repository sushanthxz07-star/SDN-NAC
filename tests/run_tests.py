#!/usr/bin/env python3
"""
run_tests.py - automated functional & security test suite.

    sudo python3 tests/run_tests.py

Starts POX (nac mode), builds the Mininet topology, runs every scenario,
prints a PASS/FAIL table and writes results/test_report.md.
Takes about 2 minutes (it waits for session timeouts and block expiry).
"""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "topology"))
from mininet.log import setLogLevel  # noqa: E402

import lab  # noqa: E402

TTL = 8
WEB, DB, AUTH = ("10.0.0.201", 8080), ("10.0.0.202", 9090), "10.0.0.100"
results = []


def check(tid, name, expected, ok, detail=""):
    results.append((tid, name, expected, "PASS" if ok else "FAIL", detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {tid:>3}  {name}  -- {detail}", flush=True)


def access(h, svc, timeout=2):
    return lab.client(h, "access", svc[0], svc[1], timeout=timeout).get("ok", False)


def ping(h, ip):
    return " 0% packet loss" in h.cmd(f"ping -c2 -W1 -i0.3 {ip}")


def tail_has(logname, text):
    with open(os.path.join(lab.LOGS, logname)) as f:
        return text in f.read()


def run(net):
    h1, h2, h3, h4, eve = (net[n] for n in ("h1", "h2", "h3", "h4", "eve"))

    print("\n== Pre-authentication ==")
    check("T1", "Unauthenticated host can reach auth server (ping)", "allowed",
          ping(h1, AUTH), "auth zone open to everyone")
    check("T2", "Unauthenticated host -> web:8080", "denied", not access(h1, WEB),
          "dropped by SDN, no flow rule")
    check("T3", "Unauthenticated host -> ping web", "denied", not ping(h1, WEB[0]), "ICMP dropped")

    print("\n== Authentication ==")
    r = lab.client(h1, "login", "alice", "wrongpass")
    check("T4", "Wrong password", "AUTH_FAIL",
          r.get("reply", {}).get("type") == "AUTH_FAIL", str(r.get("reply")))
    check("T5", "Still denied after failed login", "denied", not access(h1, WEB))
    r = lab.client(h1, "login", "mallory", "x")
    check("T6", "Unknown user gets the same generic error", "AUTH_FAIL",
          r.get("reply", {}).get("reason") == "invalid username or password", str(r.get("reply")))
    r = lab.client(h1, "login", "alice", "alice123")
    check("T7", "Valid login alice (student)", "AUTH_OK", r.get("ok"),
          f"{r.get('ms')} ms, services={[s['name'] for s in r.get('services', [])]}")
    alice_token = r.get("token")

    print("\n== Authorization (role policy) ==")
    check("T8", "alice -> web:8080", "allowed", access(h1, WEB))
    check("T9", "alice (student) -> db:9090", "denied", not access(h1, DB), "role has no db")
    r = lab.client(h2, "login", "bob", "bob123")
    check("T10", "bob (faculty) -> web and db", "allowed",
          r.get("ok") and access(h2, WEB) and access(h2, DB))
    check("T11", "Other hosts stay isolated (h3 -> web)", "denied", not access(h3, WEB))
    r = lab.client(h3, "--token", alice_token, "status")
    check("T12", "Stolen token replayed from another host", "rejected",
          not r.get("ok") and "not valid from this address" in str(r.get("reply")),
          str(r.get("reply")))
    check("T13", "Replayed token gives no network access", "denied", not access(h3, WEB))

    print("\n== Concurrency ==")
    for h in (h1, h2, h3):
        h.cmd("rm -f /tmp/nac_tokens/*")
    procs = [(h, u, p) for h, u, p in ((h1, "alice", "alice123"), (h2, "bob", "bob123"),
                                        (h3, "carol", "carol123"))]
    for h, u, p in procs:
        h.sendCmd(f"{lab.PY} {lab.APP}/client.py --json login {u} {p}")
    outs = [h.waitOutput() for h, _, _ in procs]
    ok = all('"ok": true' in o for o in outs)
    check("T14", "3 users log in simultaneously", "all AUTH_OK", ok)
    check("T15", "All 3 concurrent users can use web", "allowed",
          all(access(h, WEB) for h, _, _ in procs))

    print("\n== Revocation & timeouts ==")
    lab.client(h1, "logout")
    t0 = time.time()
    check("T16", "Logout immediately revokes access (alice)", "denied", not access(h1, WEB),
          f"checked {time.time() - t0:.1f}s after logout")
    # bob keeps renewing; carol does not
    h2.cmd(f"{lab.PY} {lab.APP}/client.py login bob bob123 --keepalive > /tmp/ka_bob.out 2>&1 &")
    time.sleep(1)
    print(f"  ...waiting {TTL + 3}s for carol's session (ttl={TTL}s) to time out")
    time.sleep(TTL + 3)
    check("T17", "Session timeout revokes access (carol, no renew)", "denied",
          not access(h3, WEB), "SESSION_EXPIRED in auth.log")
    check("T18", "Keepalive renewals keep access past TTL (bob)", "allowed", access(h2, WEB),
          "RENEW extends grant + flow hard_timeout")

    print("\n== Admin ==")
    r = lab.client(h3, "login", "carol", "carol123")
    r = lab.client(h3, "admin", "list")
    check("T19", "Non-admin cannot run admin commands", "rejected",
          not r.get("ok") and "admin role required" in str(r.get("reply")))
    lab.client(h1, "login", "admin", "admin123")
    r = lab.client(h1, "admin", "revoke", "bob")
    time.sleep(0.3)
    check("T20", "Admin revokes bob -> bob loses access", "denied",
          r.get("ok") and not access(h2, WEB))
    lab.pkill(f"{lab.APP}/client.py login bob")
    lab.client(h1, "login", "admin", "admin123")
    lab.client(h1, "bench", WEB[0], WEB[1], "--bytes", 2_000_000)
    time.sleep(5.5)                       # controller polls flow stats every 5 s
    r = lab.client(h1, "admin", "stats")
    grants = r.get("reply", {}).get("controller", {}).get("grants", [])
    rx = next((g["bytes"].get("rx", 0) for g in grants if g["ip"] == "10.0.0.1"), 0)
    check("T29", "Flow-stats monitoring reports per-host traffic", ">= 2 MB rx",
          rx >= 2_000_000, f"controller sees rx={rx} bytes for 10.0.0.1")

    print("\n== Attacks ==")
    r = lab.client(eve, "bruteforce", "bob", "--attempts", "7", "--delay", "0.1")
    blocked_reply = any("BLOCKED" in x or "NO-RESPONSE" in x for x in r.get("results", []))
    check("T21", "Brute-force guessing triggers a block", "BLOCKED", blocked_reply,
          f"results={r.get('results')}")
    check("T22", "Blocked host cut off at network level (eve -> ping auth)", "denied",
          not ping(eve, AUTH), "priority-1000 drop rule on all switches")
    r = lab.client(eve, "login", "bob", "bob123", timeout=2)
    check("T23", "Blocked host cannot log in even with the right password", "fails",
          not r.get("ok"), str(r.get("error") or r.get("reply")))
    lab.client(h4, "scan", WEB[0], "--ports", "8070-8095")
    time.sleep(0.5)
    check("T24", "Port scan by unauthenticated host is auto-blocked by controller",
          "blocked", not ping(h4, AUTH) and tail_has("controller.log", "SCAN_DETECTED"),
          "SCAN_DETECTED -> BLOCK -> event to auth server")
    check("T25", "Auth server was notified of controller's block (socket<-SDN event)",
          "logged", tail_has("auth.log", "kind=HOST_BLOCKED ip=10.0.0.4"))
    r = h1.cmd(f"{lab.PY} -c \"import socket;s=socket.create_connection(('{AUTH}',5000),3);"
               f"s.sendall(b'this is not json\\n');print(s.recv(200))\"")
    check("T26", "Malformed message -> error reply, server survives", "ERROR",
          "ERROR" in r and lab.client(h1, "login", "alice", "alice123").get("ok"),
          r.strip()[:60])

    print("\n== Expiry & failure handling ==")
    print("  ...waiting for eve's 30s block to expire")
    time.sleep(31)
    check("T27", "Block expires automatically (eve can reach auth again)", "allowed",
          ping(eve, AUTH))
    r = lab.client(h3, "login", "carol", "carol123")
    lab.pkill(os.path.join(lab.APP, "auth_server.py"))
    print(f"  ...auth server killed; waiting {TTL + 2}s")
    time.sleep(TTL + 2)
    check("T28", "Auth server crash -> grants still expire at controller (fail-closed)",
          "denied", r.get("ok") and not access(h3, WEB), "controller-side grant expiry")


def main():
    setLogLevel("warning")
    os.chdir(lab.ROOT)
    os.makedirs(lab.LOGS, exist_ok=True)
    for f in ("auth.log", "controller.log"):
        open(os.path.join(lab.LOGS, f), "w").close()
    subprocess.call(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ctrl = lab.start_controller("nac")
    net = lab.build_net(4)
    try:
        lab.start_services(net, ttl=TTL)
        run(net)
    finally:
        lab.stop_services()
        net.stop()
        lab.stop_controller(ctrl)
    passed = sum(1 for r in results if r[3] == "PASS")
    os.makedirs(os.path.join(lab.ROOT, "results"), exist_ok=True)
    path = os.path.join(lab.ROOT, "results", "test_report.md")
    with open(path, "w") as f:
        f.write(f"# Test report\n\nRun: {time.strftime('%Y-%m-%d %H:%M:%S')} - "
                f"**{passed}/{len(results)} passed** (session TTL {TTL}s)\n\n")
        f.write("| ID | Scenario | Expected | Result | Detail |\n|---|---|---|---|---|\n")
        for r in results:
            f.write("| " + " | ".join(str(x).replace("|", "/") for x in r) + " |\n")
    print(f"\n{passed}/{len(results)} tests passed -> {path}")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
