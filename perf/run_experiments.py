#!/usr/bin/env python3
"""
run_experiments.py - performance evaluation & comparison with baselines.

    sudo python3 perf/run_experiments.py [--bw 20] [--quick]
    python3 perf/plot_results.py          # graphs + summary from the JSON

Runs the same workload under three controller modes:
    open   - no security at all (plain learning switch)        <- baseline 1
    static - fixed IP allow-list, no authentication            <- baseline 2 (static approach)
    nac    - our dynamic authentication-driven access control

Measured
  E1  connection setup time to a protected service (new TCP connection)
  E2  throughput of an authorised bulk transfer
  E3  security effectiveness under 7 attack/misuse scenarios
  E4  login latency vs number of concurrent clients            (nac)
  E5  revocation latency: time until an ACTIVE session is cut  (nac vs static)
  E6  time to block a brute-force attacker / a port scanner    (nac)
  E7  controller load: packet_in messages per new connection
Results -> results/perf_results.json
"""
import argparse
import json
import os
import re
import statistics
import subprocess
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "topology"))
from mininet.log import setLogLevel  # noqa: E402

import lab  # noqa: E402

WEB, DB, AUTH = ("10.0.0.201", 8080), ("10.0.0.202", 9090), "10.0.0.100"
PERF = os.path.dirname(os.path.abspath(__file__))
N_CLIENTS = 20


def access(h, svc, timeout=2):
    return lab.client(h, "access", svc[0], svc[1], timeout=timeout)


def ping_ok(h, ip):
    return " 0% packet loss" in h.cmd(f"ping -c2 -W1 -i0.3 {ip}")


def ctrl_counters(h):
    r = lab.client(h, "admin", "stats")
    return r.get("reply", {}).get("controller", {}).get("counters", {})


def summary(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return {"n": 0}
    xs_sorted = sorted(xs)
    return {"n": len(xs), "mean": round(statistics.mean(xs), 2),
            "median": round(statistics.median(xs), 2),
            "stdev": round(statistics.stdev(xs), 2) if len(xs) > 1 else 0.0,
            "p95": round(xs_sorted[min(len(xs) - 1, int(0.95 * len(xs)))], 2),
            "min": round(xs_sorted[0], 2), "max": round(xs_sorted[-1], 2)}


def log_time(logname, pattern, after=0.0):
    """Timestamp (epoch) of the first log line matching pattern after 'after'."""
    with open(os.path.join(lab.LOGS, logname)) as f:
        for line in f:
            if re.search(pattern, line):
                ts = datetime.strptime(line[:23], "%Y-%m-%d %H:%M:%S.%f").timestamp()
                if ts >= after:
                    return ts
    return None


# ---------------------------------------------------------------- experiments
def e1_e2_e7(net, mode, trials, bulk_bytes):
    h1 = net["h1"]
    before = ctrl_counters(h1)
    setup = []
    for _ in range(trials):
        r = access(h1, WEB)
        setup.append(r.get("ms") if r.get("ok") else None)
        time.sleep(0.2)
    after = ctrl_counters(h1)
    pin = (after.get("packet_in", 0) - before.get("packet_in", 0)) / max(1, trials)
    tput = []
    for _ in range(3):
        r = lab.client(h1, "bench", WEB[0], WEB[1], "--bytes", bulk_bytes, timeout=10)
        tput.append(r.get("mbps") if r.get("ok") else None)
    return {"setup_ms": summary(setup), "setup_raw": setup,
            "throughput_mbps": summary(tput), "throughput_raw": tput,
            "packet_in_per_conn": round(pin, 2)}


def e3_security(net, mode):
    """Each scenario returns True if the attack/misuse was STOPPED by the network."""
    h1, h2, h3, eve = net["h1"], net["h2"], net["h3"], net["eve"]
    res = {}
    # 1 unauthenticated / unknown host reaches protected service
    res["Unauthenticated host -> web"] = not access(h3, WEB).get("ok")
    # 2 student reaches db (h2 logs in as alice=student; static ACL gives 10.0.0.2 web+db)
    lab.client(h2, "login", "alice", "alice123")
    res["Student -> grades DB"] = not access(h2, DB).get("ok")
    # 3 anybody sitting at an authorised machine without logging in
    lab.client(h2, "logout")
    res["No login on an authorised PC -> web"] = not access(h2, WEB).get("ok")
    # 4 access continues after logout
    lab.client(h2, "login", "alice", "alice123")
    lab.client(h2, "logout")
    res["Access after logout"] = not access(h2, WEB).get("ok")
    # 5 stolen token replayed from another machine
    r = lab.client(h2, "login", "alice", "alice123")
    lab.client(h3, "--token", r.get("token", "x"), "status")
    res["Stolen token used from another host"] = not access(h3, WEB).get("ok")
    lab.client(h2, "logout")
    # 6 brute force -> attacker cut off at network level
    lab.client(eve, "bruteforce", "bob", "--attempts", "6", "--delay", "0.05")
    res["Brute-force attacker isolated (network level)"] = not ping_ok(eve, AUTH)
    # 7 port scan -> scanner cut off
    lab.client(net["h4"], "scan", WEB[0], "--ports", "8070-8095")
    time.sleep(0.3)
    res["Port scanner isolated"] = not ping_ok(net["h4"], AUTH)
    return res


def e4_login_scaling(net, sizes, rounds):
    out = {}
    for n in sizes:
        lat, walls, fails = [], [], 0
        hosts = [net[f"h{i}"] for i in range(1, n + 1)]
        for _ in range(rounds):
            t0 = time.time()
            for i, h in enumerate(hosts, 1):
                h.sendCmd(f"{lab.PY} {lab.APP}/client.py --json login user{i:02d} pass{i:02d}")
            for h in hosts:
                o = h.waitOutput()
                try:
                    j = json.loads([x for x in o.splitlines() if x.startswith("{")][-1])
                    if j.get("ok"):
                        lat.append(j["ms"])
                    else:
                        fails += 1
                except (IndexError, ValueError):
                    fails += 1
            walls.append((time.time() - t0) * 1000)
            for h in hosts:
                h.sendCmd(f"{lab.PY} {lab.APP}/client.py --json logout")
            for h in hosts:
                h.waitOutput()
            time.sleep(0.5)
        out[str(n)] = {"login_ms": summary(lat), "failures": fails,
                       "logins_per_s": round(n * rounds / (sum(walls) / 1000), 1)}
        print(f"    N={n:2d}: mean {out[str(n)]['login_ms'].get('mean')} ms, "
              f"p95 {out[str(n)]['login_ms'].get('p95')} ms, failures {fails}", flush=True)
    return out


def e5_revocation(net, mode, trials, how="logout"):
    """Start an echo session, revoke, measure when it stops working."""
    h2, h1 = net["h2"], net["h1"]
    lats = []
    for k in range(trials):
        if mode == "nac":
            lab.client(h2, "login", "bob", "bob123")
            if how == "admin":
                lab.client(h1, "login", "admin", "admin123")   # fresh admin session
        out = f"/tmp/probe_{k}.json"
        if os.path.exists(out):
            os.remove(out)
        h2.cmd(f"{lab.PY} {PERF}/probe.py {WEB[0]} {WEB[1]} {out} 6 &")
        time.sleep(1.0)
        t_revoke = time.time()
        if how == "logout":
            lab.client(h2, "logout")
        else:
            lab.client(h1, "admin", "revoke", "bob")
        deadline = time.time() + 8
        while not os.path.exists(out) and time.time() < deadline:
            time.sleep(0.1)
        time.sleep(0.2)
        try:
            r = json.load(open(out))
        except (OSError, ValueError):
            r = {"cut": False}
        lats.append(round((r["first_fail_send"] - t_revoke) * 1000, 1) if r.get("cut") else None)
        time.sleep(0.5)
    cut = [x for x in lats if x is not None]
    return {"latency_ms": summary(cut), "raw": lats, "cut_count": len(cut), "trials": trials}


def e6_block_times(net):
    eve, h4 = net["eve"], net["h4"]
    t0 = time.time()
    lab.client(eve, "bruteforce", "bob", "--attempts", "6", "--delay", "0.0")
    t_rule = log_time("controller.log", r"BLOCK .*ip=10\.0\.0\.66", after=t0 - 0.01)
    t_detect = log_time("auth.log", r"AUTH_FAIL .*ip=10\.0\.0\.66.*failures_in_window=5",
                        after=t0 - 0.01)
    t1 = time.time()
    lab.client(h4, "scan", WEB[0], "--ports", "8000-8040")
    t_scan = log_time("controller.log", r"BLOCK .*ip=10\.0\.0\.4", after=t1 - 0.01)
    return {"bruteforce_attack_to_block_ms": round((t_rule - t0) * 1000, 1) if t_rule else None,
            "bruteforce_detect_to_rule_ms":
                round((t_rule - t_detect) * 1000, 1) if t_rule and t_detect else None,
            "portscan_start_to_block_ms": round((t_scan - t1) * 1000, 1) if t_scan else None}


def grant_rpc_times(since):
    vals = []
    with open(os.path.join(lab.LOGS, "auth.log")) as f:
        for line in f:
            m = re.search(r"grant_ms=([\d.]+)", line)
            if m and datetime.strptime(line[:23], "%Y-%m-%d %H:%M:%S.%f").timestamp() >= since:
                vals.append(float(m.group(1)))
    return summary(vals)


# ---------------------------------------------------------------- driver
def run_mode(mode, a):
    print(f"\n=== mode: {mode} ===", flush=True)
    for f in ("auth.log", "controller.log"):
        open(os.path.join(lab.LOGS, f), "w").close()
    subprocess.call(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ctrl = lab.start_controller(mode)
    net = lab.build_net(N_CLIENTS, bw=a.bw or None)
    t_start = time.time()
    res = {}
    try:
        lab.start_services(net, ttl=60)
        lab.client(net["h1"], "login", "admin", "admin123")     # admin on h1 (web+db)
        print("  E1/E2/E7 connection setup, throughput, controller load", flush=True)
        res.update(e1_e2_e7(net, mode, a.trials, a.bulk))
        print(f"    setup {res['setup_ms']}\n    tput {res['throughput_mbps']}", flush=True)
        print("  E5 revocation latency", flush=True)
        res["revocation_logout"] = e5_revocation(net, mode, a.rev_trials, "logout")
        if mode == "nac":
            res["revocation_admin"] = e5_revocation(net, mode, a.rev_trials, "admin")
        print(f"    {res['revocation_logout']['latency_ms']} cut "
              f"{res['revocation_logout']['cut_count']}/{a.rev_trials}", flush=True)
        if mode == "nac":
            print("  E4 login latency vs concurrent clients", flush=True)
            res["login_scaling"] = e4_login_scaling(net, a.sizes, a.rounds)
            res["grant_rpc_ms"] = grant_rpc_times(t_start)
            lab.client(net["h1"], "login", "admin", "admin123")
            print("  E6 time to block attackers", flush=True)
            res["block_times"] = e6_block_times(net)
            print(f"    {res['block_times']}", flush=True)
            print("    waiting 31s for blocks to expire before E3", flush=True)
            time.sleep(31)
        print("  E3 security scenarios", flush=True)
        res["security"] = e3_security(net, mode)
        for k, v in res["security"].items():
            print(f"    {'STOPPED ' if v else 'SUCCEEDED'}  {k}", flush=True)
    finally:
        lab.stop_services()
        net.stop()
        lab.stop_controller(ctrl)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bw", type=float, default=20, help="link bandwidth Mbit/s (0 = unshaped)")
    ap.add_argument("--quick", action="store_true", help="fewer repetitions")
    ap.add_argument("--modes", default="open,static,nac")
    a = ap.parse_args()
    a.trials = 10 if a.quick else 20
    a.rev_trials = 3 if a.quick else 5
    a.rounds = 2 if a.quick else 3
    a.sizes = [1, 5, 10, 20]
    a.bulk = 5_000_000 if a.quick else 10_000_000
    setLogLevel("warning")
    os.chdir(lab.ROOT)
    os.makedirs(lab.LOGS, exist_ok=True)
    results = {"meta": {"date": time.strftime("%Y-%m-%d %H:%M:%S"), "bw_mbps": a.bw,
                        "clients": N_CLIENTS, "datapath": lab.ovs_datapath(),
                        "trials": a.trials}}
    for mode in a.modes.split(","):
        results[mode] = run_mode(mode, a)
    os.makedirs(os.path.join(lab.ROOT, "results"), exist_ok=True)
    path = os.path.join(lab.ROOT, "results", "perf_results.json")
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nsaved {path}\nnext: python3 perf/plot_results.py")


if __name__ == "__main__":
    main()
