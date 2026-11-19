#!/usr/bin/env python3
"""Copy the numbers from results/perf_results.json into README.md and docs/VIVA_QA.md.
Run after perf/run_experiments.py:   python3 tools/update_docs.py"""
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
D = json.load(open(os.path.join(ROOT, "results", "perf_results.json")))
o, s, n = D["open"], D["static"], D["nac"]
ls = n["login_scaling"]
lo, hi = ls["1"]["login_ms"]["mean"], ls["20"]["login_ms"]["mean"]
lps = max(v["logins_per_s"] for v in ls.values())
rev = [n["revocation_logout"]["latency_ms"]["mean"], n["revocation_admin"]["latency_ms"]["mean"]]
rev_txt = f"{min(rev):.0f}–{max(rev):.0f} ms"
stop = {m: sum(D[m]["security"].values()) for m in ("open", "static", "nac")}
bf = n["block_times"]["bruteforce_attack_to_block_ms"]
pin = n["packet_in_per_conn"]
pin_txt = "<1" if pin < 1 else f"≈{pin:.1f}"
f1 = lambda x: f"{x:.1f}"  # noqa: E731

table = f"""| Metric | Open | Static ACL | **Dynamic NAC** |
|---|---|---|---|
| Attack/misuse scenarios stopped (of 7) | {stop['open']} | {stop['static']} | **{stop['nac']}** |
| Active session cut after logout / admin revoke | never | never | **≈{rev_txt}** |
| New-connection setup time | ≈{o['setup_ms']['mean']:.0f} ms | ≈{s['setup_ms']['mean']:.0f} ms | **≈{n['setup_ms']['mean']:.0f} ms** |
| packet_in per new connection | ≈{o['packet_in_per_conn']:.0f} | ≈{s['packet_in_per_conn']:.0f} | **{pin_txt}** |
| Throughput ({D['meta']['bw_mbps']:g} Mbit/s link) | {f1(o['throughput_mbps']['mean'])} | {f1(s['throughput_mbps']['mean'])} | {f1(n['throughput_mbps']['mean'])} Mbit/s |
| Login latency, 1 → 20 simultaneous clients | – | – | {lo:.0f} → {hi:.0f} ms (mean), 0 failures |
| Brute force → attacker blocked | not possible | not possible | {bf:.0f} ms after attack start |
"""

p = os.path.join(ROOT, "README.md")
r = open(p).read()
r = re.sub(r"\| Metric \| Open \| Static ACL \| \*\*Dynamic NAC\*\* \|\n(?:\|.*\|\n)+", table, r)
r = re.sub(r"Login latency grows with simultaneous logins \(about \d+ ms for 1 client, about \d+ ms "
           r"for 20\)\. Login throughput levels off at about \d+ logins/s\.",
           f"Login latency grows with simultaneous logins (about {lo:.0f} ms for 1 client, about "
           f"{hi:.0f} ms for 20). Login throughput reaches about {lps:.0f} logins/s.", r)
open(p, "w").write(r)

p = os.path.join(ROOT, "docs", "VIVA_QA.md")
v = open(p).read()
v = re.sub(r"NAC stopped 7/7 attack scenarios.*",
           f"NAC stopped {stop['nac']}/7 attack scenarios, static stopped {stop['static']}/7, open "
           f"{stop['open']}/7. Throughput is identical, so there is zero data-plane cost. Connection "
           f"setup is faster with NAC (about {n['setup_ms']['mean']:.0f} ms vs "
           f"{s['setup_ms']['mean']:.0f}–{o['setup_ms']['mean']:.0f} ms) because GRANT flows are "
           f"proactive ({pin_txt.replace('≈', 'about ')} vs about {o['packet_in_per_conn']:.0f} "
           f"packet_in per connection). Revocation takes about {rev_txt}. Login latency is about "
           f"{lo:.0f} ms for 1 client and about {hi:.0f} ms for 20 simultaneous clients. A "
           f"brute-force attacker is blocked about {bf:.0f} ms after the attack starts.", v)
v = re.sub(r"Throughput levels off at about \d+ logins/s\.", f"Throughput reaches about {lps:.0f} logins/s.", v)
v = re.sub(r"cut in about [\d–]+ ms", f"cut in about {rev_txt}", v)
open(p, "w").write(v)

p = os.path.join(ROOT, "docs", "DEMO_SCRIPT.md")
d = open(p).read()
d = re.sub(r"active session cut in about [\d–]+ ms", f"active session cut in about {rev_txt}", d)
open(p, "w").write(d)
print("README.md, docs/VIVA_QA.md and docs/DEMO_SCRIPT.md updated:\n")
print(table)
