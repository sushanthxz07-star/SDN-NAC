#!/usr/bin/env python3
"""plot_results.py - turn results/perf_results.json into graphs + a markdown summary.

    python3 perf/plot_results.py
Outputs results/*.png and results/perf_summary.md (no sudo needed).
"""
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "results")
D = json.load(open(os.path.join(RES, "perf_results.json")))
MODES = [m for m in ("open", "static", "nac") if m in D]
LABEL = {"open": "Open\n(no security)", "static": "Static ACL\n(baseline)",
         "nac": "Dynamic NAC\n(ours)"}
COLOR = {"nac": "#2a78d6", "static": "#eb6834", "open": "#1baf7a"}   # fixed per mode
INK, INK2, GRID, SURF = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"

plt.rcParams.update({
    "figure.facecolor": SURF, "axes.facecolor": SURF, "axes.edgecolor": GRID,
    "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
    "axes.spines.top": False, "axes.spines.right": False, "font.size": 11,
    "axes.titlesize": 13, "axes.titleweight": "bold", "axes.titlecolor": INK,
    "axes.grid": True, "axes.grid.axis": "y", "grid.color": GRID, "grid.linewidth": 0.8,
    "axes.axisbelow": True,
})


def bars(ax, names, values, errs=None, fmt="{:.1f}", unit=""):
    xs = range(len(names))
    b = ax.bar(xs, values, width=0.55, color=[COLOR[n] for n in names],
               yerr=errs, capsize=4, error_kw={"ecolor": INK2, "lw": 1},
               edgecolor=SURF, linewidth=2)
    ax.set_xticks(list(xs), [LABEL[n] for n in names])
    top = max(v + (e or 0) for v, e in zip(values, errs or [0] * len(values))) or 1
    for rect, v, e in zip(b, values, errs or [0] * len(values)):
        ax.text(rect.get_x() + rect.get_width() / 2, v + (e or 0) + top * 0.03,
                fmt.format(v) + unit, ha="center", va="bottom", color=INK, fontsize=11)
    ax.set_ylim(0, top * 1.22)
    return b


def save(fig, name):
    fig.tight_layout()
    fig.savefig(os.path.join(RES, name), dpi=150, bbox_inches="tight", pad_inches=0.2)
    plt.close(fig)
    print("wrote results/" + name)


# 1 connection setup time
fig, ax = plt.subplots(figsize=(7, 4.2))
bars(ax, MODES, [D[m]["setup_ms"]["mean"] for m in MODES],
     [D[m]["setup_ms"]["stdev"] for m in MODES], unit=" ms")
ax.set_title("New TCP connection setup time to protected service")
ax.set_ylabel("milliseconds (mean ± sd)")
save(fig, "setup_time.png")

# 2 throughput
fig, ax = plt.subplots(figsize=(7, 4.2))
bars(ax, MODES, [D[m]["throughput_mbps"]["mean"] for m in MODES],
     [D[m]["throughput_mbps"]["stdev"] for m in MODES], unit=" Mb/s")
ax.set_title(f"Bulk transfer throughput ({D['meta']['bw_mbps']:g} Mbit/s links)")
ax.set_ylabel("Mbit/s (mean ± sd)")
save(fig, "throughput.png")

# 3 controller load
fig, ax = plt.subplots(figsize=(7, 4.2))
bars(ax, MODES, [D[m]["packet_in_per_conn"] for m in MODES])
ax.set_title("Controller load: packet_in messages per new connection")
ax.set_ylabel("packet_in / connection")
save(fig, "controller_load.png")

# 4 revocation latency
if "nac" in D:
    fig, ax = plt.subplots(figsize=(7, 4.2))
    names = ["NAC: user logout", "NAC: admin revoke"]
    vals = [D["nac"]["revocation_logout"]["latency_ms"].get("mean", 0),
            D["nac"]["revocation_admin"]["latency_ms"].get("mean", 0)]
    errs = [D["nac"]["revocation_logout"]["latency_ms"].get("stdev", 0),
            D["nac"]["revocation_admin"]["latency_ms"].get("stdev", 0)]
    b = ax.bar([0, 1], vals, yerr=errs, width=0.55, color=COLOR["nac"], capsize=4,
               error_kw={"ecolor": INK2, "lw": 1}, edgecolor=SURF, linewidth=2)
    top = max(v + e for v, e in zip(vals, errs))
    for rect, v, e in zip(b, vals, errs):
        ax.text(rect.get_x() + rect.get_width() / 2, v + e + top * 0.04,
                f"{v:.0f} ms", ha="center", color=INK)
    base = [m for m in MODES if m != "nac"]
    for i, m in enumerate(base, start=2):
        ax.text(i, top * 0.08, "never cut\n(no revocation)", ha="center", va="bottom",
                color=INK2, fontsize=10)
    ax.set_xticks(list(range(2 + len(base))),
                  names + [LABEL[m].replace("\n", " ") for m in base], fontsize=9)
    ax.set_ylim(0, top * 1.3)
    ax.set_title("Time to cut an ACTIVE session after revocation")
    ax.set_ylabel("milliseconds (mean ± sd)")
    save(fig, "revocation_latency.png")

# 5 login latency vs concurrency
if "nac" in D and "login_scaling" in D["nac"]:
    ls = D["nac"]["login_scaling"]
    ns = sorted(int(k) for k in ls)
    mean = [ls[str(n)]["login_ms"]["mean"] for n in ns]
    p95 = [ls[str(n)]["login_ms"]["p95"] for n in ns]
    fig, ax = plt.subplots(figsize=(7, 4.2))
    ax.plot(ns, mean, color=COLOR["nac"], lw=2, marker="o", ms=8, label="mean",
            markeredgecolor=SURF, markeredgewidth=2)
    ax.plot(ns, p95, color=COLOR["static"], lw=2, marker="s", ms=8, label="95th percentile",
            markeredgecolor=SURF, markeredgewidth=2)
    ax.text(ns[-1], mean[-1], f"  mean {mean[-1]:.0f} ms", va="center", color=INK, fontsize=10)
    ax.text(ns[-1], p95[-1], f"  p95 {p95[-1]:.0f} ms", va="center", color=INK, fontsize=10)
    ax.set_xticks(ns)
    ax.set_xlim(0, ns[-1] * 1.3)
    ax.set_ylim(0, max(p95) * 1.2)
    ax.set_xlabel("clients logging in at the same moment")
    ax.set_ylabel("login latency (ms)")
    ax.set_title("Authentication latency vs concurrent clients")
    ax.legend(frameon=False, loc="upper left")
    save(fig, "login_scaling.png")

# 6 security matrix (figure for slides)
sec_names = list(D[MODES[0]]["security"].keys())
fig, ax = plt.subplots(figsize=(9, 0.42 * len(sec_names) + 0.6))
ax.axis("off")
cells = [[("STOPPED" if D[m]["security"][s] else "succeeded") for m in MODES] for s in sec_names]
tbl = ax.table(cellText=cells, rowLabels=sec_names,
               colLabels=[LABEL[m].replace("\n", " ") for m in MODES], loc="center",
               cellLoc="center")
tbl.auto_set_font_size(False)
tbl.set_fontsize(10)
tbl.scale(1, 1.6)
for (r, c), cell in tbl.get_celld().items():
    cell.set_edgecolor(GRID)
    if r == 0 or c == -1:
        cell.set_text_props(color=INK, weight="bold" if r == 0 else "normal")
    elif cells[r - 1][c] == "STOPPED":
        cell.set_facecolor("#dff3df")
        cell.set_text_props(color="#006300", weight="bold")
    else:
        cell.set_facecolor("#fbe3e3")
        cell.set_text_props(color="#a32020")
ax.set_title("Attack / misuse scenarios: stopped by the network?", pad=12)
save(fig, "security_matrix.png")

# markdown summary
L = [f"# Performance evaluation summary\n",
     f"Run {D['meta']['date']} · {D['meta']['clients']} client hosts · links "
     f"{D['meta']['bw_mbps']:g} Mbit/s · OVS datapath {D['meta']['datapath']} · "
     f"{D['meta']['trials']} trials per point\n",
     "## Baseline comparison\n",
     "| Metric | " + " | ".join(LABEL[m].replace("\n", " ") for m in MODES) + " |",
     "|---|" + "---|" * len(MODES)]
L.append("| Connection setup, mean (ms) | " +
         " | ".join(f"{D[m]['setup_ms']['mean']:.2f}" for m in MODES) + " |")
L.append("| Throughput, mean (Mbit/s) | " +
         " | ".join(f"{D[m]['throughput_mbps']['mean']:.2f}" for m in MODES) + " |")
L.append("| packet_in per new connection | " +
         " | ".join(f"{D[m]['packet_in_per_conn']}" for m in MODES) + " |")
L.append("| Active session cut after logout | " + " | ".join(
    (f"{D[m]['revocation_logout']['latency_ms']['mean']:.0f} ms"
     if D[m]["revocation_logout"]["cut_count"] else "never") for m in MODES) + " |")
stopped = {m: sum(D[m]["security"].values()) for m in MODES}
L.append(f"| Attack scenarios stopped (of {len(sec_names)}) | " +
         " | ".join(str(stopped[m]) for m in MODES) + " |")
L += ["", "## Security scenarios\n", "| Scenario | " + " | ".join(
    LABEL[m].replace("\n", " ") for m in MODES) + " |", "|---|" + "---|" * len(MODES)]
for s in sec_names:
    L.append(f"| {s} | " + " | ".join("stopped" if D[m]["security"][s] else "**succeeded**"
                                      for m in MODES) + " |")
if "nac" in D:
    n = D["nac"]
    L += ["", "## Dynamic NAC only\n", "| Clients logging in together | mean (ms) | p95 (ms) | "
          "failures | logins/s |", "|---|---|---|---|---|"]
    for k, v in sorted(n.get("login_scaling", {}).items(), key=lambda x: int(x[0])):
        L.append(f"| {k} | {v['login_ms']['mean']} | {v['login_ms']['p95']} | "
                 f"{v['failures']} | {v['logins_per_s']} |")
    bt = n.get("block_times", {})
    L += ["", f"- GRANT round trip auth server → controller → flow rules sent: median "
          f"{n['grant_rpc_ms'].get('median')} ms (n={n['grant_rpc_ms'].get('n')})",
          f"- Admin revoke cuts an active session in "
          f"{n['revocation_admin']['latency_ms'].get('mean')} ms (mean)",
          f"- Brute force: attack start → network block rule {bt.get('bruteforce_attack_to_block_ms')} ms; "
          f"detection → rule {bt.get('bruteforce_detect_to_rule_ms')} ms",
          f"- Port scan: scan start → automatic block {bt.get('portscan_start_to_block_ms')} ms",
          "", "Graphs: setup_time.png, throughput.png, controller_load.png, "
          "revocation_latency.png, login_scaling.png, security_matrix.png"]
open(os.path.join(RES, "perf_summary.md"), "w").write("\n".join(L) + "\n")
print("wrote results/perf_summary.md")
