# Demo script

Prepare **three terminals** in the project folder:

```bash
# T1: controller (decisions scroll here live)
./scripts/run_controller.sh
# T2: network + CLI
sudo python3 topology/nac_topo.py --ttl 30
# T3: logs
tail -f logs/auth.log logs/controller.log
```
`--ttl 30` makes the timeout demo quick. Without it the TTL is 60 s, from `policy.json`.
If anything misbehaves: Ctrl-D in T2, `sudo mn -c`, restart T1 and T2.

---

## Part A: core flow (D1, about 5 min)

| # | Type in Mininet | What happens / what to say |
|---|---|---|
| 1 | `h1 nac access 10.0.0.201 8080` | **DENIED.** "h1 is not logged in. The switch has no rule, so the packet goes to the controller, which installs a drop rule." T1 shows `ACCESS_DENIED` |
| 2 | `h1 ping -c2 10.0.0.201` | Fails too: ICMP to protected servers is denied |
| 3 | `h1 ping -c2 10.0.0.100` | Works. "The auth server is the only reachable thing before login (pre-auth zone)" |
| 4 | `sh ovs-ofctl dump-flows s1` | Only auth-zone flows and short drop flows |
| 5 | `h1 nac login alice wrongpw` | AUTH_FAIL, attempts_left=4 (logged in auth.log) |
| 6 | `h1 nac login alice alice123` | AUTH_OK, role=student, services=web. T1 shows `GRANT … proactive_rules=12` |
| 7 | `sh ovs-ofctl dump-flows s1` | **New priority-200 flows** host↔10.0.0.201:8080 with `hard_timeout`. "These were installed because of a socket event" |
| 8 | `h1 nac access 10.0.0.201 8080` | **GRANTED**, banner and echo from the web server |
| 9 | `h1 nac access 10.0.0.202 9090` | **DENIED**: the student role has no DB access |
| 10 | `h2 nac login bob bob123` then `h2 nac access 10.0.0.202 9090` | Faculty gets the DB |
| 11 | `h1 nac logout` then `h1 nac access 10.0.0.201 8080` | **REVOKE**: flows deleted, access gone immediately |

## Part B: full functionality and dynamics (D2, about 10 min)

| # | Command | Point to make |
|---|---|---|
| 12 | `h3 nac login carol carol123` (no keepalive), wait the TTL, then `h3 nac access 10.0.0.201 8080` | **Session timeout** revokes access (`SESSION_EXPIRED`) |
| 13 | `h1 nac login alice alice123 --keepalive &` | Keep-alive renews every TTL/3; access survives past the TTL |
| 14 | `h2 nac login admin admin123` then `h2 nac admin list` | Admin sees sessions, blocked hosts, stats |
| 15 | `h2 nac admin revoke alice` then `h1 nac access 10.0.0.201 8080` | **Admin revocation** cuts alice off |
| 16 | `h2 nac admin stats` | Controller view: grants, per-host **bytes from flow statistics**, packet_in counters |
| 17 | `h3 nac login carol carol123` then `h1 nac --token <carol's token> status` | Stolen token rejected: tokens are bound to their IP (`TOKEN_MISUSE` in log) |
| 18 | `eve nac bruteforce bob` | After 5 failures: **BLOCKED**, later attempts get NO-RESPONSE |
| 19 | `eve ping -c2 10.0.0.100` and `sh ovs-ofctl dump-flows s1 \| grep 1000` | Priority-1000 **drop rule**: the attacker is cut off from the whole network |
| 20 | `h3 nac logout` then `h3 nac scan 10.0.0.201 --ports 8070-8090` | Controller detects the scan **by itself** (`SCAN_DETECTED`), blocks h3, and **pushes an event to the auth server** (`NET_EVENT` in auth.log). Information flows network → application |
| 21 | wait 30 s, `eve ping -c2 10.0.0.100` | Blocks expire automatically |
| 22 | in T3: `sudo pkill -f app/auth_server.py`, wait the TTL, then access | **Fail-closed**: the controller expires grants without the auth server |

## Part C: results (D2)

Show `results/test_report.md` (29/29) and the graphs in `results/` (or the README on GitHub):
- **security matrix**: only dynamic NAC stops all 7 attacks
- **revocation**: active session cut in about 86–86 ms, while baselines never cut it
- **throughput**: identical, so no data-plane cost
- **setup time and controller load**: proactive GRANT flows make connections faster than reactive baselines
- **login scaling**: latency vs 1/5/10/20 simultaneous clients

Optional live run: `sudo python3 tests/run_tests.py` (about 2 min).
