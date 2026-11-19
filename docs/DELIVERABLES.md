# Deliverables plan: rubric → what to show → where it is

Topic 2: **Authentication and Network Access Control** (TCP). Total 40 marks = D1 (15) + D2 (25).
Final code goes in a GitHub repo with full documentation (this repo).

## Project expectations from the topic sheet: all covered

| Expectation | Where |
|---|---|
| TCP authentication server and clients | `app/auth_server.py`, `app/client.py` |
| Multiple concurrent users | thread per connection (cap 200); test T14; perf E4 (20 simultaneous logins) |
| Authentication sessions and timeouts | token + TTL + RENEW keep-alive + reaper thread; tests T17, T18 |
| Allow/deny access policies | `config/policy.json` roles → services; tests T8–T11 |
| Dynamically install and remove SDN rules | GRANT → 4 flows per service per switch; REVOKE → delete; `ovs-ofctl dump-flows` |
| Authentication and access logs | `logs/auth.log`, `logs/controller.log` |
| Test authorized and unauthorized access | `tests/run_tests.py` (29 cases), perf E3 security matrix |

---

## D1: 15 marks (first review)

| Component (marks) | What to show | Evidence in repo |
|---|---|---|
| Problem understanding & architecture (2) | Problem statement, objectives, architecture diagram, communication flow, expected behaviour (default-deny until login) | README §1–2 (mermaid diagrams) |
| TCP socket implementation (4) | Multi-threaded auth server, length-safe JSON framing (`LineReader`), challenge-response login, error handling (timeouts, malformed JSON, too many connections), concurrent clients | `app/common.py`, `app/auth_server.py` `serve_client()` |
| Mininet + SDN implementation (4) | 3-switch topology, POX controller, default-deny, flow rules with priorities, `dump-flows` | `topology/lab.py`, `controller/nac_controller.py`, README §4 |
| Socket–SDN integration (3) | **Auth event changes the network**: login → GRANT → flows appear; logout → flows disappear. Also show the control channel on :6699 | `ControllerLink` in auth_server, `_control_server` in controller |
| Initial testing & demo (2) | Denied → login → allowed → wrong role denied → logout → denied | `docs/DEMO_SCRIPT.md` part A |

## D2: 25 marks (final)

| Component (marks) | What to show | Evidence |
|---|---|---|
| Complete application functionality (4) | All roles, sessions, renew, logout, admin commands (list/revoke/block/stats), several concurrent users | DEMO_SCRIPT part B; tests T1–T20 |
| **Dynamic SDN functionality (6)** | Grant/revoke on demand, hard timeouts tied to session TTL, automatic **blocking**, controller-side **port-scan detection**, **monitoring** via flow stats, fail-closed expiry | controller `grant/revoke/block/_scan_check/_handle_FlowStatsReceived/_tick` |
| Challenging scenario / robustness (4) | **Unauthorized access** (brute force, port scan, stolen token, access after logout); **service failure** (auth server crash → access still expires) | tests T12, T21–T28 (T29: monitoring) |
| Performance evaluation & comparison (5) | Metrics under multiple conditions (1/5/10/20 clients, three modes) compared with **static ACL and open baselines** | `perf/`, `results/perf_summary.md`, 6 graphs |
| Documentation, final demo & viva (6) | README, reproducible scripts, live demo, every member can explain any part | README, `docs/VIVA_QA.md` |

---

## Suggested split for a 4-person team (equal contribution)

Everyone should still be able to run the whole demo and answer the general viva questions.

| Member | Owns | Explains in viva |
|---|---|---|
| 1 | Auth server: protocol, SCRAM login, sessions/TTL, brute-force, admin | `app/auth_server.py`, `app/common.py` |
| 2 | POX controller: policy check, flow rules, grant/revoke/block, scan detection, monitoring | `controller/nac_controller.py` |
| 3 | Mininet topology, socket↔SDN control channel, client tool, live demo | `topology/`, `app/client.py`, control channel |
| 4 | Test suite, performance experiments, graphs, documentation | `tests/`, `perf/`, `results/`, README |

## Checklist before each review

- [ ] Run `./scripts/setup.sh` on the demo laptop/VM. Then `sudo python3 tests/run_tests.py` should report 29/29.
- [ ] Re-run `sudo python3 perf/run_experiments.py` + `python3 perf/plot_results.py` **on your own VM** so the graphs are your numbers.
- [ ] Push to GitHub (README renders the diagrams and graphs).
- [ ] Rehearse `docs/DEMO_SCRIPT.md` once end-to-end. Have 3 terminals ready: controller, Mininet, `tail -f logs/*.log`.
- [ ] Each member reads their section of `docs/VIVA_QA.md`.
