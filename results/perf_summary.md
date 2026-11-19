# Performance evaluation summary

Run 2026-11-18 17:05:06 · 20 client hosts · links 20 Mbit/s · OVS datapath kernel · 20 trials per point

## Baseline comparison

| Metric | Open (no security) | Static ACL (baseline) | Dynamic NAC (ours) |
|---|---|---|---|
| Connection setup, mean (ms) | 12.27 | 12.89 | 2.68 |
| Throughput, mean (Mbit/s) | 19.13 | 19.15 | 19.18 |
| packet_in per new connection | 14.75 | 15.3 | 6.9 |
| Active session cut after logout | never | never | 86 ms |
| Attack scenarios stopped (of 7) | 0 | 2 | 7 |

## Security scenarios

| Scenario | Open (no security) | Static ACL (baseline) | Dynamic NAC (ours) |
|---|---|---|---|
| Unauthenticated host -> web | **succeeded** | stopped | stopped |
| Student -> grades DB | **succeeded** | **succeeded** | stopped |
| No login on an authorised PC -> web | **succeeded** | **succeeded** | stopped |
| Access after logout | **succeeded** | **succeeded** | stopped |
| Stolen token used from another host | **succeeded** | stopped | stopped |
| Brute-force attacker isolated (network level) | **succeeded** | **succeeded** | stopped |
| Port scanner isolated | **succeeded** | **succeeded** | stopped |

## Dynamic NAC only

| Clients logging in together | mean (ms) | p95 (ms) | failures | logins/s |
|---|---|---|---|---|
| 1 | 14.22 | 14.86 | 0 | 12.1 |
| 5 | 46.06 | 93.23 | 0 | 33.6 |
| 10 | 93.2 | 171.38 | 0 | 37.5 |
| 20 | 122.76 | 194.69 | 0 | 50.6 |

- GRANT round trip auth server → controller → flow rules sent: median 9.8 ms (n=124)
- Admin revoke cuts an active session in 86.26 ms (mean)
- Brute force: attack start → network block rule 167.6 ms; detection → rule 1.0 ms
- Port scan: scan start → automatic block 2458.0 ms

Graphs: setup_time.png, throughput.png, controller_load.png, revocation_latency.png, login_scaling.png, security_matrix.png
