# Test report

Run: 2026-11-18 17:00:10 - **29/29 passed** (session TTL 8s)

| ID | Scenario | Expected | Result | Detail |
|---|---|---|---|---|
| T1 | Unauthenticated host can reach auth server (ping) | allowed | PASS | auth zone open to everyone |
| T2 | Unauthenticated host -> web:8080 | denied | PASS | dropped by SDN, no flow rule |
| T3 | Unauthenticated host -> ping web | denied | PASS | ICMP dropped |
| T4 | Wrong password | AUTH_FAIL | PASS | {'type': 'AUTH_FAIL', 'reason': 'invalid username or password', 'attempts_left': 4} |
| T5 | Still denied after failed login | denied | PASS |  |
| T6 | Unknown user gets the same generic error | AUTH_FAIL | PASS | {'type': 'AUTH_FAIL', 'reason': 'invalid username or password', 'attempts_left': 3} |
| T7 | Valid login alice (student) | AUTH_OK | PASS | 14.35 ms, services=['web'] |
| T8 | alice -> web:8080 | allowed | PASS |  |
| T9 | alice (student) -> db:9090 | denied | PASS | role has no db |
| T10 | bob (faculty) -> web and db | allowed | PASS |  |
| T11 | Other hosts stay isolated (h3 -> web) | denied | PASS |  |
| T12 | Stolen token replayed from another host | rejected | PASS | {'type': 'ERROR', 'reason': 'token not valid from this address'} |
| T13 | Replayed token gives no network access | denied | PASS |  |
| T14 | 3 users log in simultaneously | all AUTH_OK | PASS |  |
| T15 | All 3 concurrent users can use web | allowed | PASS |  |
| T16 | Logout immediately revokes access (alice) | denied | PASS | checked 2.1s after logout |
| T17 | Session timeout revokes access (carol, no renew) | denied | PASS | SESSION_EXPIRED in auth.log |
| T18 | Keepalive renewals keep access past TTL (bob) | allowed | PASS | RENEW extends grant + flow hard_timeout |
| T19 | Non-admin cannot run admin commands | rejected | PASS |  |
| T20 | Admin revokes bob -> bob loses access | denied | PASS |  |
| T29 | Flow-stats monitoring reports per-host traffic | >= 2 MB rx | PASS | controller sees rx=2004482 bytes for 10.0.0.1 |
| T21 | Brute-force guessing triggers a block | BLOCKED | PASS | results=['AUTH_FAIL', 'AUTH_FAIL', 'AUTH_FAIL', 'AUTH_FAIL', 'BLOCKED', 'NO-RESPONSE(TimeoutError)', 'NO-RESPONSE(TimeoutError)'] |
| T22 | Blocked host cut off at network level (eve -> ping auth) | denied | PASS | priority-1000 drop rule on all switches |
| T23 | Blocked host cannot log in even with the right password | fails | PASS | timed out |
| T24 | Port scan by unauthenticated host is auto-blocked by controller | blocked | PASS | SCAN_DETECTED -> BLOCK -> event to auth server |
| T25 | Auth server was notified of controller's block (socket<-SDN event) | logged | PASS |  |
| T26 | Malformed message -> error reply, server survives | ERROR | PASS | b'{"type":"ERROR","reason":"malformed JSON"}\n' |
| T27 | Block expires automatically (eve can reach auth again) | allowed | PASS |  |
| T28 | Auth server crash -> grants still expire at controller (fail-closed) | denied | PASS | controller-side grant expiry |
