# Viva preparation: likely questions with short answers

## General / architecture
**Q: What problem does your project solve?**
On a normal network, any connected device can reach every server. We make the network itself enforce identity: until a user authenticates over TCP, the SDN switches drop that host's packets to protected services. The controller opens access only for that user's allowed services and only for the session lifetime.

**Q: Why enforce in the network instead of in each server?**
Servers need no auth code, and unauthenticated packets never reach them (so no attack surface, no port scanning). Policy lives in one place. Access can be revoked mid-connection by deleting flows.

**Q: Walk through what happens when alice logs in.**
HELLO → CHALLENGE (salt, nonce) → AUTH (proof) → server verifies → sends `GRANT {ip, services, ttl}` to POX over the TCP control channel → POX installs 4 flows per service on every switch (TCP both directions + ICMP both directions, `hard_timeout = ttl`) → acks → server replies AUTH_OK with the token.

**Q: How does the auth server talk to the controller?**
Over a persistent TCP socket to 127.0.0.1:6699 with newline-delimited JSON, authenticated by a pre-shared key. Requests carry an `id` so replies can be matched. The controller can also push events (e.g. HOST_BLOCKED after a port scan). The auth host is in Mininet's root namespace so it can reach 127.0.0.1.

## TCP sockets (member 1/3)
**Q: TCP is a byte stream. How do you separate messages?**
Each message is one JSON object terminated by `\n`. `LineReader` buffers `recv()` data and splits on newline. It handles partial and merged messages and rejects lines over 8 KB.

**Q: How do you support many clients?**
One thread per connection, capped at 200 with a semaphore (extra clients get "server busy"). Shared state (sessions, failures, blocks) is protected by an `RLock`. A separate reaper thread expires sessions.

**Q: What error handling is there?**
30 s idle timeout per connection (stops slowloris), 10 s challenge timeout, malformed JSON gets an ERROR reply, unknown message types, controller unreachable (login refused: fail closed), automatic reconnect to the controller and re-sync of live sessions.

**Q: Why TCP, not UDP?**
Authentication needs reliable, ordered delivery and a connection to bind a challenge to. Losing or reordering a challenge/proof would break the login.

## Authentication security (member 1)
**Q: Is the password sent over the network?**
No. We use a SCRAM-SHA-256-style scheme. The client proves it knows PBKDF2(password, salt) by sending `ClientKey XOR HMAC(StoredKey, user:cnonce:snonce)`. The server recovers ClientKey and checks SHA256(ClientKey) == StoredKey.

**Q: What if someone records a login and replays it?**
It fails, because each login uses new random nonces and a challenge can be answered once only.

**Q: What if users.json is stolen?**
It stores only StoredKey/ServerKey, not passwords or ClientKey, so the attacker still cannot produce a valid proof. Offline guessing is slowed by PBKDF2.

**Q: What's server_sig for?**
Mutual authentication: the client checks the server also knows the credentials, so a fake auth server is detected.

**Q: Why the same error for unknown user and wrong password?**
To prevent user enumeration. Unknown users even get a fake but stable salt.

**Q: How does brute-force protection work?**
Failures are counted per source IP in a 60 s sliding window. On the 5th failure the server sends BLOCK to the controller, which installs a priority-1000 drop rule for that IP on every switch for 30 s.

**Q: Weaknesses?**
No TLS, so the token can be sniffed. It is bound to the client IP, but IP spoofing could reuse it. Fixes: TLS via Python's `ssl` module, or binding to MAC and switch port.

## SDN / controller (member 2)
**Q: What's the default behaviour of a switch?**
Unknown packets go to the controller (packet_in). `failMode=secure`, so switches never forward on their own without the controller.

**Q: Explain your policy check.**
Blocked host → deny. To or from the auth server on TCP 5000 or ICMP → allow (pre-auth zone). Valid unexpired grant for (service IP, port) → allow, with the reply direction too. Everything else → deny with a 2 s drop flow, logged as ACCESS_DENIED.

**Q: Proactive vs reactive flows here?**
Both. On GRANT we proactively install host↔service flows on every switch where both MAC locations are known (learned from ARP), so the first packet doesn't hit the controller. Anything else is handled reactively on packet_in.

**Q: How is access revoked?**
`OFPFC_DELETE` (non-strict) with `match(dl_type=IP, nw_src=host)` and `match(nw_dst=host)` on every switch removes all of that host's flows. The next packet goes to the controller and is denied. We measured an active session being cut in about 86–86 ms.

**Q: Why hard_timeout = session TTL?**
Fail-closed. Even if the auth server or controller logic fails, flows die when the session would have. RENEW re-sends GRANT, which re-adds the flows and resets the timeout.

**Q: What does the controller do on its own (dynamic behaviour)?**
Expires grants, unblocks after the block time, detects port scans (more than 8 distinct denied (dst, port) in 10 s → auto-block and event to the auth server), and polls flow statistics every 5 s for per-host byte counts.

**Q: Why priorities 1000/200/100/50?**
Block must beat everything, grants beat reactive flows, denies are lowest. Note: in OpenFlow 1.0 an exact-match flow is treated as highest priority by OVS. That is why REVOKE/BLOCK delete the host's flows first instead of relying only on priority.

**Q: Why OpenFlow 1.0 / POX?**
POX is pure Python (easy to integrate with our Python sockets) and the course uses it. OF1.0 has everything we need: matches on IP and TCP ports, timeouts, delete, and flow stats.

## Mininet / integration (member 3)
**Q: Describe the topology.**
Edge s1 (clients h1–hN and attacker eve), core s2, server switch s3 (auth 10.0.0.100, web 10.0.0.201:8080, db 10.0.0.202:9090). It is a tree, so there are no loops and flooding is safe.

**Q: Where is socket–SDN integration in both directions?**
App → network: login/logout/timeout/brute-force cause GRANT/REVOKE/BLOCK. Network → app: the controller detects a port scan and pushes HOST_BLOCKED, and the auth server kills that host's session.

## Testing and performance (member 4)
**Q: What baselines did you compare with?**
*Open*: a plain learning switch with no security. *Static ACL*: a fixed IP allow-list with no login, no revocation, no blocking (the "static approach").

**Q: Key results?**
NAC stopped 7/7 attack scenarios, static stopped 2/7, open 0/7. Throughput is identical, so there is zero data-plane cost. Connection setup is faster with NAC (about 3 ms vs 13–12 ms) because GRANT flows are proactive (about 6.9 vs about 15 packet_in per connection). Revocation takes about 86–86 ms. Login latency is about 14 ms for 1 client and about 123 ms for 20 simultaneous clients. A brute-force attacker is blocked about 168 ms after the attack starts.

**Q: Why does login latency grow with clients?**
All 20 clients run PBKDF2 at the same moment on one VM's CPU, and the auth server is Python with a GIL. Throughput reaches about 51 logins/s. A real deployment would have separate machines.

**Q: Why does port-scan blocking take about 2.5 s?**
The scanner waits 0.3 s per closed port, and the controller needs more than 8 distinct denied targets in a 10 s window, so it triggers on the 9th port (about 9 × 0.3 s). A lower threshold reacts faster but risks false positives.

**Q: How did you measure revocation latency?**
`perf/probe.py` keeps a TCP session open and sends an echo every 10 ms. We record the revoke time and the send time of the first echo that gets no reply.

**Q: What's the "challenging scenario"?**
Unauthorized access in several forms (brute force, port scan, stolen token, access after logout), plus a service failure: killing the auth server still revokes access on time.
