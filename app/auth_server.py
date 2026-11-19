#!/usr/bin/env python3
"""
auth_server.py - TCP Authentication Server (runs on host 'auth', 10.0.0.100:5000)

Responsibilities
  * Authenticate users with a SCRAM-style challenge/response over TCP
  * Support many concurrent clients (one thread per connection, capped)
  * Maintain sessions with a TTL; clients must RENEW before it runs out
  * Enforce role-based allow/deny policy (config/policy.json)
  * Tell the SDN controller to GRANT / REVOKE / BLOCK network access
    over a persistent TCP control channel (127.0.0.1:6699)
  * Detect brute-force password guessing and get the source host blocked
  * Write every authentication / access decision to logs/auth.log

Client protocol (newline-delimited JSON over TCP port 5000)
  C: {"type":"HELLO","user":"alice","cnonce":"<hex>"}
  S: {"type":"CHALLENGE","salt":"..","iters":20000,"snonce":".."}
  C: {"type":"AUTH","proof":"<hex>"}
  S: {"type":"AUTH_OK","token":"..","ttl":60,"role":"student","services":[..],"server_sig":".."}
     {"type":"AUTH_FAIL","reason":"..","attempts_left":n}  |  {"type":"BLOCKED","seconds":n}
  C: {"type":"RENEW","token":".."}   S: {"type":"RENEW_OK","ttl":60}
  C: {"type":"LOGOUT","token":".."}  S: {"type":"BYE"}
  C: {"type":"STATUS","token":".."}  S: {"type":"STATUS","user":..,"remaining":..}
  C: {"type":"ADMIN","token":"..","action":"LIST|REVOKE|BLOCK|UNBLOCK|STATS", ...}
"""

import argparse
import collections
import hashlib
import hmac
import os
import secrets
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (AUTH_PORT, CTRL_HOST, CTRL_PORT, CTRL_SHARED_KEY, EventLog,  # noqa: E402
                    LineReader, ProtocolError, load_json, send_msg, verify_proof)

IDLE_TIMEOUT = 30          # seconds a client connection may sit idle
CHALLENGE_TIMEOUT = 10     # seconds to answer a challenge
MAX_CONNECTIONS = 200      # concurrent client connections


# ==========================================================================
# Control channel to the SDN controller
# ==========================================================================
class ControllerLink:
    """Persistent TCP connection to the POX controller's control server.

    Requests carry an 'id'; a background reader thread matches replies to
    waiting callers and forwards unsolicited events (e.g. HOST_BLOCKED after
    the controller detects a port scan) to on_event().
    """

    def __init__(self, host, port, log, on_event, on_reconnect):
        self.host, self.port, self.log = host, port, log
        self.on_event, self.on_reconnect = on_event, on_reconnect
        self.sock = None
        self.send_lock = threading.Lock()
        self.pending = {}                 # id -> [threading.Event, reply]
        self.next_id = 1
        self.connected = threading.Event()
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while True:
            try:
                s = socket.create_connection((self.host, self.port), timeout=3)
                s.settimeout(None)
                send_msg(s, {"cmd": "HELLO", "key": CTRL_SHARED_KEY, "role": "auth-server"})
                reader = LineReader(s)
                hello = reader.read_msg()
                if not hello or not hello.get("ok"):
                    raise ConnectionError("controller rejected HELLO")
                self.sock = s
                self.connected.set()
                self.log.log("CTRL_CONNECTED", controller=f"{self.host}:{self.port}")
                threading.Thread(target=self.on_reconnect, daemon=True).start()
                while True:
                    msg = reader.read_msg()
                    if msg is None:
                        raise ConnectionError("controller closed connection")
                    if "event" in msg:
                        # own thread: on_event takes the server lock, and a thread
                        # holding that lock may be waiting for a reply read here
                        threading.Thread(target=self.on_event, args=(msg,),
                                         daemon=True).start()
                    elif msg.get("id") in self.pending:
                        slot = self.pending[msg["id"]]
                        slot[1] = msg
                        slot[0].set()
            except (OSError, ProtocolError, ConnectionError) as e:
                if self.connected.is_set():
                    self.log.log("CTRL_DISCONNECTED", error=e)
                self.connected.clear()
                self.sock = None
                for slot in list(self.pending.values()):
                    slot[0].set()        # wake waiters, they will see reply=None
                time.sleep(1)

    def call(self, cmd, timeout=3.0, **fields):
        """Send a command and wait for the controller's reply (None on failure)."""
        if not self.connected.wait(timeout):
            return None
        with self.send_lock:
            rid = self.next_id
            self.next_id += 1
            slot = [threading.Event(), None]
            self.pending[rid] = slot
            try:
                send_msg(self.sock, dict(cmd=cmd, id=rid, **fields))
            except (OSError, AttributeError):
                self.pending.pop(rid, None)
                return None
        slot[0].wait(timeout)
        self.pending.pop(rid, None)
        return slot[1]


class NullControllerLink:
    """Used with --no-controller (unit testing the server outside Mininet)."""

    def call(self, cmd, timeout=3.0, **fields):
        return {"ok": True}


# ==========================================================================
# Authentication server
# ==========================================================================
class AuthServer:
    def __init__(self, args):
        self.args = args
        self.log = EventLog("auth.log")
        self.users = load_json("users.json")
        self.policy = load_json("policy.json")
        self.ttl = args.ttl or self.policy["session_ttl_seconds"]
        bf = self.policy["bruteforce"]
        self.max_fail, self.fail_window, self.block_secs = (
            bf["max_failures"], bf["window_seconds"], bf["block_seconds"])
        self.secret = os.urandom(32)          # for fake salts of unknown users
        self.lock = threading.RLock()
        self.sessions = {}                    # token -> session dict
        self.by_ip = {}                       # ip -> token
        self.by_user = {}                     # user -> token
        self.failures = collections.defaultdict(collections.deque)  # ip -> timestamps
        self.blocked = {}                     # ip -> unblock time
        self.conn_slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.stats = collections.Counter()
        if args.no_controller:
            self.ctrl = NullControllerLink()
        else:
            self.ctrl = ControllerLink(args.ctrl_host, args.ctrl_port, self.log,
                                       self.on_controller_event, self.resync_controller)

    # ------------------------------------------------------------ helpers
    def services_for(self, role):
        names = self.policy["roles"].get(role, [])
        return [dict(name=n, **{k: v for k, v in self.policy["services"][n].items()
                                if k in ("ip", "port")}) for n in names]

    def is_blocked(self, ip):
        with self.lock:
            until = self.blocked.get(ip)
            if until and until > time.time():
                return int(until - time.time()) + 1
            self.blocked.pop(ip, None)
            return 0

    def _drop_session(self, token, reason, notify_controller=True):
        """Remove a session and revoke its network access. Caller holds lock."""
        s = self.sessions.pop(token, None)
        if not s:
            return None
        if self.by_ip.get(s["ip"]) == token:
            del self.by_ip[s["ip"]]
        if self.by_user.get(s["user"]) == token:
            del self.by_user[s["user"]]
        if notify_controller:
            r = self.ctrl.call("REVOKE", ip=s["ip"], user=s["user"], reason=reason)
            ok = bool(r and r.get("ok"))
        else:
            ok = True
        self.log.log("ACCESS_REVOKED", user=s["user"], ip=s["ip"], reason=reason,
                     controller_ack=ok)
        self.stats["revoked"] += 1
        return s

    def _session_for(self, token, ip):
        """Validate a token: must exist, be unexpired and be used from its own IP."""
        s = self.sessions.get(token or "")
        if not s:
            return None, "invalid or expired session"
        if s["ip"] != ip:
            self.log.log("TOKEN_MISUSE", user=s["user"], owner_ip=s["ip"], used_from=ip)
            self.stats["token_misuse"] += 1
            return None, "token not valid from this address"
        return s, None

    def record_failure(self, ip, user, reason):
        now = time.time()
        with self.lock:
            q = self.failures[ip]
            q.append(now)
            while q and q[0] < now - self.fail_window:
                q.popleft()
            count = len(q)
        self.stats["auth_fail"] += 1
        self.log.log("AUTH_FAIL", user=user, ip=ip, reason=reason,
                     failures_in_window=count)
        if count >= self.max_fail:
            self.block_host(ip, self.block_secs, "brute-force")
            return 0
        return self.max_fail - count

    def block_host(self, ip, seconds, reason):
        with self.lock:
            self.blocked[ip] = time.time() + seconds
            self.failures.pop(ip, None)
            tok = self.by_ip.get(ip)
            if tok:
                self._drop_session(tok, f"host-blocked:{reason}")
        r = self.ctrl.call("BLOCK", ip=ip, seconds=seconds, reason=reason)
        self.stats["blocked"] += 1
        self.log.log("HOST_BLOCKED", ip=ip, seconds=seconds, reason=reason,
                     controller_ack=bool(r and r.get("ok")))

    # ------------------------------------------------- controller callbacks
    def on_controller_event(self, ev):
        """Network-side events pushed by the SDN controller."""
        if ev.get("event") == "HOST_BLOCKED":
            ip = ev.get("ip")
            with self.lock:
                self.blocked[ip] = time.time() + ev.get("seconds", self.block_secs)
                tok = self.by_ip.get(ip)
                if tok:
                    self._drop_session(tok, f"controller:{ev.get('reason')}",
                                       notify_controller=False)
            self.log.log("NET_EVENT", kind="HOST_BLOCKED", ip=ip, reason=ev.get("reason"))
        elif ev.get("event") == "HOST_UNBLOCKED":
            with self.lock:
                self.blocked.pop(ev.get("ip"), None)
            self.log.log("NET_EVENT", kind="HOST_UNBLOCKED", ip=ev.get("ip"))

    def resync_controller(self):
        """After (re)connecting, re-install grants for every live session."""
        with self.lock:
            live = list(self.sessions.values())
        for s in live:
            self.ctrl.call("GRANT", ip=s["ip"], user=s["user"], services=s["services"],
                           ttl=max(1, int(s["expires"] - time.time())))
        if live:
            self.log.log("CTRL_RESYNC", sessions=len(live))

    # ------------------------------------------------------- reaper thread
    def reaper(self):
        while True:
            time.sleep(0.5)
            now = time.time()
            with self.lock:
                for tok, s in list(self.sessions.items()):
                    if s["expires"] <= now:
                        self.log.log("SESSION_EXPIRED", user=s["user"], ip=s["ip"])
                        self._drop_session(tok, "timeout")
                for ip, until in list(self.blocked.items()):
                    if until <= now:
                        del self.blocked[ip]
                        self.log.log("HOST_UNBLOCKED", ip=ip)

    # ---------------------------------------------------- message handlers
    def handle_hello(self, conn, ip, msg, state):
        user = str(msg.get("user", ""))[:64]
        cnonce = str(msg.get("cnonce", ""))
        if not user or len(cnonce) < 16:
            return {"type": "ERROR", "reason": "HELLO needs user and cnonce (>=16 hex chars)"}
        creds = self.users.get(user)
        if creds:
            salt, iters = creds["salt"], creds["iters"]
        else:   # unknown user: fake but stable salt so usernames can't be enumerated
            salt = hmac.new(self.secret, user.encode(), hashlib.sha256).hexdigest()[:32]
            iters = 20000
        state["challenge"] = dict(user=user, cnonce=cnonce, snonce=secrets.token_hex(16),
                                  t=time.time())
        return {"type": "CHALLENGE", "salt": salt, "iters": iters,
                "snonce": state["challenge"]["snonce"]}

    def handle_auth(self, conn, ip, msg, state):
        ch = state.pop("challenge", None)       # a challenge can be answered only once
        if not ch:
            return {"type": "ERROR", "reason": "send HELLO first"}
        user = ch["user"]
        if time.time() - ch["t"] > CHALLENGE_TIMEOUT:
            left = self.record_failure(ip, user, "challenge-timeout")
            return {"type": "AUTH_FAIL", "reason": "challenge expired", "attempts_left": left}
        creds = self.users.get(user)
        server_sig = creds and verify_proof(creds, user, ch["cnonce"], ch["snonce"],
                                            msg.get("proof"))
        if not server_sig:
            left = self.record_failure(ip, user, "bad-credentials" if creds else "unknown-user")
            if left == 0:
                return {"type": "BLOCKED", "seconds": self.block_secs,
                        "reason": "too many failed attempts"}
            return {"type": "AUTH_FAIL", "reason": "invalid username or password",
                    "attempts_left": left}

        role = creds["role"]
        services = self.services_for(role)
        with self.lock:
            # one session per user and one per IP: newest login wins
            for old in {self.by_user.get(user), self.by_ip.get(ip)} - {None}:
                self._drop_session(old, "replaced-by-new-login")
            self.failures.pop(ip, None)
        t0 = time.time()
        r = self.ctrl.call("GRANT", ip=ip, user=user, services=services, ttl=self.ttl)
        grant_ms = (time.time() - t0) * 1000
        if not (r and r.get("ok")):
            self.log.log("AUTH_DENIED", user=user, ip=ip, reason="controller-unavailable")
            return {"type": "AUTH_FAIL", "reason": "network controller unavailable, try again",
                    "attempts_left": self.max_fail}
        token = secrets.token_hex(16)
        now = time.time()
        with self.lock:
            self.sessions[token] = dict(user=user, role=role, ip=ip, services=services,
                                        created=now, expires=now + self.ttl, renewals=0)
            self.by_ip[ip] = token
            self.by_user[user] = token
        self.stats["auth_ok"] += 1
        self.log.log("AUTH_OK", user=user, role=role, ip=ip,
                     services=",".join(s["name"] for s in services) or "none")
        self.log.log("ACCESS_GRANTED", user=user, ip=ip, ttl=self.ttl,
                     rules_installed=r.get("rules", "?"), grant_ms=f"{grant_ms:.1f}")
        return {"type": "AUTH_OK", "token": token, "ttl": self.ttl, "role": role,
                "services": services, "server_sig": server_sig}

    def handle_renew(self, conn, ip, msg, state):
        with self.lock:
            s, err = self._session_for(msg.get("token"), ip)
            if err:
                return {"type": "ERROR", "reason": err}
            s["expires"] = time.time() + self.ttl
            s["renewals"] += 1
        self.ctrl.call("GRANT", ip=ip, user=s["user"], services=s["services"], ttl=self.ttl)
        self.log.log("SESSION_RENEW", user=s["user"], ip=ip, renewals=s["renewals"])
        return {"type": "RENEW_OK", "ttl": self.ttl}

    def handle_logout(self, conn, ip, msg, state):
        with self.lock:
            s, err = self._session_for(msg.get("token"), ip)
            if err:
                return {"type": "ERROR", "reason": err}
            self.log.log("LOGOUT", user=s["user"], ip=ip)
            self._drop_session(msg["token"], "logout")
        return {"type": "BYE"}

    def handle_status(self, conn, ip, msg, state):
        with self.lock:
            s, err = self._session_for(msg.get("token"), ip)
            if err:
                return {"type": "ERROR", "reason": err}
            return {"type": "STATUS", "user": s["user"], "role": s["role"], "ip": s["ip"],
                    "remaining": round(s["expires"] - time.time(), 1),
                    "services": s["services"]}

    def handle_admin(self, conn, ip, msg, state):
        with self.lock:
            s, err = self._session_for(msg.get("token"), ip)
            if err:
                return {"type": "ERROR", "reason": err}
            if s["role"] not in self.policy["admin_roles"]:
                self.log.log("ADMIN_DENIED", user=s["user"], ip=ip, action=msg.get("action"))
                return {"type": "ERROR", "reason": "admin role required"}
        action = str(msg.get("action", "")).upper()
        self.log.log("ADMIN_ACTION", admin=s["user"], ip=ip, action=action,
                     target=msg.get("user") or msg.get("ip") or "-")
        if action == "LIST":
            with self.lock:
                rows = [dict(user=x["user"], role=x["role"], ip=x["ip"],
                             remaining=round(x["expires"] - time.time(), 1))
                        for x in self.sessions.values()]
                blocked = {k: round(v - time.time(), 1) for k, v in self.blocked.items()}
            return {"type": "ADMIN_OK", "sessions": rows, "blocked": blocked,
                    "stats": dict(self.stats)}
        if action == "REVOKE":
            with self.lock:
                tok = self.by_user.get(msg.get("user"))
                if not tok:
                    return {"type": "ERROR", "reason": "no active session for that user"}
                self._drop_session(tok, f"revoked-by-admin:{s['user']}")
            return {"type": "ADMIN_OK", "revoked": msg.get("user")}
        if action == "BLOCK":
            self.block_host(msg.get("ip"), int(msg.get("seconds", self.block_secs)),
                            f"admin:{s['user']}")
            return {"type": "ADMIN_OK", "blocked": msg.get("ip")}
        if action == "UNBLOCK":
            with self.lock:
                self.blocked.pop(msg.get("ip"), None)
            r = self.ctrl.call("UNBLOCK", ip=msg.get("ip"))
            self.log.log("HOST_UNBLOCKED", ip=msg.get("ip"), by=s["user"])
            return {"type": "ADMIN_OK", "unblocked": msg.get("ip"), "controller": r}
        if action == "STATS":
            r = self.ctrl.call("STATS")
            return {"type": "ADMIN_OK", "controller": r}
        return {"type": "ERROR", "reason": "unknown admin action"}

    HANDLERS = {"HELLO": handle_hello, "AUTH": handle_auth, "RENEW": handle_renew,
                "LOGOUT": handle_logout, "STATUS": handle_status, "ADMIN": handle_admin}

    # -------------------------------------------------- connection thread
    def serve_client(self, conn, addr):
        ip = addr[0]
        state = {}
        try:
            conn.settimeout(IDLE_TIMEOUT)
            left = self.is_blocked(ip)
            if left:
                self.log.log("CONN_REJECTED", ip=ip, reason="host-blocked", seconds_left=left)
                send_msg(conn, {"type": "BLOCKED", "seconds": left})
                return
            reader = LineReader(conn)
            while True:
                msg = reader.read_msg()
                if msg is None:
                    break
                mtype = str(msg.get("type", "")).upper()
                if mtype == "PING":
                    send_msg(conn, {"type": "PONG"})
                    continue
                handler = self.HANDLERS.get(mtype)
                if not handler:
                    send_msg(conn, {"type": "ERROR", "reason": f"unknown type '{mtype}'"})
                    continue
                if mtype in ("HELLO", "AUTH") and self.is_blocked(ip):
                    send_msg(conn, {"type": "BLOCKED", "seconds": self.is_blocked(ip)})
                    break
                reply = handler(self, conn, ip, msg, state)
                send_msg(conn, reply)
                if reply.get("type") == "BLOCKED":
                    break
        except socket.timeout:
            self.log.log("CONN_TIMEOUT", ip=ip)
        except ProtocolError as e:
            self.log.log("PROTOCOL_ERROR", ip=ip, error=e)
            try:
                send_msg(conn, {"type": "ERROR", "reason": str(e)})
            except OSError:
                pass
        except OSError:
            pass
        finally:
            conn.close()
            self.conn_slots.release()

    def serve_forever(self):
        threading.Thread(target=self.reaper, daemon=True).start()
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.args.host, self.args.port))
        srv.listen(128)
        self.log.log("SERVER_START", listen=f"{self.args.host}:{self.args.port}",
                     ttl=self.ttl, users=len(self.users))
        while True:
            conn, addr = srv.accept()
            if not self.conn_slots.acquire(blocking=False):
                send_msg(conn, {"type": "ERROR", "reason": "server busy"})
                conn.close()
                self.log.log("CONN_REJECTED", ip=addr[0], reason="too-many-connections")
                continue
            threading.Thread(target=self.serve_client, args=(conn, addr), daemon=True).start()


def main():
    p = argparse.ArgumentParser(description="TCP authentication server for SDN NAC")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=AUTH_PORT)
    p.add_argument("--ttl", type=int, default=0, help="session TTL seconds (default: policy.json)")
    p.add_argument("--ctrl-host", default=CTRL_HOST)
    p.add_argument("--ctrl-port", type=int, default=CTRL_PORT)
    p.add_argument("--no-controller", action="store_true",
                   help="run without an SDN controller (local testing only)")
    AuthServer(p.parse_args()).serve_forever()


if __name__ == "__main__":
    main()
