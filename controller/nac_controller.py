"""
nac_controller.py - POX SDN controller for Authentication & Network Access Control.

Run (from the project root):   ./scripts/run_controller.sh            (mode=nac)
                               ./scripts/run_controller.sh static     (baseline)
                               ./scripts/run_controller.sh open       (no security)

Modes
  nac    : default-deny. Hosts may only reach the auth server (TCP 5000 + ping)
           until the auth server sends GRANT for them. Grants expire, can be
           REVOKEd, and hosts can be BLOCKed (brute force / port scan).
  static : baseline - a fixed IP allow-list from policy.json["static_acl"].
           No authentication, no revocation, no blocking.
  open   : baseline - plain learning switch, everything allowed.

How the controller enforces policy (OpenFlow 1.0)
  * Every switch sends unknown packets to the controller (table-miss).
  * packet_in -> policy check -> ALLOW: install an exact-match flow toward the
    learned port (hard_timeout = remaining session time), or
    DENY: install a short drop flow and log it.
  * GRANT  -> proactively installs host<->service flows on every switch where
    both MAC locations are known, and records the grant.
  * REVOKE -> deletes every flow with nw_src=host or nw_dst=host on all switches.
  * BLOCK  -> priority-1000 drop rule for nw_src=host on all switches (hard timeout).
  * Port-scan detection: too many distinct denied (dst,port) attempts from one
    host in a short window -> automatic BLOCK + event pushed to the auth server.
  * Monitoring: flow statistics are polled every 5 s for per-host byte counts.

Control channel: TCP 127.0.0.1:6699, newline-delimited JSON, used by the
auth server (see app/auth_server.py ControllerLink).
"""

import collections
import json
import os
import socket
import sys
import threading
import time

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
from pox.lib.packet import ethernet, ipv4
from pox.lib.recoco import Timer

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.environ.get("NAC_HOME", os.path.dirname(_HERE)), "app"))
from common import (AUTH_IP, AUTH_PORT, CTRL_HOST, CTRL_PORT, CTRL_SHARED_KEY,  # noqa: E402
                    EventLog, LineReader, ProtocolError, load_json, send_msg)

log = core.getLogger()

PRIO_BLOCK = 1000      # drop everything from a blocked host
PRIO_GRANT = 200       # proactive flows installed at GRANT time
PRIO_ALLOW = 100       # reactive allow flows
PRIO_DENY = 50         # reactive short-lived drop flows
PRIO_IPV6_DROP = 1
ALLOW_IDLE = 15
DENY_HARD = 2          # denied flows are re-evaluated after 2 s
STATS_PERIOD = 5


class NACController(object):
    def __init__(self, mode):
        self.mode = mode
        self.elog = EventLog("controller.log")
        self.policy = load_json("policy.json")
        sd = self.policy["scan_detection"]
        self.scan_max, self.scan_window, self.scan_block = (
            sd["max_denied_flows"], sd["window_seconds"], sd["block_seconds"])
        self.service_ips = {s["ip"] for s in self.policy["services"].values()}
        self.static_acl = {}
        for ip, names in self.policy.get("static_acl", {}).items():
            if not ip.startswith("_"):
                self.static_acl[ip] = {(self.policy["services"][n]["ip"],
                                        self.policy["services"][n]["port"]) for n in names}

        self.mac_to_port = collections.defaultdict(dict)   # dpid -> {mac: port}
        self.ip_to_mac = {}
        self.grants = {}          # host ip -> {"user","services":set((ip,port)),"expires"}
        self.blocked = {}         # host ip -> unblock time
        self.denied_hist = collections.defaultdict(collections.deque)
        self.deny_log_seen = {}   # rate-limit DENY log lines
        self.host_bytes = {}      # ip -> {"tx":..,"rx":..}
        self._bytes_per_switch = {}
        self.counters = collections.Counter()
        self.ctrl_clients = []    # sockets of connected auth servers (for events)
        self.ctrl_lock = threading.Lock()

        core.openflow.addListeners(self)
        Timer(1, self._tick, recurring=True)
        Timer(STATS_PERIOD, self._request_stats, recurring=True)
        threading.Thread(target=self._control_server, daemon=True).start()
        self.elog.log("CONTROLLER_START", mode=mode, control_channel=f"{CTRL_HOST}:{CTRL_PORT}")

    # ================================================================ OpenFlow
    def _handle_ConnectionUp(self, event):
        conn = event.connection
        # drop IPv6 noise (router solicitations etc.)
        conn.send(of.ofp_flow_mod(priority=PRIO_IPV6_DROP,
                                  match=of.ofp_match(dl_type=0x86dd)))
        for ip, until in self.blocked.items():
            self._install_block(conn, ip, max(1, int(until - time.time())))
        self.elog.log("SWITCH_UP", dpid=self._dpid(event.dpid), mode=self.mode)

    def _handle_ConnectionDown(self, event):
        self.mac_to_port.pop(event.dpid, None)
        self.elog.log("SWITCH_DOWN", dpid=self._dpid(event.dpid))

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return
        self.counters["packet_in"] += 1
        dpid, in_port = event.dpid, event.port
        self.mac_to_port[dpid][packet.src] = in_port

        if packet.type == ethernet.ARP_TYPE:
            a = packet.payload
            self.ip_to_mac[str(a.protosrc)] = packet.src
            self._forward(event, packet, install=False)       # ARP always allowed
            return
        if packet.type != ethernet.IP_TYPE:
            return                                            # ignore LLDP/IPv6/...

        ip = packet.payload
        src, dst = str(ip.srcip), str(ip.dstip)
        self.ip_to_mac[src] = packet.src
        allowed, why, hard = self._check(ip, packet)
        if allowed:
            self._forward(event, packet, install=True, hard=hard)
        else:
            self._deny(event, packet, ip, why)

    # ------------------------------------------------------------- policy
    def _svc_allowed(self, host, svc_ip, port):
        if self.mode == "static":
            return (svc_ip, port) in self.static_acl.get(host, ())
        g = self.grants.get(host)
        return bool(g and g["expires"] > time.time() and (svc_ip, port) in g["services"])

    def _has_any_grant(self, host, svc_ip):
        if self.mode == "static":
            return any(s == svc_ip for s, _ in self.static_acl.get(host, ()))
        g = self.grants.get(host)
        return bool(g and g["expires"] > time.time() and any(s == svc_ip for s, _ in g["services"]))

    def _hard_timeout(self, host):
        if self.mode != "nac":
            return 0
        g = self.grants.get(host)
        return max(1, int(g["expires"] - time.time())) if g else 1

    def _check(self, ip, packet):
        """Return (allowed, reason, hard_timeout)."""
        src, dst = str(ip.srcip), str(ip.dstip)
        if self.mode == "open":
            return True, "open-mode", 0
        if src in self.blocked or dst in self.blocked:
            return False, "host-blocked", 0
        t = packet.find("tcp")
        is_icmp = ip.protocol == ipv4.ICMP_PROTOCOL
        # 1. pre-authentication zone: everyone may reach the auth server
        if dst == AUTH_IP and (is_icmp or (t and t.dstport == AUTH_PORT)):
            return True, "auth-zone", 0
        if src == AUTH_IP and (is_icmp or (t and t.srcport == AUTH_PORT)):
            return True, "auth-zone", 0
        # 2. protected services: only with a valid grant (or static ACL)
        if t:
            if self._svc_allowed(src, dst, t.dstport):
                return True, "granted", self._hard_timeout(src)
            if self._svc_allowed(dst, src, t.srcport):
                return True, "granted-reply", self._hard_timeout(dst)
        if is_icmp:
            if self._has_any_grant(src, dst):
                return True, "granted-icmp", self._hard_timeout(src)
            if self._has_any_grant(dst, src):
                return True, "granted-icmp-reply", self._hard_timeout(dst)
        return False, "no-grant", 0

    # ---------------------------------------------------------- forwarding
    def _forward(self, event, packet, install, hard=0):
        out = self.mac_to_port[event.dpid].get(packet.dst)
        if out is None or packet.dst.is_multicast:
            msg = of.ofp_packet_out(data=event.ofp, in_port=event.port)
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            event.connection.send(msg)
            return
        if out == event.port:
            return
        if install:
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match.from_packet(packet, event.port)
            msg.idle_timeout = ALLOW_IDLE
            msg.hard_timeout = hard
            msg.priority = PRIO_ALLOW
            msg.actions.append(of.ofp_action_output(port=out))
            msg.data = event.ofp
            event.connection.send(msg)
            self.counters["flows_installed"] += 1
        else:
            msg = of.ofp_packet_out(data=event.ofp, in_port=event.port)
            msg.actions.append(of.ofp_action_output(port=out))
            event.connection.send(msg)

    def _deny(self, event, packet, ip, why):
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.hard_timeout = DENY_HARD
        msg.priority = PRIO_DENY
        msg.buffer_id = event.ofp.buffer_id          # drop the buffered packet
        event.connection.send(msg)
        self.counters["denied"] += 1
        src, dst = str(ip.srcip), str(ip.dstip)
        t = packet.find("tcp")
        dport = t.dstport if t else ("icmp" if ip.protocol == 1 else ip.protocol)
        key = (src, dst, dport)
        now = time.time()
        if now - self.deny_log_seen.get(key, 0) > 5:
            self.deny_log_seen[key] = now
            self.elog.log("ACCESS_DENIED", src=src, dst=dst, dport=dport, reason=why,
                          switch=self._dpid(event.dpid))
        if self.mode == "nac" and why == "no-grant":
            self._scan_check(src, dst, dport, now)

    def _scan_check(self, src, dst, dport, now):
        if src == AUTH_IP or src in self.service_ips or src in self.blocked:
            return
        hist = self.denied_hist[src]
        hist.append((now, dst, dport))
        while hist and hist[0][0] < now - self.scan_window:
            hist.popleft()
        distinct = len({(d, p) for _, d, p in hist})
        if distinct > self.scan_max:
            self.elog.log("SCAN_DETECTED", src=src, distinct_targets=distinct,
                          window_s=self.scan_window)
            hist.clear()
            self.block(src, self.scan_block, "port-scan")

    # =========================================================== NAC actions
    def grant(self, ip, user, services, ttl):
        if self.mode != "nac":
            return {"ok": True, "note": f"{self.mode} mode ignores grants", "rules": 0}
        if ip in self.blocked:
            return {"ok": False, "error": "host is blocked"}
        svc = {(s["ip"], int(s["port"])) for s in services}
        old = self.grants.get(ip)
        is_new = not old or old["user"] != user or old["services"] != svc
        self.grants[ip] = {"user": user, "services": svc, "expires": time.time() + ttl}
        if is_new:
            self._delete_host_flows(ip)              # clear stale DENY flows
        rules = self._install_grant_flows(ip, svc, ttl)
        self.counters["grants" if is_new else "renewals"] += 1
        self.elog.log("GRANT" if is_new else "GRANT_RENEW", ip=ip, user=user, ttl=ttl,
                      services=";".join(f"{a}:{p}" for a, p in sorted(svc)),
                      proactive_rules=rules)
        return {"ok": True, "rules": rules}

    def _install_grant_flows(self, host, services, ttl):
        """Proactively install host<->service flows where both ends are located."""
        hmac = self.ip_to_mac.get(host)
        n = 0
        for conn in core.openflow.connections:
            ports = self.mac_to_port.get(conn.dpid, {})
            ph = ports.get(hmac) if hmac else None
            for svc_ip, svc_port in services:
                smac = self.ip_to_mac.get(svc_ip)
                ps = ports.get(smac) if smac else None
                if ph is None or ps is None or ph == ps:
                    continue
                rules = [
                    (of.ofp_match(dl_type=0x800, nw_proto=6, nw_src=IPAddr(host),
                                  nw_dst=IPAddr(svc_ip), tp_dst=svc_port), ps),
                    (of.ofp_match(dl_type=0x800, nw_proto=6, nw_src=IPAddr(svc_ip),
                                  nw_dst=IPAddr(host), tp_src=svc_port), ph),
                    (of.ofp_match(dl_type=0x800, nw_proto=1, nw_src=IPAddr(host),
                                  nw_dst=IPAddr(svc_ip)), ps),
                    (of.ofp_match(dl_type=0x800, nw_proto=1, nw_src=IPAddr(svc_ip),
                                  nw_dst=IPAddr(host)), ph),
                ]
                for match, port in rules:
                    fm = of.ofp_flow_mod(match=match, priority=PRIO_GRANT, hard_timeout=ttl)
                    fm.actions.append(of.ofp_action_output(port=port))
                    conn.send(fm)
                    n += 1
        self.counters["flows_installed"] += n
        return n

    def revoke(self, ip, reason="", user=None):
        g = self.grants.pop(ip, None)
        self._delete_host_flows(ip)
        if ip in self.blocked:      # keep the block rule if the host is blocked
            for conn in core.openflow.connections:
                self._install_block(conn, ip, max(1, int(self.blocked[ip] - time.time())))
        self.counters["revokes"] += 1
        self.elog.log("REVOKE", ip=ip, user=(g or {}).get("user", user), reason=reason,
                      had_grant=bool(g))
        return {"ok": True, "had_grant": bool(g)}

    def _delete_host_flows(self, ip):
        for conn in core.openflow.connections:
            for field in ("nw_src", "nw_dst"):
                fm = of.ofp_flow_mod(command=of.OFPFC_DELETE)
                fm.match = of.ofp_match(dl_type=0x800, **{field: IPAddr(ip)})
                conn.send(fm)

    def _install_block(self, conn, ip, seconds):
        fm = of.ofp_flow_mod(priority=PRIO_BLOCK, hard_timeout=seconds,
                             match=of.ofp_match(dl_type=0x800, nw_src=IPAddr(ip)))
        conn.send(fm)          # no actions = drop

    def block(self, ip, seconds, reason):
        if self.mode != "nac":
            return {"ok": False, "error": f"blocking not supported in {self.mode} mode"}
        seconds = max(1, int(seconds))
        self.blocked[ip] = time.time() + seconds
        g = self.grants.pop(ip, None)
        self._delete_host_flows(ip)
        for conn in core.openflow.connections:
            self._install_block(conn, ip, seconds)
        self.counters["blocks"] += 1
        self.elog.log("BLOCK", ip=ip, seconds=seconds, reason=reason, had_grant=bool(g))
        self._push_event({"event": "HOST_BLOCKED", "ip": ip, "seconds": seconds,
                          "reason": reason})
        return {"ok": True}

    def unblock(self, ip, reason="manual"):
        if self.blocked.pop(ip, None) is None:
            return {"ok": True, "note": "was not blocked"}
        for conn in core.openflow.connections:
            fm = of.ofp_flow_mod(command=of.OFPFC_DELETE_STRICT, priority=PRIO_BLOCK,
                                 match=of.ofp_match(dl_type=0x800, nw_src=IPAddr(ip)))
            conn.send(fm)
        self.elog.log("UNBLOCK", ip=ip, reason=reason)
        self._push_event({"event": "HOST_UNBLOCKED", "ip": ip})
        return {"ok": True}

    def stats(self):
        now = time.time()
        return {"ok": True, "mode": self.mode,
                "switches": [self._dpid(c.dpid) for c in core.openflow.connections],
                "grants": [{"ip": ip, "user": g["user"],
                            "expires_in": round(g["expires"] - now, 1),
                            "services": sorted(f"{a}:{p}" for a, p in g["services"]),
                            "bytes": self.host_bytes.get(ip, {})}
                           for ip, g in self.grants.items()],
                "blocked": {ip: round(t - now, 1) for ip, t in self.blocked.items()},
                "counters": dict(self.counters)}

    # =============================================================== timers
    def _tick(self):
        now = time.time()
        for ip, g in list(self.grants.items()):
            if g["expires"] <= now:                 # fail-closed even if auth server is gone
                self.revoke(ip, "grant-expired")
        for ip, until in list(self.blocked.items()):
            if until <= now:
                self.blocked.pop(ip, None)
                self.elog.log("UNBLOCK", ip=ip, reason="block-expired")
                self._push_event({"event": "HOST_UNBLOCKED", "ip": ip})

    def _request_stats(self):
        for conn in core.openflow.connections:
            conn.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

    def _handle_FlowStatsReceived(self, event):
        per = collections.defaultdict(lambda: {"tx": 0, "rx": 0})
        for f in event.stats:
            if f.priority not in (PRIO_ALLOW, PRIO_GRANT):
                continue
            if f.match.nw_src is not None:
                per[str(f.match.nw_src)]["tx"] += f.byte_count
            if f.match.nw_dst is not None:
                per[str(f.match.nw_dst)]["rx"] += f.byte_count
        self._bytes_per_switch[event.connection.dpid] = per
        merged = {}
        for sw in self._bytes_per_switch.values():
            for ip, c in sw.items():
                m = merged.setdefault(ip, {"tx": 0, "rx": 0})
                m["tx"], m["rx"] = max(m["tx"], c["tx"]), max(m["rx"], c["rx"])
        self.host_bytes = merged

    # ======================================================= control channel
    def _control_server(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((CTRL_HOST, CTRL_PORT))
        srv.listen(8)
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=self._control_client, args=(conn, addr),
                             daemon=True).start()

    def _run_in_pox(self, fn, *args, **kw):
        """Execute fn on POX's cooperative thread and wait for the result."""
        done, box = threading.Event(), {}

        def task():
            try:
                box["r"] = fn(*args, **kw)
            except Exception as e:          # report errors to the caller
                log.exception("control command failed")
                box["r"] = {"ok": False, "error": str(e)}
            done.set()
        core.callLater(task)
        if not done.wait(3):
            return {"ok": False, "error": "controller busy"}
        return box["r"]

    def _control_client(self, conn, addr):
        reader = LineReader(conn)
        try:
            hello = reader.read_msg()
            if hello is None:          # port probe (e.g. lab.wait_port), not a client
                return
            if hello.get("cmd") != "HELLO" or hello.get("key") != CTRL_SHARED_KEY:
                send_msg(conn, {"ok": False, "error": "bad key"})
                self.elog.log("CTRL_REJECTED", peer=f"{addr[0]}:{addr[1]}")
                return
            send_msg(conn, {"ok": True, "mode": self.mode})
            with self.ctrl_lock:
                self.ctrl_clients.append(conn)
            self.elog.log("CTRL_CLIENT", peer=f"{addr[0]}:{addr[1]}", role=hello.get("role"))
            while True:
                m = reader.read_msg()
                if m is None:
                    break
                cmd = m.get("cmd")
                if cmd == "GRANT":
                    r = self._run_in_pox(self.grant, m["ip"], m.get("user"),
                                         m.get("services", []), int(m.get("ttl", 60)))
                elif cmd == "REVOKE":
                    r = self._run_in_pox(self.revoke, m["ip"], m.get("reason", ""), m.get("user"))
                elif cmd == "BLOCK":
                    r = self._run_in_pox(self.block, m["ip"], m.get("seconds", 30),
                                         m.get("reason", ""))
                elif cmd == "UNBLOCK":
                    r = self._run_in_pox(self.unblock, m["ip"])
                elif cmd == "STATS":
                    r = self._run_in_pox(self.stats)
                elif cmd == "PING":
                    r = {"ok": True}
                else:
                    r = {"ok": False, "error": "unknown command"}
                r = dict(r, id=m.get("id"))
                with self.ctrl_lock:
                    send_msg(conn, r)
        except (OSError, ProtocolError, KeyError) as e:
            self.elog.log("CTRL_ERROR", peer=addr[0], error=repr(e))
        finally:
            with self.ctrl_lock:
                if conn in self.ctrl_clients:
                    self.ctrl_clients.remove(conn)
            conn.close()

    def _push_event(self, ev):
        with self.ctrl_lock:
            for c in list(self.ctrl_clients):
                try:
                    send_msg(c, ev)
                except OSError:
                    self.ctrl_clients.remove(c)

    @staticmethod
    def _dpid(d):
        return "s%d" % d


def launch(mode="nac"):
    if mode not in ("nac", "static", "open"):
        raise ValueError("mode must be nac, static or open")
    core.registerNew(NACController, mode)
    log.info("NAC controller running in %s mode", mode)
