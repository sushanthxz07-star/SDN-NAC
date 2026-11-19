"""
lab.py - builds the Mininet network and starts every component.

Topology (all hosts in 10.0.0.0/24):

     h1 .. hN (10.0.0.1..N)                      auth  10.0.0.100  (TCP 5000)
     eve      (10.0.0.66, attacker)    s1 ── s2 ── s3   web   10.0.0.201  (TCP 8080)
                                      (edge) (core) (server) db    10.0.0.202  (TCP 9090)

  * s1/s2/s3 are Open vSwitch switches controlled by POX (OpenFlow 1.0).
  * 'auth' is placed in the ROOT network namespace so that the auth server
    can reach the controller's control channel at 127.0.0.1:6699 while still
    being an ordinary host on the data plane for the clients.
"""
import json
import os
import shlex
import socket
import subprocess
import sys
import time

from mininet.link import Link, TCLink
from mininet.log import info
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "app")
LOGS = os.path.join(ROOT, "logs")
PY = sys.executable or "python3"

AUTH_IP, WEB_IP, DB_IP, EVE_IP = "10.0.0.100", "10.0.0.201", "10.0.0.202", "10.0.0.66"


def find_pox():
    for d in (os.environ.get("POX_DIR"), os.path.expanduser("~/pox"),
              os.path.join(os.environ.get("SUDO_USER") and
                           os.path.expanduser("~" + os.environ["SUDO_USER"]) or "/", "pox"),
              "/opt/pox"):
        if d and os.path.exists(os.path.join(d, "pox.py")):
            return d
    sys.exit("POX not found. Set POX_DIR=/path/to/pox (git clone https://github.com/noxrepo/pox)")


def port_open(host, port):
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def wait_port(host, port, timeout=15):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if port_open(host, port):
            return True
        time.sleep(0.2)
    return False


def start_controller(mode="nac"):
    """Launch POX with our component; returns the Popen handle."""
    pkill("nac_controller --mode")
    time.sleep(0.5)
    pox = find_pox()
    os.makedirs(LOGS, exist_ok=True)
    env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "controller"), NAC_HOME=ROOT)
    out = open(os.path.join(LOGS, f"pox_{mode}.out"), "w")
    p = subprocess.Popen([PY, os.path.join(pox, "pox.py"), "log.level", "--WARNING",
                          "nac_controller", f"--mode={mode}"],
                         cwd=pox, env=env, stdout=out, stderr=subprocess.STDOUT)
    if not (wait_port("127.0.0.1", 6633) and wait_port("127.0.0.1", 6699)):
        p.kill()
        sys.exit(f"controller failed to start - see logs/pox_{mode}.out")
    return p


def stop_controller(p):
    if p:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()


def ovs_datapath():
    """Kernel OVS if the module is loaded (normal VM), else userspace (containers)."""
    return "kernel" if os.path.exists("/sys/module/openvswitch") else "user"


def build_net(n_clients=3, bw=None, datapath=None):
    datapath = datapath or ovs_datapath()
    link_opts = {"bw": bw} if bw else {}
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink if bw else Link,
                  autoSetMacs=True, ipBase="10.0.0.0/24", build=False)
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6633)
    sw = {name: net.addSwitch(name, datapath=datapath, protocols="OpenFlow10",
                              failMode="secure")
          for name in ("s1", "s2", "s3")}
    for i in range(1, n_clients + 1):
        h = net.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
        net.addLink(h, sw["s1"], **link_opts)
    net.addLink(net.addHost("eve", ip=f"{EVE_IP}/24"), sw["s1"], **link_opts)
    net.addLink(sw["s1"], sw["s2"], **link_opts)
    net.addLink(sw["s2"], sw["s3"], **link_opts)
    net.addLink(net.addHost("auth", ip=f"{AUTH_IP}/24", inNamespace=False), sw["s3"], **link_opts)
    net.addLink(net.addHost("web", ip=f"{WEB_IP}/24"), sw["s3"], **link_opts)
    net.addLink(net.addHost("db", ip=f"{DB_IP}/24"), sw["s3"], **link_opts)
    net.build()
    net.start()
    if datapath == "user":
        # userspace OVS does not fill in offloaded TCP checksums -> turn offload off
        for h in net.hosts:
            for intf in h.intfNames():
                h.cmd(f"ethtool -K {intf} tx off rx off >/dev/null 2>&1")
    # wait until all switches are connected to the controller
    t0 = time.time()
    while time.time() - t0 < 20:
        if all(s.connected() for s in net.switches):
            break
        time.sleep(0.3)
    return net


def start_services(net, ttl=None):
    """Start auth server (root ns), protected services, and announce the servers."""
    stop_services()
    subprocess.call(["rm", "-rf", "/tmp/nac_tokens"])
    ttl_arg = f"--ttl {ttl}" if ttl else ""
    net["web"].cmd(f"{PY} {APP}/service_server.py --port 8080 --name web "
                   f"> {LOGS}/web.out 2>&1 &")
    net["db"].cmd(f"{PY} {APP}/service_server.py --port 9090 --name db "
                  f"> {LOGS}/db.out 2>&1 &")
    net["auth"].cmd(f"{PY} {APP}/auth_server.py --host {AUTH_IP} {ttl_arg} "
                    f"> {LOGS}/auth_server.out 2>&1 &")
    if not wait_port(AUTH_IP, 5000, 15):
        info("*** WARNING: auth server did not start, see logs/auth_server.out\n")
    time.sleep(1.0)        # let the auth server connect to the controller
    # servers ping the auth server once (allowed pre-auth) so every switch
    # learns where they are -> GRANTs can install flows proactively
    for h in ("web", "db"):
        net[h].cmd(f"ping -c1 -W1 {AUTH_IP} > /dev/null")
    for h in net.hosts:
        if h.name.startswith("h") or h.name == "eve":
            h.cmd(f"ping -c1 -W1 {AUTH_IP} > /dev/null &")
    time.sleep(1.0)


def pkill(pattern):
    # argument list, no shell: a shell's own command line would match the pattern
    subprocess.call(["pkill", "-f", pattern])


def stop_services():
    # full absolute path: only matches our python processes, not editors/terminals
    for name in ("auth_server.py", "service_server.py", "client.py"):
        pkill(os.path.join(APP, name))


def client(host, *args, timeout=None):
    """Run app/client.py on a Mininet host with --json; return the parsed result."""
    t = f"--timeout {timeout} " if timeout else ""
    cmd = f"{PY} {APP}/client.py --json {t}" + " ".join(shlex.quote(str(a)) for a in args)
    out = host.cmd(cmd)
    for line in reversed(out.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                pass
    return {"ok": False, "raw": out.strip()}
