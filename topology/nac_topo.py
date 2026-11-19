#!/usr/bin/env python3
"""
nac_topo.py - interactive demo network.

Terminal 1:  ./scripts/run_controller.sh          (POX, watch the decisions live)
Terminal 2:  sudo python3 topology/nac_topo.py    (Mininet CLI)

Options:
  --clients N          number of client hosts h1..hN (default 3)
  --ttl S              session lifetime in seconds (default from policy.json = 60)
  --bw MBPS            shape every link with TCLink (e.g. --bw 10)
  --start-controller   also launch POX from this script (logs -> logs/pox_nac.out)
  --mode nac|static|open  controller mode when --start-controller is used

Inside the CLI the short aliases below are available, e.g.
  mininet> h1 nac login alice alice123
  mininet> h1 nac access 10.0.0.201 8080
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mininet.cli import CLI          # noqa: E402
from mininet.log import setLogLevel  # noqa: E402

import lab                            # noqa: E402

BANNER = """
==========================================================================
 SDN Authentication & Network Access Control  -  demo network is up
==========================================================================
 auth 10.0.0.100:5000   web 10.0.0.201:8080   db 10.0.0.202:9090
 clients h1..h{n} (10.0.0.1..)   attacker eve (10.0.0.66)
 users: alice/alice123 (student: web)   bob/bob123 (faculty: web+db)
        admin/admin123 (admin)          carol/carol123 (student)

 Try:
   h1 nac access 10.0.0.201 8080          # DENIED - not logged in
   h1 nac login alice alice123            # authenticate -> GRANT
   h1 nac access 10.0.0.201 8080          # GRANTED
   h1 nac access 10.0.0.202 9090          # DENIED - students can't reach db
   h1 nac status ; h1 nac logout          # logout -> REVOKE
   eve nac bruteforce bob                 # brute force -> host BLOCKED
   h3 nac scan 10.0.0.201 --ports 8070-8090    # port scan -> auto-BLOCK
   sh ovs-ofctl dump-flows s1             # see the flow rules
   sh tail -n 20 logs/controller.log logs/auth.log
==========================================================================
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clients", type=int, default=3)
    ap.add_argument("--ttl", type=int, default=0)
    ap.add_argument("--bw", type=float, default=0)
    ap.add_argument("--start-controller", action="store_true")
    ap.add_argument("--mode", default="nac", choices=["nac", "static", "open"])
    a = ap.parse_args()
    setLogLevel("info")
    os.chdir(lab.ROOT)
    ctrl = lab.start_controller(a.mode) if a.start_controller else None
    if not ctrl and not lab.port_open("127.0.0.1", 6633):
        sys.exit("No controller on 127.0.0.1:6633 - start ./scripts/run_controller.sh first "
                 "or pass --start-controller")
    net = lab.build_net(a.clients, bw=a.bw or None)
    try:
        lab.start_services(net, ttl=a.ttl or None)
        # 'nac' shortcut usable from every host:  mininet> h1 nac login alice alice123
        for h in net.hosts:
            h.cmd(f"alias nac='{lab.PY} {lab.APP}/client.py'")
        print(BANNER.format(n=a.clients))
        CLI(net)
    finally:
        lab.stop_services()
        net.stop()
        lab.stop_controller(ctrl)


if __name__ == "__main__":
    main()
