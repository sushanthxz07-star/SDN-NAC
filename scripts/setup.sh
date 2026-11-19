#!/usr/bin/env bash
# One-time setup on Ubuntu 20.04/22.04/24.04 (VM or native).
#   ./scripts/setup.sh
set -e
HERE="$(cd "$(dirname "$0")/.." && pwd)"
echo "[1/4] installing Mininet, Open vSwitch and tools (needs sudo)"
sudo apt-get update -qq
sudo apt-get install -y mininet openvswitch-switch openvswitch-testcontroller \
     python3-matplotlib iperf ethtool net-tools git
"$HERE/scripts/start_ovs.sh"
echo "[2/4] getting POX into ~/pox"
if [ ! -f "$HOME/pox/pox.py" ]; then
  git clone https://github.com/noxrepo/pox.git "$HOME/pox"
fi
echo "[3/4] generating user database (config/users.json)"
python3 "$HERE/tools/make_users.py"
mkdir -p "$HERE/logs" "$HERE/results"; chmod 777 "$HERE/logs"
echo "[4/4] cleaning old Mininet state"
sudo mn -c >/dev/null 2>&1 || true
echo
echo "Done. (On WSL, run ./scripts/start_ovs.sh again after every restart.) Next:"
echo "  terminal 1:  ./scripts/run_controller.sh"
echo "  terminal 2:  sudo python3 topology/nac_topo.py"
echo "  tests:       sudo python3 tests/run_tests.py"
echo "  perf:        sudo python3 perf/run_experiments.py && python3 perf/plot_results.py"
