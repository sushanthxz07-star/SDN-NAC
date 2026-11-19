#!/usr/bin/env bash
# Start Open vSwitch. Works on a normal VM (kernel module) and on WSL/containers
# (no openvswitch kernel module -> userspace datapath; lab.py detects this).
# Run again after every WSL restart:  ./scripts/start_ovs.sh
if sudo ovs-vsctl --timeout=2 show >/dev/null 2>&1 && pgrep -x ovs-vswitchd >/dev/null; then
  echo "Open vSwitch already running"; exit 0
fi
if sudo modprobe openvswitch 2>/dev/null; then
  sudo service openvswitch-switch restart && echo "Open vSwitch started (kernel datapath)" && exit 0
fi
echo "No openvswitch kernel module (normal on WSL) - starting OVS in userspace mode"
sudo mkdir -p /var/run/openvswitch /var/log/openvswitch
sudo /usr/share/openvswitch/scripts/ovs-ctl start --no-ovs-vswitchd --system-id=random
sudo pkill -x ovs-vswitchd 2>/dev/null; sleep 0.5
sudo ovs-vswitchd --pidfile --detach --log-file
sleep 1
sudo ovs-vsctl show >/dev/null && echo "Open vSwitch started (userspace datapath)"
