#!/usr/bin/env bash
# Start the POX NAC controller.   Usage: ./scripts/run_controller.sh [nac|static|open]
MODE=${1:-nac}
HERE="$(cd "$(dirname "$0")/.." && pwd)"
for d in "$POX_DIR" "$HOME/pox" "/opt/pox"; do
  if [ -n "$d" ] && [ -f "$d/pox.py" ]; then POX_DIR="$d"; break; fi
done
[ -f "$POX_DIR/pox.py" ] || { echo "POX not found - set POX_DIR or run scripts/setup.sh"; exit 1; }
cd "$POX_DIR"
exec env PYTHONPATH="$HERE/controller" NAC_HOME="$HERE" \
  python3 pox.py log.level --INFO nac_controller --mode="$MODE"
