#!/usr/bin/env bash
# Host sensor collector -- runs INSIDE the Linux VM as root.
# Usage: sudo ./collect.sh [output_dir]
# Produces: <out>/btime.txt, <out>/process.raw, <out>/file.raw, <out>/network.raw,
#           <out>/window.txt (collection time window for sensor telemetry)
# Note (R12): agents may already be running before the sensors start. That is
# a valid deployment state, NOT an error -- their events will be marked
# identity_source=UNKNOWN by the fusion layer. No "sensor first" ordering
# is required.
set -euo pipefail

OUT="${1:-vm_out}"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT"

# Single clock anchor: boot time in epoch seconds (see normalize.py).
grep '^btime' /proc/stat | awk '{print $2}' > "$OUT/btime.txt"

# Collection window: recorded at start, finalized by the trap on stop.
date +%s > "$OUT/window.txt"

# -B none: line-buffered output so partial sessions still normalize.
# Each probe appends to its own raw file; Ctrl-C stops all three.
bpftrace -B none -o "$OUT/process.raw" "$HERE/bpftrace/process.bt" &
P1=$!
bpftrace -B none -o "$OUT/file.raw" "$HERE/bpftrace/file.bt" &
P2=$!
bpftrace -B none -o "$OUT/network.raw" "$HERE/bpftrace/network.bt" &
P3=$!

finish() {
  kill $P1 $P2 $P3 2>/dev/null || true
  date +%s >> "$OUT/window.txt"
}
trap finish INT TERM
echo "collecting into $OUT -- Ctrl-C to stop"
wait
