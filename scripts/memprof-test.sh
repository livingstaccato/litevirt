#!/usr/bin/env bash
# Profile the memory growth of one Go test package, safely.
#
#   scripts/memprof-test.sh [pkg] [cap] [extra test flags...]
#   scripts/memprof-test.sh ./internal/grpcapi 6G
#   scripts/memprof-test.sh ./internal/grpcapi 6G -test.run 'TestBackup'
#
# The test binary runs in its own transient systemd scope with MemoryMax=<cap>
# and no swap, so a runaway kills only the test, never the desktop. No sudo.
#
# Output lands in $OUT (default: /tmp/memprof-<pkg>-<timestamp>/):
#   test.log     -test.v output, each line prefixed with seconds since start
#   rss.tsv      seconds, RSS MB, goroutine-ish thread count, sampled every 1s
#   gc.log       GODEBUG=gctrace=1 lines (live heap after each GC)
#   mem.pprof    heap profile at exit (inuse = what was never released)
#   report.txt   the tests during which RSS grew the most + top of pprof
set -euo pipefail

pkg=${1:-./internal/grpcapi}
cap=${2:-6G}
shift $(( $# >= 2 ? 2 : $# ))

root=$(git rev-parse --show-toplevel)
name=$(basename "$pkg")
OUT=${OUT:-/tmp/memprof-$name-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"

echo "building $pkg -> $OUT/$name.test"
(cd "$root" && go test -c -o "$OUT/$name.test" "$pkg")

# go test runs the binary from the package dir; tests may read testdata/.
cd "$root/$pkg"

start=$(date +%s.%N)
stamp() { while IFS= read -r l; do printf '%7.1f %s\n' "$(echo "$(date +%s.%N) - $start" | bc)" "$l"; done; }

echo "running under MemoryMax=$cap (swap 0)"
set +e
GODEBUG=gctrace=1 systemd-run --user --scope --quiet --collect \
    -p MemoryMax="$cap" -p MemorySwapMax=0 -- \
    "$OUT/$name.test" -test.v -test.count=1 -test.timeout=60m \
    -test.memprofile "$OUT/mem.pprof" "$@" \
    > >(stamp > "$OUT/test.log") 2> >(stamp > "$OUT/gc.log") &
runner=$!

# Find the test process, then sample it.
for _ in $(seq 50); do pid=$(pgrep -n -f "$OUT/$name.test" || true); [[ -n $pid ]] && break; sleep 0.2; done
printf 'sec\trss_mb\tthreads\n' > "$OUT/rss.tsv"
while [[ -n ${pid:-} ]] && kill -0 "$pid" 2>/dev/null; do
    rss=$(awk '/VmRSS/{print int($2/1024)}' /proc/$pid/status 2>/dev/null || echo 0)
    thr=$(awk '/Threads/{print $2}' /proc/$pid/status 2>/dev/null || echo 0)
    printf '%.0f\t%s\t%s\n' "$(echo "$(date +%s.%N) - $start" | bc)" "$rss" "$thr" >> "$OUT/rss.tsv"
    sleep 1
done
wait $runner; rc=$?
set -e
sleep 1  # let the stamp pipes flush

python3 - "$OUT" > "$OUT/report.txt" <<'EOF'
import sys, re, bisect
out = sys.argv[1]
rss = [tuple(map(float, l.split()[:2])) for l in open(f"{out}/rss.tsv").read().splitlines()[1:] if l.strip()]
runs = []  # (start_sec, name)
for l in open(f"{out}/test.log"):
    m = re.match(r'\s*([\d.]+) === RUN\s+(\S+)$', l)
    if m and '/' not in m.group(2):
        runs.append((float(m.group(1)), m.group(2)))
t = [r[0] for r in rss]
def at(s):
    i = bisect.bisect_left(t, s)
    return rss[min(i, len(rss) - 1)][1] if rss else 0
deltas = []
for i, (s, n) in enumerate(runs):
    e = runs[i + 1][0] if i + 1 < len(runs) else (t[-1] if t else s)
    deltas.append((at(e) - at(s), n, s, e))
print(f"samples={len(rss)} tests={len(runs)} peak_rss_mb={max((r[1] for r in rss), default=0):.0f}")
print("\nRSS by elapsed second (every ~10%):")
for k in range(0, len(rss), max(1, len(rss) // 10)):
    print(f"  {rss[k][0]:6.0f}s  {rss[k][1]:6.0f} MB")
print("\nTop 25 tests by RSS growth while running (MB, test, start..end s):")
for d, n, s, e in sorted(deltas, reverse=True)[:25]:
    print(f"  {d:+7.0f}  {n}  {s:.0f}..{e:.0f}")
live = [re.search(r'(\d+)->(\d+)->(\d+) MB', l) for l in open(f"{out}/gc.log")]
live = [int(m.group(3)) for m in live if m]
if live:
    print(f"\nlive heap after GC: first={live[0]}MB max={max(live)}MB last={live[-1]}MB over {len(live)} GCs")
EOF

echo "exit=$rc (137 = killed by the $cap cap)" | tee -a "$OUT/report.txt"
if [[ -s $OUT/mem.pprof ]]; then
    go tool pprof -top -inuse_space -nodecount=30 "$OUT/$name.test" "$OUT/mem.pprof" >> "$OUT/report.txt" 2>&1 || true
else
    echo "no mem.pprof (binary was killed before exit; rerun with a narrower -test.run or a bigger cap)" >> "$OUT/report.txt"
fi
cat "$OUT/report.txt"
echo "artifacts: $OUT"
