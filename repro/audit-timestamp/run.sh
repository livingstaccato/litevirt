#!/usr/bin/env bash
# Reproduce and verify the audit-timestamp ordering fix.
#
# Run from anywhere inside a checkout of this branch:
#   bash repro/audit-timestamp/run.sh
# Needs Go 1.26+ (go.mod; GOTOOLCHAIN=auto fetches it), git, make, network
# access to GitHub. Writes nothing inside the checkout: the unfixed base
# worktree and every log go to a temporary directory it prints.
#
# Environment overrides:
#   UPSTREAM_URL  repository the fix targets (added as remote "upstream")
#   RUNS          repetitions for the statistical steps (default 1000)
#   OUT           output directory (default: a new temp dir)
#
# No pipefail: several steps run tests that are EXPECTED to fail on the base,
# and the script records those outcomes instead of stopping on them.
set -eu

UPSTREAM_URL="${UPSTREAM_URL:-https://github.com/colonelpanik/litevirt.git}"
RUNS="${RUNS:-1000}"
TMP_ROOT="${TMPDIR:-/tmp}"
OUT="${OUT:-$(mktemp -d "${TMP_ROOT%/}/audit-timestamp-repro.XXXXXX")}"

AUDIT_FLAKY='^TestAuditChain_IntactAcrossInserts$'
AUDIT_NEW='^TestAuditChain_StampsSortAsTextInTimeOrder$'
STREAM_NEW='^TestStreamEvents_DeliversARowThatArrivesLate$'

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"
mkdir -p "$OUT"
BASE_WT="$OUT/base"
SUMMARY="$OUT/summary.txt"
: > "$SUMMARY"

say() { printf '\n== %s\n' "$*"; }
result() { printf 'RESULT %-4s %s\n' "$1" "$2" | tee -a "$SUMMARY"; }
cleanup() { git -C "$ROOT" worktree remove --force "$BASE_WT" 2>/dev/null || true; }
trap cleanup EXIT

if ! git remote get-url upstream >/dev/null 2>&1; then
	git remote add upstream "$UPSTREAM_URL"
fi
git fetch --quiet upstream main
BASE=$(git merge-base HEAD upstream/main)

say "context"
echo "branch = $(git rev-parse --abbrev-ref HEAD) @ $(git rev-parse --short HEAD)"
echo "base   = $(git rev-parse --short "$BASE") (upstream main this branch is built on)"
echo "fix    = $(git log -1 --format='%h %s' -- internal/)"
echo "go     = $(go version)"
echo "os     = $(uname -srm)"
echo "out    = $OUT"
if [ -n "$(git status --porcelain -- internal cmd)" ]; then
	echo "WARNING: uncommitted changes under internal/ or cmd/ — results describe the working tree, not the branch"
fi
git worktree add --quiet --detach "$BASE_WT" "$BASE"

say "1. flaky test on BASE, $RUNS runs"
(cd "$BASE_WT" && go test ./internal/corrosion/ -run "$AUDIT_FLAKY" -count="$RUNS" -v > "$OUT/1-base-flaky.log" 2>&1) || true
base_fail=$(grep -c '^--- FAIL' "$OUT/1-base-flaky.log" || true)
echo "failures: $base_fail/$RUNS"
if [ "$base_fail" -gt 0 ]; then
	result INFO "base reproduces the flake: $base_fail/$RUNS"
else
	result INFO "base did not flake in $RUNS runs on this host (rate depends on clock resolution; not a failure of the fix)"
fi

say "2. same test on FIX, $RUNS runs"
(go test ./internal/corrosion/ -run "$AUDIT_FLAKY" -count="$RUNS" -v > "$OUT/2-fix-flaky.log" 2>&1) || true
fix_fail=$(grep -c '^--- FAIL' "$OUT/2-fix-flaky.log" || true)
echo "failures: $fix_fail/$RUNS"
if [ "$fix_fail" -eq 0 ]; then result PASS "fix: flaky test 0/$RUNS"; else result FAIL "fix: flaky test still fails $fix_fail/$RUNS"; fi

say "3. cause probe on BASE: stored stamps whenever the chain breaks"
cat > "$BASE_WT/internal/corrosion/zz_repro_probe_test.go" <<'EOF'
package corrosion

import (
	"context"
	"testing"
)

// Same inserts as TestAuditChain_IntactAcrossInserts; on a break, print the
// stored stamps in the order the verifier walks them.
func TestReproProbe_WhyTheChainBreaks(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)
	for i, action := range []string{"vm.create", "vm.start", "vm.stop"} {
		if err := InsertAuditLog(ctx, c, AuditRecord{ID: "row-" + string(rune('a'+i)), Username: "alice",
			HostName: "node-0", Action: action, Target: "vm-1", Detail: "test", Result: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := VerifyAuditChain(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if res.BrokenAt != "" {
		rows, _ := c.Query(ctx, `SELECT id, timestamp FROM audit_log ORDER BY timestamp ASC, id ASC`)
		s := ""
		for _, r := range rows {
			s += " " + r.String("id") + "=" + r.String("timestamp")
		}
		t.Errorf("BROKEN at %s; text order:%s", res.BrokenAt, s)
	}
}

// Fixed stamps, no clock: a trimmed pair must break the chain, a padded pair must not.
func TestReproProbe_FixedStamps(t *testing.T) {
	for _, tc := range []struct{ name, a, b string }{
		{"trimmed .12Z then .125Z", "2026-01-01T00:00:00.12Z", "2026-01-01T00:00:00.125Z"},
		{"trimmed 00Z then 00.5Z", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00.5Z"},
		{"padded .120000000Z then .125000000Z", "2026-01-01T00:00:00.120000000Z", "2026-01-01T00:00:00.125000000Z"},
	} {
		ctx := context.Background()
		c := newAuditTestClient(t)
		for _, r := range []AuditRecord{
			{ID: "row-a", Timestamp: tc.a, Username: "u", HostName: "node-0", Action: "x", Target: "t", Result: "ok"},
			{ID: "row-b", Timestamp: tc.b, Username: "u", HostName: "node-0", Action: "y", Target: "t", Result: "ok"},
		} {
			if err := InsertAuditLog(ctx, c, r); err != nil {
				t.Fatal(err)
			}
		}
		res, err := VerifyAuditChain(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("FIXED %s: BrokenAt=%q", tc.name, res.BrokenAt)
	}
}
EOF
(cd "$BASE_WT" && go test ./internal/corrosion/ -run '^TestReproProbe_WhyTheChainBreaks$' -count="$RUNS" -v > "$OUT/3-cause-probe.log" 2>&1) || true
grep 'BROKEN at' "$OUT/3-cause-probe.log" | sed 's/^ *zz_repro_probe_test.go:[0-9]*: //' > "$OUT/3-cause-breaks.txt" || true
total=$(wc -l < "$OUT/3-cause-breaks.txt" | tr -d ' ')
outoforder=$(grep -vc 'order: row-a=[^ ]* row-b=[^ ]* row-c=' "$OUT/3-cause-breaks.txt" || true)
mixedwidth=$(awk '{n=0; split("", w); for (i=5; i<=NF; i++) { split($i, p, "="); w[length(p[2])]=1 } for (k in w) n++; if (n>1) c++} END {print c+0}' "$OUT/3-cause-breaks.txt")
echo "breaks: $total/$RUNS; out of insert order: $outoforder; unequal stamp widths: $mixedwidth"
head -3 "$OUT/3-cause-breaks.txt"
if [ "$total" -eq 0 ]; then
	result INFO "cause probe: no breaks in $RUNS runs on this host"
elif [ "$outoforder" -eq "$total" ] && [ "$mixedwidth" -eq "$total" ]; then
	result PASS "cause: all $total breaks were stamps of unequal width stored out of insert order"
else
	result FAIL "cause: of $total breaks, $outoforder out of order and $mixedwidth mixed width — some other cause exists"
fi
(cd "$BASE_WT" && go test ./internal/corrosion/ -run '^TestReproProbe_FixedStamps$' -count=1 -v > "$OUT/3-fixed-stamps.log" 2>&1) || true
grep 'FIXED' "$OUT/3-fixed-stamps.log" | sed 's/^ *zz_repro_probe_test.go:[0-9]*: //'
if grep -q 'FIXED trimmed .12Z then .125Z: BrokenAt="row-b"' "$OUT/3-fixed-stamps.log" &&
	grep -q 'FIXED trimmed 00Z then 00.5Z: BrokenAt="row-b"' "$OUT/3-fixed-stamps.log" &&
	grep -q 'FIXED padded .120000000Z then .125000000Z: BrokenAt=""' "$OUT/3-fixed-stamps.log"; then
	result PASS "mechanism: trimmed stamps break the chain on base, padded stamps do not"
else
	result FAIL "mechanism: fixed-stamp probe did not behave as described (see 3-fixed-stamps.log)"
fi
rm "$BASE_WT/internal/corrosion/zz_repro_probe_test.go"

say "4. the two new tests on FIX"
(go test ./internal/corrosion/ -run "$AUDIT_NEW" -count=5 -v > "$OUT/4-audit-new.log" 2>&1) || true
(go test ./internal/grpcapi/ -run "$STREAM_NEW" -count=5 -race -v > "$OUT/4-stream-new.log" 2>&1) || true
grep -E '^--- ' "$OUT/4-audit-new.log" "$OUT/4-stream-new.log" | sed "s|$OUT/||"
for f in 4-audit-new 4-stream-new; do
	pass=$(grep -c '^--- PASS' "$OUT/$f.log" || true)
	# Counted, never excused: a skip here means a test declined to run, which is
	# the failure these tests were rewritten to stop producing.
	skip=$(grep -c '^--- SKIP' "$OUT/$f.log" || true)
	race=$(grep -c 'DATA RACE' "$OUT/$f.log" || true)
	if [ "$pass" -eq 5 ] && [ "$race" -eq 0 ]; then
		result PASS "fix: $f 5/5 passed"
	else
		result FAIL "fix: $f passed $pass/5, skipped $skip, data races $race (see $f.log)"
	fi
done

say "5. the new audit test against the unfixed base"
git show HEAD:internal/corrosion/audit_chain_test.go > "$BASE_WT/internal/corrosion/audit_chain_test.go"
(cd "$BASE_WT" && go test ./internal/corrosion/ -run "$AUDIT_NEW" -count=1 -v > "$OUT/5-audit-new-on-base.log" 2>&1) || true
grep -E '^--- |_test.go:' "$OUT/5-audit-new-on-base.log" || true
if grep -q '^--- FAIL: TestAuditChain_StampsSortAsTextInTimeOrder' "$OUT/5-audit-new-on-base.log"; then
	result PASS "the new audit test fails on the unfixed base"
else
	result FAIL "the new audit test did not fail on the unfixed base (see 5-audit-new-on-base.log)"
fi
echo "(the stream test is not run on base: it needs the poll-interval variable this branch adds)"
git -C "$BASE_WT" checkout --quiet -- internal/corrosion/audit_chain_test.go

say "6. full gate on FIX"
if go build ./... > "$OUT/6-build.log" 2>&1; then result PASS "go build ./..."; else result FAIL "go build ./... (see 6-build.log)"; fi
if go vet ./... > "$OUT/6-vet.log" 2>&1; then result PASS "go vet ./..."; else result FAIL "go vet ./... (see 6-vet.log)"; fi
(go test ./... > "$OUT/6-test.log" 2>&1) || true
failed=$(grep -E '^--- FAIL' "$OUT/6-test.log" | sed 's/^--- FAIL: \([^ ]*\).*/\1/' | sort -u | tr '\n' ' ')
pkgfail=$(grep -cE '^FAIL[[:space:]]' "$OUT/6-test.log" || true)
echo "packages ok: $(grep -c '^ok' "$OUT/6-test.log" || true); failing packages: $pkgfail; failing tests: ${failed:-none}"
if [ "$pkgfail" -eq 0 ]; then
	result PASS "go test ./... — every package ok"
elif [ "$(echo "$failed" | tr ' ' '\n' | grep -cvE '^(TestSIGPIPEDoesNotKillTheProcess)?$' || true)" -eq 0 ] && grep -q '^--- FAIL' "$OUT/6-test.log"; then
	result INFO "go test ./... — only TestSIGPIPEDoesNotKillTheProcess fails (known on macOS; record whether it fails on this OS)"
else
	result FAIL "go test ./... — failing tests: ${failed:-see 6-test.log}"
fi
if BASE_REF=upstream/main make ci-guards > "$OUT/6-ci-guards.log" 2>&1; then
	result PASS "make ci-guards (BASE_REF=upstream/main)"
else
	result FAIL "make ci-guards (see 6-ci-guards.log)"
fi
grep -E 'OK|FAIL' "$OUT/6-ci-guards.log" || true

say "summary ($SUMMARY)"
cat "$SUMMARY"
if grep -q '^RESULT FAIL' "$SUMMARY"; then exit 1; fi
