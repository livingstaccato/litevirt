package grpcapi

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoHandlerHoldsAVMLockAcrossAPeerForward is a source-level guard.
//
// A handler that takes the per-VM (or per-container) process lock and then
// forwards to the owning host still holds that lock for the whole round trip.
// Two nodes with a contradictory view of who owns a VM -- an in-flight
// migration, a stale host_name -- each lock it and forward to the other, and
// both block until the gRPC deadlines fire, with every other operation on that
// VM queued behind them on both hosts.
//
// The three snapshot handlers already spell this rule out ("never hold a
// process lock across a peer RPC"); DeleteVM, CutoverVM and RebuildVM did not
// follow it. A behavioural test cannot reach the arrangement without two real
// daemons and a contradictory database, so the rule is checked where it is
// actually expressible: in the shape of the code.
func TestNoHandlerHoldsAVMLockAcrossAPeerForward(t *testing.T) {
	funcRe := regexp.MustCompile(`\nfunc \(s \*Server\) (\w+)\(`)
	lockRe := regexp.MustCompile(`unlock\s*:=\s*s\.lock(VM|Container)\(`)
	// One or two tabs: a STATEMENT-level release. The closure that defines
	// releaseLock contains `unlock()` three tabs deep, and matching that would
	// let a handler pass by merely declaring the helper it never calls.
	// A trailing comment is allowed, because every call site carries one.
	releaseRe := regexp.MustCompile("^\t{1,2}(releaseLock|releaseLocks|unlock)\\(\\)(\\s*//.*)?$")

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(src)
		locs := funcRe.FindAllStringSubmatchIndex(text, -1)
		for i, loc := range locs {
			end := len(text)
			if i+1 < len(locs) {
				end = locs[i+1][0]
			}
			body := text[loc[0]:end]
			fname := text[loc[2]:loc[3]]

			lines := strings.Split(body, "\n")
			lock, forward, release := -1, -1, -1
			for n, l := range lines {
				if lock < 0 && lockRe.MatchString(l) {
					lock = n
				}
				// lockVM used in a loop (CutoverVM) appends instead.
				if lock < 0 && strings.Contains(l, "s.lockVM(") && strings.Contains(l, "append(") {
					lock = n
				}
				if lock >= 0 && release < 0 && releaseRe.MatchString(l) {
					release = n
				}
				if lock >= 0 && forward < 0 && strings.Contains(l, "s.peerClient(") {
					forward = n
				}
			}
			if lock >= 0 && forward > lock && (release < 0 || release > forward) {
				t.Errorf("%s: %s takes a per-VM lock and forwards to a peer while still "+
					"holding it; release before the forward, as the snapshot handlers do",
					name, fname)
			}
		}
	}
}
