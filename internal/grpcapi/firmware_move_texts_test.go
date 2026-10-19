package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/fwmig"
)

// Lab 2 (a2242e1f4) anomaly 5: --accept-target on a stopped cleanup records
// whether the source's state changed after the cutover, by the marker's
// hashes, never "changed" for a state the cutover left as it was.
//
// Mutation: always write "changed after the cutover" — the unchanged case is
// red.
func TestDoctorAcceptTarget_CleaningReasonSaysWhetherTheStateChanged(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "unchanged", true: "changed"}[changed], func(t *testing.T) {
			r := newFwdRig(t, fwlOpts{})
			run := r.crashAt(fwmig.PhaseReleased)
			cleaningMarker(t, r, run)
			if changed {
				r.write(r.srcStore.NvramPath(fwlVM), []byte("a variable written after the cutover"))
			}
			r.srcFake.SetState(fwlVM, "shutoff")
			if _, err := r.doctor(actAcceptTarget); err != nil {
				t.Fatalf("--accept-target: %v", err)
			}
			q, _ := filepath.Glob(filepath.Join(r.src.dataDir, fwmig.QuarantineDir, fwlVM+"-*"))
			if len(q) != 1 {
				t.Fatalf("quarantine %v, want one", q)
			}
			b, err := os.ReadFile(filepath.Join(q[0], "reason.txt"))
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(string(b), "changed after the cutover"); got != changed {
				t.Errorf("reason says changed=%v, want %v:\n%s", got, changed, b)
			}
			if !changed && !strings.Contains(string(b), "as the cutover left it") {
				t.Errorf("reason does not say the state is as the cutover left it:\n%s", b)
			}
		})
	}
}

// Lab 2 anomaly 6: the planned-state hold's text reads as sentences, each
// with its verb: the cleanup goes on by itself, and --accept-target ends the
// hold now.
//
// Mutation: the round-6 text ("...; `...--accept-target` takes ... ends the
// hold now") — red.
func TestCleanupHoldAction_PlannedStateReads(t *testing.T) {
	a := cleanupTargetHoldAction(fwmig.Marker{VM: fwlVM, Target: "dst-host"},
		&cleanupTargetHold{kind: holdTargetPlanned, why: "the target dst-host is in draining, not active"})
	for _, want := range []string{
		"This is a planned state: the cleanup goes on by itself",
		"To end the hold now, `lv doctor firmware-move <vm> --accept-target` takes the target's copy",
	} {
		if !strings.Contains(a, want) {
			t.Errorf("action %q lacks %q", a, want)
		}
	}
}

// Lab 2 anomaly 9: a host that has not answered a delete's leftovers
// request within the wait is not asked again: the text says the one request
// carries on in the background and is not repeated.
//
// Mutation: the round-6 text ("the delete keeps asking it") — red.
func TestDeletedVMLeftovers_PendingTextIsAccurate(t *testing.T) {
	if strings.Contains(deletedVMLeftoverPendingDetail, "keeps asking") ||
		!strings.Contains(deletedVMLeftoverPendingDetail, "not sent again") {
		t.Errorf("pending detail %q", deletedVMLeftoverPendingDetail)
	}
}
