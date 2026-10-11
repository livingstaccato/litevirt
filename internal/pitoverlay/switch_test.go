package pitoverlay

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// The pit_overlay release-token switch, and the residuals of the #256
// re-review 5 that block opening it.

// A new window is the feature's first data: OpenWindow writes nothing
// without the pit_overlay grant, and another feature's grant is not it.
//
// Mutation "writer unchecked" (OpenWindow does not Check its grant) — red.
func TestOpenWindow_NeedsThePITOverlayGrant(t *testing.T) {
	disk := filepath.Join(t.TempDir(), "web-root.qcow2")
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	wrote := 0
	prev := setXattr
	setXattr = func(p string, v []byte) error { wrote++; return prev(p, v) }
	defer func() { setXattr = prev }()
	for _, g := range []capabilities.FeatureGrant{{}, capabilities.GrantForTest(t, capabilities.FeatureVMLimits)} {
		if _, err := OpenWindow(g, disk); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
			t.Fatalf("OpenWindow with grant %q = %v, want ErrNoFeatureGrant", g.Feature(), err)
		}
	}
	if wrote != 0 {
		t.Fatalf("a window token was written %d time(s) without the pit_overlay grant", wrote)
	}
	if _, err := OpenWindow(grant(t), disk); err != nil {
		t.Fatalf("OpenWindow with the pit_overlay grant: %v", err)
	}
	if wrote != 1 {
		t.Fatalf("window token writes = %d, want 1", wrote)
	}
}

// P3: below the feature the verdict is still the full one — the admin
// decides from it — and the advice says why nothing was settled, without
// naming a host that cannot exist.
//
// Mutation "verdict withheld below the feature" (AssessAt returns unknown
// when the gate is closed) — red.
func TestAssessAt_BelowTheFeatureGivesTheFullVerdict(t *testing.T) {
	needQemu(t)
	disk := window(t)
	a := AssessAt(closedGate, disk, owner, false)
	if a.Verdict != Matches || !a.BelowFeature {
		t.Fatalf("below the feature: verdict %s below %v (%s), want matches, below", a.Verdict, a.BelowFeature, a.Reason)
	}
	advice := HoldAdvice("web", "root", a)
	for _, want := range []string{"pit_overlay needs " + capabilities.ReleaseToken, "lv cluster upgrade-status", "--commit --confirm"} {
		if !strings.Contains(advice, want) {
			t.Errorf("advice %q lacks %q", advice, want)
		}
	}
	if strings.Contains(advice, "upgraded host") {
		t.Errorf("advice names a host that cannot exist: %q", advice)
	}
	if d := HoldDetail("web", "root", disk, a); !strings.Contains(d, "verdict matches") || strings.Contains(d, "cannot be verified") {
		t.Errorf("hold detail %q: want the verdict, not 'cannot be verified'", d)
	}
	if b := AssessAt(openGate, disk, owner, false); b.BelowFeature || b.Verdict != Matches {
		t.Fatalf("above the feature: %+v", b)
	}
	// The verdict alone never settles: Settle below the feature holds.
	if out, err := Settle(context.Background(), closedGate, disk, owner); out != Held || err == nil || windowWrite(t, disk) {
		t.Fatalf("Settle below the feature = %v, %v", out, err)
	}
}

// P5: a forced commit that fails records the disk as it left it, like every
// other attempt, so an in-place overwrite later is never taken for that
// attempt's half-written disk within the keep-alive bound.
//
// Mutation "no end record on a failed forced commit" — red.
func TestForceCommit_AFailedAttemptRecordsItsEnd(t *testing.T) {
	needQemu(t)
	disk := window(t)
	prev := Command
	Command = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "false")
	}
	defer func() { Command = prev }()
	if err := ForceCommit(context.Background(), disk); err == nil {
		t.Fatal("a failed forced commit reported success")
	}
	b, err := readBinding(disk)
	if err != nil || b.State != StateCommitting || b.EndMtimeNs == 0 || b.EndSize == 0 {
		t.Fatalf("binding after a failed forced commit = %+v (%v), want committing with an end record", b, err)
	}
	if !Present(disk) {
		t.Fatal("the overlay was removed after a failed commit")
	}
}

// P1's building block: an overlay set aside goes back under its own name, with
// its binding, and never over one that is there now.
//
// Mutation "PutBack leaves the binding aside" — red.
func TestPutBack_RestoresTheOverlayAndItsBinding(t *testing.T) {
	needQemu(t)
	disk := window(t)
	to, err := SetAside(disk, "p1")
	if err != nil || Present(disk) {
		t.Fatalf("SetAside: %v (present %v)", err, Present(disk))
	}
	if err := PutBack(disk, to); err != nil {
		t.Fatal(err)
	}
	if !Present(disk) || !Bound(disk) {
		t.Fatalf("after PutBack: present %v bound %v", Present(disk), Bound(disk))
	}
	if _, err := os.Lstat(to); err == nil {
		t.Fatal("the set-aside name is still there")
	}
	to, _ = SetAside(disk, "p1b")
	if err := os.WriteFile(Path(disk), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PutBack(disk, to); err == nil {
		t.Fatal("PutBack renamed over an overlay that is there now")
	}
}
