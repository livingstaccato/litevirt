package fencessh_test

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/fencessh"
)

// TestFenceConfig_Decisions pins how a fence from node-a reaches node-x for
// each state of node-x's row and each enforcement.fence_ssh mode.
func TestFenceConfig_Decisions(t *testing.T) {
	type state int
	const (
		noRow state = iota
		forged
		retired
		notAccepting
		accepting
		wasAccepting
	)
	cases := []struct {
		name  string
		st    state
		mode  string
		path  string // "" with refusal set means refused
		match string // a substring of the refusal
	}{
		{"no row, auto: legacy unpinned", noRow, fencessh.ModeAuto, fence.SSHPathLegacy, ""},
		{"no row, legacy: legacy unpinned", noRow, fencessh.ModeLegacy, fence.SSHPathLegacy, ""},
		{"no row, managed: refused", noRow, fencessh.ModeManaged, "", "published no fence ssh row"},
		{"forged row, auto: refused", forged, fencessh.ModeAuto, "", "does not verify"},
		{"forged row, legacy: refused", forged, fencessh.ModeLegacy, "", "does not verify"},
		{"retired row, auto: refused", retired, fencessh.ModeAuto, "", "does not verify"},
		{"not accepting, auto: pinned", notAccepting, fencessh.ModeAuto, fence.SSHPathPinned, ""},
		{"not accepting, managed: refused", notAccepting, fencessh.ModeManaged, "", "does not accept the managed fence key"},
		{"accepting, auto: managed", accepting, fencessh.ModeAuto, fence.SSHPathManaged, ""},
		{"accepting, managed: managed", accepting, fencessh.ModeManaged, fence.SSHPathManaged, ""},
		{"accepting, legacy: pinned", accepting, fencessh.ModeLegacy, fence.SSHPathPinned, ""},
		{"was accepting, auto: still the managed key", wasAccepting, fencessh.ModeAuto, fence.SSHPathManaged, ""},
		{"was accepting, managed: still the managed key", wasAccepting, fencessh.ModeManaged, fence.SSHPathManaged, ""},
		{"was accepting, legacy: pinned", wasAccepting, fencessh.ModeLegacy, fence.SSHPathPinned, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			a := w.node("node-a", "127.0.0.2")
			x := w.node("node-x", "127.0.0.3")
			other := w.node("node-o", "127.0.0.5")
			a.publish(true, false, "127.0.0.2", 22)
			switch tc.st {
			case noRow:
				x.hostRow("127.0.0.3", 22)
			case forged:
				// node-o publishes a row for node-x under its own certificate.
				other.publish(true, false, "127.0.0.5", 22)
				o, _, _ := corrosion.GetHostFenceSSH(context.Background(), w.db, "node-o")
				o.HostName = "node-x"
				if _, err := w.db.DB().Exec(corrosion.HostFenceSSHUpsertSQL, o.HostName, o.Generation, o.FencePubkeys,
					o.SSHDHostkeys, 1, 0, "", o.CertPEM, o.Signature, "2026-10-22T00:00:00Z"); err != nil {
					t.Fatal(err)
				}
				x.hostRow("127.0.0.3", 22)
			case retired:
				x.publish(true, true, "127.0.0.3", 22)
				if _, err := w.db.DB().Exec(`UPDATE host_fence_ssh SET deleted_at = updated_at WHERE host_name = 'node-x'`); err != nil {
					t.Fatal(err)
				}
			case notAccepting:
				x.publish(false, false, "127.0.0.3", 22)
			case accepting:
				x.publish(true, true, "127.0.0.3", 22)
			case wasAccepting:
				x.publish(false, true, "127.0.0.3", 22)
			}
			sf := a.agent(tc.mode).FenceConfig(context.Background(), "node-x")
			if tc.path == "" && tc.match != "" {
				if sf.Refusal == "" || !strings.Contains(sf.Refusal, tc.match) {
					t.Fatalf("FenceConfig = %+v, want a refusal containing %q", sf, tc.match)
				}
				return
			}
			if sf.Refusal != "" || sf.Path != tc.path {
				t.Fatalf("FenceConfig = path %q refusal %q, want path %q", sf.Path, sf.Refusal, tc.path)
			}
			if tc.path != fence.SSHPathLegacy && (sf.HostKeyAlias != fencessh.Alias("node-x") ||
				!strings.Contains(string(sf.KnownHosts), fencessh.KeyLine(x.hostKey))) {
				t.Fatalf("path %q is not pinned to node-x's sshd key: %+v", sf.Path, sf)
			}
			if tc.path == fence.SSHPathManaged && (sf.BindAddress != "127.0.0.2" ||
				sf.Request != fencessh.PoweroffRequest("node-x")) {
				t.Fatalf("managed path = %+v, want BindAddress 127.0.0.2 and node-x's poweroff request", sf)
			}
		})
	}
}

// TestFenceConfig_ClonedHostKeysRefuseThePinnedPath: two hosts publishing the
// same sshd key (a cloned image) cannot be told apart by the pin, and the
// legacy command has no forced command to refuse a request for the other
// host, so the pinned path toward either is refused; the managed path, whose
// forced command checks the name, is not.
func TestFenceConfig_ClonedHostKeysRefuseThePinnedPath(t *testing.T) {
	w := newWorld(t)
	a := w.node("node-a", "127.0.0.2")
	x := w.node("node-x", "127.0.0.3")
	y := w.node("node-y", "127.0.0.4")
	y.hkPath, y.hostKey = x.hkPath, x.hostKey
	a.publish(true, false, "127.0.0.2", 22)
	x.publish(false, false, "127.0.0.3", 22)
	y.publish(true, true, "127.0.0.4", 22)
	ctx := context.Background()
	if sf := a.agent(fencessh.ModeAuto).FenceConfig(ctx, "node-x"); sf.Refusal == "" ||
		!strings.Contains(sf.Refusal, "node-y publishes one of node-x's sshd host keys") {
		t.Fatalf("pinned path toward a cloned host = %+v, want refused", sf)
	}
	if sf := a.agent(fencessh.ModeLegacy).FenceConfig(ctx, "node-y"); sf.Refusal == "" {
		t.Fatalf("legacy-mode pinned path toward a cloned host = %+v, want refused", sf)
	}
	if sf := a.agent(fencessh.ModeAuto).FenceConfig(ctx, "node-y"); sf.Refusal != "" || sf.Path != fence.SSHPathManaged {
		t.Fatalf("managed path toward a cloned host = %+v, want managed", sf)
	}
}
