package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// I2 of the switch review (P2 of the #256 re-review 5): this build never
// swaps in a binary that does not know pit_overlay — a build older than the
// release, which would start a VM on its bare disk and drop the writes an
// overlay holds — while any overlay exists on the host. Upgrades to a build
// that knows it, hosts with no overlay (set-aside orphans do not count), and
// --force are unaffected.

// A binary as the swap sees it: a script answering --release-features as this
// build does (knows), or failing on the flag as a build before it does.
func upgradeScript(knows bool) []byte {
	if knows {
		return []byte("#!/bin/sh\necho '" + ReleaseFeaturesLine() + "'\n")
	}
	return []byte("#!/bin/sh\necho 'Error: unknown flag: --release-features' >&2\nexit 1\n")
}

func upgradeWith(t *testing.T, s *Server, bin []byte, force bool) error {
	t.Helper()
	h := sha256.Sum256(bin)
	return s.UpgradeHost(&fakeUpgradeStream{ctx: adminCtx(), msgs: []*pb.UpgradeHostRequest{
		{Chunk: bin, Checksum: hex.EncodeToString(h[:]), Force: force},
	}})
}

func plantOverlay(t *testing.T, dir, name string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("overlay"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Mutations "no downgrade check at the swap" and "overlays not looked for"
// — red.
func TestUpgradeHost_NoBuildWithoutPITOverlayOverAnOverlay(t *testing.T) {
	s, dir := upgradeTestServer(t)
	s.dataDir = filepath.Join(dir, "data")
	ov := plantOverlay(t, filepath.Join(s.dataDir, "disks"), ".web-root.qcow2.lv-pit")

	err := upgradeWith(t, s, upgradeScript(false), false)
	msg := status.Convert(err).Message()
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(msg, ov) || !strings.Contains(msg, "lv resolve-pit-overlay") || !strings.Contains(msg, "lv host drain") {
		t.Fatalf("swap to a build without pit_overlay over an overlay = %v; want refused naming %s and the remedy", err, ov)
	}
	if got, _ := os.ReadFile(s.binaryPath); string(got) != "old-binary-content" {
		t.Fatalf("the binary was swapped: %q", got)
	}
	if _, err := os.Stat(s.binaryPath + ".new"); !os.IsNotExist(err) {
		t.Error("the refused staging binary was left behind")
	}

	// A build that knows pit_overlay is installed.
	knows := upgradeScript(true)
	if err := upgradeWith(t, s, knows, false); err != nil {
		t.Fatalf("swap to a build that knows pit_overlay: %v", err)
	}
	if got, _ := os.ReadFile(s.binaryPath); string(got) != string(knows) {
		t.Fatalf("the binary that knows pit_overlay was not installed")
	}
}

func TestUpgradeHost_AnOverlayInAPoolIsFoundAndForceOverrides(t *testing.T) {
	s, dir := upgradeTestServer(t)
	s.dataDir = filepath.Join(dir, "data")
	pool := filepath.Join(dir, "pool")
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "p", Driver: "local", Target: pool, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	ov := plantOverlay(t, filepath.Join(pool, "proj"), ".db-data.qcow2.lv-pit")
	if err := upgradeWith(t, s, upgradeScript(false), false); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), ov) {
		t.Fatalf("overlay in a pool: %v, want refused naming it", err)
	}
	if err := upgradeWith(t, s, upgradeScript(false), true); err != nil {
		t.Fatalf("--force: %v", err)
	}
}

func TestUpgradeHost_ASetAsideOrphanDoesNotRefuse(t *testing.T) {
	s, dir := upgradeTestServer(t)
	s.dataDir = filepath.Join(dir, "data")
	plantOverlay(t, filepath.Join(s.dataDir, "disks"), ".web-root.qcow2.lv-pit.orphan-20261011-120000")
	if err := upgradeWith(t, s, upgradeScript(false), false); err != nil {
		t.Fatalf("an orphan refused the swap: %v", err)
	}
}

// The preflight says so before anything is sent.
func TestPreflightUpgrade_ReportsPITOverlays(t *testing.T) {
	s, dir := upgradeTestServer(t)
	s.dataDir = filepath.Join(dir, "data")
	ov := plantOverlay(t, filepath.Join(s.dataDir, "disks"), ".web-root.qcow2.lv-pit")
	resp, err := s.PreflightUpgrade(adminCtx(), &pb.PreflightUpgradeRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range resp.GetFindings() {
		if f.GetCode() == "pit-overlay-present" && strings.Contains(f.GetMessage(), ov) && strings.Contains(f.GetMessage(), capabilities.ReleaseToken) {
			return
		}
	}
	t.Fatalf("findings %v: want pit-overlay-present naming %s", resp.GetFindings(), ov)
}

// The line a binary prints is the one the swap parses, and it carries
// pit_overlay.
func TestReleaseFeaturesLine_IsWhatTheProbeParses(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "lv")
	if err := os.WriteFile(bin, upgradeScript(true), 0o755); err != nil {
		t.Fatal(err)
	}
	feats, err := releaseFeaturesOf(context.Background(), bin)
	if err != nil || !strings.Contains(strings.Join(feats, ","), string(capabilities.FeaturePITOverlay)) {
		t.Fatalf("probe = %v, %v", feats, err)
	}
}
