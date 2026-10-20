package grpcapi

import (
	"bytes"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Removing or moving the movingVMStartRefusal below the pre-start work
// exposes actual ISO judgement, seed rebuild and/or native start attempts.
// The stopped control uses the same resumptive handoff and reaches all three.
func TestFinishVMReplaceRuntime_AMovingRowPreservesItsPrestartArtifacts(t *testing.T) {
	for _, state := range []string{"migrating", "stopped"} {
		t.Run(state, func(t *testing.T) {
			s, iso := staleSeedAfterAFailedAttach(t)
			fake := s.virt.(*libvirtfake.Fake)
			if err := fake.DestroyDomain("x"); err != nil {
				t.Fatal(err)
			}
			// The attach left a separate live XML view in the fake. Retire
			// that old definition before establishing the resumed target.
			if err := fake.UndefineDomain("x", false); err != nil {
				t.Fatal(err)
			}
			// Resume after the definition has already reached the target name.
			// That is a real retry boundary: no earlier rename/redefine work
			// should obscure what the final pre-start guard owns.
			dom := "<domain type='kvm'><name>x</name><uuid>uuid-x</uuid><memory unit='MiB'>512</memory><vcpu>1</vcpu><devices>" +
				"<disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='" + iso + "'/><target dev='sdb' bus='sata'/><readonly/></disk>" +
				"<interface type='bridge'><mac address='52:54:00:77:00:01'/><source bridge='br0'/></interface>" +
				"<interface type='bridge'><mac address='52:54:00:77:00:02'/><source bridge='br1'/></interface></devices></domain>"
			if err := fake.DefineDomain(dom); err != nil {
				t.Fatal(err)
			}
			if xml, err := fake.DumpXML("x"); err != nil || domainUUIDFromXML(xml) != "uuid-x" {
				t.Fatalf("setup: target live XML lacks uuid-x: %v", err)
			}
			if ours, foreign, err := s.domainOwnership("x", "uuid-x"); err != nil || !ours || foreign {
				t.Fatalf("setup: target ownership = %v/%v (%v), want ours", ours, foreign, err)
			}
			if got, err := fake.DomainState("x"); err != nil || got != "shutoff" {
				t.Fatalf("setup: target domain = %s (%v), want shutoff", got, err)
			}
			detail := ""
			if state == "migrating" {
				detail = "→ peer"
			}
			if err := corrosion.UpdateVMState(adminCtx(), s.db, "x", state, detail); err != nil {
				t.Fatal(err)
			}
			vm := vmRecord(t, s, "x")
			cl := corrosion.VMReplaceCleanup{OperationID: "op-x", AcceptedState: "running",
				Handoff: corrosion.VMReplaceHandoff{XML: dom, UUID: "uuid-x"},
				Manifest: corrosion.VMReplaceManifest{
					HostName: s.hostName, ReplacedVM: "x", Replacement: "x-next",
					ReplacementIncarnation: vm.CreatedAt, ReplacementUUID: "uuid-x",
				}}
			before := make(map[string][]byte)
			for _, path := range []string{iso, cloudinit.SeedOwnerPath(iso), cloudinit.SeedStalePath(iso)} {
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("snapshot %s: %v", path, err)
				}
				before[path] = body
			}
			definition := fake.DefinedXML("x")
			var isoAttempts, seedAttempts, startAttempts atomic.Int32
			judge := judgeCDROMs
			judgeCDROMs = func(got *Server, row *corrosion.VMRecord, xml string) (string, error) {
				isoAttempts.Add(1)
				return judge(got, row, xml)
			}
			seedHook := seedStartRebuildRaced
			seedStartRebuildRaced = func() { seedAttempts.Add(1) }
			t.Cleanup(func() {
				judgeCDROMs = judge
				seedStartRebuildRaced = seedHook
			})
			fake.FailStartDomain = func(string) error { startAttempts.Add(1); return nil }
			var gotErr error
			t.Run("handoff", func(t *testing.T) {
				useSeedISOWriter(t)
				gotErr = s.finishVMReplaceRuntime(adminCtx(), cl)
			})
			if state == "migrating" {
				// Inspect effects first so the guard-removal mutant reports the
				// intended violation even if some later admission were to fail.
				if isoAttempts.Load() != 0 || seedAttempts.Load() != 0 || startAttempts.Load() != 0 {
					t.Errorf("moving row attempted ISO/seed/start = %d/%d/%d, want 0/0/0", isoAttempts.Load(), seedAttempts.Load(), startAttempts.Load())
				}
				for path, want := range before {
					got, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(got, want) {
						t.Errorf("moving row changed artifact %s: %v", path, err)
					}
				}
				if got := fake.DefinedXML("x"); got != definition {
					t.Error("moving row changed its definition")
				}
				if gotErr == nil || !strings.Contains(gotErr.Error(), "migrating") {
					t.Errorf("moving handoff = %v, want migrating refusal", gotErr)
				}
				if got := vmRecord(t, s, "x"); got.State != "migrating" || got.StateDetail != "→ peer" {
					t.Errorf("moving row changed to %s/%s", got.State, got.StateDetail)
				}
				if got, err := fake.DomainState("x"); err != nil || got != "shutoff" {
					t.Errorf("moving domain = %s (%v), want shutoff", got, err)
				}
				return
			}
			if gotErr != nil {
				t.Fatalf("stopped control handoff: %v", gotErr)
			}
			if isoAttempts.Load() != 1 || seedAttempts.Load() != 1 || startAttempts.Load() != 1 {
				t.Errorf("stopped control ISO/seed/start = %d/%d/%d, want 1/1/1", isoAttempts.Load(), seedAttempts.Load(), startAttempts.Load())
			}
			if got, err := fake.DomainState("x"); err != nil || got != "running" {
				t.Errorf("stopped control domain = %s (%v), want running", got, err)
			}
			if nc := mustReadSeed(t, iso).NetworkConfig; !strings.Contains(nc, seedRetryB) || cloudinit.SeedMarkedStale(iso) {
				t.Errorf("stopped control did not rebuild B and clear its stale mark: %s", nc)
			}
		})
	}
}
