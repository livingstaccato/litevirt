package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

func tunedSpec(name string) *pb.VMSpec {
	return &pb.VMSpec{Name: name, Cpu: 2, MemoryMib: 512,
		Disks:   []*pb.DiskSpec{{Name: "root", Bus: "virtio", Discard: "unmap", Io: &pb.DiskIOLimits{ReadIopsSec: 321}}},
		Network: []*pb.NetworkAttachment{{Name: "tn", Queues: 4}}}
}

func renderedTuning(t *testing.T, x string) (iops int64, discard, queues bool) {
	t.Helper()
	tune, _ := lv.DiskIOTuneFromXML(x, "vda")
	return tune.ReadIopsSec, strings.Contains(x, "discard='unmap'") || strings.Contains(x, `discard="unmap"`),
		strings.Contains(x, "queues='4'") || strings.Contains(x, `queues="4"`)
}

// A clone of a tuned VM keeps the source's throttle, discard and queues: the
// clone's spec is the source's, and the domain it defines is rendered from it
// (its NICs get fresh MACs, so the queues follow by position).
//
// Mutations: delete the ApplyDiskTuning or ApplyNICTuningByPosition call in
// CloneVM — the throttle/discard or the queues check goes red.
func TestFleet_CloneOfATunedVMKeepsItsTuning(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	entry, src := c.Nodes[0], c.Nodes[1]
	setHostCapacity(t, c, src.Name, 64, 65536)
	src.Server.SetBridgeEnsure(src.Net.EnsureBridge)
	seedCloneSourceSpec(t, c, src, tunedSpec("tpl"))

	if _, err := cloneAt(t, c, entry, "tpl", "kid"); err != nil {
		t.Fatalf("clone: %v", err)
	}
	iops, discard, queues := renderedTuning(t, src.Virt.DefinedXML("kid"))
	if iops != 321 || !discard || !queues {
		t.Errorf("the clone renders throttle=%d discard=%v queues=%v, want 321/true/true:\n%s", iops, discard, queues, src.Virt.DefinedXML("kid"))
	}
}

func seedVMBackupWithSpec(t *testing.T, spec *pb.VMSpec) (repoDir, ts string) {
	t.Helper()
	repoDir = filepath.Join(t.TempDir(), "vmrepo")
	repo, err := pbsstore.Init(repoDir)
	if err != nil {
		t.Fatalf("init backup repo: %v", err)
	}
	specJSON, _ := json.Marshal(spec)
	ts = "2026-07-01T00:00:00Z"
	if _, err := pbsstore.PushDisk(context.Background(), repo, bytes.NewReader(make([]byte, 1<<20)),
		pbsstore.PushOptions{VMName: spec.Name, DiskName: "root", Timestamp: ts, VMSpecJSON: string(specJSON)}); err != nil {
		t.Fatalf("PushDisk: %v", err)
	}
	return repoDir, ts
}

func drainRestore(t *testing.T, c *Cluster, n *Node, repo, vm, ts, newName string) error {
	t.Helper()
	return restoreLiveAt(t, c, n, repo, vm, ts, newName)
}

// A backup manifest is untrusted. Before the gate opens a restore that main
// allows still works and the manifest's tuning is dropped (the older peers would
// drop it anyway); once open it is rendered; and an invalid value is refused
// before a domain is defined.
//
// Mutations: skip restrictRestoredTuning — the unlatched case renders tuning and
// the invalid case defines a domain; delete the ApplyDiskTuning/NIC calls in
// autoDefineRestoredVM — the latched case goes red.
func TestFleet_RestoreLiveTreatsAManifestsTuningAsUntrusted(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	ctx := context.Background()
	setHostCapacity(t, c, n.Name, 64, 65536)
	n.Server.SetBridgeEnsure(n.Net.EnsureBridge)

	// Not latched: the restore works and carries no tuning.
	repo, ts := seedVMBackupWithSpec(t, tunedSpec("bk"))
	if err := drainRestore(t, c, n, repo, "bk", ts, "r-open"); err != nil {
		t.Fatalf("an unlatched restore of a manifest with tuning must still work: %v", err)
	}
	if iops, discard, queues := renderedTuning(t, n.Virt.DefinedXML("r-open")); iops != 0 || discard || queues {
		t.Errorf("an unlatched restore rendered tuning: throttle=%d discard=%v queues=%v", iops, discard, queues)
	}
	if got := specOn(t, n, "r-open"); got.Disks[0].Io != nil || got.Disks[0].Discard != "" || got.Network[0].Queues != 0 {
		t.Errorf("an unlatched restore stored tuning: %+v %+v", got.Disks[0], got.Network[0])
	}

	// Latched: rendered, and recorded.
	latchIOFeature(t, c)
	repo, ts = seedVMBackupWithSpec(t, tunedSpec("bk2"))
	if err := drainRestore(t, c, n, repo, "bk2", ts, "r-latched"); err != nil {
		t.Fatalf("latched restore: %v", err)
	}
	if iops, discard, queues := renderedTuning(t, n.Virt.DefinedXML("r-latched")); iops != 321 || !discard || !queues {
		t.Errorf("a latched restore renders throttle=%d discard=%v queues=%v, want 321/true/true", iops, discard, queues)
	}

	// Latched, a hand-edited manifest: refused before anything is defined.
	bad := tunedSpec("bk3")
	bad.Network[0].Queues = 4096
	repo, ts = seedVMBackupWithSpec(t, bad)
	err := drainRestore(t, c, n, repo, "bk3", ts, "r-bad")
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("queues 4096 in a manifest: %v, want InvalidArgument", err)
	}
	if n.Virt.DomainExists("r-bad") {
		t.Error("a refused restore defined a domain")
	}
	if rec, _ := corrosion.GetVM(ctx, n.DB, "r-bad"); rec != nil {
		t.Errorf("a refused restore left a VM row (%s)", rec.State)
	}
	_ = io.EOF
}

// A RENAMED restore gives the NIC a fresh MAC; the spec it persists must record
// that MAC, or the queues (matched by MAC, or by position onto an entry with none)
// are dropped at the next redefine while the spec still says 4.
//
// Mutation: delete `n.Mac = mac` in autoDefineRestoredVM — red.
func TestFleet_RenamedRestoreKeepsTheNICsQueuesAcrossARedefine(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	ctx := context.Background()
	setHostCapacity(t, c, n.Name, 64, 65536)
	n.Server.SetBridgeEnsure(n.Net.EnsureBridge)
	latchIOFeature(t, c)
	src := tunedSpec("bk")
	src.Network[0].Mac = "52:54:00:11:22:33" // the source VM's MAC, carried in its backup
	repo, ts := seedVMBackupWithSpec(t, src)
	if err := drainRestore(t, c, n, repo, "bk", ts, "renamed"); err != nil {
		t.Fatalf("restore: %v", err)
	}
	spec := specOn(t, n, "renamed")
	ifaces, err := corrosion.GetVMInterfaces(ctx, n.DB, "renamed")
	if err != nil || len(ifaces) != 1 {
		t.Fatalf("ifaces = %+v err=%v", ifaces, err)
	}
	if spec.Network[0].Mac != ifaces[0].MAC {
		t.Errorf("the spec records MAC %q, the restored NIC has %q", spec.Network[0].Mac, ifaces[0].MAC)
	}
	nets := []lv.NetworkConfig{{MAC: ifaces[0].MAC, SpecOrdinal: ifaces[0].Ordinal + 1}}
	compose.ApplyNICTuning(nets, spec)
	if nets[0].Queues != 4 {
		t.Errorf("a redefine of the restored VM renders queues=%d, want 4", nets[0].Queues)
	}
}
