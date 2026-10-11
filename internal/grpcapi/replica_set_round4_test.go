package grpcapi

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pitoverlay"
)

// recordOwnerFence writes a fencing_log row for dead-host, age ago.
func recordOwnerFence(t *testing.T, s *Server, id, method, result string, age time.Duration) {
	t.Helper()
	ts := time.Now().Add(-age).UTC().Format(time.RFC3339)
	if err := s.db.Execute(context.Background(), `INSERT OR IGNORE INTO fencing_log (id, host_name, method, result, timestamp, detail)
		VALUES (?, 'dead-host', ?, ?, ?, '')`, id, method, result, ts); err != nil {
		t.Fatal(err)
	}
}

// promoteVia runs an operator's promotion of db: directly against this host
// (an operator's own credentials) or relayed over peer transport (another
// node, or local-root lv).
func promoteVia(t *testing.T, s *Server, relayed, force bool) {
	t.Helper()
	ctx := adminCtx()
	if relayed {
		ctx = relayedAdmin(t, s, "entry-node")
	}
	stream := &streamRecorder[pb.PromoteReplicaProgress]{ctx: ctx}
	if err := s.PromoteReplica(&pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: force, NoLocalize: true}, stream); err != nil {
		t.Fatalf("PromoteReplica: %v", err)
	}
}

// Fix round 4 ruling: an operator's promotion reattaches a shared disk only
// when its owner is PROVEN off — the newest fence on record is proof-grade (a
// verified IPMI power-off or `lv host fence-confirm`) — or removed / no longer
// a member. An owner recorded `fenced` by a fence that proves nothing (an SSH
// or watchdog request, a lenient best-effort, none at all, or a proof-grade
// fence superseded by a newer weaker one) may still be writing the disk: it is
// left unattached and the promotion reported partial with the remedy.
// --force does not change that, nor does the transport.
//
// Mutation "state alone": the verdict trusts a `fenced` state without reading
// the fence record — red.
func TestPromote_ABestEffortFencedOwnerNeverGetsTheSharedDisk(t *testing.T) {
	type fenceRow struct {
		id, method, result string
		age                time.Duration
	}
	for _, c := range []struct {
		name  string
		rows  []fenceRow
		fence bool // the shared-storage fence enforced
	}{
		{"ssh", []fenceRow{{"f1", "ssh", "fenced", time.Minute}}, false},
		{"best-effort-ssh", []fenceRow{{"f1", "best-effort-ssh", "fenced", time.Minute}}, false},
		{"watchdog", []fenceRow{{"f1", "watchdog", "fenced", time.Minute}}, true},
		{"no fence record", nil, true},
		{"ipmi superseded by a newer ssh", []fenceRow{{"f1", "ipmi", "fenced", time.Hour}, {"f2", "ssh", "fenced", time.Minute}}, false},
	} {
		for _, relayed := range []bool{false, true} {
			for _, force := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/relayed=%v/force=%v", c.name, relayed, force), func(t *testing.T) {
					s := testServer(t)
					if c.fence {
						enforceSharedStorageFence(s)
					}
					nfsDisk := nfsPromoteVM(t, s, "fenced")
					for _, r := range c.rows {
						recordOwnerFence(t, s, r.id, r.method, r.result, r.age)
					}
					promoteVia(t, s, relayed, force)
					assertSharedUnattached(t, s, nfsDisk, "dead-host is fenced, but not proven powered off")
					if p := eventDetail(t, s, "db", vmEventPromotedPartial); !strings.Contains(p, "lv host fence-confirm dead-host") {
						t.Errorf("partial = %q, want the remedy named", p)
					}
				})
			}
		}
	}
}

// Fix round 4: an owner proven off by its newest fence — an IPMI power-off,
// or an operator's `lv host fence-confirm` — gets its shared disk reattached
// to an operator's promotion, through any transport.
//
// Mutation "never reattach on the manual rule" — red.
func TestPromote_AProofGradeFencedOwnerGivesTheSharedDisk(t *testing.T) {
	for _, c := range []struct{ name, method, result string }{
		{"ipmi", "ipmi", "fenced"},
		{"fence-confirm", "manual", "manual-confirmed"},
	} {
		for _, relayed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/relayed=%v", c.name, relayed), func(t *testing.T) {
				s := testServer(t)
				nfsDisk := nfsPromoteVM(t, s, "fenced")
				recordOwnerFence(t, s, "ssh-old", "ssh", "fenced", time.Hour) // older, weaker: the newest decides
				recordOwnerFence(t, s, "pg", c.method, c.result, time.Minute)
				promoteVia(t, s, relayed, true)
				if xml := s.virt.(*libvirtfake.Fake).DefinedXML("db"); !strings.Contains(xml, nfsDisk) {
					t.Errorf("a proven-off owner's shared disk was not reattached: %s", xml)
				}
				if r := diskRowsOf(t, s, "db")["data1"]; r.Path != nfsDisk {
					t.Errorf("data1 row = %+v, want it untouched", r)
				}
			})
		}
	}
}

// Fix round 4: an owner that is removed, or no longer a member at all, needs
// no fence record: it can no longer run anything in the cluster.
//
// Mutation "removed needs a proof too" — red.
func TestPromote_ARemovedOwnerGivesTheSharedDisk(t *testing.T) {
	for _, state := range []string{"removed", ""} { // "" = no hosts row
		s := testServer(t)
		nfsDisk := nfsPromoteVM(t, s, state)
		promoteVia(t, s, true, true)
		if xml := s.virt.(*libvirtfake.Fake).DefinedXML("db"); !strings.Contains(xml, nfsDisk) {
			t.Errorf("owner %q: the shared disk was not reattached: %s", state, xml)
		}
	}
}

// Fix round 4 item 2: the point-in-time overlay sweep leaves an overlay on a
// disk shared by its POOL (storage type local, pool driver nfs) alone when
// the VM's domain is not defined here, as it does for one typed nfs: another
// host may be running the VM on it.
//
// Mutation "storage type only" (the sweep uses corrosion.DiskIsShared) — red.
func TestSweep_LeavesAPoolSharedDiskWhoseDomainIsNotDefinedHere(t *testing.T) {
	recordQemuImg(t)
	s, _, live := pitServer(t)
	s.virt = libvirtfake.New() // no domain defined here
	windowOverlay(t, live)
	ctx := context.Background()
	if err := s.db.Execute(ctx, `UPDATE vm_disks SET storage_type = 'local', storage_volume = 'nas' WHERE vm_name = 'web'`); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "nas", Driver: "nfs", Source: "nas:/vm", State: "active"}); err != nil {
		t.Fatal(err)
	}
	s.SweepPITOverlays(ctx, caughtUp)
	if !pitoverlay.Present(live) {
		t.Fatal("the sweep settled a pool-shared disk this host does not define")
	}
	if !slices.Contains(pitEventTypes(t, s, "web"), "disk.pit_overlay_left") {
		t.Errorf("not reported: %v", pitEventTypes(t, s, "web"))
	}
}
