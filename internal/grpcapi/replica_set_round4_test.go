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
					if !force {
						// Without --force the split-brain guard refuses the
						// takeover first, on the same verdict (ccguard
						// review I2): nothing is promoted.
						ctx := adminCtx()
						if relayed {
							ctx = relayedAdmin(t, s, "entry-node")
						}
						err := s.PromoteReplica(&pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", NoLocalize: true},
							&streamRecorder[pb.PromoteReplicaProgress]{ctx: ctx})
						if err == nil || !strings.Contains(err.Error(), "not proven powered off") ||
							!strings.Contains(err.Error(), "lv host fence-confirm dead-host") {
							t.Fatalf("PromoteReplica without --force = %v; want the split-brain refusal naming the remedy", err)
						}
						return
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

// Fix round 5 (review R3-I2): an owner that is removed, or no longer a member
// at all, is no proof it is off — `lv host rm --force` asks for no fence, and
// a host whose daemon died may still run its qemu on the disk. Without a
// proof-grade newest fence the disk is left unattached; with one (an IPMI
// power-off, or `lv host fence-confirm`, which a removed host accepts) it is
// reattached. "tombstoned" is a host `lv host rm` deleted; "" has no hosts
// row at all.
//
// Mutation "removed trusted alone" (the verdict reattaches a removed or
// rowless owner without the fence record) — red.
func TestPromote_ARemovedOwnerNeedsAProofToo(t *testing.T) {
	for _, state := range []string{"removed", "tombstoned", ""} {
		for _, c := range []struct {
			name, method, result string
			want                 bool
		}{
			{"no fence record", "", "", false},
			{"ssh", "ssh", "fenced", false},
			{"best-effort-ssh", "best-effort-ssh", "fenced", false},
			{"ipmi", "ipmi", "fenced", true},
			{"fence-confirm", "manual", "manual-confirmed", true},
		} {
			for _, relayed := range []bool{false, true} {
				t.Run(fmt.Sprintf("%q/%s/relayed=%v", state, c.name, relayed), func(t *testing.T) {
					s := testServer(t)
					var nfsDisk string
					if state == "tombstoned" {
						nfsDisk = nfsPromoteVM(t, s, "active")
						if err := corrosion.DeleteHost(context.Background(), s.db, "dead-host"); err != nil {
							t.Fatal(err)
						}
					} else {
						nfsDisk = nfsPromoteVM(t, s, state)
					}
					if c.method != "" {
						recordOwnerFence(t, s, "f1", c.method, c.result, time.Minute)
					}
					promoteVia(t, s, relayed, true)
					if !c.want {
						assertSharedUnattached(t, s, nfsDisk, "dead-host is no longer a member of the cluster, but not proven powered off")
						p := eventDetail(t, s, "db", vmEventPromotedPartial)
						if !strings.Contains(p, "lv host fence-confirm dead-host") {
							t.Errorf("partial = %q, want the remedy named", p)
						}
						if strings.Contains(p, "or removed") {
							t.Errorf("partial = %q still steers to removal", p)
						}
						return
					}
					if xml := s.virt.(*libvirtfake.Fake).DefinedXML("db"); !strings.Contains(xml, nfsDisk) {
						t.Errorf("a proven-off removed owner's shared disk was not reattached: %s", xml)
					}
				})
			}
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
