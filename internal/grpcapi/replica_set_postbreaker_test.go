package grpcapi

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Review R4-I1: a shared disk's owner that is no longer a member is proven off
// only by a proof-grade fence of its LAST life (corrosion.HostFenceLife, read
// through the tombstone). The name is confirmed off and removed, then re-added
// (a new machine, or the same one back in service) and runs the VM; its daemon
// dies and the operator removes it again with plain `lv host rm --force`,
// which asks for no fence. The first life's confirmation says nothing about
// the machine now behind the name, whose qemu may still be writing the disk,
// so the promotion must leave the disk unattached. A confirmation made in the
// last life, or after the second removal (the remedy the partial report
// names), still attaches it.
//
// Mutation "no life bound" (the removed-owner proof reads every fence row, as
// on 39a00290) — red on the "earlier life" rows.
func TestPromote_ARemovedOwnersProofIsBoundedByItsLastLife(t *testing.T) {
	for _, c := range []struct {
		name     string
		proof    string // "" (only the earlier life's), "last life", "after removal"
		attached bool
	}{
		{"only an earlier life's confirmation", "", false},
		{"confirmed in its last life", "last life", true},
		{"confirmed after its removal", "after removal", true},
	} {
		for _, relayed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/relayed=%v", c.name, relayed), func(t *testing.T) {
				s := testServer(t)
				ctx := context.Background()
				s.db.SetHostMembershipGate(func() bool { return true })
				if _, err := s.db.SplitHostMembership(ctx); err != nil || !s.db.HostMembershipLive() {
					t.Fatalf("split: live=%v err=%v", s.db.HostMembershipLive(), err)
				}
				confirm := func() {
					t.Helper()
					if _, err := s.FenceHost(adminCtx(), &pb.FenceHostRequest{Name: "dead-host", Confirmed: true, ConfirmManualOnly: true}); err != nil {
						t.Fatalf("fence-confirm: %v", err)
					}
				}
				remove := func() {
					t.Helper()
					if _, err := s.RemoveHost(adminCtx(), &pb.RemoveHostRequest{Name: "dead-host", Force: true}); err != nil {
						t.Fatalf("rm --force: %v", err)
					}
				}

				// The earlier life: confirmed off and removed, an hour ago.
				if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "dead-host", Address: "10.0.0.9", State: "active", CertSerial: "01"}); err != nil {
					t.Fatal(err)
				}
				confirm()
				if err := s.db.Execute(ctx, `UPDATE fencing_log SET timestamp = ? WHERE host_name = 'dead-host'`,
					time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)); err != nil {
					t.Fatal(err)
				}
				remove()

				// The last life: the name re-added, its daemon records it
				// active, and it runs db with its NFS data1.
				if err := corrosion.AdmitHost(ctx, s.db, corrosion.HostRecord{Name: "dead-host", Address: "10.0.0.9",
					SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: corrosion.HostStateJoining, CertSerial: "02"}); err != nil {
					t.Fatalf("re-add: %v", err)
				}
				if err := corrosion.UpdateHostState(ctx, s.db, "dead-host", "active"); err != nil {
					t.Fatal(err)
				}
				nfsDisk := nfsPromoteVM(t, s, "")
				if c.proof == "last life" {
					confirm()
				}
				remove() // while it is running: plain --force asks for no fence
				if c.proof == "after removal" {
					confirm()
				}
				if h, err := corrosion.GetHost(ctx, s.db, "dead-host"); err != nil || h != nil {
					t.Fatalf("GetHost = %+v, %v; want the host removed", h, err)
				}

				promoteVia(t, s, relayed, true)
				xml := s.virt.(*libvirtfake.Fake).DefinedXML("db")
				if c.attached {
					if !strings.Contains(xml, nfsDisk) {
						t.Errorf("the shared disk was not reattached over a proof of the host's last life: %s", xml)
					}
					return
				}
				assertSharedUnattached(t, s, nfsDisk, "dead-host is no longer a member of the cluster, but not proven powered off")
			})
		}
	}
}

// Review R4-m2: the partial report's remedy names the host that failed the
// verdict, never the disk row's host when that one passed, never the
// promoting host itself, and never a placeholder.
//
// Mutation "the row's host" (the advice takes d.row.HostName, as on
// 39a00290) — red on every row.
func TestPromote_ThePartialAdviceNamesTheHostThatFailed(t *testing.T) {
	for _, c := range []struct {
		name      string
		prep      func(t *testing.T, s *Server)
		want      string // a host the advice must name; "" for none
		notWant   []string
		automated bool // the coordinator's relay, marked automated, with no verified fence
	}{
		{"row on a proven-off host, VM on an unproven one", func(t *testing.T, s *Server) {
			if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: "old-src", Address: "10.0.0.7", State: "fenced"}); err != nil {
				t.Fatal(err)
			}
			if err := s.db.Execute(context.Background(), `INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail)
				VALUES ('i1', 'old-src', 'ipmi', 'fenced', ?, '')`, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)); err != nil {
				t.Fatal(err)
			}
			setData1Host(t, s, "old-src")
		}, "dead-host", []string{"fence-confirm old-src", "old-src is powered off"}, false},
		{"row on the promoting host, VM on an unproven one", func(t *testing.T, s *Server) {
			setData1Host(t, s, s.hostName)
		}, "dead-host", []string{"fence-confirm test-host", "test-host is powered off"}, false},
		{"row names no host, VM on an unproven one", func(t *testing.T, s *Server) {
			setData1Host(t, s, "")
		}, "dead-host", []string{"<host>"}, false},
		{"row names no host, VM already the promoting host's", func(t *testing.T, s *Server) {
			alreadyPromotedHere(t, s)
			setData1Host(t, s, "")
		}, "", []string{"<host>", "fence-confirm test-host", "test-host is powered off", "lv host fence-confirm"}, false},
		// The same-host rebuild judged by the promoting host itself, which an
		// automated promotion without a verified fence refuses: the failing
		// owner is the promoting host, and the advice must not name it.
		{"automated, the disk and the VM already the promoting host's", func(t *testing.T, s *Server) {
			alreadyPromotedHere(t, s)
			setData1Host(t, s, s.hostName)
		}, "", []string{"fence-confirm test-host", "test-host is powered off", "lv host fence-confirm"}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := testServer(t)
			nfsDisk := nfsPromoteVM(t, s, "fenced") // the VM's owner, dead-host: fenced by ssh only
			recordOwnerFence(t, s, "f1", "ssh", "fenced", time.Minute)
			c.prep(t, s)
			if c.automated {
				stream := &streamRecorder[pb.PromoteReplicaProgress]{ctx: relayedAdmin(t, s, "coordinator")}
				if err := s.PromoteReplica(&pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true, Automated: true}, stream); err != nil {
					t.Fatalf("PromoteReplica: %v", err)
				}
			} else {
				promoteVia(t, s, false, true)
			}
			if xml := s.virt.(*libvirtfake.Fake).DefinedXML("db"); strings.Contains(xml, nfsDisk) {
				t.Fatalf("attached: %s", xml)
			}
			p := eventDetail(t, s, "db", vmEventPromotedPartial)
			if c.want != "" {
				if want := fmt.Sprintf("once %s is powered off, `lv host fence-confirm %s`", c.want, c.want); !strings.Contains(p, want) {
					t.Errorf("partial = %q, want %q", p, want)
				}
			}
			for _, bad := range c.notWant {
				if strings.Contains(p, bad) {
					t.Errorf("partial = %q, must not contain %q", p, bad)
				}
			}
			if !strings.Contains(p, "Re-running `lv replication promote db --force` over this promotion does not attach it: it is refused") {
				t.Errorf("partial = %q, want the re-run warning kept", p)
			}
		})
	}
}

func setData1Host(t *testing.T, s *Server, host string) {
	t.Helper()
	if err := s.db.Execute(context.Background(), `UPDATE vm_disks SET host_name = ? WHERE vm_name = 'db' AND disk_name = 'data1'`, host); err != nil {
		t.Fatal(err)
	}
}
