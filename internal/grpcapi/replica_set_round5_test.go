package grpcapi

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// alreadyPromotedHere turns nfsPromoteVM's VM into one an earlier, partial
// promotion already brought to this host: the VM row and its root are this
// host's, while the shared data1 row still names dead-host (a partial
// promotion leaves it untouched), and the domain is defined here.
func alreadyPromotedHere(t *testing.T, s *Server) {
	t.Helper()
	ctx := context.Background()
	if err := s.db.Execute(ctx, `UPDATE vms SET host_name = ? WHERE name = 'db'`, s.hostName); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx, `UPDATE vm_disks SET host_name = ? WHERE vm_name = 'db' AND disk_name = 'root'`, s.hostName); err != nil {
		t.Fatal(err)
	}
	if err := s.virt.(*libvirtfake.Fake).DefineDomain("<domain><name>db</name></domain>"); err != nil {
		t.Fatal(err)
	}
}

// Review R3-I1: the reattach verdict judges a shared disk by the host its own
// row names, not by the VM's owner. After a partial promotion the VM is this
// host's, but its shared disk's row still names the old owner, which may
// still be writing it; a re-run of the promotion with --force must not
// attach it without proof that owner is off.
//
// Mutation "VM owner only" (the verdict judges vm.HostName, as on 71a99034)
// — red: the disk is attached through the "owner is this host" shortcut.
// Mutation "a row naming no host falls back to the VM's owner" — red on the
// "row names no host" rows.
func TestPromote_ARePromotionJudgesTheSharedDisksOwnOwner(t *testing.T) {
	for _, c := range []struct {
		name, state string
		fenceRow    []string // method, result
		reason      string
	}{
		{"fenced by ssh", "fenced", []string{"ssh", "fenced"}, "dead-host is fenced, but not proven powered off"},
		{"fenced, no record", "fenced", nil, "dead-host is fenced, but not proven powered off"},
		{"offline", "offline", nil, "its owner dead-host is offline, not fenced"},
		{"removed, no record", "removed", nil, "dead-host is no longer a member of the cluster, but not proven powered off"},
		{"no hosts row", "", nil, "dead-host is no longer a member of the cluster, but not proven powered off"},
		{"row names no host", "fenced", []string{"ipmi", "fenced"}, "its row names no host"},
	} {
		for _, relayed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/relayed=%v", c.name, relayed), func(t *testing.T) {
				s := testServer(t)
				nfsDisk := nfsPromoteVM(t, s, c.state)
				if c.fenceRow != nil {
					recordOwnerFence(t, s, "f1", c.fenceRow[0], c.fenceRow[1], time.Minute)
				}
				alreadyPromotedHere(t, s)
				if c.name == "row names no host" {
					// Its old owner is unknown: the VM's is already this host.
					if err := s.db.Execute(context.Background(), `UPDATE vm_disks SET host_name = '' WHERE vm_name = 'db' AND disk_name = 'data1'`); err != nil {
						t.Fatal(err)
					}
					promoteVia(t, s, relayed, true)
					if xml := s.virt.(*libvirtfake.Fake).DefinedXML("db"); strings.Contains(xml, nfsDisk) {
						t.Errorf("a shared disk with no owner to judge was attached: %s", xml)
					}
					if p := eventDetail(t, s, "db", vmEventPromotedPartial); !strings.Contains(p, c.reason) {
						t.Errorf("partial = %q, want %q", p, c.reason)
					}
					return
				}
				promoteVia(t, s, relayed, true)
				assertSharedUnattached(t, s, nfsDisk, c.reason)
			})
		}
	}
}

// Review R3-I1, the other side: the disk's owner proven off (an IPMI fence,
// or fence-confirm) lets the re-run reattach it, and a disk whose own row
// names this host (a same-host rebuild) is reattached as before.
//
// Mutation "never reattach on a re-run" (the verdict refuses any disk owned
// elsewhere) — red on the proven-off rows.
func TestPromote_ARePromotionReattachesWhenTheDisksOwnerIsProvenOff(t *testing.T) {
	for _, c := range []struct {
		name string
		prep func(t *testing.T, s *Server)
	}{
		{"ipmi", func(t *testing.T, s *Server) { recordOwnerFence(t, s, "f1", "ipmi", "fenced", time.Minute) }},
		{"fence-confirm", func(t *testing.T, s *Server) {
			recordOwnerFence(t, s, "f1", "manual", "manual-confirmed", time.Minute)
		}},
		{"row names this host", func(t *testing.T, s *Server) {
			if err := s.db.Execute(context.Background(), `UPDATE vm_disks SET host_name = ? WHERE vm_name = 'db'`, s.hostName); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := testServer(t)
			nfsDisk := nfsPromoteVM(t, s, "fenced")
			alreadyPromotedHere(t, s)
			c.prep(t, s)
			promoteVia(t, s, false, true)
			if xml := s.virt.(*libvirtfake.Fake).DefinedXML("db"); !strings.Contains(xml, nfsDisk) {
				t.Errorf("the shared disk was not reattached: %s", xml)
			}
		})
	}
}

// Review R3-I2: `lv host fence-confirm` accepts a host that has been removed
// (its hosts row tombstoned by `lv host rm`), recording the manual-confirmed
// fencing_log row alone — the host is not brought back, no membership state
// is written — and a promotion then reattaches the shared disk it owned.
// That is the remedy "secure, don't remove" keeps for an operator who has
// already run a plain `lv host rm --force`.
//
// Mutation "removed host refused" (FenceHost keeps NotFound for a tombstoned
// host) — red. Mutation "confirmation writes a state" (recordFence's 'fenced'
// state beside the row, as for a member) — red.
func TestFenceConfirm_ARemovedHostThenPromoteReattaches(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	nfsDisk := nfsPromoteVM(t, s, "offline")
	if err := corrosion.DeleteHost(ctx, s.db, "dead-host"); err != nil {
		t.Fatal(err)
	}
	// What the removal left, which the confirmation must not touch.
	membership := func() string {
		rows, err := s.db.Query(ctx, `SELECT h.state AS hs,
			(SELECT COUNT(*) FROM host_membership m WHERE m.host_name = h.name AND m.deleted_at IS NULL) AS live
			FROM hosts h WHERE h.name = 'dead-host'`)
		if err != nil || len(rows) != 1 {
			t.Fatalf("read the removed host's rows: %v (%d rows)", err, len(rows))
		}
		return fmt.Sprintf("state=%s live-membership=%d", rows[0].String("hs"), rows[0].Int64("live"))
	}
	before := membership()
	res, err := s.FenceHost(adminCtx(), &pb.FenceHostRequest{Name: "dead-host", Confirmed: true, ConfirmManualOnly: true})
	if err != nil {
		t.Fatalf("fence-confirm of a removed host: %v", err)
	}
	if res.Result != "manual-confirmed" {
		t.Errorf("result = %q, want manual-confirmed", res.Result)
	}
	// Review R4-m1: the result says the confirmation also unblocks the
	// coordinator's recovery of the workloads recorded on the removed host.
	if !strings.Contains(res.Detail, "recover every workload still recorded on dead-host") {
		t.Errorf("detail = %q, want the removed-host recovery side effect named", res.Detail)
	}
	if h, err := corrosion.GetHost(ctx, s.db, "dead-host"); err != nil || h != nil {
		t.Errorf("GetHost after fence-confirm = %+v, %v; want the host to stay removed", h, err)
	}
	if removed, err := corrosion.HostRemoved(ctx, s.db, "dead-host"); err != nil || !removed {
		t.Errorf("HostRemoved = %v, %v; want true", removed, err)
	}
	if after := membership(); after != before {
		t.Errorf("the confirmation wrote a membership state: %s, was %s", after, before)
	}
	if ok, err := corrosion.FenceRecordProvesOff(ctx, s.db, "dead-host"); err != nil || !ok {
		t.Fatalf("FenceRecordProvesOff = %v, %v; want the confirmation on record", ok, err)
	}
	promoteVia(t, s, false, true)
	if xml := s.virt.(*libvirtfake.Fake).DefinedXML("db"); !strings.Contains(xml, nfsDisk) {
		t.Errorf("the shared disk was not reattached after fence-confirm: %s", xml)
	}
}

// Review R3-m2: the partial report names the remedy that works — prove the
// owner off with `lv host fence-confirm <owner>` before promoting (pinned by
// TestFenceConfirm_ARemovedHostThenPromoteReattaches) — and warns against the
// one that does not: re-running the promotion over a partial one destroys
// the promoted domain and rebuilds or refuses its disks. It no longer
// suggests that removing the host is enough.
//
// Mutation "round 4 advice" (the old "…or removed" wording restored) — red.
func TestPromote_ThePartialAdviceNamesTheRealRemedy(t *testing.T) {
	s := testServer(t)
	nfsDisk := nfsPromoteVM(t, s, "fenced")
	recordOwnerFence(t, s, "f1", "ssh", "fenced", time.Minute)
	promoteVia(t, s, false, true)
	assertSharedUnattached(t, s, nfsDisk, "dead-host is fenced, but not proven powered off")
	p := eventDetail(t, s, "db", vmEventPromotedPartial)
	for _, want := range []string{
		"once dead-host is powered off, `lv host fence-confirm dead-host`",
		"Re-running `lv replication promote db --force` over this promotion does not attach it: it is refused",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("partial = %q, want %q", p, want)
		}
	}
	if strings.Contains(p, "or removed") {
		t.Errorf("partial = %q still says removal is enough", p)
	}
}

// Review R3-I2: FenceHost keeps its checks for a removed host. Only the
// operator's confirmation is accepted (there is nothing left to fence it by,
// and no fence is run); a name this host holds no row for at all is unknown,
// not removed, and stays NotFound; --confirmed and the admin role are still
// required.
func TestFenceHost_ARemovedHostAcceptsOnlyAConfirmation(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "gone", Address: "10.0.0.8", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteHost(ctx, s.db, "gone"); err != nil {
		t.Fatal(err)
	}
	ran := false
	s.SetFenceExecutor(func(context.Context, fence.HostConfig) fence.Result { ran = true; return fence.Result{Success: true} })

	if _, err := s.FenceHost(adminCtx(), &pb.FenceHostRequest{Name: "gone", Confirmed: true}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("fence of a removed host: err = %v, want FailedPrecondition", err)
	}
	if ran {
		t.Error("a fence was run against a removed host")
	}
	if _, err := s.FenceHost(adminCtx(), &pb.FenceHostRequest{Name: "gone", ConfirmManualOnly: true}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("fence-confirm without --confirmed: err = %v, want InvalidArgument", err)
	}
	operator := context.WithValue(context.WithValue(context.Background(), ctxKeyUsername, "op"), ctxKeyRole, "operator")
	if _, err := s.FenceHost(operator, &pb.FenceHostRequest{Name: "gone", Confirmed: true, ConfirmManualOnly: true}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("fence-confirm by an operator: err = %v, want PermissionDenied", err)
	}
	if _, err := s.FenceHost(adminCtx(), &pb.FenceHostRequest{Name: "never-existed", Confirmed: true, ConfirmManualOnly: true}); status.Code(err) != codes.NotFound {
		t.Errorf("fence-confirm of an unknown host: err = %v, want NotFound", err)
	}
	if ok, _ := corrosion.FenceRecordProvesOff(ctx, s.db, "gone"); ok {
		t.Error("a refused call recorded a confirmation")
	}
	if ok, _ := corrosion.FenceRecordProvesOff(ctx, s.db, "never-existed"); ok {
		t.Error("an unknown host got a confirmation")
	}
}

// Review R3-I1: judging the disk's own row must not stop judging the VM's
// owner. A row left naming a host the VM has since left (a migration whose
// ownership commit declined leaves the disk rows as they were) names a host
// that is not the one running the VM; the VM's owner, fenced best-effort
// only, may still be writing the disk even though the row's host is proven
// off.
//
// Mutation "the disk's row only" (sharedDiskOwners drops the VM's owner) —
// red.
func TestPromote_TheVMsOwnerIsJudgedToo(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	nfsDisk := nfsPromoteVM(t, s, "fenced") // the VM's owner, dead-host: fenced by ssh only
	recordOwnerFence(t, s, "f1", "ssh", "fenced", time.Minute)
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "old-src", Address: "10.0.0.7", State: "fenced"}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx, `INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail)
		VALUES ('i1', 'old-src', 'ipmi', 'fenced', ?, '')`, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx, `UPDATE vm_disks SET host_name = 'old-src' WHERE vm_name = 'db' AND disk_name = 'data1'`); err != nil {
		t.Fatal(err)
	}
	promoteVia(t, s, false, true)
	if xml := s.virt.(*libvirtfake.Fake).DefinedXML("db"); strings.Contains(xml, nfsDisk) {
		t.Errorf("attached while the VM's owner is not proven off: %s", xml)
	}
	p := eventDetail(t, s, "db", vmEventPromotedPartial)
	if !strings.Contains(p, "dead-host is fenced, but not proven powered off") {
		t.Errorf("partial = %q, want the VM's owner named", p)
	}
	// Review R4-m2: the remedy names the host that failed, not old-src.
	if !strings.Contains(p, "once dead-host is powered off, `lv host fence-confirm dead-host`") || strings.Contains(p, "fence-confirm old-src") {
		t.Errorf("partial = %q, want the remedy to name dead-host, not old-src", p)
	}
}

func TestSharedDiskOwners(t *testing.T) {
	for _, c := range []struct {
		disk, vm string
		want     []string
		ok       bool
	}{
		{"old", "self", []string{"old"}, true},
		{"old", "old", []string{"old"}, true},
		{"old", "other", []string{"old", "other"}, true},
		{"self", "self", nil, true},
		{"self", "", nil, true},
		{"self", "other", []string{"other"}, true},
		{"", "other", []string{"other"}, true},
		{"", "self", nil, false},
		{"", "", nil, false},
	} {
		got, ok := sharedDiskOwners(c.disk, c.vm, "self")
		if ok != c.ok || fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("sharedDiskOwners(%q, %q) = %v, %v; want %v, %v", c.disk, c.vm, got, ok, c.want, c.ok)
		}
	}
}
