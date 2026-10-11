package grpcapi

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Fix round 1: the LUN is taken by a voter-majority claim, behind the
// iscsi_lun_claim release feature (review I-1, I-2; rulings 1 and 5).

// lunGrant is iscsi_lun_claim's grant, for a test that writes the feature's
// data directly.
func lunGrant(t testing.TB) capabilities.FeatureGrant {
	return capabilities.GrantForTest(t, capabilities.FeatureISCSILUNClaim)
}

// lunClaimRows counts the LUN-key claim state this host's voter holds.
func lunClaimRows(t *testing.T, s *Server) int {
	t.Helper()
	rows, err := s.db.Query(context.Background(),
		`SELECT COUNT(*) AS n FROM local_recovery_claims WHERE target_kind = ?`, corrosion.ClaimKindLUN)
	if err != nil {
		t.Fatal(err)
	}
	return rows[0].Int("n")
}

// Until the release feature iscsi_lun_claim is open — the cluster upgrade has
// finished — nothing is allocated on an iscsi pool: refusing is safer than
// the old silent sharing. The refusal is the release gate's own text, and no
// LUN claim, promise or checkpoint is written. A create without an iscsi disk
// is untouched.
//
// Mutation: let the gate pass with no release feature — this goes red.
func TestCreateVM_ISCSI_RefusedUntilTheUpgradeFinishes(t *testing.T) {
	want := "the cluster upgrade must finish first (iscsi_lun_claim needs " + capabilities.ReleaseToken + ")"
	for _, tc := range []struct {
		name string
		gate func(s *Server)
	}{
		{"no gate wired", func(s *Server) { s.releaseFeatures = nil }},
		{"the gate refuses", func(s *Server) {
			s.SetReleaseFeatureGate(fakeFeatureGate{err: status.Error(codes.FailedPrecondition, want+": not yet: node-2 (1.9.0)")})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := lunTestServer(t)
			tc.gate(s)
			_, err := s.CreateVM(adminCtx(), lunVM("a", "lun0"))
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), want) {
				t.Fatalf("iscsi create before the release latch: got %v, want FailedPrecondition %q", err, want)
			}
			requireNoVM(t, s, "a")
			if n := lunClaimRows(t, s); n != 0 {
				t.Fatalf("a refused create left %d LUN claim rows", n)
			}
			if c, err := corrosion.GetLUNResolved(context.Background(), s.db, mustLUNKey(t, "10.0.0.1", "0")); err != nil || c != 0 {
				t.Fatalf("a refused create wrote a checkpoint: %d %v", c, err)
			}
			if _, err := s.CreateVM(adminCtx(), &pb.CreateVMRequest{Spec: &pb.VMSpec{
				Name: "plain", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: s.hostName},
				Disks: []*pb.DiskSpec{{Name: "root", Size: "1G"}},
			}}); err != nil {
				t.Fatalf("a create without an iscsi disk before the latch: %v", err)
			}
		})
	}
}

// lunCountingGate is a release-feature gate that counts its calls, refusing
// with refuse when set.
type lunCountingGate struct {
	t      testing.TB
	refuse error
	calls  *atomic.Int32
}

func (g lunCountingGate) WithFeature(ctx context.Context, f capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error {
	g.calls.Add(1)
	if g.refuse != nil {
		return g.refuse
	}
	return write(ctx, capabilities.GrantForTest(g.t, f))
}

func (g lunCountingGate) FeatureAvailable(capabilities.Feature) bool { return g.refuse == nil }

// A plain delete of a VM on a LUN is never refused by iscsi_lun_claim's gate,
// and never marks the feature used: before the feature is used nothing is
// recorded and the gate is not asked (no kept allocation exists to void); once
// it is, the record goes through the gate, and a gate refusal is logged while
// the delete stands.
//
// Mutations: ask the gate whatever the used record says — the unused stage
// goes red (a call, a record); let a gate refusal fail the delete — the
// refusing stage goes red.
func TestDeleteVM_ISCSI_PlainDeleteRecordIsGatedAndNeverRefuses(t *testing.T) {
	ctx := adminCtx()
	key := mustLUNKey(t, "10.0.0.1", "0")
	usedKey := "release_feature/" + capabilities.ReleaseToken + "/" + string(capabilities.FeatureISCSILUNClaim)
	for _, tc := range []struct {
		name       string
		used       bool
		refuse     error
		wantCalls  int32
		wantRecord bool
	}{
		{"feature unused", false, nil, 0, false},
		{"feature used, gate refuses", true, status.Error(codes.FailedPrecondition, "the cluster upgrade must finish first"), 1, false},
		{"feature used, gate grants", true, nil, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := lunTestServer(t)
			if _, err := s.CreateVM(ctx, lunVM("a", "lun0")); err != nil {
				t.Fatalf("create a: %v", err)
			}
			if !tc.used {
				if _, err := s.db.DB().ExecContext(context.Background(),
					`DELETE FROM cluster_policies WHERE key = ?`, usedKey); err != nil {
					t.Fatal(err)
				}
			}
			calls := &atomic.Int32{}
			s.SetReleaseFeatureGate(lunCountingGate{t: t, refuse: tc.refuse, calls: calls})
			if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "a"}); err != nil {
				t.Fatalf("plain delete of a: %v", err)
			}
			requireNoVM(t, s, "a")
			if got := calls.Load(); got != tc.wantCalls {
				t.Errorf("gate asked %d times, want %d", got, tc.wantCalls)
			}
			rec, err := corrosion.GetLUNPlainDelete(context.Background(), s.db, key)
			if err != nil {
				t.Fatal(err)
			}
			if (rec != "") != tc.wantRecord {
				t.Errorf("plain-delete record = %q, want recorded=%v", rec, tc.wantRecord)
			}
			if !tc.used {
				if used, _ := corrosion.ReleaseFeatureUsed(context.Background(), s.db, capabilities.ReleaseToken,
					string(capabilities.FeatureISCSILUNClaim)); used {
					t.Error("a plain delete marked iscsi_lun_claim used")
				}
			}
		})
	}
}

// Every writer of iscsi_lun_claim's data checks its grant: a gate that passes
// without minting one for the feature — the shape of a write that skipped the
// gate — allocates nothing, and the writers refuse a grant for another
// feature.
//
// Mutation: drop the grant check in decideLUNWith — this goes red.
func TestCreateVM_ISCSI_WritersCheckTheGrant(t *testing.T) {
	s := lunTestServer(t)
	s.SetReleaseFeatureGate(fakeFeatureGate{t: t, grant: false})
	_, err := s.CreateVM(adminCtx(), lunVM("a", "lun0"))
	if err == nil || !strings.Contains(err.Error(), capabilities.ErrNoFeatureGrant.Error()) {
		t.Fatalf("iscsi create with a gate that mints no grant: got %v, want a refusal for the missing grant", err)
	}
	requireNoVM(t, s, "a")
	if n := lunClaimRows(t, s); n != 0 {
		t.Fatalf("a create with no grant left %d LUN claim rows", n)
	}
	ctx := context.Background()
	other := capabilities.GrantForTest(t, capabilities.FeatureVMLimits)
	key := mustLUNKey(t, "10.0.0.1", "0")
	if err := corrosion.AdvanceLUNResolved(ctx, s.db, other, key, 3, s.hostName); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
		t.Fatalf("AdvanceLUNResolved with another feature's grant: %v", err)
	}
	if err := corrosion.RecordLUNPlainDelete(ctx, s.db, other, key, time.Now().UTC().Format(time.RFC3339Nano), s.hostName); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
		t.Fatalf("RecordLUNPlainDelete with another feature's grant: %v", err)
	}
	if _, err := s.decideLUN(ctx, other, corrosion.LUNAllocation{LUN: key, Generation: 0, ClaimID: "x",
		VMID: "x-uuid", VMName: "x", Disk: "root", Host: s.hostName}); err == nil {
		t.Fatal("decideLUN with another feature's grant decided")
	}
	el, err := s.lunElectorate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.learnLUN(ctx, other, el, key, 0); err == nil {
		t.Fatal("learnLUN with another feature's grant ran")
	}
	if n := lunClaimRows(t, s); n != 0 {
		t.Fatalf("writes with another feature's grant left %d LUN claim rows", n)
	}
	// With the grant, the same create goes through.
	s.SetReleaseFeatureGate(fakeFeatureGate{t: t, grant: true})
	if _, err := s.CreateVM(adminCtx(), lunVM("a", "lun0")); err != nil {
		t.Fatalf("iscsi create with the grant: %v", err)
	}
	if n := lunClaimRows(t, s); n == 0 {
		t.Fatal("the granted create left no LUN claim")
	}
}

// A host that cannot reach a majority of the voters allocates no LUN: the
// create is refused Unavailable, saying why, and nothing is created.
//
// Mutation: treat a decision with no majority as free — this goes red.
func TestCreateVM_ISCSI_NeedsAVoterMajority(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	inc, err := s.db.VoterIncarnation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// A three-voter generation: this host and two peers it cannot reach.
	readoptTestGeneration(t, s, []corrosion.VoterMember{
		{Name: s.hostName, Incarnation: inc}, {Name: "voter-b", Incarnation: "b"}, {Name: "voter-c", Incarnation: "c"}})
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return nil, nil, errors.New("partitioned")
	}
	_, err = s.CreateVM(ctx, lunVM("a", "lun0"))
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "majority") {
		t.Fatalf("iscsi create without a voter majority: got %v, want Unavailable naming the majority", err)
	}
	requireNoVM(t, s, "a")
}

// The image is written by qemu-img with both formats explicit, the image
// opened with no backing chain at all (a file swapped in after the standalone
// check cannot pull one in), in place on the device.
//
// Mutation: drop backing=null (or -n) from the argv — this goes red.
func TestQemuImgWrite_Argv(t *testing.T) {
	var got []string
	prev := lunQemuImg
	t.Cleanup(func() { lunQemuImg = prev })
	lunQemuImg = func(_ context.Context, args ...string) ([]byte, error) {
		got = args
		return nil, nil
	}
	for _, tc := range []struct {
		image, format string
		want          []string
	}{
		{"/var/lib/litevirt/images/cirros.qcow2", "qcow2", []string{"convert", "-n", "-O", "raw", "--image-opts",
			"driver=qcow2,file.driver=file,file.filename=/var/lib/litevirt/images/cirros.qcow2,backing=null", "/dev/lun"}},
		{"/img/a,b.raw", "raw", []string{"convert", "-n", "-O", "raw", "--image-opts",
			"driver=raw,file.driver=file,file.filename=/img/a,,b.raw", "/dev/lun"}},
	} {
		if err := qemuImgWrite(context.Background(), tc.image, tc.format, "/dev/lun"); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("argv = %q\n want %q", got, tc.want)
		}
	}
}

// The shared_lun scan writes only while its own lease is held, so two nodes
// never both raise (and page) the same condition.
//
// Mutation: run the scan without the lease — this goes red.
func TestSharedLUN_OnlyTheLeaseHolderWrites(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	insertLUNVM(t, s, "a", "host-a", "root", "/dev/disk/by-path/ip-10.0.0.1-iscsi-iqn.2020-01.com.example:store-lun-0")
	insertLUNVM(t, s, "b", "host-b", "root", "/dev/disk/by-path/ip-10.0.0.1-iscsi-iqn.2020-01.com.example:store-lun-0")
	if held, _, err := corrosion.AcquireLeaseWithTerm(ctx, s.db, sharedLUNLeaseKey, "someone-else", time.Hour, time.Now()); err != nil || !held {
		t.Fatalf("lease: %v %v", held, err)
	}
	s.sharedLUNPass(ctx, time.Minute)
	if c, ok := sharedLUNCondition(t, s); ok {
		t.Fatalf("a node without the lease raised %+v", c)
	}
}
