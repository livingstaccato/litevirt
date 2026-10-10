package grpcapi

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Fix round 1: the LUN is taken by a voter-majority claim, behind the
// iscsi_lun_claim release feature (review I-1, I-2; rulings 1 and 5).

// Until the release feature is open — the cluster upgrade has finished —
// nothing is allocated on an iscsi pool: refusing is safer than the old silent
// sharing. A create without an iscsi disk is untouched.
//
// Mutation: let the gate pass with no release feature — this goes red.
func TestCreateVM_ISCSI_RefusedUntilTheUpgradeFinishes(t *testing.T) {
	s := lunTestServer(t)
	s.releaseFeatureGate = nil
	_, err := s.CreateVM(adminCtx(), lunVM("a", "lun0"))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "the cluster upgrade must finish first") {
		t.Fatalf("iscsi create before the release latch: got %v, want FailedPrecondition", err)
	}
	requireNoVM(t, s, "a")
	if _, err := s.CreateVM(adminCtx(), &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "plain", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: s.hostName},
		Disks: []*pb.DiskSpec{{Name: "root", Size: "1G"}},
	}}); err != nil {
		t.Fatalf("a create without an iscsi disk before the latch: %v", err)
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
