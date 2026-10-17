package main

import (
	"context"
	"io"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// updateSpy is the node lv update talks to: its Ping does or does not
// advertise nic_list_position, and it lists the VM's NICs at the ordinals
// given.
type updateSpy struct {
	pb.LiteVirtClient
	listPosition bool
	ordinals     []int32
	got          *pb.UpdateVMRequest
}

func (c *updateSpy) Ping(context.Context, *pb.PingRequest, ...grpc.CallOption) (*pb.PingResponse, error) {
	return &pb.PingResponse{NicListPosition: c.listPosition}, nil
}

func (c *updateSpy) ListVMHardware(context.Context, *pb.ListVMHardwareRequest, ...grpc.CallOption) (*pb.ListVMHardwareResponse, error) {
	resp := &pb.ListVMHardwareResponse{}
	for _, o := range c.ordinals {
		resp.Devices = append(resp.Devices, &pb.HardwareDevice{Device: &pb.HardwareDevice_Nic{Nic: &pb.HardwareNIC{Ordinal: o}}})
	}
	return resp, nil
}

func (c *updateSpy) UpdateVM(_ context.Context, r *pb.UpdateVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	c.got = r
	return &pb.VM{Name: r.GetName()}, nil
}

func runUpdate(spy *updateSpy, args ...string) error {
	orig := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
		return fn(ctx, spy)
	}
	defer func() { withClient = orig }()
	cmd := newUpdateCmd()
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	return cmd.Execute()
}

// lv update numbers NICs by their position in the VM's NIC list, and says
// so in the request: without nic_by_list_position the owner reads each
// number as a spec index, as an older lv meant it.
//
// Mutation: leave the field unset — red.
func TestUpdate_NICNumbersAreListPositions(t *testing.T) {
	for _, c := range []struct {
		args []string
		want bool
	}{
		{[]string{"--nic-mtu", "1=9000", "vm"}, true},
		{[]string{"--nic-rate", "0=5", "vm"}, true},
		{[]string{"--cpu", "2", "vm"}, false},
	} {
		spy := &updateSpy{listPosition: true, ordinals: []int32{1, 2}}
		err := runUpdate(spy, c.args...)
		if err != nil || spy.got == nil || spy.got.GetNicByListPosition() != c.want {
			t.Errorf("%v: err %v, request %v; want nic_by_list_position %v", c.args, err, spy.got, c.want)
		}
	}
}

// Review m-new-1 and m-r2-2: a node whose Ping lacks nic_list_position drops
// the field and reads each number N as a spec index, applied to the NIC at
// ordinal N. While ordinals 0..N run unbroken, N means the same NIC there,
// and goes unchanged; a number at or past the first gap is refused, and
// nothing is sent.
//
// Mutations: send positions to the older node regardless — the gap cases go
// through, red; refuse every older node, or every number once there is a
// gap — the plain and before-the-gap cases are refused, red; keep the field —
// red.
func TestUpdate_NICNumbersToAnOlderNode(t *testing.T) {
	plain := &updateSpy{ordinals: []int32{0, 1, 2}}
	if err := runUpdate(plain, "--nic-mtu", "1=9000", "--nic-rate", "2=5", "--nic-rate", "3=1", "vm"); err != nil {
		t.Fatalf("plain VM on an older node: %v", err)
	}
	if g := plain.got; g == nil || g.GetNicByListPosition() || g.NicMtu[0].Ordinal != 1 || g.NicRate[0].Ordinal != 2 || g.NicRate[1].Ordinal != 3 {
		t.Errorf("plain VM on an older node: sent %v, want the numbers unchanged as spec indices", g)
	}

	// A@0, C@2, B (ordinal 1) detached: NIC 0 is A either way; NIC 1 is C,
	// which that node would read as entry 1, B's.
	before := &updateSpy{ordinals: []int32{0, 2}}
	if err := runUpdate(before, "--nic-mtu", "0=9000", "vm"); err != nil {
		t.Fatalf("--nic-mtu 0= before the gap: %v", err)
	}
	if g := before.got; g == nil || g.GetNicByListPosition() || g.NicMtu[0].Ordinal != 0 {
		t.Errorf("--nic-mtu 0= before the gap: sent %v, want it unchanged as a spec index", g)
	}
	for _, args := range [][]string{
		{"--nic-mtu", "1=9000", "vm"},                      // C, at the gap
		{"--nic-rate", "2=5", "vm"},                        // past the list, after a gap
		{"--nic-mtu", "0=9000", "--nic-rate", "1=5", "vm"}, // one exact, one not
	} {
		spy := &updateSpy{ordinals: []int32{0, 2}}
		err := runUpdate(spy, args...)
		if err == nil || !strings.Contains(err.Error(), "gap in its NIC numbering") || spy.got != nil {
			t.Errorf("%v on A@0, C@2: err %v, sent %v; want a refusal and nothing sent", args, err, spy.got)
		}
	}

	reordered := &updateSpy{ordinals: []int32{2, 1}}
	err := runUpdate(reordered, "--nic-mtu", "0=9000", "vm")
	if err == nil || !strings.Contains(err.Error(), "runs an older build") || reordered.got != nil {
		t.Errorf("A attached again (ordinals 1, 2): err %v, sent %v; want a refusal and nothing sent", err, reordered.got)
	}
}
