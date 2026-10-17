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

// Review m-new-1: a node whose Ping lacks nic_list_position drops the field
// and reads each number as a spec index, applied to the NIC at that ordinal.
// lv sends it the numbers as they are only when the VM's NIC ordinals run 0,
// 1, 2, ... (no NIC detached and attached again): there every number means
// the same NIC. Otherwise it refuses, and sends nothing.
//
// Mutations: send positions to the older node regardless — the reordered case
// goes through, red; refuse every older node — the plain case is refused,
// red.
func TestUpdate_NICNumbersToAnOlderNode(t *testing.T) {
	plain := &updateSpy{ordinals: []int32{0, 1, 2}}
	if err := runUpdate(plain, "--nic-mtu", "1=9000", "--nic-rate", "2=5", "vm"); err != nil {
		t.Fatalf("plain VM on an older node: %v", err)
	}
	if g := plain.got; g == nil || g.GetNicByListPosition() || g.NicMtu[0].Ordinal != 1 || g.NicRate[0].Ordinal != 2 {
		t.Errorf("plain VM on an older node: sent %v, want the numbers unchanged as spec indices", g)
	}

	reordered := &updateSpy{ordinals: []int32{2, 1}}
	err := runUpdate(reordered, "--nic-mtu", "1=9000", "vm")
	if err == nil || !strings.Contains(err.Error(), "runs an older build") || reordered.got != nil {
		t.Errorf("reordered VM on an older node: err %v, sent %v; want a refusal and nothing sent", err, reordered.got)
	}
}
