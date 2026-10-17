package main

import (
	"context"
	"io"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

type updateSpy struct {
	pb.LiteVirtClient
	got *pb.UpdateVMRequest
}

func (c *updateSpy) UpdateVM(_ context.Context, r *pb.UpdateVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	c.got = r
	return &pb.VM{Name: r.GetName()}, nil
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
		spy := &updateSpy{}
		orig := withClient
		withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
			return fn(ctx, spy)
		}
		cmd := newUpdateCmd()
		cmd.SetArgs(c.args)
		cmd.SetOut(io.Discard)
		err := cmd.Execute()
		withClient = orig
		if err != nil || spy.got == nil || spy.got.GetNicByListPosition() != c.want {
			t.Errorf("%v: err %v, request %v; want nic_by_list_position %v", c.args, err, spy.got, c.want)
		}
	}
}
