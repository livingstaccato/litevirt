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
// advertise nic_list_position.
type updateSpy struct {
	pb.LiteVirtClient
	listPosition bool
	got          *pb.UpdateVMRequest
}

func (c *updateSpy) Ping(context.Context, *pb.PingRequest, ...grpc.CallOption) (*pb.PingResponse, error) {
	return &pb.PingResponse{NicListPosition: c.listPosition}, nil
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
		spy := &updateSpy{listPosition: true}
		err := runUpdate(spy, c.args...)
		if err != nil || spy.got == nil || spy.got.GetNicByListPosition() != c.want {
			t.Errorf("%v: err %v, request %v; want nic_by_list_position %v", c.args, err, spy.got, c.want)
		}
	}
}

// A node whose Ping lacks nic_list_position reads each NIC number as a spec
// index, which can name another NIC: an update naming NICs is refused, and
// nothing is sent. One naming no NIC goes through.
//
// Mutations: send positions to the older node regardless — red; refuse an
// update that names no NIC — red.
func TestUpdate_NICNumbersToAnOlderNode(t *testing.T) {
	for _, args := range [][]string{
		{"--nic-mtu", "0=9000", "vm"},
		{"--nic-rate", "1=5", "vm"},
	} {
		spy := &updateSpy{}
		err := runUpdate(spy, args...)
		if err == nil || !strings.Contains(err.Error(), "runs an older build") || spy.got != nil {
			t.Errorf("%v on an older node: err %v, sent %v; want a refusal and nothing sent", args, err, spy.got)
		}
	}
	spy := &updateSpy{}
	if err := runUpdate(spy, "--cpu", "2", "vm"); err != nil || spy.got == nil {
		t.Errorf("--cpu on an older node: err %v, sent %v; want it sent", err, spy.got)
	}
}
