package main

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

type cloneCapture struct {
	pb.LiteVirtClient
	req *pb.CloneVMRequest
}

func (c *cloneCapture) CloneVM(_ context.Context, in *pb.CloneVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	c.req = in
	return &pb.VM{Name: in.Target, HostName: in.DestinationHost, State: pb.VMState_VM_STOPPED}, nil
}

// --host and --pool reach the request, and the output names the host.
//
// Mutation: drop DestinationHost or TargetPool from the request in newCloneCmd.
func TestClone_HostAndPoolFlagsReachTheRequest(t *testing.T) {
	c := &cloneCapture{}
	out, err := runFailbackCLI(t, c, "clone", "tpl", "web", "--host", "kvm2", "--pool", "ssd", "--start")
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	if c.req.GetDestinationHost() != "kvm2" || c.req.GetTargetPool() != "ssd" || !c.req.GetStart() ||
		c.req.GetSource() != "tpl" || c.req.GetTarget() != "web" {
		t.Fatalf("request = %+v", c.req)
	}
	if !strings.Contains(out, "web on kvm2") {
		t.Errorf("output = %q, want it to name the host", out)
	}
	c = &cloneCapture{}
	if _, err := runFailbackCLI(t, c, "clone", "tpl", "web"); err != nil || c.req.GetDestinationHost() != "" || c.req.GetTargetPool() != "" {
		t.Fatalf("a plain clone sent a host or pool: %+v err=%v", c.req, err)
	}
}
