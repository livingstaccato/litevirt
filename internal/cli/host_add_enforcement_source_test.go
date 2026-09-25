package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type fenceReadinessClient struct {
	pb.LiteVirtClient
	resp *pb.FenceReadiness
	err  error
}

func (f fenceReadinessClient) GetFenceReadiness(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.FenceReadiness, error) {
	return f.resp, f.err
}

func posture(host string, enforcing bool) *pb.FenceHostPosture {
	return &pb.FenceHostPosture{Host: host, Reachable: true, PostureKnown: true, Enforcing: enforcing}
}

// `lv host add` copies the enforcement block of the machine it runs on, and a
// workstation has none. A node added from a laptop to a cluster founded with
// the safe fence defaults therefore booted with both off — and as coordinator
// would reschedule after a fence nobody can confirm. When there is no block to
// copy, add asks the cluster, and refuses if any member enforces.
func TestJoinEnforcementSource(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name     string
		local    string
		client   fenceReadinessClient
		wantFail string
	}{
		{"a local block is copied as before", "enforcement:\n  shared_storage_fence: true\n", fenceReadinessClient{err: errors.New("must not be asked")}, ""},
		{"cluster enforces, nothing to copy", "", fenceReadinessClient{resp: &pb.FenceReadiness{Hosts: []*pb.FenceHostPosture{posture("node-1", true)}}}, "enforces"},
		{"cluster without a block joins as before", "", fenceReadinessClient{resp: &pb.FenceReadiness{Hosts: []*pb.FenceHostPosture{posture("node-1", false)}}}, ""},
		{"posture cannot be read", "", fenceReadinessClient{resp: &pb.FenceReadiness{Hosts: []*pb.FenceHostPosture{{Host: "node-1"}}}}, "cannot tell"},
		{"the question itself fails", "", fenceReadinessClient{err: errors.New("unavailable")}, "cannot tell"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			useConfig(t, c.local)
			err := checkJoinEnforcementSource(ctx, c.client, daemonConfigPath)
			switch {
			case c.wantFail == "" && err != nil:
				t.Errorf("refused: %v", err)
			case c.wantFail != "" && (err == nil || !strings.Contains(err.Error(), c.wantFail)):
				t.Errorf("err = %v, want a refusal mentioning %q", err, c.wantFail)
			}
		})
	}
}
