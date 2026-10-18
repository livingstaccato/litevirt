package cli

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func writeFakeBinary(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "litevirtd")
	if err := os.WriteFile(p, []byte("fake-binary-bytes"), 0755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPreStageSchema_AllOK(t *testing.T) {
	bin := writeFakeBinary(t)
	client := &mockUpgradeClient{
		preStageStream: &mockUpgradeStream{response: &pb.UpgradeHostResponse{Status: "ok", SchemaVersion: 15}},
	}
	targets := []*pb.Host{{Name: "node1"}, {Name: "node2"}}
	if err := preStageSchema(context.Background(), client, targets, nil, bin, false); err != nil {
		t.Fatalf("preStageSchema: %v", err)
	}
}

// An older daemon without the RPC returns Unimplemented — that's a graceful
// skip (fall back to plain rolling upgrade), NOT a failure that aborts.
func TestPreStageSchema_UnimplementedFallsBack(t *testing.T) {
	bin := writeFakeBinary(t)
	client := &mockUpgradeClient{
		preStageStream: &mockUpgradeStream{closeErr: status.Error(codes.Unimplemented, "method PreStageUpgrade not implemented")},
	}
	targets := []*pb.Host{{Name: "old-node"}}
	if err := preStageSchema(context.Background(), client, targets, nil, bin, false); err != nil {
		t.Fatalf("Unimplemented must NOT abort the upgrade, got: %v", err)
	}
}

// A real pre-stage failure (e.g. migration error) must abort before any binary
// is swapped, so the operator can fix it and re-run.
func TestPreStageSchema_HardFailureAborts(t *testing.T) {
	bin := writeFakeBinary(t)
	client := &mockUpgradeClient{
		preStageStream: &mockUpgradeStream{closeErr: status.Error(codes.Internal, "schema-migrate: disk full")},
	}
	targets := []*pb.Host{{Name: "node1"}}
	err := preStageSchema(context.Background(), client, targets, nil, bin, false)
	if err == nil {
		t.Fatal("expected preStageSchema to abort on a hard failure")
	}
	if !strings.Contains(err.Error(), "node1") {
		t.Errorf("error should name the failed host: %v", err)
	}
}

// HostUpgrade must abort (and swap NOTHING) when pre-staging fails.
func TestHostUpgrade_AbortsBeforeActivateOnPreStageFailure(t *testing.T) {
	bin := writeFakeBinary(t)
	activate := &mockUpgradeStream{response: &pb.UpgradeHostResponse{Status: "ok", NewVersion: "v2.0.0"}}
	client := &mockUpgradeClient{
		stream:         activate,
		preStageStream: &mockUpgradeStream{closeErr: status.Error(codes.Internal, "boom")},
		hosts:          []*pb.Host{{Name: "node1", Address: "10.0.0.1", Version: "v1.0.0"}},
	}
	err := HostUpgrade(context.Background(), client, UpgradeOpts{
		BinaryPath: bin,
		HostNames:  []string{"node1"},
		Yes:        true,
	})
	if err == nil {
		t.Fatal("HostUpgrade should fail when pre-stage fails")
	}
	if len(activate.sent) != 0 {
		t.Errorf("no binary should have been swapped after a pre-stage failure, but %d activate chunk(s) were sent", len(activate.sent))
	}
}

// --no-prestage skips phase 1 entirely and still upgrades.
func TestHostUpgrade_NoPreStageSkipsPhase1(t *testing.T) {
	bin := writeFakeBinary(t)
	activate := &mockUpgradeStream{response: &pb.UpgradeHostResponse{Status: "ok", NewVersion: "v2.0.0"}}
	// preStageStream returns an error — but with NoPreStage it must never be called.
	client := &mockUpgradeClient{
		stream:         activate,
		preStageStream: &mockUpgradeStream{closeErr: status.Error(codes.Internal, "should not be called")},
		hosts:          []*pb.Host{{Name: "node1", Address: "10.0.0.1", Version: "v1.0.0"}},
	}
	err := HostUpgrade(context.Background(), client, UpgradeOpts{
		BinaryPath: bin,
		HostNames:  []string{"node1"},
		Yes:        true,
		NoPreStage: true,
	})
	if err != nil {
		t.Fatalf("HostUpgrade --no-prestage: %v", err)
	}
	if len(activate.sent) == 0 {
		t.Error("expected the activate phase to run with --no-prestage")
	}
}

// perHostPreStageClient answers each PreStageUpgrade stream by the host its
// first message names, and records the order of the hosts pre-staged.
type perHostPreStageClient struct {
	*mockUpgradeClient
	fail      map[string]error
	preStaged []string
}

func (m *perHostPreStageClient) PreStageUpgrade(_ context.Context, _ ...grpc.CallOption) (grpc.ClientStreamingClient[pb.UpgradeHostRequest, pb.UpgradeHostResponse], error) {
	return &perHostPreStageStream{client: m}, nil
}

type perHostPreStageStream struct {
	mockUpgradeStream
	client *perHostPreStageClient
}

func (s *perHostPreStageStream) CloseAndRecv() (*pb.UpgradeHostResponse, error) {
	host := s.sent[0].GetTargetHost()
	if err := s.client.fail[host]; err != nil {
		return nil, err
	}
	s.client.preStaged = append(s.client.preStaged, host)
	return &pb.UpgradeHostResponse{Status: "ok", SchemaVersion: 69}, nil
}

// A subset upgrade pre-stages every member, not only its targets: a member
// left on the old schema refuses every push from an upgraded host. A member
// already on the version being deployed has the schema and is not streamed.
func TestHostUpgrade_PreStagesNonTargetMembers(t *testing.T) {
	bin := writeFakeBinary(t)
	activate := &mockUpgradeStream{response: &pb.UpgradeHostResponse{Status: "ok", NewVersion: "v2.0.0"}}
	client := &perHostPreStageClient{mockUpgradeClient: &mockUpgradeClient{
		stream: activate,
		hosts: []*pb.Host{
			{Name: "node1", Address: "10.0.0.1", Version: "v0.9.0"},
			{Name: "node2", Address: "10.0.0.2", Version: "v0.9.0"},
			{Name: "node3", Address: "10.0.0.3", Version: "v0.9.0"},
			// Already on the version being deployed (the connected daemon's,
			// as the fake binary cannot be probed).
			{Name: "node4", Address: "10.0.0.4", Version: "v1.0.0"},
		},
	}}
	if err := HostUpgrade(context.Background(), client, UpgradeOpts{
		BinaryPath: bin, HostNames: []string{"node1"}, Yes: true,
	}); err != nil {
		t.Fatalf("HostUpgrade node1: %v", err)
	}
	slices.Sort(client.preStaged)
	if want := []string{"node1", "node2", "node3"}; !slices.Equal(client.preStaged, want) {
		t.Fatalf("pre-staged %v, want every member %v", client.preStaged, want)
	}
	if n := len(activate.sent); n == 0 {
		t.Fatal("node1 was not upgraded")
	}
	for _, m := range activate.sent {
		if h := m.GetTargetHost(); h != "" && h != "node1" {
			t.Errorf("swapped the binary of non-target %s", h)
		}
	}
}

// A non-target member that cannot be pre-staged refuses the upgrade before any
// binary is swapped, naming the member and the command that fixes it.
func TestHostUpgrade_RefusesWhenAMemberCannotPreStage(t *testing.T) {
	for _, code := range []codes.Code{codes.Unavailable, codes.Unimplemented} {
		t.Run(code.String(), func(t *testing.T) {
			bin := writeFakeBinary(t)
			activate := &mockUpgradeStream{response: &pb.UpgradeHostResponse{Status: "ok", NewVersion: "v2.0.0"}}
			client := &perHostPreStageClient{
				mockUpgradeClient: &mockUpgradeClient{
					stream: activate,
					hosts: []*pb.Host{
						{Name: "node1", Address: "10.0.0.1", Version: "v0.9.0"},
						{Name: "node2", Address: "10.0.0.2", Version: "v0.9.0"},
					},
				},
				fail: map[string]error{"node2": status.Error(code, "cannot reach host node2")},
			}
			err := HostUpgrade(context.Background(), client, UpgradeOpts{
				BinaryPath: bin, HostNames: []string{"node1"}, Yes: true,
			})
			if err == nil {
				t.Fatal("HostUpgrade succeeded with a member that could not be pre-staged")
			}
			for _, want := range []string{"node2", "lv host upgrade node1 node2"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal %q does not contain %q", err, want)
				}
			}
			if len(activate.sent) != 0 {
				t.Errorf("%d activate chunk(s) sent after the refusal; no binary may be swapped", len(activate.sent))
			}

			// --force proceeds past a member that cannot be pre-staged.
			client.preStaged = nil
			if err := HostUpgrade(context.Background(), client, UpgradeOpts{
				BinaryPath: bin, HostNames: []string{"node1"}, Yes: true, Force: true,
			}); err != nil {
				t.Fatalf("HostUpgrade --force: %v", err)
			}
			if len(activate.sent) == 0 {
				t.Error("--force did not upgrade node1")
			}
		})
	}
}
