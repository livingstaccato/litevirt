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
	if err := preStageSchema(context.Background(), client, targets, nil, bin, nil); err != nil {
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
	if err := preStageSchema(context.Background(), client, targets, nil, bin, nil); err != nil {
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
	err := preStageSchema(context.Background(), client, targets, nil, bin, nil)
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

// perHostPreStageClient answers each member's probe (PreflightUpgrade) and
// each PreStageUpgrade stream by the host it names. unreachable fails both,
// failStage only the pre-stage. It records the hosts pre-staged, in order.
type perHostPreStageClient struct {
	*mockUpgradeClient
	unreachable map[string]error
	failStage   map[string]error
	preStaged   []string
}

func (m *perHostPreStageClient) PreflightUpgrade(_ context.Context, req *pb.PreflightUpgradeRequest, _ ...grpc.CallOption) (*pb.PreflightUpgradeResponse, error) {
	if err := m.unreachable[req.GetTargetHost()]; err != nil {
		return nil, err
	}
	return &pb.PreflightUpgradeResponse{Ok: true, Host: req.GetTargetHost()}, nil
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
	if err := s.client.unreachable[host]; err != nil {
		return nil, err
	}
	if err := s.client.failStage[host]; err != nil {
		return nil, err
	}
	s.client.preStaged = append(s.client.preStaged, host)
	return &pb.UpgradeHostResponse{Status: "ok", SchemaVersion: 69}, nil
}

// writeVersionedBinary writes a "new build" whose --version can be probed.
func writeVersionedBinary(t *testing.T, version string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "litevirtd")
	script := "#!/bin/sh\necho \"litevirt version=" + version + "\"\n"
	if err := os.WriteFile(p, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	return p
}

// swappedHosts lists the hosts the activate phase streamed a binary to.
func swappedHosts(activate *mockUpgradeStream) []string {
	var out []string
	for _, m := range activate.sent {
		if h := m.GetTargetHost(); h != "" && !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	return out
}

// A subset upgrade pre-stages every member, not only its targets: a member
// left on the old schema refuses every push from an upgraded host. A member
// already on the version of the (probed) binary has the schema and is not
// streamed.
func TestHostUpgrade_PreStagesNonTargetMembers(t *testing.T) {
	bin := writeVersionedBinary(t, "v2.0.0")
	activate := &mockUpgradeStream{response: &pb.UpgradeHostResponse{Status: "ok", NewVersion: "v2.0.0"}}
	client := &perHostPreStageClient{mockUpgradeClient: &mockUpgradeClient{
		stream: activate,
		hosts: []*pb.Host{
			{Name: "node1", Address: "10.0.0.1", Version: "v0.9.0"},
			{Name: "node2", Address: "10.0.0.2", Version: "v0.9.0"},
			{Name: "node3", Address: "10.0.0.3", Version: "v0.9.0"},
			{Name: "node4", Address: "10.0.0.4", Version: "v2.0.0"},
		},
	}}
	if err := HostUpgrade(context.Background(), client, UpgradeOpts{
		BinaryPath: bin, HostNames: []string{"node1"}, Yes: true,
	}); err != nil {
		t.Fatalf("HostUpgrade node1: %v", err)
	}
	slices.Sort(client.preStaged)
	if want := []string{"node1", "node2", "node3"}; !slices.Equal(client.preStaged, want) {
		t.Fatalf("pre-staged %v, want every member not on the binary's version %v", client.preStaged, want)
	}
	if got := swappedHosts(activate); !slices.Equal(got, []string{"node1"}) {
		t.Fatalf("swapped %v, want only node1", got)
	}
}

// When the binary cannot be probed (cross-arch, or the probe timed out), no
// member is known to be on its version: the connected daemon's version says
// nothing about the binary, so every member is pre-staged (I1).
func TestHostUpgrade_UnprobeableBinaryPreStagesEveryMember(t *testing.T) {
	bin := writeFakeBinary(t) // not executable as a program: --version cannot be probed
	activate := &mockUpgradeStream{response: &pb.UpgradeHostResponse{Status: "ok", NewVersion: "v2.0.0"}}
	client := &perHostPreStageClient{mockUpgradeClient: &mockUpgradeClient{
		stream: activate,
		hosts: []*pb.Host{
			{Name: "node1", Address: "10.0.0.1", Version: "v1.0.0"},
			// On the CONNECTED daemon's version (the mock Ping's v1.0.0).
			{Name: "node2", Address: "10.0.0.2", Version: "v1.0.0"},
		},
	}}
	if err := HostUpgrade(context.Background(), client, UpgradeOpts{
		BinaryPath: bin, HostNames: []string{"node1"}, Yes: true,
	}); err != nil {
		t.Fatalf("HostUpgrade node1: %v", err)
	}
	slices.Sort(client.preStaged)
	if want := []string{"node1", "node2"}; !slices.Equal(client.preStaged, want) {
		t.Fatalf("pre-staged %v, want %v: an unprobed binary must not skip a member", client.preStaged, want)
	}
}

// A member that cannot be pre-staged refuses the upgrade before ANY host is
// pre-staged (a pre-staged host advertises the new schema, and the member
// would refuse its pushes) and before any binary is swapped. The refusal names
// the member and every way past it. --force keeps its meaning (preflight
// blocks) and does not pass it.
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
						{Name: "node3", Address: "10.0.0.3", Version: "v0.9.0"},
					},
				},
				unreachable: map[string]error{"node3": status.Error(code, "cannot reach host node3")},
			}
			for _, force := range []bool{false, true} {
				err := HostUpgrade(context.Background(), client, UpgradeOpts{
					BinaryPath: bin, HostNames: []string{"node1"}, Yes: true, Force: force,
				})
				if err == nil {
					t.Fatalf("force=%v: HostUpgrade succeeded with a member that could not be pre-staged", force)
				}
				for _, want := range []string{"node3", "lv host upgrade node1 node3", "--skip-prestage node3", "lv host rm node3", "Nothing was pre-staged"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("force=%v: refusal %q does not contain %q", force, err, want)
					}
				}
				if len(client.preStaged) != 0 {
					t.Errorf("force=%v: pre-staged %v before refusing; a refused upgrade must change no host", force, client.preStaged)
				}
				if len(activate.sent) != 0 {
					t.Errorf("force=%v: %d activate chunk(s) sent after the refusal; no binary may be swapped", force, len(activate.sent))
				}
			}

			// --skip-prestage names the member that is down: the rest is
			// pre-staged, the target upgraded, and its preflight stays armed.
			if err := HostUpgrade(context.Background(), client, UpgradeOpts{
				BinaryPath: bin, HostNames: []string{"node1"}, Yes: true, SkipPreStage: []string{"node3"},
			}); err != nil {
				t.Fatalf("HostUpgrade --skip-prestage node3: %v", err)
			}
			slices.Sort(client.preStaged)
			if want := []string{"node1", "node2"}; !slices.Equal(client.preStaged, want) {
				t.Fatalf("--skip-prestage node3 pre-staged %v, want %v", client.preStaged, want)
			}
			if got := swappedHosts(activate); !slices.Equal(got, []string{"node1"}) {
				t.Fatalf("--skip-prestage node3 swapped %v, want node1", got)
			}
			for _, m := range activate.sent {
				if m.GetForce() {
					t.Fatal("--skip-prestage disarmed the target's preflight (Force set on UpgradeHost)")
				}
			}
		})
	}
}

// --skip-prestage only names a member that is down: one that answers is
// pre-staged anyway, and a target or a host that is not a member is an error.
func TestHostUpgrade_SkipPreStage(t *testing.T) {
	hosts := func() []*pb.Host {
		return []*pb.Host{
			{Name: "node1", Address: "10.0.0.1", Version: "v0.9.0"},
			{Name: "node2", Address: "10.0.0.2", Version: "v0.9.0"},
		}
	}
	bin := writeFakeBinary(t)

	client := &perHostPreStageClient{mockUpgradeClient: &mockUpgradeClient{
		stream: &mockUpgradeStream{response: &pb.UpgradeHostResponse{Status: "ok"}}, hosts: hosts(),
	}}
	if err := HostUpgrade(context.Background(), client, UpgradeOpts{
		BinaryPath: bin, HostNames: []string{"node1"}, Yes: true, SkipPreStage: []string{"node2"},
	}); err != nil {
		t.Fatalf("HostUpgrade: %v", err)
	}
	slices.Sort(client.preStaged)
	if want := []string{"node1", "node2"}; !slices.Equal(client.preStaged, want) {
		t.Fatalf("pre-staged %v, want %v: a named member that answers is pre-staged anyway", client.preStaged, want)
	}

	for _, tc := range []struct{ skip, want string }{
		{"node1", "node1 is a target"},
		{"node9", "node9 is not a member"},
	} {
		client := &perHostPreStageClient{mockUpgradeClient: &mockUpgradeClient{
			stream: &mockUpgradeStream{response: &pb.UpgradeHostResponse{Status: "ok"}}, hosts: hosts(),
		}}
		err := HostUpgrade(context.Background(), client, UpgradeOpts{
			BinaryPath: bin, HostNames: []string{"node1"}, Yes: true, SkipPreStage: []string{tc.skip},
		})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("--skip-prestage %s: err %v, want %q", tc.skip, err, tc.want)
		}
		if len(client.preStaged) != 0 {
			t.Errorf("--skip-prestage %s: pre-staged %v before refusing", tc.skip, client.preStaged)
		}
	}
}

// A pre-stage that fails after every member answered its probe cannot be
// undone. The rest is still pre-staged, so only the failed member is behind,
// and the refusal says what it leaves: which hosts are pre-staged, and that
// the failed member refuses their pushes until it is pre-staged or upgraded.
func TestHostUpgrade_PreStageFailureAfterProbeSaysWhatItLeft(t *testing.T) {
	bin := writeFakeBinary(t)
	activate := &mockUpgradeStream{response: &pb.UpgradeHostResponse{Status: "ok", NewVersion: "v2.0.0"}}
	client := &perHostPreStageClient{
		mockUpgradeClient: &mockUpgradeClient{
			stream: activate,
			hosts: []*pb.Host{
				{Name: "node1", Address: "10.0.0.1", Version: "v0.9.0"},
				{Name: "node2", Address: "10.0.0.2", Version: "v0.9.0"},
				{Name: "node3", Address: "10.0.0.3", Version: "v0.9.0"},
			},
		},
		failStage: map[string]error{"node2": status.Error(codes.Internal, "schema-migrate on node2: disk full")},
	}
	err := HostUpgrade(context.Background(), client, UpgradeOpts{
		BinaryPath: bin, HostNames: []string{"node1"}, Yes: true,
	})
	if err == nil {
		t.Fatal("HostUpgrade succeeded with a member whose pre-stage failed")
	}
	slices.Sort(client.preStaged)
	if want := []string{"node1", "node3"}; !slices.Equal(client.preStaged, want) {
		t.Fatalf("pre-staged %v, want every other member %v", client.preStaged, want)
	}
	for _, want := range []string{"disk full", "node1, node3", "node2 refuses", "lv host upgrade node2"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not contain %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "Nothing was pre-staged") {
		t.Errorf("refusal %q claims nothing changed after hosts were pre-staged", err)
	}
	if len(activate.sent) != 0 {
		t.Errorf("%d activate chunk(s) sent; no binary may be swapped", len(activate.sent))
	}
}
