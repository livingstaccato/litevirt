package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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

	// A named member that answers its probe but fails its pre-stage is left
	// behind with a warning, as one that does not answer is.
	client = &perHostPreStageClient{
		mockUpgradeClient: &mockUpgradeClient{
			stream: &mockUpgradeStream{response: &pb.UpgradeHostResponse{Status: "ok"}}, hosts: hosts(),
		},
		failStage: map[string]error{"node2": status.Error(codes.Internal, "exec format error")},
	}
	if err := HostUpgrade(context.Background(), client, UpgradeOpts{
		BinaryPath: bin, HostNames: []string{"node1"}, Yes: true, SkipPreStage: []string{"node2"},
	}); err != nil {
		t.Fatalf("--skip-prestage node2 whose pre-stage fails: %v", err)
	}
	if want := []string{"node1"}; !slices.Equal(client.preStaged, want) {
		t.Fatalf("pre-staged %v, want %v", client.preStaged, want)
	}

	// --skip-prestage means nothing without the pre-stage pass.
	client = &perHostPreStageClient{mockUpgradeClient: &mockUpgradeClient{
		stream: &mockUpgradeStream{response: &pb.UpgradeHostResponse{Status: "ok"}}, hosts: hosts(),
	}}
	if err := HostUpgrade(context.Background(), client, UpgradeOpts{
		BinaryPath: bin, HostNames: []string{"node1"}, Yes: true, NoPreStage: true, SkipPreStage: []string{"node2"},
	}); err == nil || !strings.Contains(err.Error(), "--no-prestage") {
		t.Errorf("--skip-prestage with --no-prestage: err %v, want a refusal naming --no-prestage", err)
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
	for _, want := range []string{"disk full", "node1, node3", "node2 refuses", "--skip-prestage node2", "built for that host"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not contain %q", err, want)
		}
	}
	// Upgrading node2 with this binary fails the same way: not an escape.
	if strings.Contains(err.Error(), "lv host upgrade node2") {
		t.Errorf("refusal %q offers lv host upgrade node2, which fails the same way", err)
	}
	if strings.Contains(err.Error(), "Nothing was pre-staged") {
		t.Errorf("refusal %q claims nothing changed after hosts were pre-staged", err)
	}
	if len(activate.sent) != 0 {
		t.Errorf("%d activate chunk(s) sent; no binary may be swapped", len(activate.sent))
	}
}

// In all-hosts mode a host already on the binary's version is neither swapped
// nor pre-staged; naming it in --skip-prestage says that, not "a target".
func TestHostUpgrade_SkipPreStageCurrentHostInAllMode(t *testing.T) {
	bin := writeVersionedBinary(t, "v2.0.0")
	client := &perHostPreStageClient{mockUpgradeClient: &mockUpgradeClient{
		stream: &mockUpgradeStream{response: &pb.UpgradeHostResponse{Status: "ok"}},
		hosts: []*pb.Host{
			{Name: "node1", Address: "10.0.0.1", Version: "v1.0.0"},
			{Name: "node2", Address: "10.0.0.2", Version: "v2.0.0"},
		},
	}}
	err := HostUpgrade(context.Background(), client, UpgradeOpts{BinaryPath: bin, Yes: true, SkipPreStage: []string{"node2"}})
	if err == nil || !strings.Contains(err.Error(), "node2 already runs v2.0.0") || strings.Contains(err.Error(), "is a target") {
		t.Fatalf("err %v, want it to say node2 already runs v2.0.0", err)
	}
	if len(client.preStaged) != 0 {
		t.Fatalf("pre-staged %v before refusing", client.preStaged)
	}
}

// A version that does not name one build (a "dev" build, or a -dirty tree)
// never marks a member current: it is pre-staged.
func TestHostUpgrade_DevOrDirtyVersionPreStagesTheMember(t *testing.T) {
	for _, v := range []string{"dev", "v1.9.0-3-gabc1234-dirty"} {
		t.Run(v, func(t *testing.T) {
			bin := writeVersionedBinary(t, v)
			client := &perHostPreStageClient{mockUpgradeClient: &mockUpgradeClient{
				stream: &mockUpgradeStream{response: &pb.UpgradeHostResponse{Status: "ok"}},
				hosts: []*pb.Host{
					{Name: "node1", Address: "10.0.0.1", Version: "v0.9.0"},
					{Name: "node2", Address: "10.0.0.2", Version: v},
				},
			}}
			if err := HostUpgrade(context.Background(), client, UpgradeOpts{
				BinaryPath: bin, HostNames: []string{"node1"}, Yes: true,
			}); err != nil {
				t.Fatalf("HostUpgrade: %v", err)
			}
			slices.Sort(client.preStaged)
			if want := []string{"node1", "node2"}; !slices.Equal(client.preStaged, want) {
				t.Fatalf("pre-staged %v, want %v: %q names no one build", client.preStaged, want, v)
			}
		})
	}
}

// concurrentProbeClient measures how many probes are in flight at once.
type concurrentProbeClient struct {
	*perHostPreStageClient
	mu            sync.Mutex
	inflight, max int
}

func (c *concurrentProbeClient) PreflightUpgrade(ctx context.Context, req *pb.PreflightUpgradeRequest, opts ...grpc.CallOption) (*pb.PreflightUpgradeResponse, error) {
	c.mu.Lock()
	c.inflight++
	c.max = max(c.max, c.inflight)
	c.mu.Unlock()
	time.Sleep(30 * time.Millisecond)
	c.mu.Lock()
	c.inflight--
	c.mu.Unlock()
	return c.perHostPreStageClient.PreflightUpgrade(ctx, req, opts...)
}

// The probes run in parallel, at most probeParallelism at once: a probe can
// take seconds on a member with slow pools, and they change nothing.
func TestHostUpgrade_ProbesInParallelWithABound(t *testing.T) {
	bin := writeFakeBinary(t)
	var hosts []*pb.Host
	for i := range 3 * probeParallelism {
		hosts = append(hosts, &pb.Host{Name: fmt.Sprintf("node%d", i), Version: "v0.9.0"})
	}
	client := &concurrentProbeClient{perHostPreStageClient: &perHostPreStageClient{mockUpgradeClient: &mockUpgradeClient{
		stream: &mockUpgradeStream{response: &pb.UpgradeHostResponse{Status: "ok"}}, hosts: hosts,
	}}}
	if err := HostUpgrade(context.Background(), client, UpgradeOpts{
		BinaryPath: bin, HostNames: []string{"node0"}, Yes: true,
	}); err != nil {
		t.Fatalf("HostUpgrade: %v", err)
	}
	if client.max < 2 || client.max > probeParallelism {
		t.Fatalf("%d probes in flight at most, want 2..%d", client.max, probeParallelism)
	}
	if len(client.preStaged) != len(hosts) {
		t.Fatalf("pre-staged %d hosts, want %d", len(client.preStaged), len(hosts))
	}
}

// In all-hosts mode a member on a version that names no one build (dev, or
// a -dirty tree) is not current: it is upgraded, so pre-staged too, not left
// on its schema to refuse every upgraded host.
func TestHostUpgrade_AllModeDevOrDirtyMemberIsNotCurrent(t *testing.T) {
	for _, v := range []string{"dev", "v1.9.0-3-gabc1234-dirty"} {
		t.Run(v, func(t *testing.T) {
			bin := writeVersionedBinary(t, v)
			activate := &mockUpgradeStream{response: &pb.UpgradeHostResponse{Status: "ok", NewVersion: v}}
			client := &perHostPreStageClient{mockUpgradeClient: &mockUpgradeClient{
				stream: activate,
				hosts: []*pb.Host{
					{Name: "node1", Address: "10.0.0.1", Version: "v0.9.0"},
					{Name: "node2", Address: "10.0.0.2", Version: v},
				},
			}}
			if err := HostUpgrade(context.Background(), client, UpgradeOpts{BinaryPath: bin, Yes: true}); err != nil {
				t.Fatalf("HostUpgrade: %v", err)
			}
			slices.Sort(client.preStaged)
			if want := []string{"node1", "node2"}; !slices.Equal(client.preStaged, want) {
				t.Fatalf("pre-staged %v, want %v", client.preStaged, want)
			}
		})
	}
}

// hangingProbeClient's probe of one host never answers until its context
// ends, like a peer forward that hangs.
type hangingProbeClient struct {
	*perHostPreStageClient
	hung string
}

func (c *hangingProbeClient) PreflightUpgrade(ctx context.Context, req *pb.PreflightUpgradeRequest, opts ...grpc.CallOption) (*pb.PreflightUpgradeResponse, error) {
	if req.GetTargetHost() == c.hung {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return c.perHostPreStageClient.PreflightUpgrade(ctx, req, opts...)
}

// A probe that does not answer within probeTimeout is a refusal: one hung
// peer cannot hold the upgrade, and nothing is pre-staged.
func TestHostUpgrade_HungProbeTimesOut(t *testing.T) {
	old := probeTimeout
	probeTimeout = 200 * time.Millisecond
	t.Cleanup(func() { probeTimeout = old })

	bin := writeFakeBinary(t)
	client := &hangingProbeClient{hung: "node2", perHostPreStageClient: &perHostPreStageClient{mockUpgradeClient: &mockUpgradeClient{
		stream: &mockUpgradeStream{response: &pb.UpgradeHostResponse{Status: "ok"}},
		hosts: []*pb.Host{
			{Name: "node1", Address: "10.0.0.1", Version: "v0.9.0"},
			{Name: "node2", Address: "10.0.0.2", Version: "v0.9.0"},
		},
	}}}
	done := make(chan error, 1)
	go func() {
		done <- HostUpgrade(context.Background(), client, UpgradeOpts{BinaryPath: bin, HostNames: []string{"node1"}, Yes: true})
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "node2") {
			t.Fatalf("err %v, want a refusal naming node2", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a hung probe held the upgrade")
	}
	if len(client.preStaged) != 0 {
		t.Fatalf("pre-staged %v after a probe timed out", client.preStaged)
	}
}
