package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

type keptDisksClient struct {
	pb.LiteVirtClient
	plan *pb.KeptDisksResponse
	reqs []*pb.KeptDisksRequest
	err  error
}

func (c *keptDisksClient) KeptDisks(_ context.Context, req *pb.KeptDisksRequest, _ ...grpc.CallOption) (*pb.KeptDisksResponse, error) {
	c.reqs = append(c.reqs, req)
	if c.err != nil {
		return nil, c.err
	}
	return c.plan, nil
}

func runKeptDisks(t *testing.T, c *keptDisksClient, tty bool, args ...string) (string, error) {
	t.Helper()
	orig, origTTY := withClient, stdinIsTerminal
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error { return fn(ctx, c) }
	stdinIsTerminal = func() bool { return tty }
	t.Cleanup(func() { withClient, stdinIsTerminal = orig, origTTY })
	cmd := newHostKeptDisksCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func keptPlan() *pb.KeptDisksResponse {
	return &pb.KeptDisksResponse{Host: "node-2", DryRun: true, Chains: []*pb.KeptDiskChain{{
		VmName: "old", Records: []string{"/var/lib/litevirt/kept-disks/old.json"},
		Files: []*pb.KeptDiskFile{{Path: "/d/old-root.s1", SizeBytes: 10}, {Path: "/d/old-root.qcow2", SizeBytes: 20, Under: true}},
	}}}
}

// A release names exactly what it removes, then sends those files as the
// confirmed set; without --yes and with no terminal it removes nothing.
//
// Mutations: send the release without expect_paths: red; skip the
// confirmation without a terminal: red.
func TestHostKeptDisks_ReleaseConfirmsExactlyWhatItRemoves(t *testing.T) {
	c := &keptDisksClient{plan: keptPlan()}
	out, err := runKeptDisks(t, c, false, "node-2", "--release", "old")
	if !errors.Is(err, errNoTTYReleaseConfirm) || len(c.reqs) != 1 || !c.reqs[0].DryRun {
		t.Fatalf("release with no terminal and no --yes = %v after %d call(s); want only the dry run, then the refusal", err, len(c.reqs))
	}
	for _, want := range []string{"/d/old-root.s1 (10 bytes)", "/d/old-root.qcow2 (20 bytes) under", "kept-disks/old.json"} {
		if !strings.Contains(out, want) {
			t.Errorf("the plan does not name %q:\n%s", want, out)
		}
	}

	c = &keptDisksClient{plan: keptPlan()}
	if _, err := runKeptDisks(t, c, false, "node-2", "--release", "old", "--yes"); err != nil {
		t.Fatalf("release --yes: %v", err)
	}
	if len(c.reqs) != 2 || c.reqs[1].DryRun || c.reqs[1].Release != "old" ||
		!slices.Equal(c.reqs[1].ExpectPaths, []string{"/d/old-root.s1", "/d/old-root.qcow2"}) {
		t.Fatalf("release --yes sent %+v; want the dry run, then the release with exactly the planned files", c.reqs)
	}
}

// A refused plan and a dry run remove nothing; an older host says so.
func TestHostKeptDisks_RefusedDryRunAndOlderHost(t *testing.T) {
	plan := keptPlan()
	plan.Chains[0].Held = "the snapshot records s1 of VM old on node-2 are taken over these files"
	c := &keptDisksClient{plan: plan}
	if _, err := runKeptDisks(t, c, true, "node-2", "--release", "old", "--yes"); err == nil ||
		!strings.Contains(err.Error(), "snapshot records s1") || len(c.reqs) != 1 {
		t.Fatalf("a held release = %v after %d call(s); want the refusal after the dry run alone", err, len(c.reqs))
	}
	c = &keptDisksClient{plan: keptPlan()}
	if _, err := runKeptDisks(t, c, true, "node-2", "--release", "old", "--dry-run"); err != nil || len(c.reqs) != 1 {
		t.Fatalf("--dry-run = %v after %d call(s); want the dry run alone", err, len(c.reqs))
	}
	c = &keptDisksClient{err: status.Error(codes.Unimplemented, "unknown method KeptDisks")}
	if _, err := runKeptDisks(t, c, true, "node-2"); err == nil || !strings.Contains(err.Error(), "runs a build without lv host kept-disks") {
		t.Fatalf("an older host = %v; want it named as a build without the command", err)
	}
}

// The deleted VM's snapshot records a release drops are named in the plan
// and sent as confirmed; an Unimplemented from the node reached says that
// node, not the target, is old, while the forwarder's own wording is kept.
//
// Mutations: send the release without expect_snapshots: red; name the target
// on every Unimplemented again: red.
func TestHostKeptDisks_SnapshotsConfirmedAndOlderBuildNamed(t *testing.T) {
	plan := keptPlan()
	plan.Chains[0].Snapshots = []string{"s1"}
	c := &keptDisksClient{plan: plan}
	out, err := runKeptDisks(t, c, false, "node-2", "--release", "old", "--yes")
	if err != nil {
		t.Fatalf("release --yes: %v", err)
	}
	if !strings.Contains(out, "the snapshot records s1 of the deleted VM old") ||
		len(c.reqs) != 2 || !slices.Equal(c.reqs[1].ExpectSnapshots, []string{"s1"}) {
		t.Fatalf("release sent %+v, printed:\n%s\nwant s1 named and confirmed", c.reqs, out)
	}
	c = &keptDisksClient{err: status.Error(codes.Unimplemented, "unknown method KeptDisks")}
	if _, err := runKeptDisks(t, c, true, "node-2"); err == nil || !strings.Contains(err.Error(), "the node this command reached runs a build without") {
		t.Errorf("an old entry node = %v; want it named as the node reached", err)
	}
	c = &keptDisksClient{err: status.Error(codes.Unimplemented, "host node-2 runs a build without lv host kept-disks; nothing was removed there")}
	if _, err := runKeptDisks(t, c, true, "node-2"); err == nil || !strings.Contains(err.Error(), "host node-2 runs a build without") {
		t.Errorf("an old target = %v; want the forwarder's wording", err)
	}
}
