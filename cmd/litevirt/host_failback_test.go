package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
)

type failbackStream struct {
	fakeStream[pb.FailbackProgress]
	frames []*pb.FailbackProgress
}

func (s *failbackStream) Recv() (*pb.FailbackProgress, error) {
	if len(s.frames) == 0 {
		return nil, io.EOF
	}
	f := s.frames[0]
	s.frames = s.frames[1:]
	return f, nil
}

type failbackClient struct {
	pb.LiteVirtClient
	frames   []*pb.FailbackProgress
	req      *pb.FailbackHostRequest
	undrains int
	started  bool
	note     string
}

func (c *failbackClient) FailbackHost(_ context.Context, in *pb.FailbackHostRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.FailbackProgress], error) {
	c.req = in
	return &failbackStream{frames: c.frames}, nil
}

func (c *failbackClient) UndrainHost(_ context.Context, in *pb.UndrainHostRequest, _ ...grpc.CallOption) (*pb.Host, error) {
	c.undrains++
	return &pb.Host{Name: in.Name, State: pb.HostState_HOST_ACTIVE, FailbackStarted: c.started, FailbackNote: c.note}, nil
}

func runFailbackCLI(t *testing.T, c pb.LiteVirtClient, args ...string) (string, error) {
	t.Helper()
	orig := cli.Connect
	cli.Connect = func(context.Context) (pb.LiteVirtClient, func(), error) { return c, func() {}, nil }
	t.Cleanup(func() { cli.Connect = orig })
	origOut := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	root := newRootCmd()
	root.SetArgs(args)
	err := root.Execute()
	w.Close()
	os.Stdout = origOut
	var b bytes.Buffer
	b.ReadFrom(r)
	return b.String(), err
}

// `lv host failback` prints each VM's result and fails when one did not move,
// so a script sees it.
//
// Mutation: ignore status "failed" in runFailback — the second case returns nil.
func TestHostFailback_PrintsResultsAndFailsOnAFailedMove(t *testing.T) {
	c := &failbackClient{frames: []*pb.FailbackProgress{
		{VmName: "a", FromHost: "h2", Status: "moved"},
		{VmName: "b", FromHost: "h2", Status: "skipped", Reason: "not opted in"},
	}}
	out, err := runFailbackCLI(t, c, "host", "failback", "h1", "--all", "--dry-run")
	if err != nil {
		t.Fatalf("failback: %v", err)
	}
	if !c.req.GetAll() || !c.req.GetDryRun() || c.req.GetName() != "h1" {
		t.Errorf("request = %+v, want h1 with all and dry-run", c.req)
	}
	for _, want := range []string{"a h2 → h1 [moved]", "b h2 → h1 [skipped]: not opted in"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	c = &failbackClient{frames: []*pb.FailbackProgress{{VmName: "a", FromHost: "h2", Status: "failed", Reason: "no"}}}
	if _, err := runFailbackCLI(t, c, "host", "failback", "h1"); err == nil || !strings.Contains(err.Error(), "did not move back") {
		t.Errorf("a failed move gave %v, want an error", err)
	}
}

// --failback follows the run the undrain started (one run, not a second), and
// the reply's note is printed. When no run started nothing is followed and no
// failback is asked for.
//
// Mutation: make undrain --failback call FailbackHost without Follow - the
// request is a second run, and asks for all.
func TestHostUndrain_FailbackFlagFollowsTheRunItStarted(t *testing.T) {
	c := &failbackClient{started: true, note: "failback of up to 2 VM(s) started in the background on node-1"}
	out, err := runFailbackCLI(t, c, "host", "undrain", "h1", "--failback")
	if err != nil {
		t.Fatalf("undrain --failback: %v", err)
	}
	if c.undrains != 1 || c.req == nil || !c.req.GetFollow() || c.req.GetAll() || c.req.GetDryRun() {
		t.Fatalf("undrains=%d request=%+v, want one undrain then a FOLLOW of the started run", c.undrains, c.req)
	}
	if !strings.Contains(out, "is now HOST_ACTIVE") || !strings.Contains(out, "started in the background on node-1") {
		t.Errorf("output = %q", out)
	}
	// No run started: nothing to follow.
	c = &failbackClient{note: "2 VM(s) a drain moved from h1 have not opted in to failback"}
	out, err = runFailbackCLI(t, c, "host", "undrain", "h1", "--failback")
	if err != nil || c.req != nil || !strings.Contains(out, "have not opted in") {
		t.Fatalf("no run started: err=%v request=%+v out=%q, want the note and no failback request", err, c.req, out)
	}
	// Without the flag nothing is asked of FailbackHost, but the note is printed.
	c = &failbackClient{started: true, note: "started"}
	if out, err := runFailbackCLI(t, c, "host", "undrain", "h1"); err != nil || c.req != nil || !strings.Contains(out, "started") {
		t.Fatalf("plain undrain: err=%v request=%+v out=%q", err, c.req, out)
	}
}

// `lv host failback --follow` asks to follow.
func TestHostFailback_FollowFlag(t *testing.T) {
	c := &failbackClient{}
	if _, err := runFailbackCLI(t, c, "host", "failback", "h1", "--follow"); err != nil || !c.req.GetFollow() {
		t.Fatalf("request = %+v err=%v, want follow", c.req, err)
	}
}
