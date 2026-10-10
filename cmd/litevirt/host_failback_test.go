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
}

func (c *failbackClient) FailbackHost(_ context.Context, in *pb.FailbackHostRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.FailbackProgress], error) {
	c.req = in
	return &failbackStream{frames: c.frames}, nil
}

func (c *failbackClient) UndrainHost(_ context.Context, in *pb.UndrainHostRequest, _ ...grpc.CallOption) (*pb.Host, error) {
	c.undrains++
	return &pb.Host{Name: in.Name, State: pb.HostState_HOST_ACTIVE}, nil
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

// --failback undrains first and then runs the failback for every VM.
func TestHostUndrain_FailbackFlagRunsItForAll(t *testing.T) {
	c := &failbackClient{}
	out, err := runFailbackCLI(t, c, "host", "undrain", "h1", "--failback")
	if err != nil {
		t.Fatalf("undrain --failback: %v", err)
	}
	if c.undrains != 1 || c.req == nil || !c.req.GetAll() || c.req.GetDryRun() {
		t.Fatalf("undrains=%d request=%+v, want one undrain then a failback of all", c.undrains, c.req)
	}
	if !strings.Contains(out, "is now HOST_ACTIVE") {
		t.Errorf("output = %q", out)
	}
	// Without the flag nothing is asked of FailbackHost.
	c = &failbackClient{}
	if _, err := runFailbackCLI(t, c, "host", "undrain", "h1"); err != nil || c.req != nil {
		t.Fatalf("plain undrain: err=%v request=%+v, want no failback", err, c.req)
	}
}
