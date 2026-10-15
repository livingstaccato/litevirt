package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// captureHA records the HA request the CLI put on the wire, and its deadline.
type captureHA struct {
	pb.LiteVirtClient
	set      *pb.SetHAPolicyRequest
	got      bool
	deadline time.Duration
}

func (c *captureHA) SetHAPolicy(ctx context.Context, in *pb.SetHAPolicyRequest, _ ...grpc.CallOption) (*pb.HAPolicyStatus, error) {
	c.set = in
	if d, ok := ctx.Deadline(); ok {
		c.deadline = time.Until(d)
	}
	return &pb.HAPolicyStatus{State: in.GetState(), FirstUsePaid: true}, nil
}

func (c *captureHA) GetHAPolicy(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.HAPolicyStatus, error) {
	c.got = true
	return &pb.HAPolicyStatus{State: "armed", FirstUsePaid: true}, nil
}

func runHACLI(t *testing.T, parent context.Context, spy *captureHA, args ...string) (string, error) {
	t.Helper()
	orig := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
		return fn(ctx, spy)
	}
	t.Cleanup(func() { withClient = orig })
	cmd := newClusterHACmd()
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage = true
	var err error
	out := captureStdout(t, func() { err = cmd.ExecuteContext(parent) })
	return out, err
}

// arm and disarm reach the request with their flags, under a deadline of at
// least 90 s even when the caller's is shorter; anything else is refused
// before it is sent.
//
// Mutation: use the caller's context for the set call — the 5 s deadline
// reaches the wire and this goes red.
func TestClusterHA_FlagsAndDeadline(t *testing.T) {
	short, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	spy := &captureHA{}
	if _, err := runHACLI(t, short, spy, "disarm", "--reason", "core switch, CHG-1234"); err != nil {
		t.Fatal(err)
	}
	if spy.set.GetState() != "disarmed" || spy.set.GetReason() != "core switch, CHG-1234" || spy.set.GetFenceDownHosts() {
		t.Fatalf("disarm request %+v", spy.set)
	}
	if spy.deadline < 90*time.Second {
		t.Fatalf("set deadline %s, want at least 90 s", spy.deadline)
	}
	spy = &captureHA{}
	if _, err := runHACLI(t, context.Background(), spy, "arm", "--fence-down-hosts"); err != nil {
		t.Fatal(err)
	}
	if spy.set.GetState() != "armed" || !spy.set.GetFenceDownHosts() {
		t.Fatalf("arm request %+v", spy.set)
	}
	spy = &captureHA{}
	if _, err := runHACLI(t, context.Background(), spy); err != nil || !spy.got || spy.set != nil {
		t.Fatalf("show: err=%v got=%v set=%+v", err, spy.got, spy.set)
	}
	for _, args := range [][]string{{"freeze"}, {"disarm", "--fence-down-hosts"}, {"--reason", "x"}, {"arm", "disarm"}} {
		spy = &captureHA{}
		if _, err := runHACLI(t, context.Background(), spy, args...); err == nil || spy.set != nil {
			t.Errorf("lv cluster ha %v: err=%v, sent %+v", args, err, spy.set)
		}
	}
}

// The status speaks the peer veto's vocabulary and says what an arm would do.
func TestPrintHAPolicy(t *testing.T) {
	var buf bytes.Buffer
	printHAPolicy(&buf, &pb.HAPolicyStatus{State: "disarmed", SetBy: "alice", At: "T1", Reason: "switch",
		Voters: []*pb.HAVoterAnswer{
			{Host: "n1", HaKnown: true, HaDisarmed: true, HaPolicyAt: "T1", Status: "confirmed"},
			{Host: "n2", Status: "not counted live"},
		},
		Regions:       []*pb.HARegionConfirmation{{Region: "east", Confirmed: true}, {Region: "west"}},
		WouldBeFenced: []string{"n3"},
	})
	out := buf.String()
	for _, want := range []string{"HA:        disarmed", "alice at T1", "switch", "First use: pending",
		"n1", "confirmed", "not counted live", "without a confirming majority: west", "Arming would fence: n3"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}
