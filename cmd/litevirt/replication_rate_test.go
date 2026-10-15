package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
)

// rateClient records the schedule request and lists canned schedules.
type rateClient struct {
	pb.LiteVirtClient
	created *pb.CreateReplicationScheduleRequest
	list    []*pb.ReplicationSchedule
	// dropRate answers as a daemon that does not know the field: no limit.
	dropRate bool
}

func (c *rateClient) CreateReplicationSchedule(_ context.Context, in *pb.CreateReplicationScheduleRequest, _ ...grpc.CallOption) (*pb.ReplicationSchedule, error) {
	c.created = in
	out := &pb.ReplicationSchedule{VmName: in.VmName, TargetPool: in.TargetPool, Cron: in.Cron, BwlimitBytesPerSec: in.GetBwlimitBytesPerSec()}
	if c.dropRate {
		out.BwlimitBytesPerSec = 0
	}
	return out, nil
}

func (c *rateClient) ListReplicationSchedules(context.Context, *pb.ListReplicationSchedulesRequest, ...grpc.CallOption) (*pb.ListReplicationSchedulesResponse, error) {
	return &pb.ListReplicationSchedulesResponse{Schedules: c.list}, nil
}

func runRateCmd(t *testing.T, c *rateClient, args ...string) (string, error) {
	t.Helper()
	orig := cli.Connect
	cli.Connect = func(context.Context) (pb.LiteVirtClient, func(), error) { return c, func() {}, nil }
	t.Cleanup(func() { cli.Connect = orig })
	root := newRootCmd()
	root.SetArgs(args)
	var err error
	out := captureStdout(t, func() { err = root.Execute() })
	return out, err
}

// --bwlimit takes the backup parser's forms; absent, the field is unset, so the
// stored limit stays; 0 is sent as an explicit 0 (clear); a bad or too-low
// value is refused before any call.
//
// Mutation: always send the parsed value — the absent case sends 0.
func TestReplicationScheduleAdd_Bwlimit(t *testing.T) {
	base := []string{"replication", "schedule", "add", "web1", "--cron", "0 * * * *", "--target-pool", "dr"}
	for _, tc := range []struct {
		flag []string
		want *int64
	}{
		{nil, nil},
		{[]string{"--bwlimit", "50MiB"}, ptrI64(50 << 20)},
		{[]string{"--bwlimit", "512K"}, ptrI64(512 << 10)},
		{[]string{"--bwlimit", "0"}, ptrI64(0)},
	} {
		c := &rateClient{}
		if _, err := runRateCmd(t, c, append(append([]string{}, base...), tc.flag...)...); err != nil {
			t.Fatalf("%v: %v", tc.flag, err)
		}
		got := c.created.BwlimitBytesPerSec
		switch {
		case tc.want == nil && got != nil:
			t.Errorf("%v: sent bwlimit %d, want it unset", tc.flag, *got)
		case tc.want != nil && (got == nil || *got != *tc.want):
			t.Errorf("%v: sent %v, want %d", tc.flag, got, *tc.want)
		}
	}
	for _, bad := range []string{"fast", "1000", "-5M"} {
		c := &rateClient{}
		if _, err := runRateCmd(t, c, append(append([]string{}, base...), "--bwlimit", bad)...); err == nil || c.created != nil {
			t.Errorf("--bwlimit %s: err=%v sent=%v, want refused before the call", bad, err, c.created != nil)
		}
	}
}

func ptrI64(v int64) *int64 { return &v }

// ls shows a RATE column: the limit, or "-" for none.
func TestReplicationScheduleLs_RateColumn(t *testing.T) {
	c := &rateClient{list: []*pb.ReplicationSchedule{
		{VmName: "web1", TargetPool: "dr", BwlimitBytesPerSec: 50 << 20},
		{VmName: "web2", TargetPool: "dr"},
	}}
	out, err := runRateCmd(t, c, "replication", "schedule", "ls")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], "RATE") {
		t.Fatalf("output:\n%s", out)
	}
	if !strings.Contains(lines[1], "50MiB/s") {
		t.Errorf("web1's row has no 50MiB/s: %q", lines[1])
	}
	col := strings.Index(lines[0], "RATE")
	if f := strings.Fields(lines[2][col:]); len(f) == 0 || f[0] != "-" {
		t.Errorf("web2's RATE column = %q, want \"-\"", lines[2][col:])
	}
}

// A limit the daemon did not store (an older daemon drops the field it does
// not know) fails the command, saying the schedule was added unlimited; a 0
// or an absent --bwlimit answered with no limit is what was asked.
//
// Mutation: drop the check — the dropped 50MiB exits 0.
func TestReplicationScheduleAdd_BwlimitDroppedByTheDaemon(t *testing.T) {
	base := []string{"replication", "schedule", "add", "web1", "--cron", "0 * * * *", "--target-pool", "dr"}
	_, err := runRateCmd(t, &rateClient{dropRate: true}, append(append([]string{}, base...), "--bwlimit", "50MiB")...)
	if err == nil || !strings.Contains(err.Error(), "without a bandwidth limit") {
		t.Fatalf("dropped 50MiB: err = %v, want it to say the schedule has no limit", err)
	}
	for _, flag := range [][]string{nil, {"--bwlimit", "0"}} {
		if _, err := runRateCmd(t, &rateClient{dropRate: true}, append(append([]string{}, base...), flag...)...); err != nil {
			t.Errorf("%v answered with no limit: %v", flag, err)
		}
	}
}

// A VM name longer than the old fixed 18-column width must not shift the
// columns after it: every row's RATE starts at the header's RATE offset.
func TestReplicationScheduleLs_LongNameKeepsColumnsAligned(t *testing.T) {
	var buf bytes.Buffer
	printReplicationSchedules(&buf, []*pb.ReplicationSchedule{
		{VmName: "e2e-rrate-3023579-2-1", TargetPool: "rrdst", BwlimitBytesPerSec: 20 << 20},
		{VmName: "short", TargetPool: "rrdst"},
	})
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want header + 2 rows:\n%s", buf.String())
	}
	col := strings.Index(lines[0], "RATE")
	for i, want := range []string{"20MiB/s", "-"} {
		line := lines[i+1]
		if len(line) <= col || !strings.HasPrefix(line[col:], want) {
			t.Errorf("row %d: RATE column at offset %d is not %q:\n%s", i, col, want, buf.String())
		}
	}
}
