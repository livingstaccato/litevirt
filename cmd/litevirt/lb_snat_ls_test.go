package main

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// `lv lb ls` and `lv lb inspect` show SNAT as on, off, or unknown (the daemon
// could not read it, so the LB may be SNATting; never shown as off).
func TestLBSNATDisplay(t *testing.T) {
	mock := newMockClient()
	mock.listLBsResp = &pb.ListLBResponse{Lbs: []*pb.LoadBalancer{
		{Name: "plain", Vip: "10.0.0.1/24", Algorithm: "roundrobin", State: "active", Snat: proto.Bool(false)},
		{Name: "natted", Vip: "10.0.0.2/24", Algorithm: "roundrobin", State: "active", Snat: proto.Bool(true)},
		{Name: "unread", Vip: "10.0.0.3/24", Algorithm: "roundrobin", State: "active"},
	}}
	out, _, err := runCmd(t, mock, "lb", "ls")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 {
		t.Fatalf("output:\n%s", out)
	}
	last := func(line string) string {
		f := strings.Fields(line)
		return f[len(f)-1]
	}
	for i, want := range []string{"SNAT", "off", "on", "unknown"} {
		if last(lines[i]) != want {
			t.Errorf("line %d %q: last column %q, want %q", i, lines[i], last(lines[i]), want)
		}
	}

	for _, tc := range []struct {
		snat *bool
		want string
	}{{proto.Bool(true), "SNAT:       on"}, {proto.Bool(false), "SNAT:       off"}, {nil, "SNAT:       unknown"}} {
		m := newMockClient()
		m.inspectLBResp = &pb.LoadBalancer{Name: "x", Snat: tc.snat}
		out, _, err := runCmd(t, m, "lb", "inspect", "x")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, tc.want+"\n") {
			t.Errorf("inspect (snat %v) output:\n%s\nwant line %q", tc.snat, out, tc.want)
		}
	}
}
