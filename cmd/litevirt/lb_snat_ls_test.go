package main

import (
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// `lv lb ls` has a SNAT column: on for an LB that SNATs, off for one that does not.
func TestLBLs_SNATColumn(t *testing.T) {
	mock := newMockClient()
	mock.listLBsResp = &pb.ListLBResponse{Lbs: []*pb.LoadBalancer{
		{Name: "plain", Vip: "10.0.0.1/24", Algorithm: "roundrobin", State: "active"},
		{Name: "natted", Vip: "10.0.0.2/24", Algorithm: "roundrobin", State: "active", Snat: true},
	}}
	out, _, err := runCmd(t, mock, "lb", "ls")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("output:\n%s", out)
	}
	col := func(line string) string {
		f := strings.Fields(line)
		return f[len(f)-1]
	}
	if !strings.Contains(lines[0], "SNAT") || col(lines[0]) != "SNAT" {
		t.Errorf("header %q has no trailing SNAT column", lines[0])
	}
	if col(lines[1]) != "off" {
		t.Errorf("plain: %q, want SNAT off", lines[1])
	}
	if col(lines[2]) != "on" {
		t.Errorf("natted: %q, want SNAT on", lines[2])
	}
}
