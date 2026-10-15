package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// macroSpy records the rule calls a --macro makes. failAt (1-based, over all
// add calls) makes that add fail.
type macroSpy struct {
	pb.LiteVirtClient
	sgAdds       []*pb.SecurityGroupRule
	clusterAdds  []*pb.FirewallRule
	hostAdds     []*pb.FirewallRule
	removed      []string
	adds         int
	failAt       int
	removeFail   map[string]bool
	removeCtxErr []error
	onAdd        func()
}

func (m *macroSpy) next() (string, error) {
	m.adds++
	if m.onAdd != nil {
		m.onAdd()
	}
	if m.failAt != 0 && m.adds == m.failAt {
		return "", errors.New("boom")
	}
	return fmt.Sprintf("id-%d", m.adds), nil
}

func (m *macroSpy) AddSecurityGroupRule(_ context.Context, in *pb.AddSecurityGroupRuleRequest, _ ...grpc.CallOption) (*pb.SecurityGroupRule, error) {
	m.sgAdds = append(m.sgAdds, in.GetRule())
	id, err := m.next()
	if err != nil {
		return nil, err
	}
	return &pb.SecurityGroupRule{Id: id}, nil
}

func (m *macroSpy) remove(ctx context.Context, id string) (*emptypb.Empty, error) {
	m.removeCtxErr = append(m.removeCtxErr, ctx.Err())
	if m.removeFail[id] {
		return nil, errors.New("remove refused")
	}
	m.removed = append(m.removed, id)
	return &emptypb.Empty{}, nil
}

func (m *macroSpy) RemoveSecurityGroupRule(ctx context.Context, in *pb.RemoveSecurityGroupRuleRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return m.remove(ctx, in.GetId())
}

func (m *macroSpy) CreateClusterFirewallRule(_ context.Context, in *pb.CreateClusterFirewallRuleRequest, _ ...grpc.CallOption) (*pb.FirewallRule, error) {
	m.clusterAdds = append(m.clusterAdds, in.GetRule())
	id, err := m.next()
	if err != nil {
		return nil, err
	}
	return &pb.FirewallRule{Id: id}, nil
}

func (m *macroSpy) DeleteClusterFirewallRule(ctx context.Context, in *pb.DeleteClusterFirewallRuleRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return m.remove(ctx, in.GetId())
}

func (m *macroSpy) CreateHostFirewallRule(_ context.Context, in *pb.CreateHostFirewallRuleRequest, _ ...grpc.CallOption) (*pb.FirewallRule, error) {
	m.hostAdds = append(m.hostAdds, in.GetRule())
	id, err := m.next()
	if err != nil {
		return nil, err
	}
	return &pb.FirewallRule{Id: id}, nil
}

func (m *macroSpy) DeleteHostFirewallRule(ctx context.Context, in *pb.DeleteHostFirewallRuleRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return m.remove(ctx, in.GetId())
}

func runMacroCLI(t *testing.T, spy *macroSpy, cmd *cobra.Command, args ...string) (string, error) {
	t.Helper()
	return runMacroCLICtx(t, context.Background(), spy, cmd, args...)
}

func runMacroCLICtx(t *testing.T, parent context.Context, spy *macroSpy, cmd *cobra.Command, args ...string) (string, error) {
	t.Helper()
	orig := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
		return fn(ctx, spy)
	}
	t.Cleanup(func() { withClient = orig })
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	var err error
	out := captureStdout(t, func() { err = cmd.ExecuteContext(parent) })
	return out, err
}

// Mutation: test `proto != ""` instead of Flags().Changed (the default "all"
// is then refused and the accepted case below goes red); test nothing (the
// explicit case goes red).
func TestSGRuleAddMacro_ExplicitProtoOrPortRefused(t *testing.T) {
	for _, extra := range [][]string{{"--proto", "tcp"}, {"--proto", "all"}, {"--port", "22"}} {
		spy := &macroSpy{}
		args := append([]string{"web", "--macro", "SSH"}, extra...)
		_, err := runMacroCLI(t, spy, newSGRuleAddCmd(), args...)
		if err == nil || !strings.Contains(err.Error(), "--macro cannot be used with") {
			t.Fatalf("%v: want a --macro refusal, got %v", extra, err)
		}
		if spy.adds != 0 {
			t.Fatalf("%v: a refused macro made %d calls", extra, spy.adds)
		}
	}
}

func TestSGRuleAddMacro_DefaultProtoAccepted(t *testing.T) {
	spy := &macroSpy{}
	out, err := runMacroCLI(t, spy, newSGRuleAddCmd(), "web", "--macro", "ssh", "--cidr", "10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if len(spy.sgAdds) != 1 {
		t.Fatalf("adds = %d", len(spy.sgAdds))
	}
	r := spy.sgAdds[0]
	if r.SgId != "web" || r.Proto != "tcp" || r.Port != "22" || r.Cidr != "10.0.0.0/8" || r.Direction != "ingress" || r.Action != "accept" {
		t.Fatalf("rule = %v", r)
	}
	if !strings.Contains(out, "id-1") {
		t.Fatalf("out = %q", out)
	}
}

// Mutation: send only the first row.
func TestSGRuleAddMacro_DNSMakesTwoCallsAndPrintsBothIDs(t *testing.T) {
	spy := &macroSpy{}
	out, err := runMacroCLI(t, spy, newSGRuleAddCmd(), "web", "--macro", "DNS")
	if err != nil {
		t.Fatal(err)
	}
	if len(spy.sgAdds) != 2 || spy.sgAdds[0].Proto != "udp" || spy.sgAdds[1].Proto != "tcp" ||
		spy.sgAdds[0].Port != "53" || spy.sgAdds[1].Port != "53" {
		t.Fatalf("adds = %v", spy.sgAdds)
	}
	if !strings.Contains(out, "id-1") || !strings.Contains(out, "id-2") {
		t.Fatalf("out = %q", out)
	}
}

// Mutation: leave the first row behind.
func TestSGRuleAddMacro_SecondFailureRemovesFirst(t *testing.T) {
	spy := &macroSpy{failAt: 2}
	_, err := runMacroCLI(t, spy, newSGRuleAddCmd(), "web", "--macro", "DNS")
	if err == nil {
		t.Fatal("want an error")
	}
	if len(spy.removed) != 1 || spy.removed[0] != "id-1" {
		t.Fatalf("removed = %v", spy.removed)
	}
}

func TestSGRuleAddMacro_UnknownRefusedBeforeAnyCall(t *testing.T) {
	spy := &macroSpy{}
	_, err := runMacroCLI(t, spy, newSGRuleAddCmd(), "web", "--macro", "nope")
	if err == nil || !strings.Contains(err.Error(), "SSH") {
		t.Fatalf("err = %v", err)
	}
	if spy.adds != 0 {
		t.Fatal("calls made")
	}
}

// Mutation: drop the comment default; send the user's spelling instead of the
// catalog's.
func TestClusterAndHostRuleAddMacro_CarryComment(t *testing.T) {
	spy := &macroSpy{}
	if _, err := runMacroCLI(t, spy, newFirewallClusterRuleCmd(), "add", "--macro", "dns", "--direction", "egress"); err != nil {
		t.Fatal(err)
	}
	if len(spy.clusterAdds) != 2 {
		t.Fatalf("cluster adds = %d", len(spy.clusterAdds))
	}
	for _, r := range spy.clusterAdds {
		if r.Comment != "macro DNS" || r.Direction != "egress" {
			t.Fatalf("rule = %v", r)
		}
	}
	spy = &macroSpy{}
	out, err := runMacroCLI(t, spy, newFirewallHostRuleCmd(), "add", "--host", "node-1", "--macro", "HTTPS")
	if err != nil {
		t.Fatal(err)
	}
	if len(spy.hostAdds) != 1 || spy.hostAdds[0].Comment != "macro HTTPS" || spy.hostAdds[0].HostName != "node-1" ||
		spy.hostAdds[0].Proto != "tcp" || spy.hostAdds[0].Port != "443" {
		t.Fatalf("host adds = %v", spy.hostAdds)
	}
	if !strings.Contains(out, "id-1") {
		t.Fatalf("out = %q", out)
	}
}

func TestClusterRuleAddMacro_ExplicitCommentKept(t *testing.T) {
	spy := &macroSpy{}
	if _, err := runMacroCLI(t, spy, newFirewallClusterRuleCmd(), "add", "--macro", "SSH", "--comment", "mine"); err != nil {
		t.Fatal(err)
	}
	if spy.clusterAdds[0].Comment != "mine" {
		t.Fatalf("comment = %q", spy.clusterAdds[0].Comment)
	}
}

func TestClusterRuleAddMacro_ExplicitProtoRefusedAndFailureRollsBack(t *testing.T) {
	spy := &macroSpy{}
	if _, err := runMacroCLI(t, spy, newFirewallClusterRuleCmd(), "add", "--macro", "SSH", "--proto", "udp"); err == nil {
		t.Fatal("want refusal")
	}
	spy = &macroSpy{failAt: 2}
	if _, err := runMacroCLI(t, spy, newFirewallHostRuleCmd(), "add", "--host", "n", "--macro", "DNS"); err == nil {
		t.Fatal("want error")
	}
	if len(spy.removed) != 1 || spy.removed[0] != "id-1" {
		t.Fatalf("removed = %v", spy.removed)
	}
}

func TestFirewallMacrosCmd_ListsCatalog(t *testing.T) {
	out, err := runMacroCLI(t, &macroSpy{}, newFirewallMacrosCmd())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"DNS", "udp 53; tcp 53", "Ceph", "tcp 6800-7300"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %q", want, out)
		}
	}
}

// Mutation: remove with the failed call's context (the cancelled one).
func TestSGRuleAddMacro_RollbackSurvivesCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	spy := &macroSpy{failAt: 2}
	spy.onAdd = func() {
		if spy.adds == 2 {
			cancel()
		}
	}
	_, err := runMacroCLICtx(t, ctx, spy, newSGRuleAddCmd(), "web", "--macro", "DNS")
	if err == nil {
		t.Fatal("want an error")
	}
	if len(spy.removed) != 1 || spy.removed[0] != "id-1" {
		t.Fatalf("removed = %v", spy.removed)
	}
	for _, e := range spy.removeCtxErr {
		if e != nil {
			t.Fatalf("rollback used a dead context: %v", e)
		}
	}
}

// Mutation: report success when a removal fails; drop the id from the error.
func TestSGRuleAddMacro_RollbackFailureNamesLeftBehindIDs(t *testing.T) {
	spy := &macroSpy{failAt: 3, removeFail: map[string]bool{"id-2": true}}
	out, err := runMacroCLI(t, spy, newSGRuleAddCmd(), "web", "--macro", "Ceph")
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "id-2") || strings.Contains(err.Error(), "id-1:") {
		t.Fatalf("err = %v", err)
	}
	if len(spy.removed) != 1 || spy.removed[0] != "id-1" {
		t.Fatalf("removed = %v", spy.removed)
	}
	if out != "" {
		t.Fatalf("a failed macro printed %q", out)
	}
}
