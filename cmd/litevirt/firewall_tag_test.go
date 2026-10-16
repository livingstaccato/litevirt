package main

import (
	"context"
	"maps"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func (m *mockClient) SetFirewallTags(_ context.Context, in *pb.SetFirewallTagsRequest, _ ...grpc.CallOption) (*pb.FirewallTags, error) {
	m.fwTagsSetReq = in
	if m.fwTagsErr != nil {
		return nil, m.fwTagsErr
	}
	tags := maps.Clone(in.GetSet())
	out := &pb.FirewallTags{Kind: in.GetKind(), Workload: in.GetWorkload(), Host: in.GetHost(),
		FwId: "0123456789abcdef0123456789abcdef", Tags: tags}
	if x := m.fwTagsSetExtra; x != nil {
		out.ReplacedFwId, out.DroppedTags = x.GetReplacedFwId(), x.GetDroppedTags()
	}
	return out, nil
}

func (m *mockClient) ListFirewallTags(_ context.Context, in *pb.ListFirewallTagsRequest, _ ...grpc.CallOption) (*pb.ListFirewallTagsResponse, error) {
	m.fwTagsLsReq = in
	if m.fwTagsErr != nil {
		return nil, m.fwTagsErr
	}
	if m.fwTags == nil {
		return nil, status.Error(codes.Unimplemented, "ListFirewallTags is not implemented")
	}
	return &pb.ListFirewallTagsResponse{Tags: m.fwTags}, nil
}

// `lv firewall tag set` sends the pairs for a VM, or a container with
// --container --host; `tag rm` sends the keys to remove.
func TestFirewallTagCLI_SetAndRm(t *testing.T) {
	m := &mockClient{}
	out, _, err := runCmd(t, m, "firewall", "tag", "set", "web-1", "role=web", "env=prod")
	if err != nil {
		t.Fatalf("tag set: %v", err)
	}
	r := m.fwTagsSetReq
	if r == nil || r.GetKind() != "vm" || r.GetWorkload() != "web-1" || r.GetHost() != "" ||
		!maps.Equal(r.GetSet(), map[string]string{"role": "web", "env": "prod"}) || len(r.GetRemove()) != 0 {
		t.Fatalf("tag set request = %+v", r)
	}
	assertContains(t, out, "Firewall tags of VM web-1 (fw_id 0123456789abcdef0123456789abcdef): env=prod role=web")

	if _, _, err := runCmd(t, m, "firewall", "tag", "set", "cache-1", "--container", "--host", "node-2", "role=web"); err != nil {
		t.Fatalf("tag set --container: %v", err)
	}
	if r := m.fwTagsSetReq; r.GetKind() != "container" || r.GetHost() != "node-2" || r.GetWorkload() != "cache-1" {
		t.Fatalf("container tag set request = %+v", r)
	}

	if _, _, err := runCmd(t, m, "firewall", "tag", "rm", "web-1", "env"); err != nil {
		t.Fatalf("tag rm: %v", err)
	}
	if r := m.fwTagsSetReq; r.GetKind() != "vm" || len(r.GetSet()) != 0 || !slices.Equal(r.GetRemove(), []string{"env"}) {
		t.Fatalf("tag rm request = %+v", r)
	}
}

// A tag set that replaced a copied identity says so, naming the identity and
// the tags cleared from both holders (D3 review m-6); one that did not says
// nothing more.
//
// Mutation: drop the note — red.
func TestFirewallTagCLI_SetNamesTheTagsACopyDropped(t *testing.T) {
	m := &mockClient{fwTagsSetExtra: &pb.FirewallTags{ReplacedFwId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		DroppedTags: map[string]string{"role": "db", "env": "prod"}}}
	out, _, err := runCmd(t, m, "firewall", "tag", "set", "web-1", "role=web")
	if err != nil {
		t.Fatalf("tag set: %v", err)
	}
	assertContains(t, out, "note: VM web-1 held firewall identity aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, which another workload holds too")
	assertContains(t, out, "were cleared from both: env=prod role=db.")
	plain, _, err := runCmd(t, &mockClient{}, "firewall", "tag", "set", "web-1", "role=web")
	if err != nil || strings.Contains(plain, "note:") {
		t.Fatalf("a plain tag set printed %q (%v)", plain, err)
	}
}

func TestFirewallTagCLI_RefusesBadArguments(t *testing.T) {
	m := &mockClient{}
	for _, args := range [][]string{
		{"firewall", "tag", "set", "web-1", "role"},
		{"firewall", "tag", "set", "web-1", "=web"},
		{"firewall", "tag", "set", "web-1", "--host", "node-2", "role=web"},
		{"firewall", "tag", "ls", "--host", "node-2"},
	} {
		if _, _, err := runCmd(t, m, args...); err == nil {
			t.Errorf("%v: accepted", args)
		}
	}
	if m.fwTagsSetReq != nil || m.fwTagsLsReq != nil {
		t.Errorf("a refused command reached the daemon: %+v %+v", m.fwTagsSetReq, m.fwTagsLsReq)
	}
}

// An older daemon answers Unimplemented: lv says to upgrade it.
func TestFirewallTagCLI_OlderDaemon(t *testing.T) {
	m := &mockClient{fwTagsErr: status.Error(codes.Unimplemented, "unknown method SetFirewallTags")}
	_, _, err := runCmd(t, m, "firewall", "tag", "set", "web-1", "role=web")
	if err == nil || !strings.Contains(err.Error(), "upgrade the daemon") {
		t.Fatalf("against an older daemon: %v", err)
	}
}

// `tag ls` lists the tagged workloads, an orphan row marked as not applied.
func TestFirewallTagCLI_Ls(t *testing.T) {
	m := &mockClient{fwTags: []*pb.FirewallTags{
		{Kind: "vm", Workload: "web-1", FwId: "aa", Tags: map[string]string{"role": "web"}},
		{Kind: "container", Workload: "cache-1", Host: "node-2", FwId: "bb", Tags: map[string]string{"env": "prod"}},
		{Kind: "vm", Workload: "web-1", FwId: "cc", Tags: map[string]string{"role": "db"}, Orphan: true},
		{Kind: "vm", Workload: "broken", FwId: "dd", Unreadable: true},
	}}
	out, _, err := runCmd(t, m, "firewall", "tag", "ls", "web-1")
	if err != nil {
		t.Fatalf("tag ls: %v", err)
	}
	if m.fwTagsLsReq.GetWorkload() != "web-1" || m.fwTagsLsReq.GetKind() != "" {
		t.Fatalf("ls request = %+v", m.fwTagsLsReq)
	}
	for _, want := range []string{"KIND", "web-1", "role=web", "node-2", "cache-1", "env=prod", "role=db (an earlier incarnation's row, not applied)",
		"unreadable (a member of no tag group)"} {
		assertContains(t, out, want)
	}
	if _, _, err := runCmd(t, m, "firewall", "tag", "ls", "--container", "--host", "node-2"); err != nil {
		t.Fatalf("tag ls --container: %v", err)
	}
	if r := m.fwTagsLsReq; r.GetKind() != "container" || r.GetHost() != "node-2" || r.GetWorkload() != "" {
		t.Fatalf("ls --container request = %+v", r)
	}
}

// `lv inspect` prints the Firewall tags line on stderr (the JSON on stdout
// stays parseable); an older daemon prints none.
//
// Mutation: drop the line — red.
func TestFirewallTagCLI_InspectLine(t *testing.T) {
	m := newMockClient()
	m.fwTags = []*pb.FirewallTags{{Kind: "vm", Workload: "web-1", FwId: "aa", Tags: map[string]string{"role": "web", "env": "prod"}}}
	out, errOut, err := runCmd(t, m, "inspect", "web-1")
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	assertContains(t, errOut, "Firewall tags: env=prod role=web")
	assertNotContains(t, out, "Firewall tags")
	if r := m.fwTagsLsReq; r.GetKind() != "vm" || r.GetWorkload() != "web-1" {
		t.Fatalf("inspect asked %+v", r)
	}

	old := newMockClient()
	_, errOut, err = runCmd(t, old, "inspect", "web-1")
	if err != nil || strings.Contains(errOut, "Firewall tags") {
		t.Fatalf("against an older daemon: err=%v stderr=%q", err, errOut)
	}
}

// `lv cutover` prints the replaced VM's tags the daemon says were left.
func TestFirewallTagCLI_CutoverPrintsTagsLeft(t *testing.T) {
	m := newMockClient()
	m.fwTagsLeft = "the replaced VM web-1's firewall tags (fw_id aa) stay with it: role=web. To set them again (sg.write): lv firewall tag set web-1 role=web"
	out, _, err := runCmd(t, m, "cutover", "web-1")
	if err != nil {
		t.Fatalf("cutover: %v", err)
	}
	assertContains(t, out, "Note: "+m.fwTagsLeft)
}

type ctInspectTagsMock struct {
	ctInspectMock
	tags []*pb.FirewallTags
	got  *pb.ListFirewallTagsRequest
}

func (m *ctInspectTagsMock) ListFirewallTags(_ context.Context, in *pb.ListFirewallTagsRequest, _ ...grpc.CallOption) (*pb.ListFirewallTagsResponse, error) {
	m.got = in
	return &pb.ListFirewallTagsResponse{Tags: m.tags}, nil
}

// `lv ct inspect` shows the Firewall tags line in its fields: the tags,
// none, no identity yet, or an earlier incarnation's row (m-3).
func TestCTInspect_FirewallTagsLine(t *testing.T) {
	for want, tags := range map[string][]*pb.FirewallTags{
		"Firewall tags:  role=web":                        {{Kind: "container", Workload: "blct", Host: "node-4", FwId: "aa", Tags: map[string]string{"role": "web"}}},
		"Firewall tags:  none (no firewall identity yet)": {{Kind: "container", Workload: "blct", Host: "node-4"}},
		"Firewall tags:  none (a row for an earlier incarnation of this name exists, fw_id bb, not applied)": {
			{Kind: "container", Workload: "blct", Host: "node-4", FwId: "aa"},
			{Kind: "container", Workload: "blct", Host: "node-3", FwId: "bb", Tags: map[string]string{"role": "web"}, Orphan: true},
		},
	} {
		m := &ctInspectTagsMock{tags: tags}
		out, err := runCTInspect(t, m, "ct", "inspect", "blct", "--host", "node-4")
		if err != nil {
			t.Fatalf("ct inspect: %v", err)
		}
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
		if m.got.GetKind() != "container" || m.got.GetWorkload() != "blct" || m.got.GetHost() != "node-4" {
			t.Errorf("asked %+v", m.got)
		}
	}
}
