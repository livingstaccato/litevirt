package grpcapi

import (
	"strconv"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A cold move defines the source's XML on the target, and that XML carries
// <shares> rendered for the SOURCE's cgroup version. The target re-renders it
// for its own from the stored weight: a weight of 977 rendered on a cgroup v1
// source is out of range on a v2 target, and 100 rendered on a v2 source is a
// tenth of its neighbours on a v1 target.
//
// The XML carries a value no host would render (55555), so the test is not
// satisfied by a host whose own scale happens to match.
//
// Mutation: define req.DomainXml unchanged — red.
func TestEnsureFirmwareState_DefinesSharesOnTheTargetsScale(t *testing.T) {
	s := testServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	s.dataDir = t.TempDir()
	insertTestVMWithSpec(t, adminCtx(), s.db, "os1", "src-host", "stopped", `{"name":"os1","cpu_shares":977}`)
	xml := `<domain type='kvm'><name>os1</name><cputune><shares>55555</shares></cputune></domain>`
	if _, err := s.EnsureFirmwareState(diskPeerCtx(t, s), &pb.EnsureFirmwareStateRequest{VmName: "os1", DomainXml: xml, AttemptId: "a1"}); err != nil {
		t.Fatalf("EnsureFirmwareState: %v", err)
	}
	want := "<shares>" + strconv.Itoa(lv.HostCPUShares(977)) + "</shares>"
	if got := fake.DefinedXML("os1"); !strings.Contains(got, want) || strings.Contains(got, "55555") {
		t.Errorf("defined XML = %s, want %s (this host's scale for weight 977)", got, want)
	}
}

// The target reports its cgroup version in EnsureDisks, so a live migration's
// source can render the destination definition for it.
//
// Mutation: drop CgroupMode from the response — red.
func TestEnsureDisks_ReportsTheCgroupVersion(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	insertTestVMWithSpec(t, adminCtx(), s.db, "os1", "src-host", "running", `{"name":"os1"}`)
	resp, err := s.EnsureDisks(diskPeerCtx(t, s), &pb.EnsureDisksRequest{VmName: "os1"})
	if err != nil {
		t.Fatalf("EnsureDisks: %v", err)
	}
	if resp.GetCgroupMode() != lv.CgroupMode() {
		t.Errorf("cgroup_mode = %q, want %q", resp.GetCgroupMode(), lv.CgroupMode())
	}
}
