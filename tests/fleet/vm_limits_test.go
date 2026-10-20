package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// The noisy-neighbour controls: a VM's CPU cap and weight and a NIC's bandwidth
// cap are settable in the compose file, rendered into the domain, applied to the
// running domain without a restart, and survive every rebuild of the definition.

const composeLimitsBase = `name: upd

images:
  test:
    source: file:///dev/null

vms:
  db:
    image: test
    cpu: 2
    memory: 512
    cpu-limit: 1
    cpu-shares: 200
    placement:
      host: node-0
    network:
      - name: hc
        rate: 2
`

// 1 core is a 100000us quota per 100000us period across the WHOLE domain
// (global_quota), whatever the vCPU count; 2 MB/s = 2000 KB/s (libvirt's unit),
// both directions; cpu-shares is the cgroup v2 weight.
var sharesFor200 = fmt.Sprintf("<shares>%d</shares>", lv.HostCPUShares(200))

const (
	quotaFor1Core = "<global_quota>100000</global_quota>"
	rateFor2      = `<inbound average="2000"`
)

// latchRelease wires every node's release-feature gate against its real
// checker and waits for the policy gate the used record travels through.
func latchRelease(t *testing.T, c *Cluster) map[string]*health.Checker {
	t.Helper()
	gates := gateAll(t, c)
	wireReleaseFeatures(t, c, gates)
	for _, n := range c.Nodes {
		if !gates[n.Name].Enforced(context.Background(), capabilities.FailoverScopeV1) {
			t.Fatalf("%s: failover_scope_v1 did not latch", n.Name)
		}
	}
	return gates
}

// newLimitsNode is newUpdateNode with the release-feature gate wired: this
// build is the whole fleet, so release_2026_11_v1 latches on the first use.
func newLimitsNode(t *testing.T) (*Node, pb.LiteVirtClient) {
	t.Helper()
	c, node, client := newComposeFailNode(t)
	node.Server.SetBridgeEnsure(node.Net.EnsureBridge)
	latchRelease(t, c)
	if _, err := client.CreateNetwork(context.Background(), &pb.CreateNetworkRequest{
		Name: "hc", Type: "isolated", Subnet: "172.16.50.0/24", Dhcp: true,
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	return node, client
}

func setupLimitsVM(t *testing.T) (context.Context, *Node, pb.LiteVirtClient, vmIdentity) {
	t.Helper()
	node, client := newLimitsNode(t)
	ctx := context.Background()
	deployClean(t, ctx, client, composeLimitsBase)
	waitRunning(t, ctx, node, "db")
	return ctx, node, client, identityOf(t, ctx, node, "db", true)
}

// libvirt writes attributes single-quoted and the generator double-quoted;
// the two are the same document.
func normQuotes(s string) string { return strings.ReplaceAll(s, "'", `"`) }

func mustContain(t *testing.T, what, xml string, wants ...string) {
	t.Helper()
	xml = normQuotes(xml)
	for _, w := range wants {
		if !strings.Contains(xml, w) {
			t.Errorf("%s lacks %q:\n%s", what, w, xml)
		}
	}
}

func mustNotContain(t *testing.T, what, xml string, nots ...string) {
	t.Helper()
	xml = normQuotes(xml)
	for _, n := range nots {
		if strings.Contains(xml, n) {
			t.Errorf("%s still has %q:\n%s", what, n, xml)
		}
	}
}

func TestFleet_VMLimitsAreRenderedAtCreate(t *testing.T) {
	ctx, node, _, _ := setupLimitsVM(t)
	xml := node.Virt.DefinedXML("db")
	mustContain(t, "created domain", xml, quotaFor1Core, "<global_period>100000</global_period>", sharesFor200, rateFor2, `<outbound average="2000"`)
	spec := storedSpec(t, ctx, node, "db")
	if spec.CpuLimit != 1 || spec.CpuShares != 200 || spec.Network[0].RateMbSec != 2 {
		t.Errorf("stored spec limits = %v/%v/%v, want 1/200/2", spec.CpuLimit, spec.CpuShares, spec.Network[0].RateMbSec)
	}
}

func TestFleet_ComposeLimitChangesApplyLiveToTheRunningVM(t *testing.T) {
	ctx, node, client, before := setupLimitsVM(t)

	next := edit(t, composeLimitsBase, "cpu-limit: 1\n", "cpu-limit: 1.5\n")
	next = edit(t, next, "cpu-shares: 200\n", "cpu-shares: 400\n")
	next = edit(t, next, "rate: 2\n", "rate: 4\n")
	if phase, detail := planDetailFor(t, ctx, client, next, "db"); phase != "update" || !strings.Contains(detail, "in place") {
		t.Errorf("plan for a limit change = %s %q, want an update applied in place", phase, detail)
	}
	from := len(node.Virt.EventLog())
	deployClean(t, ctx, client, next)
	// The same VM, never redefined or restarted.
	assertSameVM(t, ctx, node, "db", before, from, false)

	xml := node.Virt.DefinedXML("db")
	// 1.5 cores = 150000us per period across the domain; 4 MB/s = 4000 KB/s.
	mustContain(t, "updated domain", xml, "<global_quota>150000</global_quota>", fmt.Sprintf("<shares>%d</shares>", lv.HostCPUShares(400)), `<inbound average="4000"`)
	mustNotContain(t, "updated domain", xml, quotaFor1Core, sharesFor200, rateFor2)
	sawTune, sawRate := false, false
	for _, e := range node.Virt.EventLog()[from:] {
		switch e.Op {
		case "set-cputune":
			sawTune = true
		case "set-nic-rate":
			sawRate = true
		case "stop", "start", "destroy":
			t.Errorf("a limit change %s the VM", e.Op)
		}
	}
	if !sawTune || !sawRate {
		t.Errorf("limit change did not reach libvirt (cputune=%v nic-rate=%v)", sawTune, sawRate)
	}
	spec := storedSpec(t, ctx, node, "db")
	if spec.CpuLimit != 1.5 || spec.CpuShares != 400 || spec.Network[0].RateMbSec != 4 {
		t.Errorf("stored spec limits = %v/%v/%v, want 1.5/400/4", spec.CpuLimit, spec.CpuShares, spec.Network[0].RateMbSec)
	}
	// Converged.
	if phase, detail := planDetailFor(t, ctx, client, next, "db"); phase != "no-change" {
		t.Errorf("re-applying the file plans %s %q, want no change", phase, detail)
	}

	// Dropping the keys removes the caps — a declarative file's meaning.
	bare := edit(t, next, "    cpu-limit: 1.5\n    cpu-shares: 400\n", "")
	bare = edit(t, bare, "        rate: 4\n", "")
	deployClean(t, ctx, client, bare)
	xml = node.Virt.DefinedXML("db")
	mustNotContain(t, "uncapped domain", xml, "<global_quota>150000</global_quota>", "<bandwidth>")
	spec = storedSpec(t, ctx, node, "db")
	if spec.CpuLimit != 0 || spec.Network[0].RateMbSec != 0 {
		t.Errorf("caps survived their removal: limit=%v rate=%v", spec.CpuLimit, spec.Network[0].RateMbSec)
	}
}

func TestFleet_UpdateVMLimitsOnAStoppedVMEditTheConfigOnly(t *testing.T) {
	ctx, node, client, _ := setupLimitsVM(t)
	if _, err := client.StopVM(ctx, &pb.StopVMRequest{Name: "db"}); err != nil {
		t.Fatal(err)
	}
	limit, shares := 0.5, int32(0)
	if _, err := client.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "db", CpuLimit: &limit, CpuShares: &shares,
		NicRate: []*pb.NICRateUpdate{{Ordinal: 0, RateMbSec: 1}}}); err != nil {
		t.Fatalf("UpdateVM: %v", err)
	}
	xml := node.Virt.DefinedXML("db")
	// 0.5 core = 50000us per period; shares 0 restores the HOST's default weight
	// (100 on cgroup v2, never a hard-coded 1024); 1 MB/s = 1000 KB/s.
	mustContain(t, "stopped domain", xml, "<global_quota>50000</global_quota>",
		fmt.Sprintf("<shares>%d</shares>", lv.HostCPUShares(lv.DefaultCPUWeight())), `<inbound average="1000"`)
	if rec := storedSpec(t, ctx, node, "db"); rec.CpuLimit != 0.5 || rec.CpuShares != 0 {
		t.Errorf("spec = limit %v shares %d, want 0.5 / 0 (default)", rec.CpuLimit, rec.CpuShares)
	}
}

func TestFleet_UpdateVMLimitsAreRefusedWhenInvalid(t *testing.T) {
	ctx, node, client, _ := setupLimitsVM(t)
	pre := node.Virt.DefinedXML("db")
	tooBig, tooSmall, badShares := 3.0, 0.001, int32(20000)
	for name, req := range map[string]*pb.UpdateVMRequest{
		"limit above vcpus":     {Name: "db", CpuLimit: &tooBig},
		"limit below the floor": {Name: "db", CpuLimit: &tooSmall},
		"shares below range":    {Name: "db", CpuShares: &badShares},
		"nic out of range":      {Name: "db", NicRate: []*pb.NICRateUpdate{{Ordinal: 5, RateMbSec: 1}}},
		"negative rate":         {Name: "db", NicRate: []*pb.NICRateUpdate{{Ordinal: 0, RateMbSec: -1}}},
	} {
		_, err := client.UpdateVM(ctx, req)
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: err = %v, want InvalidArgument", name, err)
		}
	}
	if got := node.Virt.DefinedXML("db"); got != pre {
		t.Errorf("a refused update changed the domain:\n%s", got)
	}
	// A vCPU shrink must not strand the VM's existing limit above its new count.
	if _, err := client.StopVM(ctx, &pb.StopVMRequest{Name: "db"}); err != nil {
		t.Fatal(err)
	}
	bigger := 1.5
	if _, err := client.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "db", CpuLimit: &bigger}); err != nil {
		t.Fatal(err)
	}
	_, err := client.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "db", Cpu: 1})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "existing cpu limit") {
		t.Errorf("shrink to 1 vCPU under a 1.5-core limit: err = %v, want InvalidArgument naming the existing limit", err)
	}
}

func TestFleet_UpdateVMLimitsRollBackWhenLibvirtRefuses(t *testing.T) {
	ctx, node, client, _ := setupLimitsVM(t)
	node.Virt.FailSetNICRate = func(string, string, float64) error { return errors.New("injected: domiftune refused") }
	limit := 0.5
	_, err := client.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "db", CpuLimit: &limit,
		NicRate: []*pb.NICRateUpdate{{Ordinal: 0, RateMbSec: 9}}})
	if status.Code(err) != codes.Internal {
		t.Fatalf("err = %v, want Internal", err)
	}
	// The CPU half had already been applied; it is put back, and the spec never moved.
	xml := node.Virt.DefinedXML("db")
	mustContain(t, "rolled-back domain", xml, quotaFor1Core, rateFor2)
	if spec := storedSpec(t, ctx, node, "db"); spec.CpuLimit != 1 || spec.Network[0].RateMbSec != 2 {
		t.Errorf("spec limits = %v/%v after a refused update, want 1/2", spec.CpuLimit, spec.Network[0].RateMbSec)
	}
}

// The limits are baked into every way the definition is rebuilt: the in-place
// patch of a vCPU resize (the quota is per vCPU, so it must move), and a full
// regeneration from the spec (which is what a failover does).
func TestFleet_VMLimitsSurviveRedefine(t *testing.T) {
	ctx, node, client, _ := setupLimitsVM(t)
	if _, err := client.StopVM(ctx, &pb.StopVMRequest{Name: "db"}); err != nil {
		t.Fatal(err)
	}
	// In-place patch: 2 → 4 vCPUs moves nothing — the cap is the domain's, not per vCPU.
	if _, err := client.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "db", Cpu: 4}); err != nil {
		t.Fatalf("UpdateVM cpu: %v", err)
	}
	mustContain(t, "resized domain", node.Virt.DefinedXML("db"), quotaFor1Core, sharesFor200, rateFor2)

	// Full regeneration (a machine-type change cannot be patched in place).
	if _, err := client.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "db", Machine: "pc"}); err != nil {
		t.Fatalf("UpdateVM machine: %v", err)
	}
	mustContain(t, "regenerated domain", node.Virt.DefinedXML("db"), quotaFor1Core, sharesFor200, rateFor2, `<outbound average="2000"`)
}

// A VM rebuilt on a new host after a failover is defined from its stored spec by
// the reconciler (internal/health), not CreateVM: its caps must be there too.
func TestFleet_VMLimitsSurviveFailoverRebuild(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	a, survivor := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()

	if _, err := c.SelfClient(a).CreateNetwork(ctx, &pb.CreateNetworkRequest{
		Name: "hc", Type: "isolated", Subnet: "172.16.50.0/24", Dhcp: true,
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	disk := filepath.Join(t.TempDir(), "root.qcow2")
	if err := os.WriteFile(disk, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	spec := `{"name":"db","cpu":4,"memory_mib":512,"cpu_limit":2,"cpu_shares":300,` +
		`"network":[{"name":"hc","rate_mb_sec":5}]}`
	if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
		Name: "db", HostName: survivor.Name, Spec: spec, State: "pending", CPUActual: 4, MemActual: 512,
	}, []corrosion.InterfaceRecord{
		{VMName: "db", NetworkName: "hc", Ordinal: 0, MAC: "52:54:00:aa:bb:01"},
	}, []corrosion.DiskRecord{
		{VMName: "db", DiskName: "root", HostName: survivor.Name, Path: disk},
	}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	rec := health.NewReconciler(survivor.Name, t.TempDir(), survivor.DB, survivor.Virt)
	rec.SetNetworkProvision(survivor.Net.Provision)
	rec.ReconcileOnce(ctx)

	// 2 cores = 200000us per period across the domain; 5 MB/s = 5000 KB/s.
	mustContain(t, "rebuilt domain", survivor.Virt.DefinedXML("db"),
		"<global_quota>200000</global_quota>", fmt.Sprintf("<shares>%d</shares>", lv.HostCPUShares(300)), `<inbound average="5000"`, `<outbound average="5000"`)
}

// ── the vm_limits release gate ──────────────────────────────────────────────────

const limitlessCompose = `name: upd

images:
  test:
    source: file:///dev/null

vms:
  db:
    image: test
    cpu: 2
    memory: 512
    placement:
      host: node-0
`

func domainsDefined(n *Node) int {
	c := 0
	for _, e := range n.Virt.EventLog() {
		if e.Op == "define" {
			c++
		}
	}
	return c
}

// Until the release token latches, a stack that sets a limit is refused before any
// VM exists, and a stack without one deploys as it does on main. This node has
// no gate wired, so the token has not latched.
func TestFleet_VMLimitsRefusedUntilTheTokenLatches_Deploy(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()

	limited := strings.Replace(limitlessCompose, "    memory: 512\n", "    memory: 512\n    cpu-limit: 1\n", 1)
	stream, err := client.DeployStack(ctx, &pb.DeployStackRequest{ComposeYaml: limited})
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(errText(err), "cluster upgrade") {
		t.Fatalf("deploy with cpu-limit before the latch: err = %v, want FailedPrecondition naming the cluster upgrade", err)
	}
	if rec, _ := corrosion.GetVM(ctx, node.DB, "db"); rec != nil {
		t.Errorf("a VM was created despite the refusal: %+v", rec)
	}
	if n := domainsDefined(node); n != 0 {
		t.Errorf("%d domain(s) defined despite the refusal", n)
	}

	deployClean(t, ctx, client, limitlessCompose)
	if rec, _ := corrosion.GetVM(ctx, node.DB, "db"); rec == nil {
		t.Fatal("a limitless stack did not deploy before the latch")
	}
	// ...and a later edit that adds a limit is refused, leaving the VM as it was.
	pre := node.Virt.DefinedXML("db")
	stream, err = client.DeployStack(ctx, &pb.DeployStackRequest{ComposeYaml: limited})
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("adding cpu-limit to a deployed stack before the latch: err = %v", err)
	}
	if got := node.Virt.DefinedXML("db"); got != pre || strings.Contains(got, "cputune") {
		t.Errorf("a refused update changed the domain:\n%s", got)
	}
}

// A limit sent to a VM another host owns is gated by the OWNER, the node that
// performs the write: the entry node has the release feature wired and would
// pass it, but the owner has no gate (it has not latched), so the forwarded
// request is refused there and nothing is applied or persisted.
func TestFleet_VMLimitsAreGatedOnTheOwner(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	entry, owner := c.Nodes[0], c.Nodes[1]
	putVM(t, owner, "far", 2, "stopped")
	owner.Virt.SetState("far", "stopped")
	before := len(owner.Virt.EventLog())
	latchRelease(t, c)
	owner.Server.SetReleaseFeatureGate(nil) // the owner has not latched

	limit := 1.0
	_, err := c.SelfClient(entry).UpdateVM(context.Background(), &pb.UpdateVMRequest{Name: "far", CpuLimit: &limit})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(errText(err), "the cluster upgrade must finish first (vm_limits needs "+capabilities.ReleaseToken+")") {
		t.Fatalf("err = %v, want the release refusal from the owner", err)
	}
	for _, e := range owner.Virt.EventLog()[before:] {
		t.Errorf("the owner applied work for a refused limit: %s %s", e.Op, e.Note)
	}
	if got := specCPULimit(t, owner, "far"); got != 0 {
		t.Errorf("cpu_limit persisted as %v despite the refusal", got)
	}
	if featureUsedOn(t, entry, capabilities.ReleaseToken, string(capabilities.FeatureVMLimits)) {
		t.Error("a use was recorded for a refused limit")
	}
}

// Latched: a limit is accepted and the vm_limits use is on record; a limitless
// VM before it never marks the feature used.
func TestFleet_VMLimitsRecordTheUseOnFirstLimit(t *testing.T) {
	c, node, client := newComposeFailNode(t)
	node.Server.SetBridgeEnsure(node.Net.EnsureBridge)
	latchRelease(t, c)
	ctx := context.Background()
	deployClean(t, ctx, client, limitlessCompose)
	if featureUsedOn(t, node, capabilities.ReleaseToken, string(capabilities.FeatureVMLimits)) {
		t.Fatal("a limitless deploy marked vm_limits used")
	}
	limit := 1.0
	var err error
	eventually(t, 10*time.Second, "the first limit to be accepted", func() bool {
		_, err = client.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "db", CpuLimit: &limit})
		return err == nil
	})
	if !featureUsedOn(t, node, capabilities.ReleaseToken, string(capabilities.FeatureVMLimits)) {
		t.Fatal("vm_limits is not recorded as used after a limit was applied")
	}
	if got := specCPULimit(t, node, "db"); got != 1 {
		t.Errorf("cpu_limit = %v, want 1", got)
	}
}

func specCPULimit(t *testing.T, n *Node, name string) float64 {
	t.Helper()
	rec, err := corrosion.GetVM(context.Background(), n.DB, name)
	if err != nil || rec == nil {
		t.Fatalf("GetVM %s: %v %v", name, rec, err)
	}
	spec := &pb.VMSpec{}
	if err := json.Unmarshal([]byte(rec.Spec), spec); err != nil {
		t.Fatal(err)
	}
	return spec.CpuLimit
}

// CreateVM itself (not only the compose path in front of it) refuses a limit
// before the token latches, and a limitless create on the same node works.
func TestFleet_VMLimitsRefusedUntilTheTokenLatches_CreateVM(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	spec := &pb.VMSpec{Name: "direct", Image: "test", Cpu: 2, MemoryMib: 512, CpuShares: 512,
		Placement: &pb.PlacementSpec{Host: node.Name}}
	_, err := client.CreateVM(ctx, &pb.CreateVMRequest{Spec: spec})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(errText(err), "cluster upgrade") {
		t.Fatalf("CreateVM with cpu_shares before the latch: err = %v, want FailedPrecondition naming the cluster upgrade", err)
	}
	if rec, _ := corrosion.GetVM(ctx, node.DB, "direct"); rec != nil || domainsDefined(node) != 0 {
		t.Errorf("a refused create left state behind: row=%+v defines=%d", rec, domainsDefined(node))
	}
	spec.CpuShares = 0
	if _, err := client.CreateVM(ctx, &pb.CreateVMRequest{Spec: spec}); err != nil {
		t.Errorf("limitless CreateVM before the latch: %v", err)
	}
}

// A compose file that lowers the cpu count and the limit together deploys: the
// reconfigure carries the new limit with the new count, so the old limit is
// never judged against the new count.
func TestFleet_ComposeShrinkWithAMatchingLimitDeploys(t *testing.T) {
	node, client := newLimitsNode(t)
	ctx := context.Background()
	big := edit(t, composeLimitsBase, "    cpu: 2\n", "    cpu: 4\n")
	big = edit(t, big, "cpu-limit: 1\n", "cpu-limit: 3\n")
	deployClean(t, ctx, client, big)
	waitRunning(t, ctx, node, "db")

	small := edit(t, big, "    cpu: 4\n", "    cpu: 2\n")
	small = edit(t, small, "cpu-limit: 3\n", "cpu-limit: 1\n")
	deployClean(t, ctx, client, small)
	waitRunning(t, ctx, node, "db")

	spec := storedSpec(t, ctx, node, "db")
	if spec.Cpu != 2 || spec.CpuLimit != 1 {
		t.Errorf("spec cpu=%d limit=%v, want 2 / 1", spec.Cpu, spec.CpuLimit)
	}
	mustContain(t, "shrunk domain", node.Virt.DefinedXML("db"), quotaFor1Core, "<vcpu>2</vcpu>")
	if phase, detail := planDetailFor(t, ctx, client, small, "db"); phase != "no-change" {
		t.Errorf("re-applying the file plans %s %q, want no change", phase, detail)
	}
}

// ── fix round 1 ─────────────────────────────────────────────────────────────

func vmLimitsUsed(t *testing.T, n *Node) bool {
	t.Helper()
	return featureUsedOn(t, n, capabilities.ReleaseToken, string(capabilities.FeatureVMLimits))
}

// I1: a caller who may not create VMs never records a release use. The gate
// has cluster-wide, durable side effects (a rollback below the release then
// quarantines), so it runs only after RBAC and validation.
//
// Mutation: gate before RequirePerm in createVM — the viewer's request
// records the use and goes red.
func TestFleet_ViewerCreatingALimitedVMRecordsNoUse(t *testing.T) {
	c, node, client := newComposeFailNode(t)
	latchRelease(t, c)
	ctx := context.Background()
	if _, err := client.CreateUser(ctx, &pb.CreateUserRequest{Username: "vw", Password: "p4ssw0rd", Role: "viewer"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	tok, err := client.CreateToken(ctx, &pb.CreateTokenRequest{Username: "vw", Name: "t"})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	viewer := c.bearerClient(node, tok.Token)
	_, err = viewer.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{Name: "nope", Image: "test", Cpu: 2, MemoryMib: 512,
		CpuLimit: 1, Placement: &pb.PlacementSpec{Host: node.Name}}})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("viewer CreateVM with a limit: err = %v, want PermissionDenied", err)
	}
	if vmLimitsUsed(t, node) {
		t.Fatal("a refused viewer recorded the vm_limits use")
	}
}

// I2: an entry node forwarding a limit-bearing update first drives and checks
// the latch, without recording: an owner on an older build would ignore the
// field and answer success. The refusal is the release's; the owner is never
// handed the request and nothing is recorded.
//
// Mutation: drop the entry check — the (latched) owner accepts and the test
// goes red.
func TestFleet_EntryNodeRefusesALimitUpdateItCannotLatch(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	entry, owner := c.Nodes[0], c.Nodes[1]
	putVM(t, owner, "far", 2, "stopped")
	owner.Virt.SetState("far", "stopped")
	before := len(owner.Virt.EventLog())
	latchRelease(t, c)
	entry.Server.SetReleaseFeatureGate(nil) // the entry has not latched; the owner has

	limit := 1.0
	_, err := c.SelfClient(entry).UpdateVM(context.Background(), &pb.UpdateVMRequest{Name: "far", CpuLimit: &limit})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(errText(err), "the cluster upgrade must finish first (vm_limits needs "+capabilities.ReleaseToken+")") {
		t.Fatalf("err = %v, want the release refusal from the entry node", err)
	}
	for _, e := range owner.Virt.EventLog()[before:] {
		t.Errorf("the owner was handed work for a refused limit: %s %s", e.Op, e.Note)
	}
	if got := specCPULimit(t, owner, "far"); got != 0 {
		t.Errorf("cpu_limit persisted as %v", got)
	}
	if vmLimitsUsed(t, owner) {
		t.Error("the entry-node refusal recorded a use")
	}
	// A limitless update through the same entry is never refused.
	onboot := true
	if _, err := c.SelfClient(entry).UpdateVM(context.Background(), &pb.UpdateVMRequest{Name: "far", Onboot: &onboot}); err != nil {
		t.Errorf("limitless forwarded update refused: %v", err)
	}
}

// I3: the stack check covers every limit kind in the whole file before any VM
// is deployed: a limitless VM first, a shares-only or rate-only VM later, and
// no VM is created.
//
// Mutation: only look at cpu-limit — the shares-only and rate-only variants
// go red (the limitless VM is created first).
func TestFleet_StackLimitCheckCoversEveryKindAndTheWholeFile(t *testing.T) {
	for name, vmExtra := range map[string]string{
		"shares":    "    cpu-shares: 200\n",
		"nic rate":  "    network:\n      - name: hc\n        rate: 2\n",
		"cpu-limit": "    cpu-limit: 1\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, node, client := newComposeFailNode(t)
			ctx := context.Background()
			y := limitlessCompose + "  zlimited:\n    image: test\n    cpu: 2\n    memory: 512\n" + vmExtra + "    placement:\n      host: node-0\n"
			stream, err := client.DeployStack(ctx, &pb.DeployStackRequest{ComposeYaml: y})
			if err == nil {
				_, err = stream.Recv()
			}
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(errText(err), "the cluster upgrade must finish first") {
				t.Fatalf("err = %v, want the release refusal", err)
			}
			if rec, _ := corrosion.GetVM(ctx, node.DB, "db"); rec != nil {
				t.Errorf("the limitless VM was created before the refusal: %+v", rec)
			}
		})
	}
}

// I4: a dry run, and a deploy that fails validation, never record a use.
//
// Mutation: gate in the stack precheck with the recording gate — the dry run
// records the use and goes red.
func TestFleet_DryRunAndFailedValidationRecordNoUse(t *testing.T) {
	c, node, client := newComposeFailNode(t)
	node.Server.SetBridgeEnsure(node.Net.EnsureBridge)
	latchRelease(t, c)
	ctx := context.Background()
	limited := strings.Replace(limitlessCompose, "    memory: 512\n", "    memory: 512\n    cpu-limit: 1\n", 1)
	stream, err := client.DeployStack(ctx, &pb.DeployStackRequest{ComposeYaml: limited, DryRun: true})
	if err == nil {
		for {
			if _, err = stream.Recv(); err != nil {
				break
			}
		}
	}
	if err != nil && err != io.EOF {
		t.Fatalf("dry run: %v", err)
	}
	if vmLimitsUsed(t, node) {
		t.Fatal("a dry run recorded the vm_limits use")
	}
	// A limit above the VM's vCPUs fails validation before any write.
	_, err = client.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{Name: "bad", Image: "test", Cpu: 2, MemoryMib: 512,
		CpuLimit: 99, Placement: &pb.PlacementSpec{Host: node.Name}}})
	if err == nil {
		t.Fatal("a limit above the vCPU count was accepted")
	}
	if vmLimitsUsed(t, node) {
		t.Fatal("a create that failed validation recorded the use")
	}
}

// M1 and M4: an update that fails validation records no use, and a valid one
// has the use on record BEFORE the limit reaches the domain.
//
// Mutation: gate before mergeLimitUpdate (or after applyLimitsToDomain) —
// the invalid update records, or the hook sees no record, and goes red.
func TestFleet_LimitUpdateRecordsTheUseAfterValidationAndBeforeTheWrite(t *testing.T) {
	node, client := newLimitsNode(t)
	ctx := context.Background()
	deployClean(t, ctx, client, limitlessCompose)
	waitRunning(t, ctx, node, "db")
	over := 99.0
	if _, err := client.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "db", CpuLimit: &over}); err == nil {
		t.Fatal("a limit above the vCPU count was accepted")
	}
	if vmLimitsUsed(t, node) {
		t.Fatal("an invalid limit update recorded the use")
	}
	var usedAtWrite, wrote bool
	node.Virt.FailSetCPUTune = func(string, float64, int) error {
		wrote = true
		usedAtWrite = vmLimitsUsed(t, node)
		return nil
	}
	limit := 1.5
	eventually(t, 10*time.Second, "the update to be accepted", func() bool {
		_, err := client.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "db", CpuLimit: &limit})
		return err == nil
	})
	if !wrote {
		t.Fatal("the limit never reached the domain")
	}
	if !usedAtWrite {
		t.Fatal("the vm_limits use was not on record when the limit reached the domain")
	}
}

// I5: a live migration of a VM with a weight asks the target for its cgroup
// version and hands libvirt the weight and that version, so the destination
// definition is rendered on the target's scale.
//
// Mutation: skip the target's report (do not ask when only the weight needs
// it) — target_cgroup is empty and the test goes red.
func TestFleet_LiveMigrationCarriesTheWeightAndTheTargetsCgroup(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	defer c.Stop()
	src, dst := c.Nodes[0], c.Nodes[1]
	spec, _ := json.Marshal(&pb.VMSpec{Name: "pp1", Cpu: 1, MemoryMib: 256, CpuShares: 977})
	if err := corrosion.InsertVM(context.Background(), src.DB, corrosion.VMRecord{
		Name: "pp1", HostName: src.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	src.Virt.SetState("pp1", "running")
	st, err := c.SelfClient(src).MigrateVM(context.Background(), &pb.MigrateVMRequest{
		VmName: "pp1", TargetHost: dst.Name, Strategy: pb.MigrateStrategy_MIGRATE_LIVE,
	})
	if err != nil {
		t.Fatalf("MigrateVM: %v", err)
	}
	for {
		if _, err := st.Recv(); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("migration: %v", err)
		}
	}
	note := ""
	for _, e := range src.Virt.EventLog() {
		if e.Op == "migrate" {
			note = e.Note
		}
	}
	if !strings.Contains(note, "shares_weight=977") || !strings.Contains(note, "target_cgroup="+lv.CgroupMode()) {
		t.Fatalf("libvirt migrate = %q, want the weight 977 and the target's cgroup %s", note, lv.CgroupMode())
	}
}

// A create that carries a limit, on a latched cluster, has the use on record
// and the cap in the domain; the gate sits immediately before the define.
//
// Mutation: drop the recording gate before DefineDomain in createVM — the
// use is never recorded and the test goes red.
func TestFleet_LatchedCreateWithALimitRecordsTheUse(t *testing.T) {
	c, node, client := newComposeFailNode(t)
	latchRelease(t, c)
	ctx := context.Background()
	var err error
	eventually(t, 10*time.Second, "a limited create to be accepted", func() bool {
		_, err = client.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{Name: "lim", Image: "test", Cpu: 2, MemoryMib: 512,
			CpuLimit: 1, Placement: &pb.PlacementSpec{Host: node.Name}}})
		return err == nil
	})
	if !vmLimitsUsed(t, node) {
		t.Fatal("the vm_limits use is not recorded after a limited create")
	}
	mustContain(t, "created domain", node.Virt.DefinedXML("lim"), quotaFor1Core)
}

// ── fix round 2 ─────────────────────────────────────────────────────────────

// recordRefuser passes the non-recording latch step but refuses the recording
// gate, as an acknowledgement timeout does after the latch.
type recordRefuser struct{}

func (recordRefuser) WithFeature(context.Context, capabilities.Feature, func(context.Context, capabilities.FeatureGrant) error) error {
	return status.Error(codes.Unavailable, "a host did not acknowledge in time")
}
func (recordRefuser) FeatureAvailable(capabilities.Feature) bool                 { return true }
func (recordRefuser) FeatureRefusal(context.Context, capabilities.Feature) error { return nil }

// N1: the recording gate runs BEFORE the guest is stopped: a refused (or slow)
// limit-bearing reconfigure never stops a running VM.
//
// Mutation: record after stopVMLocked — the guest is shut down and the test
// goes red.
func TestFleet_RefusedLimitUpdateWithRestartNeverStopsTheGuest(t *testing.T) {
	node, client := newLimitsNode(t)
	ctx := context.Background()
	deployClean(t, ctx, client, limitlessCompose)
	waitRunning(t, ctx, node, "db")
	node.Server.SetReleaseFeatureGate(recordRefuser{})
	before := len(node.Virt.EventLog())
	limit, restart := 2.0, true
	_, err := client.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "db", Cpu: 4, CpuLimit: &limit, AllowRestart: &restart})
	if err == nil {
		t.Fatal("the update was accepted although the gate refused it")
	}
	for _, e := range node.Virt.EventLog()[before:] {
		switch e.Op {
		case "shutdown", "destroy", "start", "define":
			t.Errorf("a refused limit update touched the guest: %s %s", e.Op, e.Note)
		}
	}
}

// N2 (live): a VM whose weight was set and cleared stores 0, but its domain
// carries an explicit <shares> of the default. The live migration still asks
// the target for its cgroup version and hands libvirt the default weight.
//
// Mutation: vmSharesWeight returns the stored weight only — red.
func TestFleet_LiveMigrationOfAClearedWeightCarriesTheDefault(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	defer c.Stop()
	src, dst := c.Nodes[0], c.Nodes[1]
	spec, _ := json.Marshal(&pb.VMSpec{Name: "pp1", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(context.Background(), src.DB, corrosion.VMRecord{
		Name: "pp1", HostName: src.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := src.Virt.DefineDomain(`<domain type='kvm'><name>pp1</name><cputune><shares>1024</shares></cputune></domain>`); err != nil {
		t.Fatal(err)
	}
	src.Virt.SetState("pp1", "running")
	st, err := c.SelfClient(src).MigrateVM(context.Background(), &pb.MigrateVMRequest{
		VmName: "pp1", TargetHost: dst.Name, Strategy: pb.MigrateStrategy_MIGRATE_LIVE,
	})
	if err != nil {
		t.Fatalf("MigrateVM: %v", err)
	}
	for {
		if _, err := st.Recv(); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("migration: %v", err)
		}
	}
	note := ""
	for _, e := range src.Virt.EventLog() {
		if e.Op == "migrate" {
			note = e.Note
		}
	}
	if !strings.Contains(note, "shares_weight=100") || !strings.Contains(note, "target_cgroup="+lv.CgroupMode()) {
		t.Fatalf("libvirt migrate = %q, want the default weight 100 and the target's cgroup %s", note, lv.CgroupMode())
	}
}

// ── fix round 3 ─────────────────────────────────────────────────────────────

// R1: spec-only refusals (here a bogus cpu-mode) come before the recording
// gate and before any stop: a doomed limit update on a running VM, after the
// latch, never stops the guest and never records the use.
//
// Mutation: leave the cpu-mode check where it was (after the stop) — the guest
// is shut down and the use is recorded, red.
func TestFleet_DoomedLimitUpdateWithRestartNeitherStopsNorRecords(t *testing.T) {
	node, client := newLimitsNode(t)
	ctx := context.Background()
	deployClean(t, ctx, client, limitlessCompose)
	waitRunning(t, ctx, node, "db")
	before := len(node.Virt.EventLog())
	limit, restart := 2.0, true
	_, err := client.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "db", CpuMode: "bogus", CpuLimit: &limit, AllowRestart: &restart})
	if err == nil {
		t.Fatal("an update with a bogus cpu-mode was accepted")
	}
	for _, e := range node.Virt.EventLog()[before:] {
		switch e.Op {
		case "shutdown", "destroy", "start", "define":
			t.Errorf("a doomed update touched the guest: %s %s", e.Op, e.Note)
		}
	}
	if vmLimitsUsed(t, node) {
		t.Fatal("a doomed update recorded the vm_limits use")
	}
}

// R1, every other branch of validateRedefineRequest: max_cpu without live
// resize, max_cpu below cpu, and a secure_boot or tpm toggle over existing
// firmware state without --force are refused before the recording gate and
// before any stop, exactly as the cpu-mode case above. Each is the only check
// that refuses its request (no copy of it runs later), so a deleted branch
// would also let the request through.
//
// Mutations (one per branch of validateRedefineRequest, each red): drop the
// live-resize check; drop the max_cpu >= cpu check; drop the secure_boot
// check; drop the tpm check.
func TestFleet_DoomedRedefineWithRestartIsRefusedBeforeTheGuestIsTouched(t *testing.T) {
	cases := []struct {
		name     string
		setup    func(t *testing.T, node *Node, spec *pb.VMSpec)
		req      func(r *pb.UpdateVMRequest)
		code     codes.Code
		contains string
	}{
		{
			name: "max_cpu without live resize",
			req:  func(r *pb.UpdateVMRequest) { m := int32(4); r.MaxCpu = &m },
			code: codes.FailedPrecondition, contains: liveResizeRefusal,
		},
		{
			name:  "max_cpu below cpu",
			setup: func(t *testing.T, node *Node, _ *pb.VMSpec) { node.Server.SetLiveResize(true) },
			req:   func(r *pb.UpdateVMRequest) { m := int32(1); r.MaxCpu = &m },
			code:  codes.InvalidArgument, contains: "max_cpu (1) must be >= cpu (2)",
		},
		{
			name: "secure_boot over existing NVRAM",
			setup: func(t *testing.T, node *Node, _ *pb.VMSpec) {
				p := node.FW.NvramPath("db")
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte("vars"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			req:  func(r *pb.UpdateVMRequest) { on := true; r.SecureBoot = &on },
			code: codes.FailedPrecondition, contains: "changing secure_boot on \"db\" with existing firmware state",
		},
		{
			name: "tpm over existing TPM state",
			setup: func(t *testing.T, node *Node, spec *pb.VMSpec) {
				if spec.Uuid == "" {
					t.Fatal("setup: db has no uuid in its spec")
				}
				dir := node.FW.SwtpmDir(spec.Uuid)
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "tpm2-00.permall"), []byte("state"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			req:  func(r *pb.UpdateVMRequest) { on := true; r.Tpm = &on },
			code: codes.FailedPrecondition, contains: "changing tpm on \"db\" with existing TPM state",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			node, client := newLimitsNode(t)
			ctx := context.Background()
			deployClean(t, ctx, client, limitlessCompose)
			waitRunning(t, ctx, node, "db")
			if tc.setup != nil {
				tc.setup(t, node, storedSpec(t, ctx, node, "db"))
			}
			before := len(node.Virt.EventLog())
			limit, restart := 2.0, true
			req := &pb.UpdateVMRequest{Name: "db", CpuLimit: &limit, AllowRestart: &restart}
			tc.req(req)
			_, err := client.UpdateVM(ctx, req)
			if status.Code(err) != tc.code || !strings.Contains(errText(err), tc.contains) {
				t.Fatalf("err = %v, want %s containing %q", err, tc.code, tc.contains)
			}
			for _, e := range node.Virt.EventLog()[before:] {
				switch e.Op {
				case "shutdown", "destroy", "start", "define":
					t.Errorf("a doomed update touched the guest: %s %s", e.Op, e.Note)
				}
			}
			if vmLimitsUsed(t, node) {
				t.Fatal("a doomed update recorded the vm_limits use")
			}
		})
	}
}

// The unlatched twin on the restart path: refused by the precheck, guest
// untouched, nothing recorded.
func TestFleet_UnlatchedLimitUpdateWithRestartNeverStopsTheGuest(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	deployClean(t, ctx, client, limitlessCompose)
	waitRunning(t, ctx, node, "db")
	before := len(node.Virt.EventLog())
	limit, restart := 2.0, true
	_, err := client.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "db", Cpu: 4, CpuLimit: &limit, AllowRestart: &restart})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(errText(err), "the cluster upgrade must finish first") {
		t.Fatalf("err = %v, want the release refusal", err)
	}
	for _, e := range node.Virt.EventLog()[before:] {
		switch e.Op {
		case "shutdown", "destroy", "start", "define":
			t.Errorf("a refused update touched the guest: %s %s", e.Op, e.Note)
		}
	}
}

// R2: a cold move re-renders <shares> from the weight the SOURCE sends, not
// from the target's replica.
//
// Mutation: do not set SharesWeight on the request — the target leaves the
// source's rendering (54321) in place, red.
func TestFleet_ColdMigrationRendersTheSourcesWeightOnTheTarget(t *testing.T) {
	sc := newColdStoppedScenario(t)
	_ = sc.src.Virt.UndefineDomain("os1", false)
	if err := sc.src.Virt.DefineDomain(`<domain type='kvm'><name>os1</name><uuid>11111111-2222-4333-8444-555555555555</uuid>` +
		`<cputune><shares>54321</shares></cputune><devices>` +
		`<disk type='file' device='disk'><driver name='qemu' type='raw'/><source file='` + sc.disk + `'/><target dev='vda'/></disk>` +
		`<disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='` + sc.shared + `'/><target dev='vdb'/></disk>` +
		`</devices></domain>`); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "os1", Cpu: 1, MemoryMib: 256, CpuShares: 977})
	if err := sc.src.DB.Execute(context.Background(), `UPDATE vms SET spec = ? WHERE name = 'os1'`, string(spec)); err != nil {
		t.Fatal(err)
	}
	if err := sc.migrateCold(t); err != nil {
		t.Fatalf("cold migration: %v", err)
	}
	got := sc.dst.Virt.DefinedXML("os1")
	want := fmt.Sprintf("<shares>%d</shares>", lv.HostCPUShares(977))
	if !strings.Contains(got, want) || strings.Contains(got, "<shares>54321</shares>") {
		t.Fatalf("target definition = %s, want %s", got, want)
	}
}
