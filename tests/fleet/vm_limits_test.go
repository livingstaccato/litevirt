package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
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
    cpu-shares: 2048
    placement:
      host: node-0
    network:
      - name: hc
        rate: 2
`

// 2 MB/s = 2e6 B/s = 1953 KiB/s, both directions.
const (
	quotaFor1Of2  = "<quota>50000</quota>"
	sharesFor2048 = "<shares>2048</shares>"
	rateFor2      = `<inbound average="1953"`
)

// newLimitsNode is newUpdateNode with a real capability gate wired, on which
// vm_limits_v1 has latched: this build is the whole fleet.
func newLimitsNode(t *testing.T) (*Node, pb.LiteVirtClient) {
	t.Helper()
	c, node, client := newComposeFailNode(t)
	node.Server.SetBridgeEnsure(node.Net.EnsureBridge)
	gates := gateAll(t, c)
	if !gates[node.Name].Enforced(context.Background(), capabilities.VMLimitsV1) {
		t.Fatal("vm_limits_v1 did not latch on a uniform build — advertisement is build-static")
	}
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
	mustContain(t, "created domain", xml, quotaFor1Of2, "<period>100000</period>", sharesFor2048, rateFor2, `<outbound average="1953"`)
	spec := storedSpec(t, ctx, node, "db")
	if spec.CpuLimit != 1 || spec.CpuShares != 2048 || spec.Network[0].RateMbSec != 2 {
		t.Errorf("stored spec limits = %v/%v/%v, want 1/2048/2", spec.CpuLimit, spec.CpuShares, spec.Network[0].RateMbSec)
	}
}

func TestFleet_ComposeLimitChangesApplyLiveToTheRunningVM(t *testing.T) {
	ctx, node, client, before := setupLimitsVM(t)

	next := edit(t, composeLimitsBase, "cpu-limit: 1\n", "cpu-limit: 1.5\n")
	next = edit(t, next, "cpu-shares: 2048\n", "cpu-shares: 512\n")
	next = edit(t, next, "rate: 2\n", "rate: 4\n")
	if phase, detail := planDetailFor(t, ctx, client, next, "db"); phase != "update" || !strings.Contains(detail, "in place") {
		t.Errorf("plan for a limit change = %s %q, want an update applied in place", phase, detail)
	}
	from := len(node.Virt.EventLog())
	deployClean(t, ctx, client, next)
	// The same VM, never redefined or restarted.
	assertSameVM(t, ctx, node, "db", before, from, false)

	xml := node.Virt.DefinedXML("db")
	// 1.5 cores over 2 vCPUs = 75000 per vCPU; 4 MB/s = 3906 KiB/s.
	mustContain(t, "updated domain", xml, "<quota>75000</quota>", "<shares>512</shares>", `<inbound average="3906"`)
	mustNotContain(t, "updated domain", xml, quotaFor1Of2, sharesFor2048, rateFor2)
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
	if spec.CpuLimit != 1.5 || spec.CpuShares != 512 || spec.Network[0].RateMbSec != 4 {
		t.Errorf("stored spec limits = %v/%v/%v, want 1.5/512/4", spec.CpuLimit, spec.CpuShares, spec.Network[0].RateMbSec)
	}
	// Converged.
	if phase, detail := planDetailFor(t, ctx, client, next, "db"); phase != "no-change" {
		t.Errorf("re-applying the file plans %s %q, want no change", phase, detail)
	}

	// Dropping the keys removes the caps — a declarative file's meaning.
	bare := edit(t, next, "    cpu-limit: 1.5\n    cpu-shares: 512\n", "")
	bare = edit(t, bare, "        rate: 4\n", "")
	deployClean(t, ctx, client, bare)
	xml = node.Virt.DefinedXML("db")
	mustNotContain(t, "uncapped domain", xml, "<quota>75000</quota>", "<bandwidth>")
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
	// 0.5 over 2 vCPUs = 25000; shares 0 restores the 1024 default; 1 MB/s = 977 KiB/s.
	mustContain(t, "stopped domain", xml, "<quota>25000</quota>", "<shares>1024</shares>", `<inbound average="977"`)
	if rec := storedSpec(t, ctx, node, "db"); rec.CpuLimit != 0.5 || rec.CpuShares != 0 {
		t.Errorf("spec = limit %v shares %d, want 0.5 / 0 (default)", rec.CpuLimit, rec.CpuShares)
	}
}

func TestFleet_UpdateVMLimitsAreRefusedWhenInvalid(t *testing.T) {
	ctx, node, client, _ := setupLimitsVM(t)
	pre := node.Virt.DefinedXML("db")
	tooBig, tooSmall, badShares := 3.0, 0.001, int32(1)
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
	mustContain(t, "rolled-back domain", xml, quotaFor1Of2, rateFor2)
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
	// In-place patch: 2 → 4 vCPUs halves the per-vCPU quota for the same 1-core cap.
	if _, err := client.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "db", Cpu: 4}); err != nil {
		t.Fatalf("UpdateVM cpu: %v", err)
	}
	mustContain(t, "resized domain", node.Virt.DefinedXML("db"), "<quota>25000</quota>", sharesFor2048, rateFor2)
	mustNotContain(t, "resized domain", node.Virt.DefinedXML("db"), quotaFor1Of2)

	// Full regeneration (a machine-type change cannot be patched in place).
	if _, err := client.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "db", Machine: "pc"}); err != nil {
		t.Fatalf("UpdateVM machine: %v", err)
	}
	mustContain(t, "regenerated domain", node.Virt.DefinedXML("db"), "<quota>25000</quota>", sharesFor2048, rateFor2, `<outbound average="1953"`)
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

	// 2 cores over 4 vCPUs = 50000 each; 5 MB/s = 4883 KiB/s.
	mustContain(t, "rebuilt domain", survivor.Virt.DefinedXML("db"),
		"<quota>50000</quota>", "<shares>300</shares>", `<inbound average="4883"`, `<outbound average="4883"`)
}

// ── the vm_limits_v1 gate ──────────────────────────────────────────────────

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

// Until vm_limits_v1 latches, a stack that sets a limit is refused before any
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

// A limit sent to a VM another host owns is refused at the ENTRY node, before it
// is forwarded: an older owner would apply nothing and drop the fields from the
// spec it rewrites. The owner never sees the request.
func TestFleet_VMLimitsAreNeverForwardedBeforeTheLatch(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	entry, owner := c.Nodes[0], c.Nodes[1]
	putVM(t, owner, "far", 2, "stopped")
	owner.Virt.SetState("far", "stopped")
	before := len(owner.Virt.EventLog())

	limit := 1.0
	_, err := c.SelfClient(entry).UpdateVM(context.Background(), &pb.UpdateVMRequest{Name: "far", CpuLimit: &limit})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(errText(err), "cluster upgrade") {
		t.Fatalf("err = %v, want FailedPrecondition naming the cluster upgrade", err)
	}
	for _, e := range owner.Virt.EventLog()[before:] {
		t.Errorf("the owner was handed work for a refused limit: %s %s", e.Op, e.Note)
	}
	if got := specCPULimit(t, owner, "far"); got != 0 {
		t.Errorf("cpu_limit persisted as %v despite the refusal", got)
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
