package fleet

// A generated MAC is one no NIC of the cluster records, and two hosts that
// drew one MAC at the same moment are named by a mac_duplicate condition on
// each, with neither guest's MAC rewritten.
//
// Mutations, each turning the named test red:
//   - CreateVM draws with lv.GenerateMAC again (AvoidsAndConcurrentRaises:
//     mc gets the taken MAC);
//   - attachNICOwner draws with lv.GenerateMAC again (AttachAvoids);
//   - ReconcileMACCollisions raises nothing (AvoidsAndConcurrentRaises);
//   - StartVM skips refuseStartOnSharedMAC (AvoidsAndConcurrentRaises);
//   - a container's derived MAC is used though another NIC holds it
//     (ContainerNameReusedAfterAMigrate, create and clone);
//   - container holders are keyed by host and name, not lineage
//     (ContainerNameReusedAfterAMigrate, the parked migrate);
//   - RestoreContainer keeps a held MAC (ContainerRestoreBesideItsOriginal).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/health"
)

// forcedMACs makes every node's MAC draw return seq in order, then repeat
// its last entry.
func forcedMACs(t *testing.T, seq ...string) {
	t.Helper()
	var mu sync.Mutex
	i := 0
	t.Cleanup(grpcapi.SetMACDrawForTests(func() string {
		mu.Lock()
		defer mu.Unlock()
		m := seq[min(i, len(seq)-1)]
		i++
		return m
	}))
}

func createOneNIC(t *testing.T, c *Cluster, n *Node, name, net string) {
	t.Helper()
	if _, err := c.SelfClient(n).CreateVM(context.Background(), &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: name, Cpu: 1, MemoryMib: 128,
		Placement: &pb.PlacementSpec{Host: n.Name},
		Network:   []*pb.NetworkAttachment{{Name: net}},
	}}); err != nil {
		t.Fatalf("CreateVM %s on %s: %v", name, n.Name, err)
	}
}

func nicMACsOf(t *testing.T, n *Node, vm string) []string {
	t.Helper()
	nics, err := corrosion.MergedVMNICs(context.Background(), n.DB, vm)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, x := range nics {
		out = append(out, strings.ToLower(x.MAC))
	}
	return out
}

func TestFleet_MAC_AvoidsAndConcurrentRaises(t *testing.T) {
	const dup, next = "52:54:00:7a:00:01", "52:54:00:7a:00:02"
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	a, b := c.Nodes[0], c.Nodes[1]
	for _, n := range c.Nodes {
		n.Server.SetBridgeEnsure(func(string) error { return nil })
	}

	// Two hosts, each before seeing the other's row, draw one MAC.
	c.Partition(a, b)
	forcedMACs(t, dup)
	createOneNIC(t, c, a, "ma", "lan")
	createOneNIC(t, c, b, "mb", "lan")
	c.Heal(a, b)
	pumpMutations(t, c, a, b)
	pumpMutations(t, c, b, a)

	for _, n := range c.Nodes {
		n.Server.ReconcileMACCollisions(ctx)
		row, ok, err := corrosion.GetHealthCondition(ctx, n.DB, grpcapi.NICIdentityEvaluator, grpcapi.CondMACDuplicate, "host", n.Name)
		if err != nil || !ok || row.Lifecycle == corrosion.ConditionResolved {
			t.Fatalf("%s: condition %+v ok=%v err=%v; want it open", n.Name, row, ok, err)
		}
		for _, want := range []string{dup, "VM ma", "host " + a.Name, "VM mb", "host " + b.Name} {
			if !strings.Contains(row.Evidence, want) {
				t.Errorf("%s: evidence %q does not name %q", n.Name, row.Evidence, want)
			}
		}
	}
	// Neither guest's MAC was rewritten, in its domain or its rows.
	for _, x := range []struct {
		n  *Node
		vm string
	}{{a, "ma"}, {b, "mb"}} {
		xml, err := x.n.Virt.DumpXML(x.vm)
		if err != nil || !strings.Contains(strings.ToLower(xml), dup) {
			t.Errorf("%s's domain on %s no longer has MAC %s (err %v)", x.vm, x.n.Name, dup, err)
		}
		if got := nicMACsOf(t, x.n, x.vm); len(got) != 1 || got[0] != dup {
			t.Errorf("%s's NIC rows on %s = %v, want [%s]", x.vm, x.n.Name, got, dup)
		}
	}

	// A stopped guest on the shared MAC is refused a start.
	if _, err := c.SelfClient(a).StopVM(ctx, &pb.StopVMRequest{Name: "ma", Force: true}); err != nil {
		t.Fatalf("StopVM ma: %v", err)
	}
	if _, err := c.SelfClient(a).StartVM(ctx, &pb.StartVMRequest{Name: "ma"}); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "mb") {
		t.Fatalf("start of ma on a MAC mb holds: got %v, want FailedPrecondition naming mb", err)
	}

	// A host that sees the MAC draws again.
	forcedMACs(t, dup, next)
	createOneNIC(t, c, a, "mc", "lan")
	if got := nicMACsOf(t, a, "mc"); len(got) != 1 || got[0] != next {
		t.Fatalf("mc's MAC = %v, want [%s]: a MAC the cluster records was handed out", got, next)
	}

	// Once one of the two is gone, the condition resolves on both hosts.
	if _, err := c.SelfClient(b).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "mb"}); err != nil {
		t.Fatalf("DeleteVM mb: %v", err)
	}
	pumpMutations(t, c, b, a)
	for _, n := range c.Nodes {
		n.Server.ReconcileMACCollisions(ctx)
		row, ok, err := corrosion.GetHealthCondition(ctx, n.DB, grpcapi.NICIdentityEvaluator, grpcapi.CondMACDuplicate, "host", n.Name)
		if err != nil || !ok || row.Lifecycle != corrosion.ConditionResolved {
			t.Fatalf("%s after mb is deleted: condition %+v ok=%v err=%v; want resolved", n.Name, row, ok, err)
		}
	}
	if _, err := c.SelfClient(a).StartVM(ctx, &pb.StartVMRequest{Name: "ma"}); err != nil {
		t.Fatalf("start of ma once its MAC is its own: %v", err)
	}
}

func TestFleet_MAC_AttachAvoids(t *testing.T) {
	const free = "52:54:00:7a:01:01"
	c, _ := mergedNICsCluster(t, false)
	home := c.Nodes[0]
	ctx := context.Background()
	for vm, mac := range map[string]string{"av1": mnA, "av2": mnB} {
		if _, err := c.SelfClient(home).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
			Name: vm, Cpu: 1, MemoryMib: 128,
			Placement: &pb.PlacementSpec{Host: home.Name},
			Network:   []*pb.NetworkAttachment{{Name: "na", Mac: mac}},
		}}); err != nil {
			t.Fatalf("CreateVM %s: %v", vm, err)
		}
	}
	forcedMACs(t, mnA, free)
	nic := mustAttachNIC(t, c, home, "av2", "nc")
	if got := strings.ToLower(nic.MAC); got != free {
		t.Fatalf("attached NIC's MAC = %s, want %s: av1's MAC was handed to av2", got, free)
	}
}

// A clone's NICs get MACs no NIC of the cluster records.
func TestFleet_MAC_CloneAvoids(t *testing.T) {
	const tplMAC, taken, free = "52:54:00:7a:02:01", "52:54:00:7a:02:02", "52:54:00:7a:02:03"
	f := newCloneFleet(t)
	ctx := context.Background()
	for _, n := range f.c.Nodes {
		n.Server.SetBridgeEnsure(func(string) error { return nil })
	}
	if err := corrosion.InsertVM(ctx, f.entry.DB, corrosion.VMRecord{Name: "holder", HostName: f.dst.Name, State: "running"},
		[]corrosion.InterfaceRecord{{VMName: "holder", NetworkName: "lan", MAC: taken}}, nil); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "tpl", Cpu: 1, MemoryMib: 256,
		Network: []*pb.NetworkAttachment{{Name: "lan", Mac: tplMAC}}})
	if err := f.entry.DB.Execute(ctx, `UPDATE vms SET spec = ? WHERE name = 'tpl'`, string(spec)); err != nil {
		t.Fatal(err)
	}
	forcedMACs(t, taken, free)
	if _, err := f.clone(t, &pb.CloneVMRequest{Target: "cl1", DestinationHost: f.dst.Name}); err != nil {
		t.Fatalf("clone: %v", err)
	}
	if got := nicMACsOf(t, f.entry, "cl1"); len(got) != 1 || got[0] != free {
		t.Fatalf("the clone's MACs = %v, want [%s]: holder's MAC was handed to the clone", got, free)
	}
}

// A container's derived MAC repeats for its host, name and NIC: once a
// container migrates away, a create or a clone of its name on the host it
// left derives the MAC it holds. Each draws a fresh one, and the clone's
// config gets it. A migrate whose source was parked leaves two rows of one
// container, which is not a collision.
func TestFleet_MAC_ContainerNameReusedAfterAMigrate(t *testing.T) {
	c := ctMigrateCluster(t)
	src, dst := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	seedContainerNetwork(t, c)
	macOf := func(n *Node, name string) string {
		t.Helper()
		ifs := containerIfaces(t, n, name)
		if len(ifs) != 1 {
			t.Fatalf("%s on %s has NICs %+v, want one", name, n.Name, ifs)
		}
		return strings.ToLower(ifs[0].MAC)
	}

	// Create.
	createContainerOnNetwork(t, c, src, "web")
	moved := macOf(src, "web")
	if err := runMigrate(t, c, src, dst, "web", stagingRepo(t)); err != nil {
		t.Fatalf("migrate web: %v", err)
	}
	createContainerOnNetwork(t, c, src, "web")
	if got := macOf(src, "web"); got == moved || got == "" {
		t.Fatalf("the new web on %s has MAC %s; the migrated web holds %s", src.Name, got, moved)
	}

	// Clone.
	createContainerOnNetwork(t, c, src, "tpl")
	createContainerOnNetwork(t, c, src, "web2")
	moved2 := macOf(src, "web2")
	if err := runMigrate(t, c, src, dst, "web2", stagingRepo(t)); err != nil {
		t.Fatalf("migrate web2: %v", err)
	}
	if _, err := c.SelfClient(src).CloneContainer(ctx, &pb.CloneContainerRequest{Source: "tpl", Target: "web2", HostName: src.Name}); err != nil {
		t.Fatalf("clone tpl to web2: %v", err)
	}
	got := macOf(src, "web2")
	if got == moved2 {
		t.Fatalf("the clone web2 on %s has the migrated web2's MAC %s", src.Name, got)
	}
	if cfg := strings.ToLower(src.CT.NICMACSet("web2", 0)); cfg != got {
		t.Fatalf("the clone's config MAC = %q, want its row's %s", cfg, got)
	}

	// A parked migrate: two live rows of one container.
	createContainerOnNetwork(t, c, src, "park")
	src.CT.FailDelete(errors.New("simulated source runtime delete failure"))
	if err := runMigrate(t, c, src, dst, "park", stagingRepo(t)); err == nil || !strings.Contains(err.Error(), "source runtime cleanup failed") {
		t.Fatalf("premise: the migrate was to land and park its source, got %v", err)
	}
	src.CT.FailDelete(nil)

	for _, n := range c.Nodes {
		n.Server.ReconcileMACCollisions(ctx)
		if row, ok, err := corrosion.GetHealthCondition(ctx, n.DB, grpcapi.NICIdentityEvaluator, grpcapi.CondMACDuplicate, "host", n.Name); err != nil ||
			(ok && row.Lifecycle != corrosion.ConditionResolved) {
			t.Errorf("%s raised mac_duplicate: %+v (err %v)", n.Name, row, err)
		}
	}
}

// An operator restore beside the live original on another host is a new
// container: it lands with a MAC of its own, in its row and its config,
// never the original's.
func TestFleet_MAC_ContainerRestoreBesideItsOriginalGetsItsOwnMAC(t *testing.T) {
	c := ctMigrateCluster(t)
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	seedContainerNetwork(t, c)
	const name = "ct-back"
	createContainerOnNetwork(t, c, a, name)
	orig := strings.ToLower(containerIfaces(t, a, name)[0].MAC)
	repo, ts := backupContainer(t, c, a, name)
	st, err := c.SelfClient(b).RestoreContainer(ctx, &pb.RestoreContainerRequest{
		RepoPath: repo, Name: name, Timestamp: ts, HostName: b.Name,
	})
	var statuses []string
	if err == nil {
		for {
			var p *pb.RestoreContainerProgress
			if p, err = st.Recv(); err != nil {
				break
			}
			statuses = append(statuses, p.GetStatus())
		}
	}
	// The copy lands; it may not take the original's address.
	if err != io.EOF && !strings.Contains(fmt.Sprint(err), "unavailable IPs") {
		t.Fatalf("restore beside the original: %v", err)
	}
	ifs := containerIfaces(t, b, name)
	if len(ifs) != 1 {
		t.Fatalf("the copy on %s has NICs %+v, want one", b.Name, ifs)
	}
	got := strings.ToLower(ifs[0].MAC)
	if got == orig || got == "" {
		t.Fatalf("the copy's MAC = %q, the original's %s: want one of its own", got, orig)
	}
	// The caller and the audit are told: the old MAC, its holder, the new one.
	want := "MAC " + orig + " is held by container " + name + " (network " + ctNetName + ", host " + a.Name + "); restored with " + got
	told := false
	for _, st := range statuses {
		told = told || strings.Contains(st, want)
	}
	if !told {
		t.Errorf("no progress message %q; got %q", want, statuses)
	}
	if rows, qerr := b.DB.Query(ctx, `SELECT detail FROM audit_log WHERE action = 'ct.restore' AND target = ?`, name); qerr != nil {
		t.Fatal(qerr)
	} else {
		audited := false
		for _, r := range rows {
			audited = audited || strings.Contains(r.String("detail"), want)
		}
		if !audited {
			t.Errorf("no ct.restore audit row says %q", want)
		}
	}
	for _, n := range c.Nodes {
		n.Server.ReconcileMACCollisions(ctx)
		if row, ok, err := corrosion.GetHealthCondition(ctx, n.DB, grpcapi.NICIdentityEvaluator, grpcapi.CondMACDuplicate, "host", n.Name); err != nil ||
			(ok && row.Lifecycle != corrosion.ConditionResolved) {
			t.Errorf("%s raised mac_duplicate: %+v (err %v)", n.Name, row, err)
		}
	}
}

// A running VM whose NIC's MAC another VM holds is not cold-moved by a
// drain: refused before its shutdown, it keeps running where it is, and the
// refusal names both NICs and the way out. (A move that went ahead would end
// in a start the shared MAC refuses, leaving the guest stopped.)
func TestFleet_MAC_DrainLeavesARunningVMOnASharedMACRunning(t *testing.T) {
	const dup = "52:54:00:7a:03:01"
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	ctx := context.Background()
	if err := corrosion.InsertInterface(ctx, sc.src.DB, corrosion.InterfaceRecord{VMName: "os1", NetworkName: "lan", MAC: dup}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, sc.src.DB, corrosion.VMRecord{Name: "holder", HostName: sc.dst.Name, State: "running"},
		[]corrosion.InterfaceRecord{{VMName: "holder", NetworkName: "lan", MAC: dup}}, nil); err != nil {
		t.Fatal(err)
	}

	progress, err := sc.drain(t)
	assertIncomplete(t, err)
	p := progress["os1"]
	if p == nil || p.Status != "failed" || !strings.Contains(p.Error, "left running on "+sc.src.Name) ||
		!strings.Contains(p.Error, "VM holder") || !strings.Contains(p.Error, "lv detach-nic os1 "+dup) {
		t.Fatalf("drain progress for os1 = %+v, want failed: left running, naming holder and lv detach-nic", p)
	}
	if n := sc.srcOps("shutdown"); n != 0 {
		t.Errorf("os1 was shut down %d time(s) for a move its shared MAC refuses", n)
	}
	vm := sc.vm(t)
	if vm.HostName != sc.src.Name || vm.State != "running" {
		t.Errorf("os1 row = host %s state %s, want host %s state running", vm.HostName, vm.State, sc.src.Name)
	}
	if active, _ := sc.src.Virt.DomainIsActive("os1"); !active {
		t.Errorf("os1's domain is not running on %s", sc.src.Name)
	}
}

// The drain's source tells the target, over peer mTLS, that a start ends its
// cold move: with no drain journal replicated to the target at all, that
// start is not refused for a shared MAC, so the guest is not left stopped.
// The same start without the marker is refused.
func TestFleet_MAC_ADrainResumeStartNeedsNoReplicatedJournal(t *testing.T) {
	const dup = "52:54:00:7a:04:01"
	c := New(t, Options{Nodes: 2}) // independent databases; nothing replicates unless pumped
	src, dst := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	for _, n := range c.Nodes {
		n.Server.SetBridgeEnsure(func(string) error { return nil })
	}
	if _, err := c.SelfClient(dst).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "rv", Cpu: 1, MemoryMib: 128, Placement: &pb.PlacementSpec{Host: dst.Name},
		Network: []*pb.NetworkAttachment{{Name: "lan", Mac: dup}},
	}}); err != nil {
		t.Fatalf("CreateVM rv: %v", err)
	}
	if _, err := c.SelfClient(dst).StopVM(ctx, &pb.StopVMRequest{Name: "rv", Force: true}); err != nil {
		t.Fatalf("StopVM rv: %v", err)
	}
	if err := corrosion.InsertVM(ctx, dst.DB, corrosion.VMRecord{Name: "holder", HostName: dst.Name, State: "running"},
		[]corrosion.InterfaceRecord{{VMName: "holder", NetworkName: "lan", MAC: dup}}, nil); err != nil {
		t.Fatal(err)
	}
	// rv's row as a drain's move hands it over: stopped for the move.
	if err := localExec(ctx, dst.DB, `UPDATE vms SET state_detail = ? WHERE name = 'rv'`, health.DrainStopDetail("op-rv")); err != nil {
		t.Fatal(err)
	}
	if open, err := corrosion.DrainColdMoveOpenTo(ctx, dst.DB, "rv", dst.Name); err != nil || open {
		t.Fatalf("premise: %s holds an open drain move of rv (%v, %v)", dst.Name, open, err)
	}

	peer := c.PeerClient(src, dst)
	if _, err := peer.StartVM(ctx, &pb.StartVMRequest{Name: "rv"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("an unmarked start on a shared MAC: got %v, want FailedPrecondition", err)
	}
	rv, err := corrosion.GetVM(ctx, dst.DB, "rv")
	if err != nil || rv == nil {
		t.Fatalf("rv on %s: %v", dst.Name, err)
	}
	mctx := metadata.AppendToOutgoingContext(ctx, grpcapi.DrainResumeFromMDKey, src.Name,
		grpcapi.DrainResumeEpochMDKey, strconv.FormatInt(rv.OwnerEpoch, 10), grpcapi.DrainResumeOpMDKey, "op-rv")
	if _, err := peer.StartVM(mctx, &pb.StartVMRequest{Name: "rv"}); err != nil {
		t.Fatalf("the drain source's resume start: %v", err)
	}
	if active, _ := dst.Virt.DomainIsActive("rv"); !active {
		t.Fatalf("rv is not running on %s after the resume start", dst.Name)
	}
}

// A drain's start on the target carries the source's drain-resume marker,
// and a holder of the guest's MAC that appears after the preflight does not
// leave the guest stopped: it runs on the target.
func TestFleet_MAC_ADrainStartCarriesTheResumeMarker(t *testing.T) {
	const dup = "52:54:00:7a:05:01"
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	ctx := context.Background()
	if err := corrosion.InsertInterface(ctx, sc.src.DB, corrosion.InterfaceRecord{VMName: "os1", NetworkName: "lan", MAC: dup}); err != nil {
		t.Fatal(err)
	}
	sc.dst.Server.SetBridgeEnsure(func(string) error { return nil })
	var marker, epoch []string
	var rowEpoch int64 = -1
	sc.dst.HookUnary("StartVM", func(hctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
		if md, ok := metadata.FromIncomingContext(hctx); ok {
			marker = md.Get(grpcapi.DrainResumeFromMDKey)
			epoch = md.Get(grpcapi.DrainResumeEpochMDKey)
		}
		if vm, _ := corrosion.GetVM(ctx, sc.dst.DB, "os1"); vm != nil {
			rowEpoch = vm.OwnerEpoch
		}
		// A holder of os1's MAC appears after the preflight passed.
		if err := corrosion.InsertVM(ctx, sc.dst.DB, corrosion.VMRecord{Name: "late", HostName: sc.dst.Name, State: "running"},
			[]corrosion.InterfaceRecord{{VMName: "late", NetworkName: "lan", MAC: dup}}, nil); err != nil {
			t.Error(err)
		}
		return handler(hctx, req)
	})

	progress, err := sc.drain(t)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if p := progress["os1"]; p == nil || p.Status != "done" || p.Error != "" {
		t.Fatalf("drain progress for os1 = %+v, want done with no error", p)
	}
	if len(marker) != 1 || marker[0] != sc.src.Name {
		t.Fatalf("the target's StartVM got drain-resume marker %v, want [%s]", marker, sc.src.Name)
	}
	if len(epoch) != 1 || epoch[0] != strconv.FormatInt(rowEpoch, 10) {
		t.Fatalf("the marker's epoch = %v, want the handed-over row's %d", epoch, rowEpoch)
	}
	if active, _ := sc.dst.Virt.DomainIsActive("os1"); !active {
		t.Fatalf("os1 is not running on %s", sc.dst.Name)
	}
}
