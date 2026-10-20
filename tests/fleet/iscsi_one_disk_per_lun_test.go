// Fleet scenarios for "one iSCSI LUN, one disk" across hosts.
//
// An iscsi pool is one LUN, and every disk created on it is that LUN. Two VMs
// on two hosts with a disk on it write one block device and corrupt it. A
// create takes the LUN by a voter-majority claim (the recovery-claim voters,
// key lun/<target>/<lun>@<generation>): two concurrent creates cannot both get
// a majority, a host cut off from the majority allocates nothing, and a LUN
// already taken is released only once the create that took it is proven gone
// — asked of the host that ran it (LUNHolders, peer-only, over real mTLS).
// These run on independent replicas, with real replication and real claim
// RPCs between the nodes.

package fleet

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/storage"
)

const fleetLUNTarget = "iqn.2020-01.com.example:fleet"

// newLUNFleet is three nodes on independent replicas under an adopted voter
// generation, with the iscsi_lun_claim release feature open; iscsiadm is a
// no-op.
func newLUNFleet(t *testing.T) *Cluster {
	t.Helper()
	return newLUNFleetN(t, 3)
}

// newLUNFleetN is newLUNFleet with n nodes.
func newLUNFleetN(t *testing.T, nodes int) *Cluster {
	t.Helper()
	c := newLUNFleetGated(t, nodes)
	openLUNFeature(t, c)
	return c
}

// newLUNFleetGated is newLUNFleetN with each node's real release-feature gate
// wired and iscsi_lun_claim not yet used.
func newLUNFleetGated(t *testing.T, nodes int) *Cluster {
	t.Helper()
	t.Cleanup(storage.OverrideISCSICommandForTest(func(context.Context, string, ...string) ([]byte, error) {
		return nil, nil
	}))
	c := New(t, Options{Nodes: nodes, IndependentReplicas: true, FaultSeed: 7301})
	runGenesis(t, c)
	for _, n := range c.Nodes {
		wireLUNReleaseGate(t, c, n)
	}
	// (No setHostCapacity: its raw UPDATE of hosts is not a registered
	// replicated shape, and on independent replicas it back-pressures every
	// push behind it. The harness's hosts already have room.)
	return c
}

// wireLUNReleaseGate gives n the release-feature gate the daemon wires: a
// real health.Checker over real Pings and the real acknowledgement RPC (the
// per-node half of wireReleaseFeatures). The server's own capability gate is
// left as the LUN scenarios had it. cluster_policies stays writable, as the
// LUN checkpoint and the used record both need.
func wireLUNReleaseGate(t *testing.T, c *Cluster, n *Node) *health.Checker {
	t.Helper()
	if err := mkdirAll(filepath.Dir(markerBase(c, n))); err != nil {
		t.Fatalf("mkdir markers for %s: %v", n.Name, err)
	}
	g := health.NewChecker(n.Name, n.PKIDir, n.DB)
	g.SetPeerPinger(n.Server.PeerCapabilities)
	g.SetActivationMarker(markerBase(c, n))
	n.DB.SetClusterPolicyGate(func() bool { return true })
	g.SetReleaseUseConfirmer(n.Server.PeerHoldsReleaseFeatureUse)
	n.Server.SetReleaseFeatureGate(g)
	n.DB.SetReplicationSourceGate(n.Server.ReleaseSourceAllowed)
	n.Server.SetWALQuarantined(n.DB.WALQuarantined)
	corrosion.WireUnknownReleaseObserver(c.ctx, g, corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0))
	return g
}

// openLUNFeature latches the release token and records iscsi_lun_claim's use
// on every node — what the first iSCSI create after the upgrade does — so a
// scenario that later cuts a node off still allocates on the majority side.
func openLUNFeature(t *testing.T, c *Cluster) {
	t.Helper()
	ctx := context.Background()
	for _, n := range c.Nodes {
		n := n
		eventually(t, 20*time.Second, n.Name+" to open iscsi_lun_claim", func() bool {
			return writeFeature(ctx, n, capabilities.FeatureISCSILUNClaim) == nil
		})
	}
}

// addLUNPool gives every node a pool `name` on LUN lun of the fleet target,
// node i reaching it through portal(i). Pools are host-scoped: each node's
// row is written to its own database.
func addLUNPool(t *testing.T, c *Cluster, name string, lun int, portal func(i int) string) {
	t.Helper()
	for i, n := range c.Nodes {
		if err := corrosion.UpsertStoragePool(context.Background(), n.DB, corrosion.StoragePoolRecord{
			HostName: n.Name, Name: name, Driver: "iscsi", Source: fleetLUNTarget, State: "active",
			Options: map[string]string{"portal": portal(i), "lun": fmt.Sprint(lun)},
		}); err != nil {
			t.Fatalf("pool %s on %s: %v", name, n.Name, err)
		}
	}
}

func onePortal(int) string { return "10.9.9.9:3260" }

// createOnLUN asks node n to create VM name on n with one disk on pool.
func createOnLUN(c *Cluster, n *Node, name, pool string) error {
	_, err := c.SelfClient(n).CreateVM(context.Background(), &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: name, Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n.Name},
		Disks: []*pb.DiskSpec{{Name: "root", Size: "1G", Storage: pool}},
	}})
	return err
}

func lunVMOn(t *testing.T, n *Node, name string) bool {
	t.Helper()
	rec, err := corrosion.GetVM(context.Background(), n.DB, name)
	if err != nil {
		t.Fatalf("GetVM %s on %s: %v", name, n.Name, err)
	}
	return rec != nil
}

// A LUN another host's VM already is refuses the create, naming that VM.
// Another LUN of the same target is free.
//
// Mutation: treat a LUN decided for another VM as free (skip the release
// check) — b is created on a's LUN and this goes red.
func TestFleet_ISCSI_ALUNTakenOnAnotherHostIsRefused(t *testing.T) {
	c := newLUNFleet(t)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	addLUNPool(t, c, "san", 0, onePortal)

	if err := createOnLUN(c, n0, "a", "san"); err != nil {
		t.Fatalf("create a on %s: %v", n0.Name, err)
	}
	err := createOnLUN(c, n1, "b", "san")
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), `VM "a"`) {
		t.Fatalf("create b on a's LUN on %s: got %v, want FailedPrecondition naming VM \"a\"", n1.Name, err)
	}
	if lunVMOn(t, n1, "b") {
		t.Error("the refused VM b was persisted")
	}
	addLUNPool(t, c, "san1", 1, onePortal)
	if err := createOnLUN(c, n1, "b", "san1"); err != nil {
		t.Fatalf("create b on another LUN: %v", err)
	}
}

// One LUN reached through a different portal on each host — one storage
// subnet per host — is still one LUN: the second VM is refused.
//
// Mutation: key the LUN by its portal again — this goes red.
func TestFleet_ISCSI_ALUNThroughTwoPortalsIsOneLUN(t *testing.T) {
	c := newLUNFleet(t)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	addLUNPool(t, c, "san", 0, func(i int) string { return fmt.Sprintf("10.0.%d.5:3260", i+1) })
	if err := createOnLUN(c, n0, "a", "san"); err != nil {
		t.Fatalf("create a: %v", err)
	}
	if err := createOnLUN(c, n1, "b", "san"); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), `VM "a"`) {
		t.Fatalf("create b on a's LUN through another portal: got %v, want FailedPrecondition naming VM \"a\"", err)
	}
}

// A create holds its LUN from the claim until its disk rows commit. A create
// on another host meanwhile learns the LUN is decided for it, asks its host,
// is told the create is in flight, and is refused (retryably) naming it.
//
// Mutation: release the in-flight registration as soon as the claim is
// decided — b's create sees a's allocation as gone, takes the next
// generation, and this goes red.
func TestFleet_ISCSI_AnInFlightCreateHoldsItsLUN(t *testing.T) {
	c := newLUNFleet(t)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	addLUNPool(t, c, "san", 0, onePortal)

	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	n0.Virt.FailDefineDomain = func(string) error {
		once.Do(func() { close(entered) })
		<-release
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- createOnLUN(c, n0, "a", "san") }()
	select {
	case <-entered:
	case <-time.After(20 * time.Second):
		t.Fatal("a's create never reached its domain definition")
	}
	err := createOnLUN(c, n1, "b", "san")
	close(release)
	if status.Code(err) != codes.Aborted || !strings.Contains(err.Error(), `VM "a"`) {
		t.Fatalf("create b while a's create holds the LUN: got %v, want Aborted naming VM \"a\"", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("a's create: %v", err)
	}
}

// Free-running races, one LUN per round: whatever the interleaving, at most
// one of two concurrent creates on two hosts takes the LUN, and a loser is
// told why.
//
// Mutation: decide each create's LUN with no voters (a local decision) —
// both win and this goes red.
func TestFleet_ISCSI_RacingCreatesAtMostOneWins(t *testing.T) {
	c := newLUNFleet(t)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	for round := 0; round < 6; round++ {
		pool := fmt.Sprintf("san%d", round)
		addLUNPool(t, c, pool, round, onePortal)
		names := []string{fmt.Sprintf("a%d", round), fmt.Sprintf("b%d", round)}
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i, n := range []*Node{n0, n1} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = createOnLUN(c, n, names[i], pool)
			}()
		}
		wg.Wait()
		won := 0
		for i, err := range errs {
			switch status.Code(err) {
			case codes.OK:
				won++
			case codes.Aborted, codes.FailedPrecondition, codes.Unavailable:
				// A loser names the winner; two creates that each outran the
				// other's ballot may both lose, with a retryable refusal.
				_ = names[1-i]
			default:
				t.Errorf("round %d create %s: %v", round, names[i], err)
			}
		}
		if won > 1 {
			t.Fatalf("round %d: both creates took LUN %d", round, round)
		}
	}
}

// A host cut off from a majority of the voters allocates no LUN at all — its
// create is refused Unavailable — while the majority side goes on.
//
// Mutation: fall back to a local decision when no majority answers — the
// minority create succeeds and this goes red.
func TestFleet_ISCSI_APartitionedMinorityAllocatesNothing(t *testing.T) {
	c := newLUNFleet(t)
	n0, n2 := c.Nodes[0], c.Nodes[2]
	addLUNPool(t, c, "san", 0, onePortal)
	// A full partition: replication, claim RPCs and probes all fail between
	// n2 and the other two, in both directions.
	c.Kill(n2)

	err := createOnLUN(c, n2, "lonely", "san")
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "majority") {
		t.Fatalf("create on the minority side: got %v, want Unavailable naming the majority", err)
	}
	if lunVMOn(t, n2, "lonely") {
		t.Error("the minority create was persisted")
	}
	if err := createOnLUN(c, n0, "a", "san"); err != nil {
		t.Fatalf("create on the majority side: %v", err)
	}
}

// lunClaimsOn counts the LUN-key claim state n's voter holds.
func lunClaimsOn(t *testing.T, n *Node) int {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT COUNT(*) AS n FROM local_recovery_claims WHERE target_kind = ?`, corrosion.ClaimKindLUN)
	if err != nil {
		t.Fatalf("read LUN claims on %s: %v", n.Name, err)
	}
	return rows[0].Int("n")
}

// Before the release feature is open — mid-upgrade — no host allocates a LUN:
// with one host still on the previous build (advertising nothing, as a
// quarantined or older host does) an iSCSI create is refused with the release
// gate's text, and no use, no LUN claim and no VM is written anywhere. Once
// the fleet is uniform the create goes through, and every voter holds the
// feature's used record before it holds any LUN claim: a voter never holds a
// claim a rolled-back build would not keep without the record that
// quarantines that build.
//
// Mutations: let iscsiLUNClaimGate pass without the release gate — stage 1
// goes red; write the claim before the gate's record (call the gate after
// allocating) — the watcher goes red.
func TestFleet_ISCSI_RefusedUntilTheUpgradeFinishes(t *testing.T) {
	c := newLUNFleetGated(t, 3)
	ctx := context.Background()
	n0, old := c.Nodes[0], c.Nodes[2]
	addLUNPool(t, c, "san", 0, onePortal)
	feature := string(capabilities.FeatureISCSILUNClaim)

	// 1. One host on the previous build.
	old.Server.SetWALQuarantined(func() bool { return true })
	want := "the cluster upgrade must finish first (iscsi_lun_claim needs " + capabilities.ReleaseToken + ")"
	err := createOnLUN(c, n0, "a", "san")
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), want) {
		t.Fatalf("create before the latch: got %v, want FailedPrecondition %q", err, want)
	}
	for _, n := range c.Nodes {
		if featureUsedOn(t, n, capabilities.ReleaseToken, feature) {
			t.Fatalf("%s holds a use of %s after only a refusal", n.Name, feature)
		}
		if k := lunClaimsOn(t, n); k != 0 {
			t.Fatalf("%s holds %d LUN claim rows after a refused create", n.Name, k)
		}
		if lunVMOn(t, n, "a") {
			t.Fatalf("%s holds the refused VM", n.Name)
		}
	}

	// 2. Uniform fleet: the create goes through, and no voter ever holds a
	// LUN claim without the used record.
	old.Server.SetWALQuarantined(old.DB.WALQuarantined)
	var violation atomic.Value
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			for _, n := range c.Nodes {
				rows, qerr := n.DB.Query(ctx,
					`SELECT COUNT(*) AS n FROM local_recovery_claims WHERE target_kind = ?`, corrosion.ClaimKindLUN)
				if qerr != nil || rows[0].Int("n") == 0 {
					continue
				}
				if used, uerr := corrosion.ReleaseFeatureUsed(ctx, n.DB, capabilities.ReleaseToken, feature); uerr == nil && !used {
					violation.Store(n.Name)
				}
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	eventually(t, 30*time.Second, "the iSCSI create to be accepted on a uniform fleet", func() bool {
		return createOnLUN(c, n0, "a", "san") == nil
	})
	close(stop)
	<-done
	if v := violation.Load(); v != nil {
		t.Fatalf("%s held a LUN claim before it held the %s use record", v, feature)
	}
	claimed := 0
	for _, n := range c.Nodes {
		if !featureUsedOn(t, n, capabilities.ReleaseToken, feature) {
			t.Errorf("%s does not hold the %s use record", n.Name, feature)
		}
		claimed += lunClaimsOn(t, n)
	}
	if claimed == 0 {
		t.Fatal("the create went through with no voter holding a LUN claim")
	}
}

// ── fix round 2 ─────────────────────────────────────────────────────────────

// N-1: a replica that holds no hosts row for the host that took an earlier
// allocation — one still catching up — must not read the missing row as the
// host's removal. With that host unreachable, the LUN stays held:
// Unavailable, naming it.
//
// Mutation: release an allocation whose host has no live row here — the
// create on n0 takes a's LUN and this goes red.
func TestFleet_ISCSI_AnAllocationByAHostThisReplicaHasNotSeenIsHeld(t *testing.T) {
	c := newLUNFleet(t)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	addLUNPool(t, c, "san", 0, onePortal)
	if err := createOnLUN(c, n1, "a", "san"); err != nil {
		t.Fatalf("create a on %s: %v", n1.Name, err)
	}
	// Every push of a's rows has landed on n0 before they are taken away,
	// so no late one brings them back.
	eventually(t, convergeTimeout, "a's row to reach every node", func() bool {
		for _, n := range c.Nodes {
			if !lunVMOn(t, n, "a") {
				return false
			}
		}
		return true
	})
	c.Kill(n1)
	// n0 has never seen n1, nor a: a replica still catching up. node-2 must
	// not hand a's rows back to it either (a push or relay of rows it
	// already had made this flaky under -race).
	c.SetLinkFault(c.Nodes[2], n0, LinkFault{Block: true})
	ctx := context.Background()
	for _, q := range []string{`DELETE FROM hosts WHERE name = ?`, `DELETE FROM vm_disks WHERE vm_name = 'a' AND ? <> ''`,
		`DELETE FROM vms WHERE name = 'a' AND ? <> ''`} {
		if _, err := n0.DB.DB().ExecContext(ctx, q, n1.Name); err != nil {
			t.Fatal(err)
		}
	}
	err := createOnLUN(c, n0, "b", "san")
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), n1.Name) {
		t.Fatalf("create on a LUN an unseen host took: got %v, want Unavailable naming %s", err, n1.Name)
	}
}

// N-2: a guest whose row is gone but whose domain still uses the LUN holds
// it — the host that took the allocation answers from its libvirt domains.
//
// Mutation: answer from rows and registrations only — n0 takes the LUN and
// this goes red.
func TestFleet_ISCSI_ADomainWithoutARowHoldsItsLUN(t *testing.T) {
	c := newLUNFleet(t)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	addLUNPool(t, c, "san", 0, onePortal)
	if err := createOnLUN(c, n1, "a", "san"); err != nil {
		t.Fatalf("create a: %v", err)
	}
	if err := corrosion.DeleteVM(context.Background(), n1.DB, "a"); err != nil {
		t.Fatal(err)
	}
	eventually(t, convergeTimeout, "a's delete to reach n0", func() bool { return !lunVMOn(t, n0, "a") })
	if !n1.Virt.DomainExists("a") {
		t.Fatal("the scenario needs a's domain to outlive its row")
	}
	err := createOnLUN(c, n0, "b", "san")
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), `"a"`) {
		t.Fatalf("create on a LUN a rowless domain uses: got %v, want FailedPrecondition naming a", err)
	}
}

// N-4 / C-1: a rebuild moves the VM's claim — with one voter down it still
// has a majority and decides the next allocation, on the rebuilding host —
// and with no majority at all it is refused before the teardown, the VM left
// as it was.
//
// Mutation: drop the claim from the rebuild preflight — the second rebuild
// tears the VM down, then fails, and this goes red.
func TestFleet_ISCSI_ARebuildKeepsItsClaimAndJudgesItBeforeTheTeardown(t *testing.T) {
	c := newLUNFleet(t)
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	addLUNPool(t, c, "san", 0, onePortal)
	if err := createOnLUN(c, n0, "a", "san"); err != nil {
		t.Fatalf("create a: %v", err)
	}
	ctx := context.Background()
	c.Kill(n2)
	if _, err := c.SelfClient(n0).RebuildVM(ctx, &pb.RebuildVMRequest{Name: "a"}); err != nil {
		t.Fatalf("rebuild with a voter majority: %v", err)
	}
	k := corrosion.LUNClaimKey(fleetLUNKey(0), 1)
	if st, found, _ := n0.DB.ClaimState(ctx, k); !found || st.Value == nil || st.Value.LUN == nil || st.Value.LUN.Host != n0.Name {
		t.Fatalf("the rebuild did not move the claim to allocation 1 on %s: %+v", n0.Name, st)
	}
	c.Kill(n1)
	_, err := c.SelfClient(n0).RebuildVM(ctx, &pb.RebuildVMRequest{Name: "a"})
	if err == nil || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("rebuild with no voter majority: got %v, want a refusal before the teardown", err)
	}
	if !lunVMOn(t, n0, "a") || !n0.Virt.DomainExists("a") {
		t.Fatal("the refused rebuild tore the VM down")
	}
}

func fleetLUNKey(lun int) string {
	k, _, _ := storage.FixedDevice(storage.Config{Driver: "iscsi", Source: fleetLUNTarget,
		Options: map[string]string{"lun": fmt.Sprint(lun)}})
	return k
}

// raceDuringCreate runs racer once any node's libvirt is asked to define vm —
// inside the create, after any teardown — and returns racer's error.
func raceDuringCreate(t *testing.T, c *Cluster, vm string, racer func() error) (wait func() error) {
	t.Helper()
	var once sync.Once
	res := make(chan error, 1)
	for _, n := range c.Nodes {
		n.Virt.FailDefineDomain = func(xml string) error {
			if strings.Contains(xml, "<name>"+vm+"</name>") {
				once.Do(func() { res <- racer() })
			}
			return nil
		}
	}
	t.Cleanup(func() {
		for _, n := range c.Nodes {
			n.Virt.FailDefineDomain = nil
		}
	})
	return func() error {
		select {
		case err := <-res:
			return err
		case <-time.After(30 * time.Second):
			t.Fatal("the racer never ran: the create never defined its domain")
			return nil
		}
	}
}

// C-1, the reviewer's scenario: web is created on node-1 (allocation 0 names
// node-1); a rolling recreate runs from node-0 and places web on node-3; while
// web's create is under way on node-3 — its old incarnation torn down on
// node-1, and that tombstone everywhere — a create on node-2 puts a data disk
// on web's LUN. The racer must be refused: the recreate moved the claim to a
// new allocation on node-0, which holds it.
//
// Mutation: keep web's old allocation instead of moving it (round 2) — the
// racer asks node-1, hears nothing, takes the LUN, and this goes red.
func TestFleet_ISCSI_ARecreateFromAnotherNodeMovesTheClaim(t *testing.T) {
	recreateRace(t, "    update:\n      strategy: rolling\n")
}

// The same race through the default (inline) deploy update, which deletes and
// re-creates in place: it too moves the claim before the delete.
//
// Mutation: drop the LUN preflight from the inline recreate — the recreate
// cannot take its LUN over, and this goes red.
func TestFleet_ISCSI_AnInlineRecreateMovesTheClaim(t *testing.T) {
	recreateRace(t, "")
}

// recreateRace is the C-1 scenario with the given compose update block.
func recreateRace(t *testing.T, update string) {
	t.Helper()
	c, web, stack := lunWebStack(t, update)
	n0, n1, n2, n3 := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]
	ctx := context.Background()
	wait := raceDuringCreate(t, c, web, func() error {
		eventually(t, convergeTimeout, "web's teardown to reach node-1 and node-2", func() bool {
			return !lunVMOn(t, n1, web) && !lunVMOn(t, n2, web)
		})
		return createOnLUN(c, n2, "db", "san")
	})
	// A disk-topology change recreates; the new placement is node-3.
	deployCollect(t, ctx, c.SelfClient(n0), stack(n3.Name, "      scratch: 1G\n"))
	if err := wait(); status.Code(err) != codes.Aborted && status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a create on web's LUN during web's recreate: got %v, want it refused", err)
	} else if !strings.Contains(err.Error(), web) {
		t.Fatalf("the racer's refusal does not name %s: %v", web, err)
	}
	if lunVMOn(t, n2, "db") {
		t.Fatal("the racer's VM was persisted: two guests on one LUN")
	}
}

// lunWebStack is the reviewer's four-node fleet: a pool on LUN 0, the test
// image on every node, and stack st's VM web created on node-1 with a data
// disk on the LUN — its row on every node, and agreed. stack(host, extra)
// renders st placed on host, extra adding disk lines, with update as its
// update block.
func lunWebStack(t *testing.T, update string) (*Cluster, string, func(host, extra string) string) {
	t.Helper()
	c := newLUNFleetN(t, 4)
	n1 := c.Nodes[1]
	addLUNPool(t, c, "san", 0, onePortal)
	ctx := context.Background()
	for _, n := range c.Nodes {
		// Each node's own catalog row, written locally through the catalog's
		// registered statement: a raw INSERT is not a registered replicated
		// shape, and on independent replicas it stalls every push behind it.
		if err := corrosion.InsertImage(ctx, n.DB, corrosion.ImageRecord{Name: "test", Format: "qcow2",
			SourceURL: "file:///dev/null", Checksum: "deadbeef", SizeBytes: 1024}); err != nil {
			t.Fatalf("seed image: %v", err)
		}
		if err := writeEmptyImageFile(n.Server.ImagePathForTests("test")); err != nil {
			t.Fatalf("stage image file: %v", err)
		}
	}
	stack := func(host, extra string) string {
		return "name: st\nimages:\n  test:\n    source: file:///dev/null\nvms:\n  web:\n    image: test\n    cpu: 1\n    memory: 256\n    disks:\n      data: { size: \"1G\", storage: san }\n" +
			extra + update + "    placement:\n      host: " + host + "\n"
	}
	deployCollect(t, ctx, c.SelfClient(n1), stack(n1.Name, ""))
	web := ""
	eventually(t, convergeTimeout, "web to exist on node-1", func() bool {
		vms, _ := corrosion.ListVMs(ctx, n1.DB, "", "")
		for _, v := range vms {
			if v.HostName == n1.Name {
				web = v.Name
				return true
			}
		}
		return false
	})
	eventually(t, convergeTimeout, "web's row to reach every node", func() bool {
		for _, n := range c.Nodes {
			if !lunVMOn(t, n, web) {
				return false
			}
		}
		return true
	})
	waitVMAgreed(t, c, web)
	return c, web, stack
}

// C-1 for a VM that moved: web is created on node-1 and migrated to node-2,
// so its allocation names node-1. Its rebuild runs on node-2. A create on
// node-0 during the rebuild's create must still be refused: the rebuild
// moves the claim to node-2, which holds it.
//
// Mutation: keep web's old allocation (round 2) — the racer asks node-1,
// hears nothing, takes the LUN, and this goes red.
func TestFleet_ISCSI_ARebuildOfAMovedVMMovesTheClaim(t *testing.T) {
	c := newLUNFleet(t)
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	addLUNPool(t, c, "san", 0, onePortal)
	ctx := context.Background()
	if err := createOnLUN(c, n1, "web", "san"); err != nil {
		t.Fatalf("create web: %v", err)
	}
	// The move, as a migration leaves it: the rows name node-2, the domain is
	// on node-2, and allocation 0 still names node-1, which created web.
	rec, err := corrosion.GetVM(ctx, n1.DB, "web")
	if err != nil || rec == nil {
		t.Fatalf("web on %s: %v", n1.Name, err)
	}
	if err := corrosion.TransferVMOwnerWithDisks(ctx, n1.DB, "web", n2.Name, rec.State, rec.OwnerEpoch); err != nil {
		t.Fatalf("move web to %s: %v", n2.Name, err)
	}
	if err := n2.Virt.DefineDomain(n1.Virt.DefinedXML("web")); err != nil {
		t.Fatal(err)
	}
	n1.Virt.VanishDomain("web")
	eventually(t, convergeTimeout, "web to be on node-2 everywhere", func() bool {
		for _, n := range c.Nodes {
			rec, _ := corrosion.GetVM(ctx, n.DB, "web")
			if rec == nil || rec.HostName != n2.Name {
				return false
			}
		}
		return true
	})
	waitVMAgreed(t, c, "web")
	// It was moved to node-2 for good: its spec pins node-2, so the rebuild
	// re-creates it there (each replica's copy, written in place).
	pinned := strings.Replace(rec.Spec, `"host":"`+n1.Name+`"`, `"host":"`+n2.Name+`"`, 1)
	if pinned == rec.Spec {
		t.Fatalf("web's spec does not pin %s: %s", n1.Name, rec.Spec)
	}
	for _, n := range c.Nodes {
		if _, err := n.DB.DB().ExecContext(ctx, `UPDATE vms SET spec = ? WHERE name = 'web'`, pinned); err != nil {
			t.Fatal(err)
		}
	}
	wait := raceDuringCreate(t, c, "web", func() error {
		eventually(t, convergeTimeout, "web's teardown to reach node-1 and node-0", func() bool {
			return !lunVMOn(t, n1, "web") && !lunVMOn(t, n0, "web")
		})
		return createOnLUN(c, n0, "db", "san")
	})
	if _, err := c.SelfClient(n2).RebuildVM(ctx, &pb.RebuildVMRequest{Name: "web"}); err != nil {
		t.Fatalf("rebuild of the moved web: %v", err)
	}
	if err := wait(); err == nil || !strings.Contains(err.Error(), "web") {
		t.Fatalf("a create on web's LUN during its rebuild: got %v, want it refused naming web", err)
	}
	if lunVMOn(t, n0, "db") {
		t.Fatal("the racer's VM was persisted: two guests on one LUN")
	}
}

// waitVMAgreed waits until every node's row of vm agrees on what a recreate's
// teardown checks it by: incarnation, host, owner epoch and spec generation.
func waitVMAgreed(t *testing.T, c *Cluster, vm string) {
	t.Helper()
	ctx := context.Background()
	eventually(t, convergeTimeout, vm+"'s row to agree on every node", func() bool {
		var first *corrosion.VMRecord
		for _, n := range c.Nodes {
			rec, err := corrosion.GetVM(ctx, n.DB, vm)
			if err != nil || rec == nil {
				return false
			}
			if first == nil {
				first = rec
				continue
			}
			if rec.CreatedAt != first.CreatedAt || rec.HostName != first.HostName ||
				rec.OwnerEpoch != first.OwnerEpoch || rec.SpecGeneration != first.SpecGeneration {
				return false
			}
		}
		return true
	})
}
