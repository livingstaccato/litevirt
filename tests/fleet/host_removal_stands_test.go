// Fleet scenarios for a removal that a lagging node's later write to the
// removed host races (corrosion/host_removal_stands.go): the host stays
// removed over the WAL and in anti-entropy, and a re-add still converges.
package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

const removedHost = "wl"

// removalRace is three split nodes holding wl live, node-0 removing it while
// node-2 lags, and node-2 then recording wl's state, stamped after the
// removal it has not seen. Over the WAL, node-1 hears node-2's write before
// node-0's removal: node-0 is cut from node-1 until it has. With aeFirst,
// anti-entropy runs between every pair while node-2's WAL is still cut. A
// non-nil prepare runs on wl's converged row before the race.
func removalRace(t *testing.T, aeFirst bool, prepare func(c *Cluster)) *Cluster {
	t.Helper()
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 5535})
	for _, n := range c.Nodes {
		splitMembership(t, n)
	}
	remover, mid, lagging := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	if err := corrosion.InsertHost(ctx, remover.DB, corrosion.HostRecord{
		Name: removedHost, Address: "10.0.0.9", SSHUser: "root", CertSerial: "s1", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	if prepare != nil {
		prepare(c)
	}

	c.Isolate(lagging)
	c.SetLinkFaultBoth(remover, mid, LinkFault{Block: true})
	if err := removeAdmission(t, remover); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := corrosion.UpdateHostState(ctx, lagging.DB, removedHost, "offline"); err != nil {
		t.Fatal(err)
	}
	if h, _ := corrosion.GetHost(ctx, lagging.DB, removedHost); h == nil {
		t.Fatalf("fixture: %s does not hold %s live", lagging.Name, removedHost)
	}
	if aeFirst {
		hostAntiEntropyRound(t, c)
		assertRemoved(t, c, "after anti-entropy, the WAL still cut")
	} else {
		c.SetLinkFaultBoth(lagging, mid, LinkFault{})
		eventually(t, convergeTimeout, mid.Name+" to apply "+lagging.Name+"'s state write", func() bool {
			h, _ := corrosion.GetHost(ctx, mid.DB, removedHost)
			return h != nil && h.State == "offline"
		})
	}
	c.ClearLinkFaults()
	eventually(t, convergeTimeout, "the WAL to drain", func() bool {
		n, err := undelivered(c.Nodes)
		return err == nil && n == 0
	})
	return c
}

// removeAdmission is `lv host rm` of wl on n once the host_incarnation
// release feature is granted: the removal names the serial of the admission
// n holds (corrosion.DeleteHostAdmissionIf).
func removeAdmission(t *testing.T, n *Node) error {
	t.Helper()
	ctx := context.Background()
	inc, at, serial, deleted, found, err := corrosion.HostIncarnationOf(ctx, n.DB, removedHost)
	if err != nil || !found || deleted {
		t.Fatalf("%s: %s is not live to remove: found=%v deleted=%v err=%v", n.Name, removedHost, found, deleted, err)
	}
	applied, err := corrosion.DeleteHostAdmissionIf(ctx, n.DB, removedHost, serial, corrosion.HostIncarnation{N: inc, At: at},
		capabilities.GrantForTest(t, capabilities.FeatureHostIncarnation))
	if err == nil && !applied {
		t.Fatalf("%s: the removal of %s was not applied", n.Name, removedHost)
	}
	return err
}

// assertRemoved fails for each node that lists wl or counts its vote.
func assertRemoved(t *testing.T, c *Cluster, when string) {
	t.Helper()
	ctx := context.Background()
	for _, n := range c.Nodes {
		if h, err := corrosion.GetHost(ctx, n.DB, removedHost); err != nil || h != nil {
			t.Errorf("%s, %s: GetHost(%s) = %+v (err %v), want it removed", when, n.Name, removedHost, h, err)
		}
		hosts, err := corrosion.ListHosts(ctx, n.DB)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range hosts {
			if h.Name == removedHost {
				t.Errorf("%s, %s: ListHosts lists %s (%s)", when, n.Name, removedHost, h.State)
			}
		}
		if votes(t, n, removedHost) {
			t.Errorf("%s, %s: %s votes", when, n.Name, removedHost)
		}
	}
}

// hostAntiEntropyRound merges every node's full state into every other node,
// the peer-only sensitive lane included.
func hostAntiEntropyRound(t *testing.T, c *Cluster) {
	t.Helper()
	for _, a := range c.Nodes {
		for _, b := range c.Nodes {
			if a == b {
				continue
			}
			if err := b.DB.MergeStateBytesLWW(pullDump(t, c, a)); err != nil {
				t.Fatalf("merge %s into %s: %v", a.Name, b.Name, err)
			}
			if err := b.DB.MergeSensitiveStateBytesLWW(a.DB.DumpSensitiveStateBytes()); err != nil {
				t.Fatalf("merge %s's sensitive state into %s: %v", a.Name, b.Name, err)
			}
		}
	}
}

// TestFleet_ALaggingHostStateWriteDoesNotBringBackARemovedHost: node-0
// removes wl while node-2 lags, and node-2 then records wl's state. wl stays
// removed on every node for GetHost, ListHosts and the voter set: over the
// WAL alone, and when anti-entropy runs before the WAL heals.
//
// Mutations: the WAL removal left to the clock (hostRemovalEndsLocalAdmission
// returns false) turns "the WAL first" red on node-1 and node-2; anti-entropy
// deciding two rows at incarnation 0 by the clock (sameLegacyAdmission
// returns false) turns "anti-entropy first" red on every node; the hosts tie
// chain without ruleRemovedAdmission leaves "the WAL first" apart on hosts.
func TestFleet_ALaggingHostStateWriteDoesNotBringBackARemovedHost(t *testing.T) {
	t.Run("the WAL first", func(t *testing.T) {
		c := removalRace(t, false, nil)
		assertRemoved(t, c, "over the WAL")
		hostAntiEntropyRound(t, c)
		assertRemoved(t, c, "after anti-entropy")
		c.WaitConverged(t, convergeTimeout)
	})
	t.Run("anti-entropy first", func(t *testing.T) {
		c := removalRace(t, true, nil)
		assertRemoved(t, c, "after the WAL heals")
		hostAntiEntropyRound(t, c)
		assertRemoved(t, c, "after a second anti-entropy round")
		c.WaitConverged(t, convergeTimeout)
	})
}

// TestFleet_ARemovedHostReaddedAfterALaggingWriteConverges: after the race
// above, wl is added again, once by the counted re-admission (a new
// incarnation) and once by the legacy one (incarnation 0, a new created_at
// stamp). Every node holds the new admission live, with its certificate.
//
// Mutation: sameLegacyAdmission ignoring created_at (any two rows at 0) turns
// "legacy" red: the tombstone of the first admission ends the second on
// every node after anti-entropy.
func TestFleet_ARemovedHostReaddedAfterALaggingWriteConverges(t *testing.T) {
	for _, counted := range []bool{true, false} {
		name := "legacy"
		if counted {
			name = "counted"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			c := removalRace(t, false, nil)
			remover, lagging := c.Nodes[0], c.Nodes[2]
			assertRemoved(t, c, "before the re-add")
			// node-2 is cut again and still holds whatever the WAL left it.
			c.Isolate(lagging)
			h := corrosion.HostRecord{Name: removedHost, Address: "10.0.0.9", SSHUser: "root",
				CertSerial: "s2", State: corrosion.HostStateJoining}
			if counted {
				if _, _, err := corrosion.AdmitHostV2(ctx, remover.DB, h,
					capabilities.GrantForTest(t, capabilities.FeatureHostIncarnation)); err != nil {
					t.Fatal(err)
				}
			} else if err := corrosion.AdmitHost(ctx, remover.DB, h); err != nil {
				t.Fatal(err)
			}
			hostAntiEntropyRound(t, c)
			c.ClearLinkFaults()
			eventually(t, convergeTimeout, "the WAL to drain", func() bool {
				n, err := undelivered(c.Nodes)
				return err == nil && n == 0
			})
			hostAntiEntropyRound(t, c)
			for _, n := range c.Nodes {
				got, err := corrosion.GetHost(ctx, n.DB, removedHost)
				if err != nil || got == nil || got.CertSerial != "s2" {
					t.Errorf("%s: GetHost(%s) = %+v (err %v), want the re-added host with s2", n.Name, removedHost, got, err)
				}
			}
			c.WaitConverged(t, convergeTimeout)
		})
	}
}

// TestFleet_ARemovedHostOfAnOlderBuild: rows an older build wrote, mid-roll.
// Such a build inserts created_at in whole seconds and re-admits without
// stamping a new one.
//
//   - "its row stays removed": wl's row carries an older build's created_at,
//     and the race above still ends with wl removed everywhere once
//     anti-entropy has run (the serial tells the admission);
//   - "an unstamped re-add is not undone": node-2 missed a re-add an older
//     build made, and still holds the removal; nodes 0 and 1 hold the re-added
//     row under the same created_at with the new certificate. Anti-entropy
//     takes the re-add everywhere.
//
// Mutations: sameLegacyAdmission comparing created_at alone (no serial) turns
// "an unstamped re-add is not undone" red on every node; sameLegacyAdmission
// returning false turns "its row stays removed" red on every node.
func TestFleet_ARemovedHostOfAnOlderBuild(t *testing.T) {
	const legacyCreated = "2026-01-01T00:00:00Z"
	asOlderBuild := func(c *Cluster) {
		for _, n := range c.Nodes {
			if _, err := n.DB.DB().Exec(`UPDATE hosts SET created_at = ? WHERE name = ?`, legacyCreated, removedHost); err != nil {
				t.Fatal(err)
			}
		}
		c.WaitConverged(t, convergeTimeout)
	}
	t.Run("its row stays removed", func(t *testing.T) {
		c := removalRace(t, false, asOlderBuild)
		hostAntiEntropyRound(t, c)
		assertRemoved(t, c, "after anti-entropy")
		c.WaitConverged(t, convergeTimeout)
	})
	t.Run("an unstamped re-add is not undone", func(t *testing.T) {
		ctx := context.Background()
		c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 5536})
		for _, n := range c.Nodes {
			splitMembership(t, n)
		}
		if err := corrosion.InsertHost(ctx, c.Nodes[0].DB, corrosion.HostRecord{
			Name: removedHost, Address: "10.0.0.9", SSHUser: "root", CertSerial: "s1", State: "active",
		}); err != nil {
			t.Fatal(err)
		}
		c.WaitConverged(t, convergeTimeout)
		asOlderBuild(c)
		c.Isolate(c.Nodes[0])
		c.Isolate(c.Nodes[1])
		c.Isolate(c.Nodes[2])
		const removedAt, readdedAt = "2026-02-01T00:00:00.000000000Z", "2026-02-02T00:00:00.000000000Z"
		if _, err := c.Nodes[2].DB.DB().Exec(`UPDATE hosts SET deleted_at = ?, updated_at = ? WHERE name = ?`,
			removedAt, removedAt, removedHost); err != nil {
			t.Fatal(err)
		}
		for _, n := range c.Nodes[:2] {
			if _, err := n.DB.DB().Exec(`UPDATE hosts SET cert_serial = 's2', deleted_at = NULL, updated_at = ? WHERE name = ?`,
				readdedAt, removedHost); err != nil {
				t.Fatal(err)
			}
		}
		hostAntiEntropyRound(t, c)
		for _, n := range c.Nodes {
			got, err := corrosion.GetHost(ctx, n.DB, removedHost)
			if err != nil || got == nil || got.CertSerial != "s2" {
				t.Errorf("%s: GetHost(%s) = %+v (err %v), want the re-added host with s2", n.Name, removedHost, got, err)
			}
		}
	})
}

// The race on a counted admission (incarnation 1): over the WAL alone, before
// any anti-entropy, the removal stands on every node (review V1).
//
// Red on 8932d0b39 (node-1 and node-2 skip the removal as older); mutation:
// hostRemovalEndsLocalAdmission always false turns it red.
func TestFleet_ACountedAdmissionsRemovalStandsOverTheWAL(t *testing.T) {
	ctx := context.Background()
	counted := func(c *Cluster) {
		n0 := c.Nodes[0]
		if err := corrosion.DeleteHost(ctx, n0.DB, removedHost); err != nil {
			t.Fatal(err)
		}
		c.WaitConverged(t, convergeTimeout)
		if _, _, err := corrosion.AdmitHostV2(ctx, n0.DB, corrosion.HostRecord{Name: removedHost,
			Address: "10.0.0.9", SSHUser: "root", CertSerial: "s1b", State: "active"},
			capabilities.GrantForTest(t, capabilities.FeatureHostIncarnation)); err != nil {
			t.Fatal(err)
		}
		c.WaitConverged(t, convergeTimeout)
		for _, n := range c.Nodes {
			if inc, _, _, del, found, err := corrosion.HostIncarnationOf(ctx, n.DB, removedHost); err != nil || !found || del || inc != 1 {
				t.Fatalf("fixture: %s holds inc=%d del=%v found=%v err=%v", n.Name, inc, del, found, err)
			}
		}
	}
	c := removalRace(t, false, counted)
	assertRemoved(t, c, "counted, over the WAL")
	hostAntiEntropyRound(t, c)
	assertRemoved(t, c, "counted, after anti-entropy")
	c.WaitConverged(t, convergeTimeout)
}

// Rolling upgrade (review P1, I1): wl was admitted by THIS build (InsertHost writes a
// fixed-width created_at), removed, and re-added by a v1.9.0 node, whose
// AdmitHost keeps created_at and changes only the serial. node-2 (this build)
// missed the re-add's WAL entry and holds the removal. Anti-entropy must take
// the re-add, never the old removal.
//
// Red on 3c268d2c7, where sameLegacyAdmission took one fixed-width stamp for
// one admission whatever the serial, so the old tombstone won on every node.
// Mutation: sameLegacyAdmission accepting a stamped created_at without the
// serial turns it red.
func TestFleet_AV190ReaddOverAStampedRowIsNotUndone(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 5537})
	for _, n := range c.Nodes {
		splitMembership(t, n)
	}
	if err := corrosion.InsertHost(ctx, c.Nodes[0].DB, corrosion.HostRecord{
		Name: removedHost, Address: "10.0.0.9", SSHUser: "root", CertSerial: "s1", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	c.Isolate(c.Nodes[0])
	c.Isolate(c.Nodes[1])
	c.Isolate(c.Nodes[2])
	const removedAt, readdedAt = "2026-02-01T00:00:00.000000000Z", "2026-02-02T00:00:00.000000000Z"
	if _, err := c.Nodes[2].DB.DB().Exec(`UPDATE hosts SET deleted_at = ?, updated_at = ? WHERE name = ?`,
		removedAt, removedAt, removedHost); err != nil {
		t.Fatal(err)
	}
	// v1.9.0's re-admission: serial and clock change, created_at is kept.
	for _, n := range c.Nodes[:2] {
		if _, err := n.DB.DB().Exec(`UPDATE hosts SET cert_serial = 's2', deleted_at = NULL, updated_at = ? WHERE name = ?`,
			readdedAt, removedHost); err != nil {
			t.Fatal(err)
		}
	}
	hostAntiEntropyRound(t, c)
	for _, n := range c.Nodes {
		got, err := corrosion.GetHost(ctx, n.DB, removedHost)
		if err != nil || got == nil || got.CertSerial != "s2" {
			t.Errorf("%s: GetHost(%s) = %+v (err %v), want the re-added host with s2", n.Name, removedHost, got, err)
		}
	}
}

// wl's row carries an older build's whole-second created_at (any host v1.9.0
// inserted and nobody re-admitted since). Once host_membership_split_v1 has
// latched, the removal stands over the WAL too, before any anti-entropy: no
// node lists wl, which is what checkAllPeers and recoverHosts read (review P2,
// M1).
//
// Red on 8932d0b39 and on 3c268d2c7, which left whole-second rows to
// anti-entropy; mutation: the WAL rule refusing a whole-second created_at
// turns it red on node-1 and node-2.
func TestFleet_AnOlderBuildsRowStaysRemovedOverTheWAL(t *testing.T) {
	const legacyCreated = "2026-01-01T00:00:00Z"
	c := removalRace(t, false, func(c *Cluster) {
		for _, n := range c.Nodes {
			if _, err := n.DB.DB().Exec(`UPDATE hosts SET created_at = ? WHERE name = ?`, legacyCreated, removedHost); err != nil {
				t.Fatal(err)
			}
		}
		c.WaitConverged(t, convergeTimeout)
	})
	assertRemoved(t, c, "older build's row, over the WAL")
}

// wl is removed twice, by node-2 while partitioned and then by
// node-0, and node-0 re-adds it with the legacy AdmitHost (incarnation 0, a
// new stamp). node-1 applies node-0's removal and re-add first, and node-2's
// earlier removal only after. That removal predates the re-add's stamp and
// must not end it, over the WAL or after anti-entropy (review V2, M2).
//
// A guard: green on 8932d0b39 and on 109a8a2b4. node-2's removal names s1,
// whose WHERE no row under s2 matches.
func TestFleet_AnEarlierSecondRemovalDoesNotEndALegacyReadd(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 5538})
	for _, n := range c.Nodes {
		splitMembership(t, n)
	}
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	if err := corrosion.InsertHost(ctx, n0.DB, corrosion.HostRecord{
		Name: removedHost, Address: "10.0.0.9", SSHUser: "root", CertSerial: "s1", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	c.Isolate(n2)
	if err := removeAdmission(t, n2); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := removeAdmission(t, n0); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.AdmitHost(ctx, n0.DB, corrosion.HostRecord{Name: removedHost, Address: "10.0.0.9",
		SSHUser: "root", CertSerial: "s2", State: corrosion.HostStateJoining}); err != nil {
		t.Fatal(err)
	}
	eventually(t, convergeTimeout, n1.Name+" to apply the re-add", func() bool {
		h, _ := corrosion.GetHost(ctx, n1.DB, removedHost)
		return h != nil && h.CertSerial == "s2"
	})
	c.ClearLinkFaults()
	eventually(t, convergeTimeout, "the WAL to drain", func() bool {
		n, err := undelivered(c.Nodes)
		return err == nil && n == 0
	})
	check := func(when string) {
		for _, n := range c.Nodes {
			got, err := corrosion.GetHost(ctx, n.DB, removedHost)
			if err != nil || got == nil || got.CertSerial != "s2" {
				t.Errorf("%s, %s: GetHost(%s) = %+v (err %v), want the re-added host with s2", when, n.Name, removedHost, got, err)
			}
		}
	}
	check("over the WAL")
	hostAntiEntropyRound(t, c)
	check("after anti-entropy")
}

// The removal that waited out a rolling upgrade (fix round 2). Mid-roll the
// host_incarnation release feature is not granted, so node-0's removal of wl
// is the previous shape, naming no serial. node-2 does not hear it. A v1.9.0
// node then re-adds wl, keeping its created_at and changing only the serial
// (emulated on nodes 0 and 1), and node-2 takes that re-add by anti-entropy.
// host_membership_split_v1 latches on node-2, and only then does the removal
// reach it. The re-add stands on every node, over the WAL and after
// anti-entropy.
//
// Red on 109a8a2b4, whose WAL rule took a serial-less removal at incarnation 0
// once the latch had formed: the tombstone carried the re-add's serial, and
// anti-entropy spread it. Mutation: the WAL rule ending the local admission on
// a removal that names no serial turns it red on every node.
func TestFleet_ARemovalPendingAcrossTheRollDoesNotEndAV190Readd(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 5539})
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	if err := corrosion.InsertHost(ctx, n0.DB, corrosion.HostRecord{
		Name: removedHost, Address: "10.0.0.9", SSHUser: "root", CertSerial: "s1", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	c.Isolate(n2)
	if err := corrosion.DeleteHost(ctx, n0.DB, removedHost); err != nil {
		t.Fatal(err)
	}
	eventually(t, convergeTimeout, n1.Name+" to apply the removal", func() bool {
		h, _ := corrosion.GetHost(ctx, n1.DB, removedHost)
		return h == nil
	})
	time.Sleep(10 * time.Millisecond)
	readdedAt := time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z07:00")
	for _, n := range []*Node{n0, n1} {
		if _, err := n.DB.DB().Exec(`UPDATE hosts SET cert_serial = 's2', deleted_at = NULL, updated_at = ? WHERE name = ?`,
			readdedAt, removedHost); err != nil {
			t.Fatal(err)
		}
	}
	if err := n2.DB.MergeStateBytesLWW(pullDump(t, c, n0)); err != nil {
		t.Fatal(err)
	}
	if h, _ := corrosion.GetHost(ctx, n2.DB, removedHost); h == nil || h.CertSerial != "s2" {
		t.Fatalf("fixture: %s did not take the re-add by anti-entropy: %+v", n2.Name, h)
	}
	for _, n := range c.Nodes {
		n.DB.SetHostMembershipGate(func() bool { return true })
	}
	c.ClearLinkFaults()
	eventually(t, convergeTimeout, "the WAL to drain", func() bool {
		n, err := undelivered(c.Nodes)
		return err == nil && n == 0
	})
	check := func(when string) {
		for _, n := range c.Nodes {
			got, err := corrosion.GetHost(ctx, n.DB, removedHost)
			if err != nil || got == nil || got.CertSerial != "s2" {
				t.Errorf("%s, %s: GetHost(%s) = %+v (err %v), want the re-added host with s2", when, n.Name, removedHost, got, err)
			}
		}
	}
	check("over the WAL")
	hostAntiEntropyRound(t, c)
	check("after anti-entropy")
}

// Mixed versions (fix round 2): a removal in the previous shape, as a
// previous-release node (or this build before the host_incarnation release
// feature) writes it, races node-2's later state write. It names no serial,
// so over the WAL it is left to the clock, as before; anti-entropy then
// removes wl everywhere by created_at and serial. And a removal that names a
// serial ends only that admission: node-0 removes s1 after node-2 renewed wl
// to s3 unseen, and node-2 keeps s3 over the WAL.
//
// Mutation: the WAL rule ending the local admission on a removal that names
// no serial turns "the previous shape" red on node-2. "a renewal" is a guard:
// the removal's own WHERE names the serial.
func TestFleet_HostRemovalShapesMixed(t *testing.T) {
	t.Run("the previous shape", func(t *testing.T) {
		ctx := context.Background()
		c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 5540})
		for _, n := range c.Nodes {
			splitMembership(t, n)
		}
		n0, n2 := c.Nodes[0], c.Nodes[2]
		if err := corrosion.InsertHost(ctx, n0.DB, corrosion.HostRecord{
			Name: removedHost, Address: "10.0.0.9", SSHUser: "root", CertSerial: "s1", State: "active",
		}); err != nil {
			t.Fatal(err)
		}
		c.WaitConverged(t, convergeTimeout)
		c.Isolate(n2)
		if err := corrosion.DeleteHost(ctx, n0.DB, removedHost); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
		if err := corrosion.UpdateHostState(ctx, n2.DB, removedHost, "offline"); err != nil {
			t.Fatal(err)
		}
		c.ClearLinkFaults()
		eventually(t, convergeTimeout, "the WAL to drain", func() bool {
			n, err := undelivered(c.Nodes)
			return err == nil && n == 0
		})
		if h, _ := corrosion.GetHost(ctx, n2.DB, removedHost); h == nil {
			t.Errorf("%s ended its newer row on a removal that names no admission", n2.Name)
		}
		hostAntiEntropyRound(t, c)
		assertRemoved(t, c, "after anti-entropy")
		c.WaitConverged(t, convergeTimeout)
	})
	t.Run("a renewal", func(t *testing.T) {
		ctx := context.Background()
		c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 5541})
		for _, n := range c.Nodes {
			splitMembership(t, n)
		}
		n0, n2 := c.Nodes[0], c.Nodes[2]
		if err := corrosion.InsertHost(ctx, n0.DB, corrosion.HostRecord{
			Name: removedHost, Address: "10.0.0.9", SSHUser: "root", CertSerial: "s1", State: "active",
		}); err != nil {
			t.Fatal(err)
		}
		c.WaitConverged(t, convergeTimeout)
		c.Isolate(n2)
		if err := removeAdmission(t, n0); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
		if _, err := n2.DB.DB().Exec(`UPDATE hosts SET cert_serial = 's3', updated_at = ? WHERE name = ?`,
			time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z07:00"), removedHost); err != nil {
			t.Fatal(err)
		}
		c.ClearLinkFaults()
		eventually(t, convergeTimeout, "the WAL to drain", func() bool {
			n, err := undelivered(c.Nodes)
			return err == nil && n == 0
		})
		if h, _ := corrosion.GetHost(ctx, n2.DB, removedHost); h == nil || h.CertSerial != "s3" {
			t.Errorf("%s: a removal of s1 ended its s3 row: %+v", n2.Name, h)
		}
	})
}
