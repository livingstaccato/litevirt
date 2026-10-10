package fleet

import (
	"context"
	"encoding/json"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/daemon"
	"github.com/litevirt/litevirt/internal/pki"
)

// runCertWatches ticks every node's certificate watch (re-record a renewed
// serial, process owed revocations) until the returned stop is called, as the
// daemons do every 30s.
func runCertWatches(c *Cluster) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			for _, n := range c.Nodes {
				daemon.CertWatchOnce(ctx, n.Name, n.PKIDir, n.DB, n.Server)
			}
			select {
			case <-ctx.Done():
			case <-time.After(150 * time.Millisecond):
			}
		}
	}()
	return func() { cancel(); wg.Wait() }
}

func revokedOn(n *Node, serial string) bool {
	s, ok := new(big.Int).SetString(serial, 16)
	return ok && pki.IsCertRevoked(n.PKIDir, s)
}

// TestFleet_RenewCert_ProductPath drives `lv host renew-cert` itself — the CLI
// code, the host-side key generation and atomic install, the real certificate
// watch on every node and real replication — against a 3-node cluster with an
// explicit voter generation. Genesis is decided by all three members, so it
// needs node-0's accept.
//
// While node-2 runs with auth.trust_rotated_peer_certs it does not pin, so
// revoking node-0's replaced certificate would leave generation 1
// unverifiable for it: the revocation is OWED — a replicated
// certificate/revocation_owed condition carrying the signed CRL, the serial
// unrevoked everywhere. Once node-2 turns the switch off, every node pins, the
// hold protects no one, and the cluster publishes the revocation by itself.
// A second renewal, with the pin in force everywhere, revokes the replaced
// certificate AT ONCE — although generation 1 still carries an accept signed
// with a replaced key — and owes nothing.
//
// Mutations: drop the trust_rotated_peer_certs condition from
// revocationHoldReason — the first renewal revokes at once; drop
// ProcessOwedRevocations from the certificate watch — the owed revocation is
// never published; make revocationHoldReason always hold — the second renewal
// is owed too.
func TestFleet_RenewCert_ProductPath(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 7713})
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	c.WaitConverged(t, convergeTimeout)
	runGenesis(t, c)
	withOperatorPKI(t, n1)
	n2.Server.SetTrustRotatedPeerCerts(true)
	stop := runCertWatches(c)
	defer stop()
	eventually(t, convergeTimeout, "every node to see that node-2 does not pin", func() bool {
		for _, n := range c.Nodes {
			cnd, ok, err := corrosion.GetHealthCondition(ctx, n.DB, "certificate", "trust_rotated_peer_certs", "host", n2.Name)
			if err != nil || !ok || cnd.Lifecycle == corrosion.ConditionResolved {
				return false
			}
		}
		return true
	})

	renew := func() (prev, next string) {
		t.Helper()
		prevCert, err := pki.ServedHostCertificate(n0.PKIDir)
		if err != nil {
			t.Fatal(err)
		}
		prev = strings.ToLower(prevCert.SerialNumber.Text(16))
		probe := cli.GRPCProbe(n0.Address, n0.Port)
		err = cli.RenewHostCertOn(ctx, c.SelfClient(n1), &cli.LocalRemotePKI{Dir: n0.PKIDir}, probe, n0.Name,
			cli.RenewCertOptions{Wait: 20 * time.Second})
		if err != nil {
			t.Fatalf("renew-cert %s: %v", n0.Name, err)
		}
		nextCert, err := pki.ServedHostCertificate(n0.PKIDir)
		if err != nil {
			t.Fatal(err)
		}
		next = strings.ToLower(nextCert.SerialNumber.Text(16))
		if from, ok := pki.RenewedFromSerial(nextCert); !ok || from != prev {
			t.Fatalf("%s serves %s, not a successor of %s", n0.Name, next, prev)
		}
		return prev, next
	}

	prev, next := renew()
	eventually(t, convergeTimeout, "every node to record the renewed serial and hold the owed revocation", func() bool {
		for _, n := range c.Nodes {
			_, rec, _, _ := hostRowOf(t, n, n0.Name)
			if !strings.EqualFold(rec, next) || owedFor(t, n, n0.Name, prev) == "" {
				return false
			}
		}
		return true
	})
	for _, n := range c.Nodes {
		_, _ = corrosion.SyncClusterCRL(ctx, n.DB, n.PKIDir)
		if revokedOn(n, prev) {
			t.Fatalf("%s revoked %s although node-2 does not pin and generation 1 needs its accept", n.Name, prev)
		}
	}

	// node-2 turns the recovery switch off: no node is left that the hold
	// protects, and the cluster publishes the owed revocation by itself.
	n2.Server.SetTrustRotatedPeerCerts(false)
	eventually(t, convergeTimeout, "the owed revocation to be published once no node needs the hold", func() bool {
		for _, n := range c.Nodes {
			_, _ = corrosion.SyncClusterCRL(ctx, n.DB, n.PKIDir)
			if !revokedOn(n, prev) || owedFor(t, n, n0.Name, prev) != corrosion.ConditionResolved {
				return false
			}
		}
		return true
	})

	// Every node pins: the next renewal revokes at once and owes nothing.
	prev2, _ := renew()
	eventually(t, convergeTimeout, "the second replaced certificate to be revoked everywhere at once", func() bool {
		for _, n := range c.Nodes {
			_, _ = corrosion.SyncClusterCRL(ctx, n.DB, n.PKIDir)
			if !revokedOn(n, prev2) {
				return false
			}
		}
		return true
	})
	for _, n := range c.Nodes {
		if l := owedFor(t, n, n0.Name, prev2); l != "" {
			t.Fatalf("%s: a renewal under the pin was owed (%s)", n.Name, l)
		}
	}
}

// owedFor returns the lifecycle of the revocation_owed condition for
// host/serial on n, or "" when there is none.
func owedFor(t *testing.T, n *Node, host, serial string) string {
	t.Helper()
	conds, err := corrosion.ListHealthConditions(context.Background(), n.DB, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, cnd := range conds {
		if cnd.Evaluator != "certificate" || cnd.Code != "revocation_owed" || cnd.SubjectID != host+"/"+serial {
			continue
		}
		var ev struct {
			CRLPEM string `json:"crl_pem"`
		}
		if json.Unmarshal([]byte(cnd.Evidence), &ev) != nil || ev.CRLPEM == "" {
			t.Fatalf("%s: the owed revocation carries no CRL: %s", n.Name, cnd.Evidence)
		}
		return cnd.Lifecycle
	}
	return ""
}
