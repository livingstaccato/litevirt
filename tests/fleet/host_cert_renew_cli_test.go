package fleet

import (
	"context"
	"encoding/json"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
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
// explicit voter generation.
//
// Genesis is decided by all three members, so renewing node-0 makes the
// revocation of its replaced certificate unsafe: generation 1 would no longer
// verify for a node adopting it later. The successor is served and recorded
// cluster-wide; the revocation is OWED — a replicated certificate/revocation_owed
// condition carrying the signed CRL, the serial unrevoked everywhere. Once the
// voter set changes (generation 2, which the renewed node-0 signs with its new
// certificate) the cluster publishes the revocation by itself and resolves the
// condition.
//
// Mutations: make revocationSafeForVoters always answer safe — the serial is
// revoked at once; drop ProcessOwedRevocations from the certificate watch —
// the owed revocation is never published.
func TestFleet_RenewCert_ProductPath(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 7713})
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	c.WaitConverged(t, convergeTimeout)
	runGenesis(t, c)
	withOperatorPKI(t, n1)
	stop := runCertWatches(c)
	defer stop()

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

	// Genesis is decided by every member, so node-0's accept is needed by the
	// newest generation: revoking its replaced certificate now would leave a
	// node that adopts generation 1 later without an anchor. Owed, not revoked.
	prev2, next := renew()
	eventually(t, convergeTimeout, "every node to record the renewed serial and hold the owed revocation", func() bool {
		for _, n := range c.Nodes {
			_, rec, _, _ := hostRowOf(t, n, n0.Name)
			if !strings.EqualFold(rec, next) || owedFor(t, n, n0.Name, prev2) == "" {
				return false
			}
		}
		return true
	})
	for _, n := range c.Nodes {
		_, _ = corrosion.SyncClusterCRL(ctx, n.DB, n.PKIDir)
		if revokedOn(n, prev2) {
			t.Fatalf("%s revoked %s although generation 1 needs its accept", n.Name, prev2)
		}
	}

	// The voter set changes; node-0 signs with its renewed certificate. Now the
	// newest generation does not lean on the replaced key and the cluster
	// publishes the owed revocation by itself.
	if resp, err := c.SelfClient(n1).ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "rm", Host: n2.Name}); err != nil ||
		resp.GetGeneration() != 2 {
		t.Fatalf("lv cluster voter rm %s: %+v %v", n2.Name, resp, err)
	}
	adoptAll(t, c, 2)
	eventually(t, convergeTimeout, "the owed revocation to be published once safe", func() bool {
		for _, n := range c.Nodes {
			_, _ = corrosion.SyncClusterCRL(ctx, n.DB, n.PKIDir)
			if !revokedOn(n, prev2) || owedFor(t, n, n0.Name, prev2) != corrosion.ConditionResolved {
				return false
			}
		}
		return true
	})
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
