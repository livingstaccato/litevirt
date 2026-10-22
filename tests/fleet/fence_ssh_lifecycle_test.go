package fleet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// TestFleet_FenceSSH_RemovedHostLeavesEveryFile: `lv host rm` of node-2
// revokes its certificate and removes its host row; its row is retired on
// every node, and its key leaves every survivor's authorized_keys. node-2,
// once the CRL reaches it, trusts no peer's key either: a machine taken out
// of the cluster stops trusting it.
//
// Mutation: drop the retirement on removal (retireFenceSSH) and the
// live-host filter — node-2's key stays rendered, red.
func TestFleet_FenceSSH_RemovedHostLeavesEveryFile(t *testing.T) {
	ctx := context.Background()
	c, fs, gates := fenceSSHFleetGates(t, 3, 2614)
	publishAndRender(t, c, fs)
	a := c.Nodes[0]
	withOperatorPKI(t, a)
	seedQuorum(c, gates, c.Nodes...)
	if err := cli.HostRemove(ctx, c.SelfClient(a), "node-2", false); err != nil {
		t.Fatalf("lv host rm node-2: %v", err)
	}
	eventually(t, convergeTimeout, "node-2's row to be retired on every survivor", func() bool {
		for _, n := range c.Nodes[:2] {
			r, ok, err := corrosion.GetHostFenceSSH(ctx, n.DB, "node-2")
			if err != nil || !ok || !r.Deleted {
				return false
			}
		}
		return true
	})
	syncCRL(t, c.Nodes[0], c.Nodes[1])
	syncAll(t, fs["node-0"], fs["node-1"])
	wantRendered(t, fs, []string{"node-0", "node-1"}, []string{"node-0", "node-1"})

	// The CRL reaches node-2 itself.
	crl, err := os.ReadFile(filepath.Join(a.PKIDir, "crl.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := pki.InstallCRL(fs["node-2"].n.PKIDir, crl); err != nil {
		t.Fatal(err)
	}
	syncAll(t, fs["node-2"])
	if got := fs["node-2"].authorizedKeys(t); len(got) != 0 {
		t.Fatalf("removed node-2 still trusts %v", got)
	}
}

// TestFleet_FenceSSH_DeadRemovalLeavesEveryFile: `lv host rm --dead` of a
// fenced, powered-off host retires its row and takes its key out of every
// survivor's authorized_keys, as `lv host rm` does.
func TestFleet_FenceSSH_DeadRemovalLeavesEveryFile(t *testing.T) {
	ctx := context.Background()
	c, fs := fenceSSHFleet(t, 4, 2615)
	publishAndRender(t, c, fs)
	a, d := c.Nodes[0], c.Nodes[3]
	genesisByTick(t, c, a)
	enableRecoveryClaims(t, c)
	c.Kill(d)
	if err := corrosion.InsertFenceLog(ctx, a.DB, corrosion.FenceLogRecord{ID: "confirm-" + d.Name, HostName: d.Name,
		Method: "manual", Result: "manual-confirmed", Detail: "operator powered it off"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateHostState(ctx, a.DB, d.Name, "fenced"); err != nil {
		t.Fatal(err)
	}
	withOperatorPKI(t, a)
	if err := cli.HostRemoveDead(ctx, c.SelfClient(a), d.Name, false); err != nil {
		t.Fatalf("lv host rm --dead %s: %v", d.Name, err)
	}
	survivors := []string{"node-0", "node-1", "node-2"}
	eventually(t, convergeTimeout, "node-3's row to be retired on every survivor", func() bool {
		for _, n := range c.Nodes[:3] {
			r, ok, err := corrosion.GetHostFenceSSH(ctx, n.DB, d.Name)
			if err != nil || !ok || !r.Deleted {
				return false
			}
		}
		return true
	})
	syncCRL(t, c.Nodes[:3]...)
	syncAll(t, fs["node-0"], fs["node-1"], fs["node-2"])
	wantRendered(t, fs, survivors, survivors)
}

// TestFleet_FenceSSH_RenewCertWaitsForTheResign: `lv host renew-cert` of
// node-0 does not revoke the replaced certificate while node-0's row is still
// signed by it — revoked first, every peer would refuse to fence node-0 until
// node-0 re-signed — and the owed revocation is published once node-0's
// daemon has re-signed the row with its renewed certificate. node-0's key is
// rendered on every peer throughout.
//
// Mutation: drop the fence-ssh hold (fenceSSHHold) — the replaced serial is
// revoked at once and node-0's row stops verifying, red.
func TestFleet_FenceSSH_RenewCertWaitsForTheResign(t *testing.T) {
	ctx := context.Background()
	c, fs := fenceSSHFleet(t, 3, 2616)
	publishAndRender(t, c, fs)
	runGenesis(t, c)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	withOperatorPKI(t, n1)
	stop := runCertWatches(c)
	defer stop()

	prevCert, err := pki.ServedHostCertificate(n0.PKIDir)
	if err != nil {
		t.Fatal(err)
	}
	prev := strings.ToLower(prevCert.SerialNumber.Text(16))
	if err := cli.RenewHostCertOn(ctx, c.SelfClient(n1), &cli.LocalRemotePKI{Dir: n0.PKIDir},
		cli.GRPCProbe(n0.Address, n0.Port), n0.Name, cli.RenewCertOptions{Wait: 20 * time.Second}); err != nil {
		t.Fatalf("renew-cert %s: %v", n0.Name, err)
	}
	// The renewal is done; node-0's daemon has not re-signed its row yet.
	time.Sleep(time.Second)
	syncCRL(t, c.Nodes...)
	for _, n := range c.Nodes {
		if revokedOn(n, prev) {
			t.Fatalf("%s revoked %s while node-0's fence ssh row is still signed by it", n.Name, prev)
		}
	}
	syncAll(t, fs["node-1"], fs["node-2"])
	wantRendered(t, fs, []string{"node-1", "node-2"}, names(c.Nodes))

	// node-0's daemon re-signs; the owed revocation is then published.
	syncAll(t, fs["node-0"])
	eventually(t, convergeTimeout, "the replaced certificate to be revoked once node-0 re-signed", func() bool {
		for _, n := range c.Nodes {
			_, _ = corrosion.SyncClusterCRL(ctx, n.DB, n.PKIDir)
			if !revokedOn(n, prev) {
				return false
			}
		}
		return true
	})
	syncAll(t, fs["node-1"], fs["node-2"])
	wantRendered(t, fs, []string{"node-1", "node-2"}, names(c.Nodes))
	next, err := pki.ServedHostCertificate(n0.PKIDir)
	if err != nil {
		t.Fatal(err)
	}
	r, _, _ := corrosion.GetHostFenceSSH(ctx, n1.DB, n0.Name)
	cert, err := pki.ParseCertPEM([]byte(r.CertPEM))
	if err != nil || !strings.EqualFold(cert.SerialNumber.Text(16), next.SerialNumber.Text(16)) {
		t.Fatalf("node-0's row on node-1 is signed by %v (%v), want the renewed %s", cert.SerialNumber, err, next.SerialNumber.Text(16))
	}
}
