// Fleet scenario: a host removed for good and added back under its name, on a
// rebuilt machine with an empty database, inherits nothing from the machine
// removed before it, and its row converges.
//
// On the kvm003-f3 lab (main-b3368d7c, 2026-10-03), node-5 was given IPMI
// credentials, removed with `lv host rm --dead`, rebuilt and re-added with
// `lv host add`. The re-admission set only the identity columns, so node-1 and
// node-2, which held the old row, kept ipmi_user and ipmi_pass from the old
// machine; node-3 and node-4, rebuilt afterwards, held none. The old machine's
// host_fence_credentials row stayed live on every node, the rebuilt ones too,
// so every node served its password as the new machine's. node-5's boot write
// then stamped one updated_at on both versions of the row, and `lv doctor
// divergence` reported equal_updated_at_different_content for good.
package fleet

import (
	"context"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// rebuildWithEmptyDB stands in for reinstalling n's machine: a new host
// certificate, and a daemon on an EMPTY database that knows its peers' rows
// (its replicator dials them through the hosts table) and nothing else, as a
// node set up by `lv host add` boots. Its gRPC server comes back on the same
// port. Returns the new certificate's serial; the daemon has not booted yet —
// see bootRebuiltNode.
func rebuildWithEmptyDB(t *testing.T, c *Cluster, n, peer *Node) string {
	t.Helper()
	ctx := context.Background()
	if n.replStarted {
		n.repl.Stop()
		n.replStarted = false
	}
	n.Stop()
	n.DB.Close()

	c.mintHostCert(n)
	serial, err := pki.CertSerial(filepath.Join(n.PKIDir, "host.crt"))
	if err != nil {
		t.Fatalf("read %s's new certificate serial: %v", n.Name, err)
	}

	db, err := corrosion.NewSharedTestClient("fleet-rebuilt-"+n.Name, n.Name)
	if err != nil {
		t.Fatalf("open %s's new database: %v", n.Name, err)
	}
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema for rebuilt %s: %v", n.Name, err)
	}
	db.MarkReplicaCaughtUpForTests("fleet-rebuild")
	db.SetCredentialsSplitGate(func() bool { return true })
	n.DB = db

	// The peers' rows, copied in place and never logged: what the node needs
	// to dial them, and nothing that would replicate back out.
	rows, err := peer.DB.Query(ctx, `SELECT * FROM hosts WHERE name != ?`, n.Name)
	if err != nil {
		t.Fatalf("read %s's peer rows: %v", peer.Name, err)
	}
	for _, r := range rows {
		marks := strings.TrimSuffix(strings.Repeat("?, ", len(r.Columns)), ", ")
		if _, err := db.DB().Exec(`INSERT INTO hosts (`+strings.Join(r.Columns, ", ")+`) VALUES (`+marks+`)`,
			r.Values...); err != nil {
			t.Fatalf("seed a peer row on rebuilt %s: %v", n.Name, err)
		}
	}
	nodes := c.Nodes
	db.SetMembersForTests(func() []corrosion.PeerInfo {
		var peers []corrosion.PeerInfo
		for _, o := range nodes {
			if o != n {
				peers = append(peers, corrosion.PeerInfo{Name: o.Name, Addr: net.JoinHostPort(o.Address, "7946")})
			}
		}
		return peers
	})

	l, err := net.Listen("tcp", net.JoinHostPort(n.Address, strconv.Itoa(n.Port)))
	if err != nil {
		t.Fatalf("rebind %s on port %d: %v", n.Name, n.Port, err)
	}
	n.Listener = l
	c.buildServer(n)
	for _, o := range c.Nodes {
		if o != n {
			c.SetLinkFaultBoth(n, o, LinkFault{})
		}
	}
	n.repl.SetProofReplicaGate(func(context.Context, string) bool { return true })
	n.repl.Start(c.ctx)
	n.replStarted = true
	return serial
}

// bootRebuiltNode is the rebuilt daemon's start: registerHost, which finds no
// row of its own on the empty database and inserts one, then the boot write
// (daemon.go).
func bootRebuiltNode(t *testing.T, n *Node, serial string) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.RegisterHost(ctx, n.DB, corrosion.HostRecord{
		Name: n.Name, Address: n.Address, SSHUser: "root", SSHPort: 22, GRPCPort: n.Port,
		State: "active", CertSerial: serial, CPUTotal: 64, MemTotal: 262144, FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatalf("register rebuilt %s: %v", n.Name, err)
	}
	if err := corrosion.UpdateHostStartup(ctx, n.DB, n.Name, "active", "v-rebuilt", 64, 262144, 0, true); err != nil {
		t.Fatalf("boot write of rebuilt %s: %v", n.Name, err)
	}
}

// fenceSettings is what a node would fence host with: its resolved IPMI
// target and credentials, and its live credential row's secret, if any.
type fenceSettings struct {
	strategy, addr, user, pass string
	credRow                    string
	hasCredRow                 bool
}

func fenceSettingsOf(t *testing.T, n *Node, host string) fenceSettings {
	t.Helper()
	ctx := context.Background()
	h, err := corrosion.GetHost(ctx, n.DB, host)
	if err != nil || h == nil {
		t.Fatalf("%s: GetHost(%s) = %+v, %v", n.Name, host, h, err)
	}
	fs := fenceSettings{strategy: h.FenceStrategy, addr: h.IPMIAddress, user: h.IPMIUser, pass: h.IPMIPass}
	rows, err := n.DB.Query(ctx,
		`SELECT ipmi_pass FROM host_fence_credentials WHERE host_name = ? AND deleted_at IS NULL`, host)
	if err != nil {
		t.Fatalf("%s: read credential row: %v", n.Name, err)
	}
	if len(rows) > 0 {
		fs.hasCredRow, fs.credRow = true, rows[0].String("ipmi_pass")
	}
	return fs
}

// convergeByAntiEntropy runs full anti-entropy passes on every node until
// their digests agree, or fails naming the tables still apart.
func convergeByAntiEntropy(t *testing.T, c *Cluster, timeout time.Duration) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(timeout)
	for {
		for _, n := range c.Nodes {
			corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
		}
		apart, err := divergence(c.Nodes)
		if err != nil {
			t.Fatalf("divergence: %v", err)
		}
		if len(apart) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the cluster did not converge after the re-added host booted; tables still apart: %v", apart)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// TestFleet_ReaddedHostInheritsNoSettings: d is configured for IPMI fencing,
// with a role-neutral set of per-host settings besides, and every node holds
// its credential row. d dies, is removed for good, and is added back on a
// rebuilt machine with an empty database. Once its daemon boots, no node holds
// the old machine's IPMI target, user or password, in the hosts row or in a
// live credential row, and every node's state digest agrees.
//
// Mutations: (1) apply the re-admission without its reset form — a, b and o
// keep the old IPMI user and settings, and the hosts row stays apart from d's
// under one updated_at; (2) skip retiring the credential row — every node,
// d included once anti-entropy reaches it, serves the old password.
func TestFleet_ReaddedHostInheritsNoSettings(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: 3302})
	a, b, o, d := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]
	// credentials_split_v1 is latched on the lab, as on any current cluster.
	for _, n := range c.Nodes {
		n.DB.SetCredentialsSplitGate(func() bool { return true })
	}
	c.WaitConverged(t, convergeTimeout)

	const oldPass = "Ipmi-Probe-0928"
	ratio := 4.0
	if _, err := c.SelfClient(a).ConfigureHost(ctx, &pb.ConfigureHostRequest{
		Name: d.Name, FenceStrategy: "ipmi", IpmiAddress: "10.77.1.15", IpmiUser: "probe", IpmiPass: oldPass,
		WatchdogDev: "/dev/watchdog0", CpuOvercommit: &ratio,
	}); err != nil {
		t.Fatalf("configure IPMI on %s: %v", d.Name, err)
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if fs := fenceSettingsOf(t, n, d.Name); fs.user != "probe" || fs.pass != oldPass || fs.credRow != oldPass {
			t.Fatalf("fixture: %s holds %+v for %s, want the configured IPMI credentials", n.Name, fs, d.Name)
		}
	}

	// d dies, is confirmed off and is removed for good.
	d.Stop()
	c.Kill(d)
	if err := a.DB.Execute(ctx,
		`INSERT OR IGNORE INTO fencing_log (id, host_name, method, result, timestamp, detail) VALUES (?, ?, ?, ?, ?, ?)`,
		"confirm-"+d.Name, d.Name, "manual", "manual-confirmed",
		time.Now().Add(-12*time.Minute).UTC().Format(time.RFC3339), "operator confirmation"); err != nil {
		t.Fatalf("fence-confirm %s: %v", d.Name, err)
	}
	if err := corrosion.UpdateHostState(ctx, a.DB, d.Name, "fenced"); err != nil {
		t.Fatalf("record %s fenced: %v", d.Name, err)
	}
	withOperatorPKI(t, a)
	if err := cli.HostRemoveDead(ctx, c.SelfClient(a), d.Name, false); err != nil {
		t.Fatalf("lv host rm --dead %s: %v", d.Name, err)
	}
	survivors := []*Node{a, b, o}
	eventually(t, convergeTimeout, "the removal to reach every survivor", func() bool {
		for _, n := range survivors {
			if h, err := corrosion.GetHost(ctx, n.DB, d.Name); err != nil || h != nil {
				return false
			}
		}
		return true
	})

	// The machine is rebuilt, and `lv host add` admits its new certificate
	// before setup starts the daemon (host_init.go).
	serial := rebuildWithEmptyDB(t, c, d, a)
	if _, err := c.SelfClient(a).AdmitHost(ctx, &pb.AdmitHostRequest{
		Name: d.Name, Address: d.Address, CertSerial: serial,
	}); err != nil {
		t.Fatalf("admit %s again: %v", d.Name, err)
	}
	eventually(t, convergeTimeout, "the admission to reach every survivor", func() bool {
		for _, n := range survivors {
			if h, err := corrosion.GetHost(ctx, n.DB, d.Name); err != nil || h == nil || h.CertSerial != serial {
				return false
			}
		}
		return true
	})

	bootRebuiltNode(t, d, serial)
	convergeByAntiEntropy(t, c, 2*convergeTimeout)

	for _, n := range c.Nodes {
		fs := fenceSettingsOf(t, n, d.Name)
		if fs.addr != "" || fs.user != "" || fs.pass != "" || fs.hasCredRow || fs.strategy == "ipmi" {
			t.Errorf("%s would fence the rebuilt %s as the machine removed before it: %+v", n.Name, d.Name, fs)
		}
	}
	rows, err := a.DB.Query(ctx, `SELECT watchdog_dev, cpu_overcommit FROM hosts WHERE name = ?`, d.Name)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read %s's row: %d %v", d.Name, len(rows), err)
	}
	if rows[0].String("watchdog_dev") != "" || rows[0].Float("cpu_overcommit") != 0 {
		t.Errorf("the rebuilt %s kept the old machine's watchdog %q and cpu overcommit %v",
			d.Name, rows[0].String("watchdog_dev"), rows[0].Float("cpu_overcommit"))
	}
}
