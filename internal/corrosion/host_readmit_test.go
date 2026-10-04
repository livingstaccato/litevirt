package corrosion

import (
	"context"
	"testing"
)

// Re-admitting a host over its tombstone must not hand the new machine any of
// the old one's per-host settings.
//
// Observed on the kvm003-f3 lab, 2026-10-03 (main-b3368d7c): node-5 was set up
// with IPMI credentials, removed with `lv host rm --dead`, rebuilt and re-added
// under its name. The re-admission statement set only the identity columns, so
// every node that still held the old row kept the old machine's ipmi_user and
// ipmi_pass, and its live host_fence_credentials row went on being served as
// the new machine's fence password everywhere. node-5's later boot write
// touched none of those columns, so the nodes that had the old row and the
// nodes rebuilt since held different content under one updated_at: a
// replication tie that never resolves.

const readmitSerial = "0a0b0c0d0e0f"

// oldIncarnation registers host-x, gives it every per-host setting and a
// credential row (the split latched), and removes it.
func oldIncarnation(t *testing.T, c *Client) {
	t.Helper()
	ctx := context.Background()
	c.SetCredentialsSplitGate(func() bool { return true })
	if err := InsertHost(ctx, c, HostRecord{
		Name: "host-x", Address: "10.0.0.15", SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
		State: "active", CertSerial: "01old", CPUTotal: 8, MemTotal: 16384, DiskTotal: 100,
		FenceStrategy: "best-effort", Version: "v-old", CapacityPolicyHash: "old-policy",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := SetHostLabel(ctx, c, "host-x", "gpu", "a100"); err != nil {
		t.Fatalf("SetHostLabel: %v", err)
	}
	// The operator's `lv host config`, in ConfigureHost's own statements.
	const ts = "2026-09-28T10:21:08.331604576Z"
	if _, err := c.DB().Exec(`UPDATE hosts SET fence_strategy = 'ipmi', ipmi_address = '10.0.1.15',
		ipmi_user = 'probe', ipmi_pass = 'Ipmi-Probe-0928', watchdog_dev = '/dev/watchdog0',
		role = 'witness', region = 'rack-a', cpu_overcommit = 4, mem_overcommit = 1.5,
		cpu_reserve = 2, mem_reserve_mib = 2048, schema_version = 50, updated_at = ?
		WHERE name = 'host-x'`, ts); err != nil {
		t.Fatalf("configure host-x: %v", err)
	}
	if _, err := c.DB().Exec(HostFenceCredentialUpsertSQL, "host-x", "Ipmi-Probe-0928", ts); err != nil {
		t.Fatalf("credential row: %v", err)
	}
	if err := DeleteHost(ctx, c, "host-x"); err != nil {
		t.Fatalf("DeleteHost: %v", err)
	}
	// The lab's host was removed by a release whose DeleteHost left the
	// credential row live (host_delete_credential_test.go covers today's).
	// A re-admission must retire such a row itself.
	if _, err := c.DB().Exec(`UPDATE host_fence_credentials SET ipmi_pass = 'Ipmi-Probe-0928',
		deleted_at = NULL, updated_at = ? WHERE host_name = 'host-x'`, ts); err != nil {
		t.Fatalf("restore the live credential row: %v", err)
	}
}

// hostSettings is every per-host setting column of host-x, as stored.
type hostSettings struct {
	fence, ipmiAddr, ipmiUser, ipmiPass, watchdog, labels, role, region string
	cpuOver, memOver                                                    float64
	cpuReserve, memReserve                                              int
	policy, version                                                     string
	schema, cpu, mem, disk                                              int
	cpuNull, memNull, diskNull                                          bool
	deleted                                                             bool
}

func readHostSettings(t *testing.T, c *Client) hostSettings {
	t.Helper()
	// Text columns are read through quote(), so NULL and '' differ: a fresh
	// row holds NULL where it names no value, and a tie compares content.
	rows, err := c.Query(context.Background(), `SELECT quote(fence_strategy) AS fence_strategy,
		quote(ipmi_address) AS ipmi_address, quote(ipmi_user) AS ipmi_user, quote(ipmi_pass) AS ipmi_pass,
		quote(watchdog_dev) AS watchdog_dev, quote(labels) AS labels, quote(role) AS role,
		quote(region) AS region, cpu_overcommit, mem_overcommit, cpu_reserve, mem_reserve_mib,
		quote(capacity_policy_hash) AS capacity_policy_hash, quote(version) AS version, schema_version,
		cpu_total, mem_total, disk_total, deleted_at
		FROM hosts WHERE name = 'host-x'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read host-x: rows=%d err=%v", len(rows), err)
	}
	r := rows[0]
	return hostSettings{
		fence: r.String("fence_strategy"), ipmiAddr: r.String("ipmi_address"), ipmiUser: r.String("ipmi_user"),
		ipmiPass: r.String("ipmi_pass"), watchdog: r.String("watchdog_dev"), labels: r.String("labels"),
		role: r.String("role"), region: r.String("region"),
		cpuOver: r.Float("cpu_overcommit"), memOver: r.Float("mem_overcommit"),
		cpuReserve: r.Int("cpu_reserve"), memReserve: r.Int("mem_reserve_mib"),
		policy: r.String("capacity_policy_hash"), version: r.String("version"), schema: r.Int("schema_version"),
		cpu: r.Int("cpu_total"), mem: r.Int("mem_total"), disk: r.Int("disk_total"),
		cpuNull: r.get("cpu_total") == nil, memNull: r.get("mem_total") == nil, diskNull: r.get("disk_total") == nil,
		deleted: r.String("deleted_at") != "",
	}
}

// freshSettings is what the columns hold on a host row nobody has configured:
// the schema defaults. A machine admitted for the first time, or a fresh
// daemon's own InsertHost on a node that never held the old row, leaves every
// column it does not name at these values, so a re-admission must too.
var freshSettings = hostSettings{
	fence: "'best-effort'", ipmiAddr: "NULL", ipmiUser: "NULL", ipmiPass: "NULL", watchdog: "NULL",
	labels: "NULL", role: "'worker'", region: "'default'",
	cpuReserve: -1, memReserve: -1,
	policy: "''", version: "''",
	cpuNull: true, memNull: true, diskNull: true,
}

// liveCredential reports host-x's live host_fence_credentials row, if any.
func liveCredential(t *testing.T, c *Client) (string, bool) {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT ipmi_pass FROM host_fence_credentials WHERE host_name = 'host-x' AND deleted_at IS NULL`)
	if err != nil {
		t.Fatalf("read credential row: %v", err)
	}
	if len(rows) == 0 {
		return "", false
	}
	return rows[0].String("ipmi_pass"), true
}

func assertNoOldIncarnation(t *testing.T, c *Client) {
	t.Helper()
	got := readHostSettings(t, c)
	if got.deleted {
		t.Fatal("host-x is still tombstoned; the re-admission did not apply")
	}
	if got != freshSettings {
		t.Errorf("the re-admitted row kept the previous machine's settings:\n got  %+v\n want %+v", got, freshSettings)
	}
	if pass, ok := liveCredential(t, c); ok {
		t.Errorf("the previous machine's credential row is still live (ipmi_pass %q)", pass)
	}
	h, err := GetHost(context.Background(), c, "host-x")
	if err != nil || h == nil {
		t.Fatalf("GetHost: %+v, %v", h, err)
	}
	if h.IPMIUser != "" || h.IPMIPass != "" || h.IPMIAddress != "" {
		t.Errorf("a fence of the new machine would authenticate as the old one: ipmi %q / %q @ %q",
			h.IPMIUser, h.IPMIPass, h.IPMIAddress)
	}
}

// The node `lv host add` runs on.
func TestAdmitHost_ReadmissionResetsThePreviousMachinesSettings(t *testing.T) {
	c := newTestDB(t)
	oldIncarnation(t, c)
	if err := AdmitHost(context.Background(), c, HostRecord{
		Name: "host-x", Address: "10.0.0.15", SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
		State: HostStateJoining, CertSerial: readmitSerial,
	}); err != nil {
		t.Fatalf("AdmitHost: %v", err)
	}
	assertNoOldIncarnation(t, c)
}

// Every node the admission replicates to, which is where the lab's tie came
// from: they all held the old row.
func TestReplicatedReadmission_ResetsTheReceiversOldRow(t *testing.T) {
	c := newTestDB(t)
	oldIncarnation(t, c)
	const ts = "2999-01-01T00:00:00.000001Z"
	applyRemote(t, c, "2999000000000-0000-peer", Statement{SQL: readmitHostSQL, Params: []interface{}{
		"10.0.0.15", "root", 22, 7443, HostStateJoining, readmitSerial, ts, "host-x", readmitSerial,
	}})
	assertNoOldIncarnation(t, c)
}

// A receiver whose gate is still closed holds a credential row only because a
// latched peer wrote it, and must retire it all the same: its reader takes
// that row whenever one exists.
func TestReplicatedReadmission_RetiresTheCredentialWithTheGateClosed(t *testing.T) {
	c := newTestDB(t)
	oldIncarnation(t, c)
	c.SetCredentialsSplitGate(func() bool { return false })
	applyRemote(t, c, "2999000000000-0000-peer", Statement{SQL: readmitHostSQL, Params: []interface{}{
		"10.0.0.15", "root", 22, 7443, HostStateJoining, readmitSerial, "2999-01-01T00:00:00.000001Z", "host-x", readmitSerial,
	}})
	assertNoOldIncarnation(t, c)
}

// The retirement is stamped with the admission's own updated_at, so every node
// writes the same tombstone, and a credential written after the admission —
// the new machine's, set through `lv host config` — is not touched by a
// re-admission that reaches this node late.
func TestReplicatedReadmission_KeepsANewerCredential(t *testing.T) {
	c := newTestDB(t)
	oldIncarnation(t, c)
	const newer = "2999-06-01T00:00:00.000001Z"
	if _, err := c.DB().Exec(HostFenceCredentialUpsertSQL, "host-x", "new-machine", newer); err != nil {
		t.Fatal(err)
	}
	applyRemote(t, c, "2999000000000-0000-peer", Statement{SQL: readmitHostSQL, Params: []interface{}{
		"10.0.0.15", "root", 22, 7443, HostStateJoining, readmitSerial, "2999-01-01T00:00:00.000001Z", "host-x", readmitSerial,
	}})
	if pass, ok := liveCredential(t, c); !ok || pass != "new-machine" {
		t.Errorf("credential row = %q (live %v); a credential newer than the re-admission must stand", pass, ok)
	}

	rows, err := c.Query(context.Background(),
		`SELECT deleted_at, updated_at FROM host_fence_credentials WHERE host_name = 'host-x'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read credential: %d %v", len(rows), err)
	}
	if rows[0].String("updated_at") != newer {
		t.Errorf("credential updated_at = %s, want %s", rows[0].String("updated_at"), newer)
	}
}

func TestReplicatedReadmission_StampsTheCredentialTombstoneWithItsOwnClock(t *testing.T) {
	c := newTestDB(t)
	oldIncarnation(t, c)
	const ts = "2999-01-01T00:00:00.000001Z"
	applyRemote(t, c, "2999000000000-0000-peer", Statement{SQL: readmitHostSQL, Params: []interface{}{
		"10.0.0.15", "root", 22, 7443, HostStateJoining, readmitSerial, ts, "host-x", readmitSerial,
	}})
	rows, err := c.Query(context.Background(),
		`SELECT ipmi_pass, deleted_at, updated_at FROM host_fence_credentials WHERE host_name = 'host-x'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read credential: %d %v", len(rows), err)
	}
	r := rows[0]
	if r.String("updated_at") != ts || r.String("deleted_at") != ts || r.String("ipmi_pass") != "" {
		t.Errorf("credential row = (pass %q, deleted_at %q, updated_at %q); want an empty tombstone at %s, "+
			"which every node derives from the same admission", r.String("ipmi_pass"),
			r.String("deleted_at"), r.String("updated_at"), ts)
	}
}

// The admission keeps its wire shape: a receiver on the previous release knows
// this fingerprint and no other, and a shape it does not know back-pressures
// the sender's whole stream. The reset travels with the fingerprint's
// disposition instead (host_readmit.go).
func TestAdmitHost_KeepsItsWireShape(t *testing.T) {
	const wire = "stmtshape/v1:cf5b17ce5093a08851b54207c28ffddf23738000f51d6ba776a38a4fc568b388"
	e, err := LedgerEntryFor(readmitHostSQL)
	if err != nil {
		t.Fatal(err)
	}
	if e.Fingerprint != wire {
		t.Errorf("readmitHostSQL fingerprint %s, want the previous release's %s", e.Fingerprint, wire)
	}
	if e.Disposition != DispHostReadmit {
		t.Errorf("disposition %s, want %s", e.Disposition, DispHostReadmit)
	}
	if got, ok := stmtLedger[wire]; !ok || got.Disposition != DispHostReadmit {
		t.Errorf("generated ledger entry = %+v (present %v), want disposition %s", got, ok, DispHostReadmit)
	}
}
