package corrosion

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"modernc.org/sqlite"
)

// Explicit opt-in only. This image never contains initialized Client state or
// any voter, authority, application, origin, session, or historical data.
type privateSeedRecord struct {
	image, digest, shape, catalog, executable, sqlite                         string
	constructorNS, initNS, initialValidationNS, sanitizeNS, exportNS, totalNS int64
}
type privateSeedPublisher struct {
	once   sync.Once
	record privateSeedRecord
	err    error
}

func (p *privateSeedPublisher) get(build func() (privateSeedRecord, error)) (privateSeedRecord, error) {
	p.once.Do(func() {
		r, err := build()
		if err != nil {
			p.err = err
			return
		}
		if len(r.image) == 0 {
			p.err = fmt.Errorf("empty image publication")
			return
		}
		p.record = r
	})
	return p.record, p.err
}

var privateSeedProcess privateSeedPublisher
var privateSeedActive atomic.Int64
var privateSeedBinary struct {
	once   sync.Once
	digest string
	err    error
}

func privateSeedExecutable() (string, error) {
	privateSeedBinary.once.Do(func() {
		path, err := os.Executable()
		if err != nil {
			privateSeedBinary.err = err
			return
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			privateSeedBinary.err = err
			return
		}
		privateSeedBinary.digest = privateSeedHash(raw)
	})
	return privateSeedBinary.digest, privateSeedBinary.err
}
func privateSeedHash(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func privateSeedCatalog() string {
	var b strings.Builder
	for _, m := range schemaMigrationLedger {
		fmt.Fprintf(&b, "%s\x00%s\n", m.ID, sha256hex(m.SQL))
	}
	return privateSeedHash([]byte(b.String()))
}

// Deliberately closed inventory: a new table/schema requires a reviewed update,
// rather than silently inheriting that table and its data into every clone.
const privateSeedTableInventory = `acknowledged_tie_versions acknowledged_ties applied_migrations audit_chain_heads audit_key_lifecycle audit_log audit_signing_keys backup_repos backup_schedules bgp_peers clock_skew cluster cluster_crl cluster_firewall_rules cluster_policies container_backups container_interfaces container_restarts container_snapshots containers crl_versions dns_records fencing_log firewall_defaults health_conditions health_evaluator_status host_capacity_observations host_fence_credentials host_fence_redfish host_fence_ssh host_firewall_rules host_fw_intent host_health host_labels host_membership host_networks host_pci_devices host_runtime host_runtime_usage hosts idempotency_keys image_hosts images ip_allocations ip_sets lb_backends lb_configs leader_election leader_lease_terms local_abandoned_proofs local_automation_admissions local_automation_aggregate_conflicts local_automation_aggregate_copies local_automation_aggregate_maxima local_automation_aggregate_sources local_automation_aggregates local_automation_aliases local_automation_anchors local_automation_authority local_automation_bindings local_automation_credential_issuance local_automation_cut_records local_automation_cuts local_automation_execution_artifacts local_automation_execution_progress local_automation_execution_terminals local_automation_executors local_automation_history local_automation_identities local_automation_identity_continuity local_automation_key_epochs local_automation_key_recipients local_automation_lifetimes local_automation_local_audits local_automation_local_rows local_automation_names local_automation_owners local_automation_payload_wrappings local_automation_prefix local_automation_publications local_automation_receiver_audits local_automation_receiver_components local_automation_receiver_current local_automation_receiver_established local_automation_receiver_jobs local_automation_receiver_pages local_automation_receiver_records local_automation_receiver_refs local_automation_receiver_requests local_automation_receiver_sources local_automation_receiver_validations local_automation_recovery local_automation_requests local_automation_resources local_automation_retained_completions local_automation_retained_deliveries local_automation_retained_objects local_automation_semantic_heads local_automation_source_jobs local_automation_staging local_automation_target_operations local_automation_target_reservations local_incarnation_claims local_recovery_claims local_term_bindings local_voter_adoption local_voter_incarnation local_voter_seals mutation_log mutation_seen netbox_bindings netbox_host_config netbox_objects netbox_sync_queue network_vteps networks notification_routes notification_targets operation_steps operations project_authority_epochs project_quotas projects quota_reservations rebalance_proposals recovery_code_sets recovery_codes registry_credentials replication_checkpoints replication_watermarks reseed_generation reseed_in_progress resource_mappings role_bindings roles runtime_action_proofs schema_state security_groups service_endpoints session_factors session_groups sessions sg_rules snapshots sqlite_sequence stacks storage_pools token_credentials tokens user_2fa user_2fa_sets user_credentials user_enrollment_codes user_identity_bindings user_lifecycle users vm_backups vm_disks vm_events vm_interfaces vm_locks vm_nics vm_pci_intent vm_pci_realizations vm_restarts vms volumes voter_configs`

func privateSeedRows(c *Client, q string, args ...any) ([]Row, error) {
	return c.Query(context.Background(), q, args...)
}
func privateSeedShape(c *Client) (string, error) {
	rows, err := privateSeedRows(c, `SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name`)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(rows)
	return string(raw), err
}
func privateSeedValidate(c *Client, identity, initialized bool, shape string) error {
	ctx := context.Background()
	if CurrentSchemaVersion != 91 || len(schemaMigrationLedger) != 219 {
		return fmt.Errorf("compiled schema/catalog changed")
	}
	tables, err := privateSeedRows(c, `SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(tables))
	for _, r := range tables {
		names = append(names, r.String("name"))
	}
	if strings.Join(names, " ") != privateSeedTableInventory {
		return fmt.Errorf("unexpected table inventory")
	}
	for _, name := range names {
		rows, err := privateSeedRows(c, `SELECT count(*) AS n FROM "`+strings.ReplaceAll(name, `"`, `""`)+`"`)
		if err != nil {
			return err
		}
		want := int64(0)
		switch name {
		case "schema_state":
			want = 1
		case "applied_migrations":
			want = 219
		case "local_voter_incarnation":
			if identity {
				want = 1
			}
		}
		if len(rows) != 1 || rows[0].Int64("n") != want {
			return fmt.Errorf("nonempty or wrong schema inventory %s: %+v want %d", name, rows, want)
		}
	}
	rows, err := privateSeedRows(c, `SELECT id,checksum FROM applied_migrations ORDER BY id`)
	if err != nil {
		return err
	}
	got := map[string]string{}
	for _, r := range rows {
		got[r.String("id")] = r.String("checksum")
	}
	if len(rows) != 219 || len(got) != 219 {
		return fmt.Errorf("migration receipt inventory")
	}
	for _, m := range schemaMigrationLedger {
		if got[m.ID] != sha256hex(m.SQL) {
			return fmt.Errorf("migration checksum %s", m.ID)
		}
	}
	rows, err = privateSeedRows(c, `SELECT id,version FROM schema_state`)
	if err != nil {
		return err
	}
	if len(rows) != 1 || rows[0].Int64("id") != 1 || rows[0].Int64("version") != 91 || derivedSchemaVersion(ctx, c) != 91 {
		return fmt.Errorf("schema version differs")
	}
	if err = c.ExecuteLocal(ctx, func(tx *LocalTx) error { return automationVerifyUpdateIndexesTx(ctx, tx) }); err != nil {
		return err
	}
	rows, err = privateSeedRows(c, `PRAGMA integrity_check`)
	if err != nil {
		return err
	}
	if len(rows) != 1 || rows[0].String("integrity_check") != "ok" {
		return fmt.Errorf("integrity differs")
	}
	actual, err := privateSeedShape(c)
	if err != nil {
		return err
	}
	if shape != "" && actual != shape {
		return fmt.Errorf("physical schema differs")
	}
	if initialized {
		if c.effectiveDBSchema.Load() != 91 || c.acknowledgedTies == nil || c.acknowledgedVersions == nil {
			return fmt.Errorf("actual InitSchema client state absent")
		}
	} else if c.effectiveDBSchema.Load() != 0 || c.acknowledgedTies != nil || c.acknowledgedVersions != nil {
		return fmt.Errorf("pre-Init client was initialized")
	}
	return nil
}

type privateSeedOwner struct {
	db, keeper        *sql.DB
	sever             *writeSever
	generations       *tableGenerations
	clock             any
	dsn               string
	gate              *func() bool
	journal           string
	synchronous, busy int64
}

func privateSeedPragma(c *Client) (string, int64, int64, error) {
	j, e := privateSeedRows(c, `PRAGMA journal_mode`)
	if e != nil {
		return "", 0, 0, e
	}
	s, e := privateSeedRows(c, `PRAGMA synchronous`)
	if e != nil {
		return "", 0, 0, e
	}
	b, e := privateSeedRows(c, `PRAGMA busy_timeout`)
	if e != nil {
		return "", 0, 0, e
	}
	if len(j) != 1 || len(s) != 1 || len(b) != 1 {
		return "", 0, 0, fmt.Errorf("missing memory PRAGMA")
	}
	return j[0].String("journal_mode"), s[0].Int64("synchronous"), b[0].Int64("timeout"), nil
}
func privateSeedCapture(c *Client) (privateSeedOwner, error) {
	o := privateSeedOwner{db: c.db, keeper: c.memKeeper, sever: c.writeSever, generations: c.tableGens, clock: c.clock, dsn: c.dsn, gate: c.leaseTermLedger.Load()}
	var err error
	o.journal, o.synchronous, o.busy, err = privateSeedPragma(c)
	if err != nil {
		return o, err
	}
	if c.db == nil || c.memKeeper == nil || c.db == c.memKeeper || c.memKeeper.Stats().OpenConnections == 0 || c.writeSever == nil || c.writeSever.state.Load() != severOff || c.writeSever.refused.Load() != 0 || c.writeSever.landed.Load() != 0 || c.writeSever.pastTheLock.Load() != 0 {
		return o, fmt.Errorf("constructor keeper/sever initial state")
	}
	rows, err := privateSeedRows(c, `SELECT name FROM sqlite_master`)
	if err != nil {
		return o, err
	}
	if len(rows) != 0 || c.effectiveDBSchema.Load() != 0 || c.acknowledgedTies != nil || c.acknowledgedVersions != nil {
		return o, fmt.Errorf("constructor not empty")
	}
	return o, privateSeedCheckOwner(c, o)
}
func privateSeedCheckOwner(c *Client, o privateSeedOwner) error {
	if c.db != o.db || c.memKeeper != o.keeper || c.writeSever != o.sever || c.tableGens != o.generations || c.clock != o.clock || c.dsn != o.dsn || c.leaseTermLedger.Load() != o.gate {
		return fmt.Errorf("constructor owner changed")
	}
	if c.dataDir != "" || c.hwm != nil || c.outOfProcess || c.hostName != "test-node" || c.clock == nil || c.replicatorNotify == nil || c.membershipNotify == nil || !strings.HasPrefix(c.dsn, "file:testdb") || !strings.Contains(c.dsn, "?mode=memory&cache=shared&_pragma=busy_timeout(5000)") {
		return fmt.Errorf("memory constructor config changed")
	}
	peers, assumed := c.sensitiveMerges.snapshot()
	if !assumed || len(peers) != 0 || !c.MayMintLeaseTerm() || c.claimCertVerifier.Load() != nil || c.releaseFeatureGate.Load() != nil || c.continuityReleaseRestorer.Load() != nil {
		return fmt.Errorf("constructor gate/private authority defaults changed")
	}
	j, s, b, err := privateSeedPragma(c)
	if err != nil {
		return err
	}
	if j != o.journal || s != o.synchronous || b != o.busy || j != "memory" || b != 5000 {
		return fmt.Errorf("memory PRAGMA changed")
	}
	rows, err := privateSeedRows(c, `PRAGMA database_list`)
	if err != nil {
		return err
	}
	main := 0
	for _, r := range rows {
		if r.String("name") == "main" {
			main++
			if r.String("file") != "" {
				return fmt.Errorf("memory became disk")
			}
		}
	}
	if main != 1 {
		return fmt.Errorf("memory main database absent")
	}
	return nil
}

// Finish closes only its remote endpoint; Raw/connection ownership never escapes.
func privateSeedTransfer(c *Client, path string, restore bool) error {
	ctx := context.Background()
	c.mu.Lock()
	defer c.mu.Unlock()
	conn, err := c.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	mode := "rwc"
	if restore {
		mode = "ro"
	}
	uri := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=" + mode}).String()
	return conn.Raw(func(raw any) error {
		api, ok := raw.(interface {
			NewBackup(string) (*sqlite.Backup, error)
			NewRestore(string) (*sqlite.Backup, error)
		})
		if !ok {
			return fmt.Errorf("pinned backup API unavailable: %T", raw)
		}
		var b *sqlite.Backup
		var err error
		if restore {
			b, err = api.NewRestore(uri)
		} else {
			b, err = api.NewBackup(uri)
		}
		if err != nil {
			return err
		}
		more, stepErr := b.Step(-1)
		finishErr := b.Finish()
		if stepErr != nil {
			return errors.Join(stepErr, finishErr)
		}
		if finishErr != nil {
			return finishErr
		}
		if more {
			return fmt.Errorf("backup incomplete")
		}
		return nil
	})
}
func privateSeedBuild() (record privateSeedRecord, err error) {
	startAll := time.Now()
	dir, err := os.MkdirTemp("", "private-schema-donor-")
	if err != nil {
		return record, err
	}
	start := time.Now()
	c, err := NewTestClient()
	record.constructorNS = time.Since(start).Nanoseconds()
	if err != nil {
		_ = os.RemoveAll(dir)
		return record, err
	}
	defer func() {
		err = errors.Join(err, c.Close(), os.RemoveAll(dir))
		record.totalNS = time.Since(startAll).Nanoseconds()
		if err != nil {
			record = privateSeedRecord{}
		}
	}()
	owner, err := privateSeedCapture(c)
	if err != nil {
		return record, err
	}
	start = time.Now()
	err = InitSchema(context.Background(), c)
	record.initNS = time.Since(start).Nanoseconds()
	if err != nil {
		return record, err
	}
	oldInc, err := c.VoterIncarnation(context.Background())
	if err != nil {
		return record, err
	}
	start = time.Now()
	err = privateSeedValidate(c, true, true, "")
	if err != nil {
		return record, err
	}
	record.shape, err = privateSeedShape(c)
	if err != nil {
		return record, err
	}
	record.initialValidationNS = time.Since(start).Nanoseconds()
	start = time.Now()
	err = c.execLocal(context.Background(), `DELETE FROM local_voter_incarnation WHERE id=1`)
	if err != nil {
		return record, err
	}
	if err = c.execLocal(context.Background(), `VACUUM`); err != nil {
		return record, err
	}
	if err = privateSeedValidate(c, false, true, record.shape); err != nil {
		return record, err
	}
	if err = privateSeedCheckOwner(c, owner); err != nil {
		return record, err
	}
	record.sanitizeNS = time.Since(start).Nanoseconds()
	path := filepath.Join(dir, "schema-only.db")
	start = time.Now()
	if err = privateSeedTransfer(c, path, false); err != nil {
		return record, err
	}
	record.exportNS = time.Since(start).Nanoseconds()
	raw, err := os.ReadFile(path)
	if err != nil {
		return record, err
	}
	if len(raw) == 0 || len(raw) > 16<<20 || bytes.Contains(raw, []byte(oldInc)) {
		return record, fmt.Errorf("bounded sanitized image retains donor identity")
	}
	record.image = string(raw)
	record.digest = privateSeedHash(raw)
	record.catalog = privateSeedCatalog()
	record.executable, err = privateSeedExecutable()
	if err != nil {
		return record, err
	}
	rows, err := privateSeedRows(c, `SELECT sqlite_version() AS v`)
	if err != nil {
		return record, err
	}
	record.sqlite = rows[0].String("v")
	return record, nil
}

type privateSeedTimings struct{ ConstructorNS, RestoreNS, PrecheckNS, InitNS, ValidationNS, CleanupNS int64 }
type privateSeedClient struct {
	c        *Client
	owner    privateSeedOwner
	dir      string
	timing   privateSeedTimings
	once     sync.Once
	closeErr error
}

func (p *privateSeedClient) close() error {
	p.once.Do(func() {
		start := time.Now()
		p.closeErr = errors.Join(p.c.Close(), os.RemoveAll(p.dir))
		p.timing.CleanupNS = time.Since(start).Nanoseconds()
		privateSeedActive.Add(-1)
	})
	return p.closeErr
}
func privateSeedOpenImage(image string) (p *privateSeedClient, err error) {
	dir, err := os.MkdirTemp("", "private-schema-clone-")
	if err != nil {
		return nil, err
	}
	start := time.Now()
	c, err := NewTestClient()
	ctor := time.Since(start).Nanoseconds()
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	p = &privateSeedClient{c: c, dir: dir, timing: privateSeedTimings{ConstructorNS: ctor}}
	privateSeedActive.Add(1)
	defer func() {
		if err != nil {
			err = errors.Join(err, p.close())
			p = nil
		}
	}()
	p.owner, err = privateSeedCapture(c)
	if err != nil {
		return p, err
	}
	path := filepath.Join(dir, "schema-only.db")
	if err = os.WriteFile(path, []byte(image), 0400); err != nil {
		return p, err
	}
	start = time.Now()
	err = privateSeedTransfer(c, path, true)
	p.timing.RestoreNS = time.Since(start).Nanoseconds()
	return p, err
}
func privateSeedCloneRecord(record privateSeedRecord) (p *privateSeedClient, err error) {
	exe, err := privateSeedExecutable()
	if err != nil {
		return nil, err
	}
	if len(record.image) == 0 || len(record.image) > 16<<20 || privateSeedHash([]byte(record.image)) != record.digest || record.executable != exe || record.catalog != privateSeedCatalog() || record.shape == "" {
		return nil, fmt.Errorf("seed image/executable/catalog binding differs")
	}
	p, err = privateSeedOpenImage(record.image)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, p.close())
			p = nil
		}
	}()
	start := time.Now()
	rows, e := privateSeedRows(p.c, `SELECT sqlite_version() AS v`)
	if e != nil {
		return p, e
	}
	if len(rows) != 1 || rows[0].String("v") != record.sqlite {
		return p, fmt.Errorf("SQLite binding differs")
	}
	if err = privateSeedCheckOwner(p.c, p.owner); err != nil {
		return p, err
	}
	if err = privateSeedValidate(p.c, false, false, record.shape); err != nil {
		return p, err
	}
	p.timing.PrecheckNS = time.Since(start).Nanoseconds()
	start = time.Now()
	err = InitSchema(context.Background(), p.c)
	p.timing.InitNS = time.Since(start).Nanoseconds()
	if err != nil {
		return p, err
	}
	start = time.Now()
	if err = privateSeedValidate(p.c, true, true, record.shape); err != nil {
		return p, err
	}
	if err = privateSeedCheckOwner(p.c, p.owner); err != nil {
		return p, err
	}
	inc, e := p.c.VoterIncarnation(context.Background())
	decoded, de := hex.DecodeString(inc)
	gen, valid := p.c.tableGens.get("local_voter_incarnation")
	if e != nil || de != nil || len(decoded) != 16 || !valid || gen == 0 {
		return p, fmt.Errorf("actual fresh hooked incarnation absent: %v/%v", e, de)
	}
	p.timing.ValidationNS = time.Since(start).Nanoseconds()
	return p, nil
}
func privateSeedNew() (p *privateSeedClient, record privateSeedRecord, err error) {
	record, err = privateSeedProcess.get(privateSeedBuild)
	if err != nil {
		return nil, record, err
	}
	p, err = privateSeedCloneRecord(record)
	return p, record, err
}
func privateSeedCheck(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func privateSeedMust(t *testing.T, ok bool, f string, args ...any) {
	t.Helper()
	if !ok {
		t.Fatalf(f, args...)
	}
}
func privateSeedLog(t *testing.T, kind string, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	privateSeedCheck(t, err)
	t.Logf("PRIVATE_SCHEMA_SEED_%s %s", kind, raw)
}

func privateSeedKeeperAndSever(t *testing.T, p *privateSeedClient) {
	t.Helper()
	c := p.c
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	inc, err := c.VoterIncarnation(ctx)
	privateSeedCheck(t, err)
	c.db.SetMaxIdleConns(0)
	defer sizeConnPool(c.db)
	privateSeedMust(t, c.db.Stats().OpenConnections == 0 && c.db.Stats().InUse == 0, "primary connections still own memory")
	var kept string
	privateSeedCheck(t, c.memKeeper.QueryRowContext(ctx, `SELECT incarnation FROM local_voter_incarnation WHERE id=1`).Scan(&kept))
	privateSeedMust(t, kept == inc, "keeper lost identity")
	got, err := c.VoterIncarnation(ctx)
	privateSeedCheck(t, err)
	privateSeedMust(t, got == inc, "hook reconnect lost memory")
	before, err := privateSeedRows(c, `SELECT * FROM schema_state`)
	privateSeedCheck(t, err)
	fence := c.FenceWritesForTests()
	select {
	case <-fence.Held():
	case <-ctx.Done():
		fence.Kill()
		fence.Lift()
		t.Fatal(ctx.Err())
	}
	fence.Kill()
	_, err = c.db.ExecContext(ctx, `UPDATE schema_state SET updated_at=updated_at WHERE id=1`)
	refused, landed := fence.Lift()
	after, e := privateSeedRows(c, `SELECT * FROM schema_state`)
	privateSeedCheck(t, e)
	privateSeedMust(t, err != nil && refused > 0 && landed == 0 && reflect.DeepEqual(before, after), "writeSever failed actual refusal/rollback: %d/%d %v", refused, landed, err)
	gen, valid := c.tableGens.get("schema_state")
	result, err := c.db.ExecContext(ctx, `UPDATE schema_state SET updated_at=updated_at WHERE id=1`)
	privateSeedCheck(t, err)
	affected, err := result.RowsAffected()
	privateSeedCheck(t, err)
	next, nv := c.tableGens.get("schema_state")
	after, err = privateSeedRows(c, `SELECT * FROM schema_state`)
	privateSeedCheck(t, err)
	privateSeedMust(t, affected == 1 && valid && nv && next > gen && reflect.DeepEqual(before, after), "Lift/hooked write failed")
	privateSeedCheck(t, privateSeedCheckOwner(c, p.owner))
}

func TestPrivateMemorySchemaSeedControls(t *testing.T) {
	ctx := context.Background()
	// These are actual unsafe restores before the guarded consumer is called.
	for _, mode := range []string{"retained-incarnation", "business-state"} {
		t.Run(mode, func(t *testing.T) {
			donor, err := NewTestClient()
			privateSeedCheck(t, err)
			t.Cleanup(func() { privateSeedCheck(t, donor.Close()) })
			privateSeedCheck(t, InitSchema(ctx, donor))
			inc, err := donor.VoterIncarnation(ctx)
			privateSeedCheck(t, err)
			if mode == "business-state" {
				privateSeedCheck(t, donor.execLocal(ctx, `DELETE FROM local_voter_incarnation`))
				privateSeedCheck(t, UpsertNetwork(ctx, donor, NetworkRecord{Name: "unsafe-network", Type: "bridge", Config: `{}`}))
			}
			path := filepath.Join(t.TempDir(), "unsafe.db")
			privateSeedCheck(t, privateSeedTransfer(donor, path, false))
			raw, err := os.ReadFile(path)
			privateSeedCheck(t, err)
			unsafe, err := privateSeedOpenImage(string(raw))
			privateSeedCheck(t, err)
			defer func() { privateSeedCheck(t, unsafe.close()) }()
			privateSeedCheck(t, InitSchema(ctx, unsafe.c))
			if mode == "retained-incarnation" {
				got, e := unsafe.c.VoterIncarnation(ctx)
				privateSeedCheck(t, e)
				privateSeedMust(t, got == inc, "unvalidated actual restore no longer retains donor incarnation")
			} else {
				got, e := GetNetwork(ctx, unsafe.c, "unsafe-network")
				privateSeedCheck(t, e)
				privateSeedMust(t, got != nil && got.Type == "bridge", "unvalidated actual restore no longer carries business row")
			}
			record, err := privateSeedProcess.get(privateSeedBuild)
			privateSeedCheck(t, err)
			record.image = string(raw)
			record.digest = privateSeedHash(raw)
			bad, err := privateSeedCloneRecord(record)
			if bad != nil {
				defer bad.close()
			}
			privateSeedMust(t, err != nil && bad == nil, "unsafe image was returned to a fixture: %v", err)
			privateSeedLog(t, "UNSAFE_WITNESS", map[string]any{"kind": mode, "actual_unsafe_import_observed": true, "guarded_consumer_refused": true})
		})
	}
	var image privateSeedRecord
	t.Run("first-owner-lifetime", func(t *testing.T) {
		p, r, err := privateSeedNew()
		privateSeedCheck(t, err)
		image = r
		t.Cleanup(func() { privateSeedCheck(t, p.close()) })
	})
	t.Run("after-first-owner-cleanup", func(t *testing.T) {
		privateSeedMust(t, privateSeedActive.Load() == 0, "first clone still live")
		p, err := privateSeedCloneRecord(image)
		privateSeedCheck(t, err)
		defer func() { privateSeedCheck(t, p.close()) }()
		privateSeedKeeperAndSever(t, p)
	})
	t.Run("concurrent-publication-and-failure", func(t *testing.T) {
		var pub privateSeedPublisher
		var calls atomic.Int64
		start := make(chan struct{})
		type result struct {
			r privateSeedRecord
			e error
		}
		out := make(chan result, 2)
		for i := 0; i < 2; i++ {
			go func() {
				<-start
				r, e := pub.get(func() (privateSeedRecord, error) { calls.Add(1); return image, nil })
				out <- result{r, e}
			}()
		}
		close(start)
		for i := 0; i < 2; i++ {
			r := <-out
			privateSeedCheck(t, r.e)
			privateSeedMust(t, r.r.image == image.image, "partial image publication")
		}
		privateSeedMust(t, calls.Load() == 1, "builder repeated")
		var fail privateSeedPublisher
		sentinel := errors.New("owned builder failure")
		for i := 0; i < 2; i++ {
			r, e := fail.get(func() (privateSeedRecord, error) { return image, sentinel })
			privateSeedMust(t, e == sentinel && r.image == "", "failed publisher retained usable bytes")
		}
	})
	t.Run("concurrent-clones-isolation-and-close", func(t *testing.T) {
		start := make(chan struct{})
		type result struct {
			p *privateSeedClient
			e error
		}
		out := make(chan result, 2)
		for i := 0; i < 2; i++ {
			go func() { <-start; p, e := privateSeedCloneRecord(image); out <- result{p, e} }()
		}
		close(start)
		var pair [2]*privateSeedClient
		var cloneErrors []error
		for i := range pair {
			r := <-out
			pair[i] = r.p
			cloneErrors = append(cloneErrors, r.e)
			if r.p != nil {
				t.Cleanup(func() { privateSeedCheck(t, r.p.close()) })
			}
		}
		privateSeedCheck(t, errors.Join(cloneErrors...))
		a, b := pair[0], pair[1]
		ai, e := a.c.VoterIncarnation(ctx)
		privateSeedCheck(t, e)
		bi, e := b.c.VoterIncarnation(ctx)
		privateSeedCheck(t, e)
		privateSeedMust(t, ai != bi && a.c.dsn != b.c.dsn && a.c.memKeeper != b.c.memKeeper && a.c.writeSever != b.c.writeSever && a.c.tableGens != b.c.tableGens && a.c.clock != b.c.clock, "concurrent clones share owners/identity")
		privateSeedCheck(t, UpsertNetwork(ctx, a.c, NetworkRecord{Name: "only-a", Type: "bridge", Config: `{}`}))
		row, e := GetNetwork(ctx, b.c, "only-a")
		privateSeedCheck(t, e)
		privateSeedMust(t, row == nil, "business write crossed clone")
		privateSeedCheck(t, a.close())
		_, e = os.Stat(a.dir)
		privateSeedMust(t, errors.Is(e, os.ErrNotExist), "closed clone retained file")
		privateSeedKeeperAndSever(t, b)
		privateSeedCheck(t, UpsertNetwork(ctx, b.c, NetworkRecord{Name: "only-b", Type: "bridge", Config: `{}`}))
		row, e = GetNetwork(ctx, b.c, "only-b")
		privateSeedCheck(t, e)
		privateSeedMust(t, row != nil, "surviving clone cannot write")
		c, e := privateSeedCloneRecord(image)
		privateSeedCheck(t, e)
		defer func() { privateSeedCheck(t, c.close()) }()
		privateSeedCheck(t, privateSeedValidate(c.c, true, true, image.shape))
		privateSeedMust(t, image.image == privateSeedProcess.record.image && image.digest == privateSeedHash([]byte(image.image)), "shared immutable image mutated")
	})
	for _, mode := range []string{"unknown-table", "business-row", "authority-row", "identity-row", "checksum", "receipt-count", "physical-schema", "required-index", "image-binding", "catalog-binding", "executable-binding"} {
		t.Run(mode, func(t *testing.T) {
			r := image
			if mode == "image-binding" {
				r.digest = "bad"
			} else if mode == "catalog-binding" {
				r.catalog = "bad"
			} else if mode == "executable-binding" {
				r.executable = "bad"
			} else {
				p, e := privateSeedOpenImage(image.image)
				privateSeedCheck(t, e)
				defer func() { privateSeedCheck(t, p.close()) }()
				switch mode {
				case "unknown-table":
					e = p.c.execLocal(ctx, `CREATE TABLE unexpected_seed_table(value TEXT)`)
				case "business-row":
					e = UpsertNetwork(ctx, p.c, NetworkRecord{Name: "contaminated", Type: "bridge", Config: `{}`})
				case "authority-row":
					e = p.c.execLocal(ctx, `INSERT INTO local_automation_lifetimes(kind,name,witness,origin,valid,retired) VALUES('principal','contaminated','witness','birth',1,0)`)
				case "identity-row":
					e = p.c.mintVoterIncarnation(ctx)
				case "checksum":
					e = p.c.execLocal(ctx, `UPDATE applied_migrations SET checksum='bad' WHERE id=(SELECT id FROM applied_migrations LIMIT 1)`)
				case "receipt-count":
					e = p.c.execLocal(ctx, `DELETE FROM applied_migrations WHERE id=(SELECT id FROM applied_migrations LIMIT 1)`)
				case "physical-schema":
					e = p.c.execLocal(ctx, `ALTER TABLE schema_state ADD COLUMN unexpected_seed_column TEXT`)
				case "required-index":
					e = p.c.execLocal(ctx, `DROP INDEX automation_admission_resource_desired`)
					if e == nil {
						e = p.c.execLocal(ctx, strings.Replace(automationUpdateIndexSQL, "sequence DESC", "sequence ASC", 1))
					}
				}
				privateSeedCheck(t, e)
				path := filepath.Join(t.TempDir(), "mutant.db")
				privateSeedCheck(t, privateSeedTransfer(p.c, path, false))
				raw, e := os.ReadFile(path)
				privateSeedCheck(t, e)
				r.image = string(raw)
				r.digest = privateSeedHash(raw)
			}
			before := privateSeedActive.Load()
			bad, e := privateSeedCloneRecord(r)
			if bad != nil {
				defer bad.close()
			}
			privateSeedMust(t, e != nil && bad == nil && privateSeedActive.Load() == before, "mutant %s returned usable client/leaked owner: %v", mode, e)
		})
	}
	t.Run("actual-index-refusal-and-correction", func(t *testing.T) {
		p, e := privateSeedOpenImage(image.image)
		privateSeedCheck(t, e)
		defer func() { privateSeedCheck(t, p.close()) }()
		wrong := strings.Replace(automationUpdateIndexSQL, "sequence DESC", "sequence ASC", 1)
		privateSeedCheck(t, p.c.execLocal(ctx, `DROP INDEX automation_admission_resource_desired`))
		privateSeedCheck(t, p.c.execLocal(ctx, wrong))
		ledgerBefore, e := privateSeedRows(p.c, `SELECT * FROM applied_migrations ORDER BY id`)
		privateSeedCheck(t, e)
		privateSeedMust(t, len(ledgerBefore) == 219, "negative index image lacks its complete valid ledger")
		e = InitSchema(ctx, p.c)
		privateSeedMust(t, e != nil && strings.Contains(e.Error(), "required schema index") && strings.Contains(e.Error(), "order differs"), "actual InitSchema accepted corrupted physical index: %v", e)
		ledgerAfter, e := privateSeedRows(p.c, `SELECT * FROM applied_migrations ORDER BY id`)
		privateSeedCheck(t, e)
		privateSeedMust(t, reflect.DeepEqual(ledgerBefore, ledgerAfter), "failed index initialization changed the complete migration ledger")
		inc, e := p.c.VoterIncarnation(ctx)
		privateSeedCheck(t, e)
		rows, e := privateSeedRows(p.c, `SELECT sql FROM sqlite_master WHERE name='automation_admission_resource_desired'`)
		privateSeedCheck(t, e)
		privateSeedMust(t, len(rows) == 1 && rows[0].String("sql") == wrong, "refusal repaired wrong index")
		privateSeedCheck(t, p.c.execLocal(ctx, `DROP INDEX automation_admission_resource_desired`))
		privateSeedCheck(t, p.c.execLocal(ctx, automationUpdateIndexSQL))
		privateSeedCheck(t, InitSchema(ctx, p.c))
		ledgerAfter, e = privateSeedRows(p.c, `SELECT * FROM applied_migrations ORDER BY id`)
		privateSeedCheck(t, e)
		privateSeedMust(t, reflect.DeepEqual(ledgerBefore, ledgerAfter), "index-only correction changed the complete migration ledger")
		got, e := p.c.VoterIncarnation(ctx)
		privateSeedCheck(t, e)
		privateSeedMust(t, got == inc, "correction replaced actual incarnation")
		privateSeedCheck(t, privateSeedValidate(p.c, true, true, image.shape))
	})
	privateSeedMust(t, privateSeedActive.Load() == 0, "control leaked clone owners")
	privateSeedLog(t, "CONTROLS", map[string]any{"all_required_controls": !t.Failed(), "table_inventory": 168, "actual_unsafe_witnesses": 2, "image_sha256": image.digest, "donor_total_ns": image.totalNS})
}
