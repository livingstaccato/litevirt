package corrosion

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"modernc.org/sqlite"
)

func updateSnapshot(t *testing.T, c *Client) map[string][]Row {
	t.Helper()
	out := executionStorageSnapshot(t, c)
	for _, d := range automationSemanticTables {
		if _, ok := out[d.table]; ok {
			continue
		}
		rows, e := c.Query(context.Background(), "SELECT * FROM "+d.table+" ORDER BY rowid")
		if e != nil {
			t.Fatal(e)
		}
		out[d.table] = rows
	}
	return out
}

// Execute the actual write first, then return an injected failure; FULL must
// roll back even writes that reached SQLite and later receipt/head persistence.
type updateFaultDriver struct {
	driver.Driver
	prefix string
	fired  *bool
}
type updateFaultConn struct {
	driver.Conn
	prefix string
	fired  *bool
}

var updateInjected = errors.New("conditional update completed-write fault")

func (d updateFaultDriver) Open(s string) (driver.Conn, error) {
	c, e := d.Driver.Open(s)
	return updateFaultConn{c, d.prefix, d.fired}, e
}
func (c updateFaultConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
}
func (c updateFaultConn) QueryContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, a)
}
func (c updateFaultConn) ExecContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	r, e := c.Conn.(driver.ExecerContext).ExecContext(ctx, q, a)
	if e == nil && strings.HasPrefix(strings.TrimSpace(q), c.prefix) {
		*c.fired = true
		return nil, updateInjected
	}
	return r, e
}
func updateInject(t *testing.T, c *Client, prefix string) *bool {
	t.Helper()
	fired := new(bool)
	name := fmt.Sprintf("update-fault-%d", targetInsertDriverID.Add(1))
	sql.Register(name, updateFaultDriver{&sqlite.Driver{}, prefix, fired})
	db, e := sql.Open(name, c.dsn)
	if e != nil {
		t.Fatal(e)
	}
	db.SetMaxOpenConns(1)
	if e = db.Ping(); e != nil {
		t.Fatal(e)
	}
	c.mu.Lock()
	old := c.db
	c.db = db
	c.mu.Unlock()
	if e = old.Close(); e != nil {
		t.Fatal(e)
	}
	return fired
}
func TestAutomationUpdateFULLAtomicFailures(t *testing.T) {
	for _, prefix := range []string{"UPDATE local_automation_resources SET", "UPDATE local_automation_bindings SET", "INSERT INTO local_automation_admissions(", "INSERT INTO local_automation_requests ", "INSERT INTO local_automation_history ", "INSERT INTO local_automation_semantic_heads("} {
		t.Run(prefix, func(t *testing.T) {
			f := updateFixture(t)
			config := updateConfig(t, f.config)
			config.Labels = map[string]string{"role": "db"}
			d := updateDecision(t, f, `{"labels":{"values":{"role":"db"}}}`, config, "rev:atomic", updateOrigin(f))
			record := f.sign(d)
			before := updateSnapshot(t, f.c)
			fired := updateInject(t, f.c, prefix)
			_, e := applySharedAutomation(t, f.c, record, contract.Reduce, automationFreshAnchor)
			if !*fired || !errors.Is(e, updateInjected) {
				t.Fatal("actual update boundary not reached", prefix, *fired, e)
			}
			if !reflect.DeepEqual(before, updateSnapshot(t, f.c)) {
				t.Fatal("FULL update failure leaked history/effect/receipt/head", prefix)
			}
		})
	}
}
func TestAutomationUpdateFULLTypedStorageBounds(t *testing.T) {
	for _, mode := range []string{"missing-index", "broaden-index", "extra-index", "blob-config", "negative-sequence", "text-sequence", "oversized-config", "noncanonical-config", "unknown-method", "extra-admission", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := updateFixture(t)
			ctx := context.Background()
			if e := f.c.ExecuteLocal(ctx, func(tx *LocalTx) error { return automationVerifyUpdateIndexesTx(ctx, tx) }); e != nil {
				t.Fatal("positive exact index", e)
			}
			config := updateConfig(t, f.config)
			config.Labels = map[string]string{"role": "db"}
			first := f.sign(updateDecision(t, f, `{"labels":{"values":{"role":"db"}}}`, config, "rev:typed", updateOrigin(f)))
			receipt := f.apply(t, first)
			d := updateDecision(t, f, `{}`, config, "rev:typed", contract.HistoryReference{Sequence: receipt.Sequence, Digest: first.Value.MustDigest()})
			record := f.sign(d)
			if mode == "cancel" {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				if e := f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
					_, e := automationUpdateInverseClosureTx(cancelled, tx, "", contract.Prefix{ClusterUID: "established-cluster", Sequence: d.Sequence - 1, Digest: d.ParentDigest}, contract.ResourceReference{ClusterUID: "established-cluster", ProjectUID: "project-uid", Kind: "vm", UID: "resource-uid"}, nil)
					return e
				}); !errors.Is(e, context.Canceled) {
					t.Fatal("closure ignored cancellation", e)
				}
				return
			}
			statements := map[string]string{
				"missing-index":       `DROP INDEX automation_admission_resource_desired`,
				"broaden-index":       `DROP INDEX automation_admission_resource_desired`,
				"extra-index":         `CREATE INDEX update_unapproved_extra ON local_automation_admissions(sequence)`,
				"blob-config":         `UPDATE local_automation_admissions SET configuration_json=CAST(configuration_json AS BLOB) WHERE method='admit_update'`,
				"negative-sequence":   `UPDATE local_automation_admissions SET sequence=-1 WHERE method='admit_update'`,
				"text-sequence":       `UPDATE local_automation_admissions SET sequence='not-a-number' WHERE method='admit_update'`,
				"oversized-config":    `UPDATE local_automation_admissions SET configuration_json=printf('%.*c',1048577,'x') WHERE method='admit_update'`,
				"noncanonical-config": `UPDATE local_automation_admissions SET configuration_json=' '||configuration_json WHERE method='admit_update'`,
				"unknown-method":      `UPDATE local_automation_admissions SET method='admit_replacement' WHERE method='admit_update'`,
				"extra-admission":     `INSERT INTO local_automation_admissions SELECT stage,'extra-update',cluster_uid,project_uid,owner_id,management_key,resource_uid,request_id,principal_uid,method,payload_id,binding_generation,admitted_generation,sequence,configuration_json FROM local_automation_admissions WHERE method='admit_update'`,
			}
			if e := f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				if mode == "negative-sequence" {
					if _, e := tx.tx.ExecContext(ctx, `PRAGMA ignore_check_constraints=ON`); e != nil {
						return e
					}
					defer tx.tx.ExecContext(ctx, `PRAGMA ignore_check_constraints=OFF`)
				}
				_, e := tx.tx.ExecContext(ctx, statements[mode])
				if e != nil {
					return e
				}
				if mode == "broaden-index" {
					_, e = tx.tx.ExecContext(ctx, `CREATE INDEX automation_admission_resource_desired ON local_automation_admissions(stage,cluster_uid,resource_uid,sequence DESC,operation_id)`)
				}
				return e
			}); e != nil {
				t.Fatal(e)
			}
			before := updateSnapshot(t, f.c)
			if _, e := applySharedAutomation(t, f.c, record, contract.Reduce, automationFreshAnchor); e == nil {
				t.Fatal("update accepted corrupt typed storage/index", mode)
			}
			if !reflect.DeepEqual(before, updateSnapshot(t, f.c)) {
				t.Fatal("typed refusal changed corrupt stage", mode)
			}
		})
	}
}

func TestAutomationUpdateFULLSchemaIndexCoexistence(t *testing.T) {
	f := updateFixture(t)
	if e := f.c.ExecuteLocal(context.Background(), func(tx *LocalTx) error { return automationVerifySemanticSchemaTx(context.Background(), tx) }); e != nil {
		t.Fatal("update partial index must coexist with existing exact semantic/key index audit", e)
	}
}

func TestAutomationUpdateFULLKeyInventoryAfterUpdate(t *testing.T) {
	f, _, _ := updateFirst(t)
	ctx := context.Background()
	head, e := f.c.AutomationHead(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		cfg, e := localAutomationKeySource{tx}.keyMembership(ctx, 1)
		if e != nil {
			return e
		}
		p := contract.Projection{Head: head}
		if e = automationResolveKeyProjectionTx(ctx, tx, "", &p, &automationKeyLookup{generation: 1, configDigest: cfg.MembersHash}, nil); e != nil {
			return e
		}
		if p.KeyTransition == nil || len(p.KeyTransition.Admissions) != 0 {
			return fmt.Errorf("update counted as a new payload birth")
		}
		return nil
	}); e != nil {
		t.Fatal("existing create-only key inventory rejected a supported update", e)
	}
}

// Interleave a real negative predecessor change after storage's re-reads and
// immediately before the conditional write. Removing its SQL predicates must
// make this causal assertion fail even though the earlier reads were correct.
type updateCASDriver struct {
	driver.Driver
	fired   *bool
	binding bool
}
type updateCASConn struct {
	driver.Conn
	fired   *bool
	binding bool
}

func (d updateCASDriver) Open(s string) (driver.Conn, error) {
	c, e := d.Driver.Open(s)
	return updateCASConn{c, d.fired, d.binding}, e
}
func (c updateCASConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
}
func (c updateCASConn) QueryContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, a)
}
func (c updateCASConn) ExecContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	table := "local_automation_resources"
	if c.binding {
		table = "local_automation_bindings"
	}
	if !*c.fired && strings.HasPrefix(strings.TrimSpace(q), "UPDATE "+table+" SET") {
		*c.fired = true
		column := "uid"
		if c.binding {
			column = "resource_uid"
		}
		if _, e := c.Conn.(driver.ExecerContext).ExecContext(ctx, "UPDATE "+table+" SET revision='interleaved-predecessor' WHERE stage='' AND "+column+"='resource-uid'", nil); e != nil {
			return nil, e
		}
	}
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, a)
}
func TestAutomationUpdateFULLStorageCASPredicates(t *testing.T) {
	for _, binding := range []bool{false, true} {
		t.Run(fmt.Sprint(binding), func(t *testing.T) {
			f, first, config := updateFirst(t)
			d := updateNext(t, f, first, config)
			record := f.sign(d)
			before := updateSnapshot(t, f.c)
			fired := new(bool)
			name := fmt.Sprintf("update-cas-%d", targetInsertDriverID.Add(1))
			sql.Register(name, updateCASDriver{&sqlite.Driver{}, fired, binding})
			db, e := sql.Open(name, f.c.dsn)
			if e != nil {
				t.Fatal(e)
			}
			db.SetMaxOpenConns(1)
			if e = db.Ping(); e != nil {
				t.Fatal(e)
			}
			f.c.mu.Lock()
			old := f.c.db
			f.c.db = db
			f.c.mu.Unlock()
			old.Close()
			if _, e = applySharedAutomation(t, f.c, record, contract.Reduce, automationFreshAnchor); !*fired || e == nil || !strings.Contains(e.Error(), "CAS failed") {
				t.Fatal("conditional predecessor SQL did not refuse interleaved drift", *fired, e)
			}
			if !reflect.DeepEqual(before, updateSnapshot(t, f.c)) {
				t.Fatal("CAS refusal did not roll back interleaved write and receipt/head")
			}
		})
	}
}

type updateReadDriver struct {
	driver.Driver
	bodies *int
}
type updateReadConn struct {
	driver.Conn
	bodies *int
}

func (d updateReadDriver) Open(s string) (driver.Conn, error) {
	c, e := d.Driver.Open(s)
	return updateReadConn{c, d.bodies}, e
}
func (c updateReadConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
}
func (c updateReadConn) ExecContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, a)
}
func (c updateReadConn) QueryContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(q, "configuration_json FROM local_automation_admissions") {
		*c.bodies++
	}
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, a)
}
func TestAutomationUpdateFULLLongOwnershipSuffixAndCancellation(t *testing.T) {
	f, first, _ := updateFirst(t)
	ctx := context.Background()
	for i := 0; i < 24; i++ {
		updateTransferTo(t, f, fmt.Sprintf("suffix-owner-%02d", i))
	}
	head, e := f.c.AutomationHead(ctx)
	if e != nil {
		t.Fatal(e)
	}
	ref := contract.ResourceReference{ClusterUID: head.ClusterUID, ProjectUID: "project-uid", Kind: "vm", UID: "resource-uid"}
	bodies := new(int)
	name := fmt.Sprintf("update-read-%d", targetInsertDriverID.Add(1))
	sql.Register(name, updateReadDriver{&sqlite.Driver{}, bodies})
	db, e := sql.Open(name, f.c.dsn)
	if e != nil {
		t.Fatal(e)
	}
	db.SetMaxOpenConns(1)
	if e = db.Ping(); e != nil {
		t.Fatal(e)
	}
	old := f.c.db
	f.c.db = db
	old.Close()
	if e = f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		a, e := automationLatestDesiredAdmissionTx(ctx, tx, "", head, ref)
		if e != nil {
			return e
		}
		d, _ := automationDecision(first.Value)
		if a.Sequence != d.Sequence || a.OperationID != "update-op-16" {
			return fmt.Errorf("ownership suffix entered desired lookup: %+v", a)
		}
		rows, e := tx.Query(ctx, `SELECT count(*) AS n FROM local_automation_admissions INDEXED BY automation_admission_resource_desired WHERE stage='' AND cluster_uid=? AND resource_uid=? AND method IN ('admit_create','admit_update')`, head.ClusterUID, ref.UID)
		if e != nil {
			return e
		}
		if len(rows) != 1 || rows[0].Int64("n") != 2 {
			return fmt.Errorf("ownership rows entered partial desired index")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if *bodies != 1 {
		t.Fatal("desired lookup loaded unbounded bodies", *bodies)
	}
	frames := 0
	observed := context.WithValue(ctx, automationKeyBodyObserverKey{}, func(uint64, []byte) { frames++ })
	if e = f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		_, e := automationUpdateInverseClosureTx(observed, tx, "", head, ref, nil)
		return e
	}); e != nil {
		t.Fatal("positive complete long-suffix closure", e)
	}
	rows, e := f.c.Query(ctx, `SELECT count(*) AS n FROM local_automation_admissions WHERE stage=''`)
	if e != nil || len(rows) != 1 {
		t.Fatal(e)
	}
	if frames != int(head.Sequence)+int(rows[0].Int64("n")) {
		t.Fatal("closure frame work exceeded exact linear prefix-plus-admissions bound", frames, head.Sequence, rows)
	}
	// Prefix traversal and reverse closure remain linear, independently of the
	// bounded desired lookup. Both cancellation positions must abort the owner.
	for _, phase := range []string{"window", "reverse"} {
		cancelled, cancel := context.WithCancel(ctx)
		fired := false
		highest := uint64(0)
		observed := context.WithValue(cancelled, automationKeyBodyObserverKey{}, func(sequence uint64, _ []byte) {
			if phase == "window" && sequence == 64 || phase == "reverse" && highest == head.Sequence && sequence < head.Sequence {
				fired = true
				cancel()
			}
			if sequence > highest {
				highest = sequence
			}
		})
		before := updateSnapshot(t, f.c)
		e = f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
			_, e := automationUpdateInverseClosureTx(observed, tx, "", head, ref, nil)
			return e
		})
		cancel()
		if !fired || !errors.Is(e, context.Canceled) {
			t.Fatal("closure cancellation not observed", phase, fired, e)
		}
		if !reflect.DeepEqual(before, updateSnapshot(t, f.c)) {
			t.Fatal("cancelled closure persisted partial state", phase)
		}
	}
}

// Observe actual driver-returned cells, before LocalTx.Query eagerly stores
// them. Refusal after a huge key was returned is insufficient for this oracle.
type updateCellAudit struct {
	mu                                                                  sync.Mutex
	enabled                                                             bool
	maxKeyBytes, blobKeys, badConfigReads, allConfigReads, reversePages int
	badOperation                                                        string
	onPage                                                              func(int)
}

func (o *updateCellAudit) reset(bad string, onPage func(int)) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.enabled = true
	o.maxKeyBytes = 0
	o.blobKeys = 0
	o.badConfigReads = 0
	o.allConfigReads = 0
	o.reversePages = 0
	o.badOperation = bad
	o.onPage = onPage
}
func (o *updateCellAudit) stop() (int, int, int, int, int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.enabled = false
	return o.maxKeyBytes, o.blobKeys, o.badConfigReads, o.allConfigReads, o.reversePages
}

type updateCellDriver struct {
	driver.Driver
	audit *updateCellAudit
}
type updateCellConn struct {
	driver.Conn
	audit *updateCellAudit
}
type updateCellRows struct {
	driver.Rows
	audit           *updateCellAudit
	operationColumn int
}

func (d updateCellDriver) Open(name string) (driver.Conn, error) {
	c, e := d.Driver.Open(name)
	return updateCellConn{c, d.audit}, e
}
func (c updateCellConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
}
func (c updateCellConn) ExecContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, a)
}
func (c updateCellConn) QueryContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	o := c.audit
	o.mu.Lock()
	var callback func(int)
	page := 0
	if o.enabled {
		if strings.Contains(q, "FROM local_automation_admissions WHERE stage=? AND rowid") {
			o.reversePages++
			page = o.reversePages
			callback = o.onPage
		}
		if strings.Contains(q, "configuration_json FROM local_automation_admissions") {
			o.allConfigReads++
			for _, v := range a {
				switch value := v.Value.(type) {
				case string:
					if value == o.badOperation {
						o.badConfigReads++
					}
				case []byte:
					if bytes.Equal(value, []byte(o.badOperation)) {
						o.badConfigReads++
					}
				}
			}
		}
	}
	o.mu.Unlock()
	if callback != nil {
		callback(page)
	}
	rows, e := c.Conn.(driver.QueryerContext).QueryContext(ctx, q, a)
	if e != nil {
		return rows, e
	}
	column := -1
	if strings.Contains(q, "FROM local_automation_admissions") {
		for i, name := range rows.Columns() {
			if name == "operation_id" {
				column = i
			}
		}
	}
	return updateCellRows{rows, o, column}, nil
}
func (r updateCellRows) Next(values []driver.Value) error {
	e := r.Rows.Next(values)
	if e != nil {
		return e
	}
	o := r.audit
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.enabled || r.operationColumn < 0 {
		return nil
	}
	switch value := values[r.operationColumn].(type) {
	case string:
		if len(value) > o.maxKeyBytes {
			o.maxKeyBytes = len(value)
		}
	case []byte:
		o.blobKeys++
		if len(value) > o.maxKeyBytes {
			o.maxKeyBytes = len(value)
		}
	}
	return nil
}
func updateAttachCellAudit(t *testing.T, c *Client) *updateCellAudit {
	t.Helper()
	audit := &updateCellAudit{}
	name := fmt.Sprintf("update-cell-audit-%d", targetInsertDriverID.Add(1))
	sql.Register(name, updateCellDriver{&sqlite.Driver{}, audit})
	db, e := sql.Open(name, c.dsn)
	if e != nil {
		t.Fatal(e)
	}
	db.SetMaxOpenConns(1)
	if e = db.Ping(); e != nil {
		t.Fatal(e)
	}
	c.mu.Lock()
	old := c.db
	c.db = db
	c.mu.Unlock()
	if e = old.Close(); e != nil {
		t.Fatal(e)
	}
	return audit
}
func updatePoisonAdmission(t *testing.T, c *Client, key any, resource string) {
	t.Helper()
	if e := c.ExecuteLocal(context.Background(), func(tx *LocalTx) error {
		_, e := tx.tx.ExecContext(context.Background(), `INSERT INTO local_automation_admissions(stage,operation_id,cluster_uid,project_uid,owner_id,management_key,resource_uid,request_id,principal_uid,method,payload_id,binding_generation,admitted_generation,sequence,configuration_json) SELECT stage,?,cluster_uid,project_uid,owner_id,management_key,?,request_id,principal_uid,method,payload_id,binding_generation,admitted_generation,sequence,configuration_json FROM local_automation_admissions WHERE stage='' AND method='admit_update' ORDER BY sequence DESC LIMIT 1`, key, resource)
		return e
	}); e != nil {
		t.Fatal("negative-only extra admission setup", e)
	}
}
func updateRemovePoison(t *testing.T, c *Client, key any) {
	t.Helper()
	if e := c.ExecuteLocal(context.Background(), func(tx *LocalTx) error {
		_, e := tx.tx.ExecContext(context.Background(), `DELETE FROM local_automation_admissions WHERE stage='' AND operation_id=?`, key)
		return e
	}); e != nil {
		t.Fatal(e)
	}
}
func TestAutomationUpdateFULLAdmissionKeyReadBounds(t *testing.T) {
	f, first, config := updateFirst(t)
	updateTransfer(t, f)
	ctx := context.Background()
	firstDecision, _ := automationDecision(first.Value)
	previous := contract.HistoryReference{Sequence: firstDecision.Sequence, Digest: first.Value.MustDigest()}
	// Exactly64 genuine admissions place an extra unrelated key on reverse page2.
	updateAppendBoundaryCreates(t, f, 61)
	rows, e := f.c.Query(ctx, `SELECT count(*) AS n FROM local_automation_admissions WHERE stage=''`)
	if e != nil || len(rows) != 1 || rows[0].Int64("n") != 64 {
		t.Fatal("genuine boundary prerequisite", rows, e)
	}
	audit := updateAttachCellAudit(t, f.c)
	head, e := f.c.AutomationHead(ctx)
	if e != nil {
		t.Fatal(e)
	}
	ref := contract.ResourceReference{ClusterUID: head.ClusterUID, ProjectUID: "project-uid", Kind: "vm", UID: "resource-uid"}
	if e = f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		_, e := automationUpdateInverseClosureTx(ctx, tx, "", head, ref, nil)
		return e
	}); e != nil {
		t.Fatal("positive64-row complete closure", e)
	}
	// Prove the driver observer actually sees both selected key cells and the
	// one legitimate body read before asserting zero bad-row body reads.
	audit.reset(fmt.Sprintf("update-op-%d", firstDecision.Sequence), nil)
	if e = f.c.ExecuteLocal(ctx, func(tx *LocalTx) error { _, e := automationLatestDesiredAdmissionTx(ctx, tx, "", head, ref); return e }); e != nil {
		t.Fatal("positive bounded desired lookup", e)
	}
	positiveKey, positiveBlob, positiveBody, positiveAll, _ := audit.stop()
	if positiveKey == 0 || positiveKey > contract.MaxStringBytes || positiveBlob != 0 || positiveBody != 1 || positiveAll != 1 {
		t.Fatal("actual selected-key/body observer not exercised", positiveKey, positiveBlob, positiveBody, positiveAll)
	}
	nextConfig := updateConfig(t, config)
	nextConfig.Labels = map[string]string{"role": "bounded"}
	proposal := f.sign(updateDecision(t, f, `{"labels":{"values":{"role":"bounded"}}}`, nextConfig, "rev:bounded", previous))
	for _, mode := range []string{"reverse-text", "reverse-blob", "desired-text", "desired-blob"} {
		t.Run(mode, func(t *testing.T) {
			var key any = strings.Repeat("z", 2<<20)
			if strings.HasSuffix(mode, "blob") {
				key = bytes.Repeat([]byte{'z'}, 2<<20)
			}
			resource := "unrelated-resource"
			if strings.HasPrefix(mode, "desired") {
				resource = "resource-uid"
			}
			updatePoisonAdmission(t, f.c, key, resource)
			defer updateRemovePoison(t, f.c, key)
			before := updateSnapshot(t, f.c)
			bad := strings.Repeat("z", 2<<20)
			audit.reset(bad, nil)
			var failure error
			if strings.HasPrefix(mode, "reverse") {
				_, failure = applySharedAutomation(t, f.c, proposal, contract.Reduce, automationFreshAnchor)
			} else {
				failure = f.c.ExecuteLocal(ctx, func(tx *LocalTx) error { _, e := automationLatestDesiredAdmissionTx(ctx, tx, "", head, ref); return e })
			}
			maxKey, blobs, badBodies, allBodies, pages := audit.stop()
			if failure == nil {
				t.Fatal("malformed key was filtered into acceptance", mode)
			}
			if maxKey == 0 || maxKey > contract.MaxStringBytes || blobs != 0 {
				t.Fatalf("unbounded or invalid key cell materialized before rejection: mode=%s max=%d blobs=%d", mode, maxKey, blobs)
			}
			if badBodies != 0 || strings.HasPrefix(mode, "desired") && allBodies != 0 {
				t.Fatal("configuration loaded before candidate key/type/length rejection", mode, badBodies, allBodies)
			}
			if strings.HasPrefix(mode, "reverse") && pages != 2 {
				t.Fatal("reverse malformed key did not reach actual second bounded page", pages)
			}
			if !reflect.DeepEqual(before, updateSnapshot(t, f.c)) {
				t.Fatal("malformed key refusal changed full state", mode)
			}
		})
	}
	cancelled, cancel := context.WithCancel(ctx)
	hit := false
	before := updateSnapshot(t, f.c)
	audit.reset("", func(page int) {
		if page == 2 {
			hit = true
			cancel()
		}
	})
	e = f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		_, e := automationUpdateInverseClosureTx(cancelled, tx, "", head, ref, nil)
		return e
	})
	audit.stop()
	cancel()
	if !hit || !errors.Is(e, context.Canceled) {
		t.Fatal("second reverse-page cancellation was ignored", hit, e)
	}
	if !reflect.DeepEqual(before, updateSnapshot(t, f.c)) {
		t.Fatal("cancelled page traversal changed full state")
	}
}
func TestAutomationUpdateFULLRealOverflowBeforeBody(t *testing.T) {
	f, first, config := updateFirst(t)
	ctx := context.Background()
	proposal := f.sign(updateNext(t, f, first, config))
	d, _ := automationDecision(first.Value)
	operation := fmt.Sprintf("update-op-%d", d.Sequence)
	audit := updateAttachCellAudit(t, f.c)
	audit.reset(operation, nil)
	if e := f.c.ExecuteLocal(ctx, func(tx *LocalTx) error { _, e := automationAdmissionRecordTx(ctx, tx, "", operation); return e }); e != nil {
		t.Fatal("positive typed admission prerequisite", e)
	}
	_, _, positiveBody, positiveAll, _ := audit.stop()
	if positiveBody != 1 || positiveAll != 1 {
		t.Fatal("actual valid configuration body read not observed", positiveBody, positiveAll)
	}
	if e := f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		_, e := tx.tx.ExecContext(ctx, `UPDATE local_automation_admissions SET sequence=9223372036854775808 WHERE stage='' AND operation_id=?`, operation)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	rows, e := f.c.Query(ctx, `SELECT typeof(sequence) AS kind,sequence>9223372036854775807 AS outside FROM local_automation_admissions WHERE stage='' AND operation_id=?`, operation)
	if e != nil || len(rows) != 1 || rows[0].String("kind") != "real" || rows[0].Int64("outside") != 1 {
		t.Fatal("actual SQLite out-int64 REAL not constructed", rows, e)
	}
	before := updateSnapshot(t, f.c)
	audit.reset(operation, nil)
	_, e = applySharedAutomation(t, f.c, proposal, contract.Reduce, automationFreshAnchor)
	_, _, badBodies, _, _ := audit.stop()
	if e == nil || badBodies != 0 {
		t.Fatal("REAL overflow admitted or configuration fetched before typed refusal", e, badBodies)
	}
	if !reflect.DeepEqual(before, updateSnapshot(t, f.c)) {
		t.Fatal("REAL overflow refusal changed full state")
	}
}

// Fill a reverse page with independent genuine create admissions, so preparing
// the bounded-read fixture does not repeatedly run the update prefix closure.
func updateAppendBoundaryCreates(t *testing.T, f *executionStorageFixture, count int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < count; i++ {
		head, e := f.c.AutomationHead(ctx)
		if e != nil {
			t.Fatal(e)
		}
		d, e := automationDecision(f.admission.Value)
		if e != nil {
			t.Fatal(e)
		}
		a, e := contract.DecodeAssignment(d)
		if e != nil {
			t.Fatal(e)
		}
		body, e := contract.DecodeCreateBindingBody(d.Command)
		if e != nil {
			t.Fatal(e)
		}
		name := fmt.Sprintf("bounded-extra-%02d", i)
		d.Sequence = head.Sequence + 1
		d.ParentDigest = head.Digest
		d.Command.RequestID = name + "-request"
		d.Command.ManagementKey = name
		body.Desired.Name = name
		a.OperationID = name + "-operation"
		a.Binding.ResourceUID = name + "-uid"
		a.Binding.DomainUUID = fmt.Sprintf("11111111-1111-4111-8111-%012x", i+2)
		a.Binding.Incarnation = name + "-incarnation"
		a.Binding.Revision = "rev:" + name
		a.Binding.Configuration.Name = name
		for n := range body.Desired.NICs {
			mac := fmt.Sprintf("02:00:00:01:%02x:%02x", n, i+1)
			body.Desired.NICs[n].MAC = &mac
			a.Binding.Configuration.NICs[n].MAC = &mac
		}
		d.Command.Body = automationExecutionJSON(t, body)
		d.Assignment = automationExecutionJSON(t, a)
		r := f.apply(t, f.sign(d))
		if r.State != "accepted" || r.ResourceUID != name+"-uid" {
			t.Fatal("genuine boundary create admission missing", r)
		}
	}
}
