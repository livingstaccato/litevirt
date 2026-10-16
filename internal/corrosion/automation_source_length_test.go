package corrosion

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/litevirt/litevirt/internal/pki"
	"modernc.org/sqlite"
)

// Observe real SQLite query execution at its driver boundary. This is a test
// recorder, not a production SQL callback, verifier or alternate data source.
type sourceReadAuditDriver struct {
	driver.Driver
	bodies *atomic.Int64
}
type sourceReadAuditConn struct {
	driver.Conn
	bodies *atomic.Int64
}

func (d *sourceReadAuditDriver) Open(name string) (driver.Conn, error) {
	c, err := d.Driver.Open(name)
	if err != nil {
		return nil, err
	}
	return &sourceReadAuditConn{Conn: c, bodies: d.bodies}, nil
}
func (c *sourceReadAuditConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
}
func (c *sourceReadAuditConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "SELECT "+automationCutSections[8].columns+" FROM voter_configs") || strings.HasPrefix(query, "SELECT id,job,revision,artifact,evidence,membership FROM local_automation_publications") {
		c.bodies.Add(1)
	}
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
}

var sourceReadDriverSequence atomic.Uint64

func TestSourceLengthGuardAvoidsBodyQuery(t *testing.T) {
	ctx := context.Background()
	var bodies atomic.Int64
	name := fmt.Sprintf("source-read-audit-%d", sourceReadDriverSequence.Add(1))
	sql.Register(name, &sourceReadAuditDriver{Driver: &sqlite.Driver{}, bodies: &bodies})
	db, err := sql.Open(name, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE voter_configs(generation INTEGER PRIMARY KEY,members_json TEXT,members_hash TEXT,change TEXT,certificate TEXT,created_by TEXT,created_at TEXT,deleted_at TEXT)`); err != nil {
		t.Fatal(err)
	}
	members := []VoterMember{{Name: "a", Incarnation: "actual"}}
	if _, err := db.Exec(`INSERT INTO voter_configs VALUES(1,?,?,?,?,?,?,NULL)`, `[{"name":"a","incarnation":"actual"}]`, MembersHash(members), VoterChangeGenesis, "retained", "a", "t"); err != nil {
		t.Fatal(err)
	}
	read := func() error {
		tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return err
		}
		defer tx.Rollback()
		_, err = sourceReadConfig(ctx, &LocalTx{tx: tx}, 1)
		return err
	}
	if err := read(); err != nil {
		t.Fatal("bounded real row refused", err)
	}
	if bodies.Load() != 1 {
		t.Fatal("body-query recorder did not observe positive query")
	}
	if _, err := db.Exec(`UPDATE voter_configs SET certificate=?`, strings.Repeat("x", maxSourceCertificateBytes+1)); err != nil {
		t.Fatal(err)
	}
	if err := read(); err == nil {
		t.Fatal("oversized certificate accepted")
	}
	if bodies.Load() != 1 {
		t.Fatal("oversized SQL body was fetched before refusal")
	}
}

func TestSourcePublicationLengthGuardAvoidsBodyQuery(t *testing.T) {
	ctx := context.Background()
	var bodies atomic.Int64
	name := fmt.Sprintf("publication-read-audit-%d", sourceReadDriverSequence.Add(1))
	sql.Register(name, &sourceReadAuditDriver{Driver: &sqlite.Driver{}, bodies: &bodies})
	db, err := sql.Open(name, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE local_automation_publications(id TEXT PRIMARY KEY,job TEXT,revision INTEGER,artifact BLOB,evidence BLOB,membership BLOB)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO local_automation_publications VALUES(?, 'job', 1, ?, x'', x'')`, strings.Repeat("a", 64), []byte("bounded malformed artifact")); err != nil {
		t.Fatal(err)
	}
	c := &Client{db: db}
	if _, _, err := c.readSourcePublication(ctx, 0, 1); err == nil {
		t.Fatal("malformed bounded artifact accepted")
	}
	if bodies.Load() != 1 {
		t.Fatal("recorder did not observe bounded body query")
	}
	for _, column := range []string{"artifact", "evidence", "membership"} {
		limit := map[string]int{"artifact": maxSourceArtifactBytes, "evidence": pki.MaxHostTrustEvidenceBytes, "membership": maxSourceMembershipEvidenceBytes}[column]
		// zeroblob creates the over-bound stored value inside SQLite without a Go body.
		if _, err := db.Exec(`UPDATE local_automation_publications SET `+column+`=zeroblob(?)`, limit+1); err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.readSourcePublication(ctx, 0, 1); err == nil {
			t.Fatal("oversized publication accepted", column)
		}
		if bodies.Load() != 1 {
			t.Fatal("over-bound publication body fetched", column)
		}
		if _, err := db.Exec(`UPDATE local_automation_publications SET ` + column + `=x''`); err != nil {
			t.Fatal(err)
		}
	}
}
