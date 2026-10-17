package corrosion

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

func receiverAudited(t *testing.T, c *Client) string {
	t.Helper()
	h := sha256.New()
	for _, table := range []string{"audits", "refs", "requests"} {
		rows, err := c.Query(context.Background(), `SELECT * FROM local_automation_receiver_`+table+` ORDER BY rowid`)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(rows)
		sourceHash(h, raw)
	}
	return hex.EncodeToString(h.Sum(nil))
}
func TestReceiverSourceAuditEveryTerminalRequired(t *testing.T) {
	p, r, q, exportCtx, _ := receiverFixture(t)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverThrough(t, p, r, a, q, exportCtx, 11)
	if err = r.AuditSource(ctx, a, "a"); err != nil {
		t.Fatal("complete positive", err)
	}
	active, derived := receiverActive(t, r.client), receiverAudited(t, r.client)
	for component := 0; component < 12; component++ {
		t.Run(fmt.Sprint(component), func(t *testing.T) {
			if _, err = r.client.db.Exec(`UPDATE local_automation_receiver_components SET terminal=0 WHERE attempt=? AND source='a' AND component=?`, a.id, component); err != nil {
				t.Fatal(err)
			}
			stored := receiverStored(t, r.client)
			if err = r.AuditSource(ctx, a, "a"); err == nil {
				t.Fatal("incomplete source audited")
			}
			if receiverAudited(t, r.client) != derived || receiverActive(t, r.client) != active || receiverStored(t, r.client) != stored {
				t.Fatal("failed audit changed durable evidence or active state")
			}
			if _, err = r.client.db.Exec(`UPDATE local_automation_receiver_components SET terminal=1 WHERE attempt=? AND source='a' AND component=?`, a.id, component); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Mutation victim: remove the audit's exact stored job/revision predicate while
// leaving its immutable binding blob untouched. The current owner alone cannot
// establish that a corrupted job row still describes the intended publication.
func TestReceiverSourceAuditExactJobBinding(t *testing.T) {
	p, r, q, exportCtx, _ := receiverFixture(t)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverThrough(t, p, r, a, q, exportCtx, 11)
	if err = r.AuditSource(ctx, a, "a"); err != nil {
		t.Fatal("valid job refused", err)
	}
	active, derived := receiverActive(t, r.client), receiverAudited(t, r.client)
	if _, err = r.client.db.Exec(`UPDATE local_automation_receiver_jobs SET job='foreign' WHERE id=?`, a.id); err != nil {
		t.Fatal(err)
	}
	if err = r.AuditSource(ctx, a, "a"); err == nil {
		t.Fatal("foreign stored job audited under unchanged binding")
	}
	if receiverActive(t, r.client) != active || receiverAudited(t, r.client) != derived {
		t.Fatal("foreign job changed audited state")
	}
}

func TestReceiverSourceAuditFinalGuards(t *testing.T) {
	for _, mode := range []string{"held-inert", "cancel", "expired-attempt", "selection", "trust", "rollback", "not-full"} {
		t.Run(mode, func(t *testing.T) {
			p, r, q, exportCtx, _ := receiverFixture(t)
			ctx := context.Background()
			a, err := r.Begin(ctx, q.Intent, nil)
			if err != nil {
				t.Fatal(err)
			}
			receiverThrough(t, p, r, a, q, exportCtx, 11)
			active, derived := receiverActive(t, r.client), receiverAudited(t, r.client)
			if mode == "not-full" {
				r.client.db.SetMaxOpenConns(1)
				if _, err = r.client.db.Exec(`PRAGMA synchronous=NORMAL`); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "trust" {
				var policy atomic.Bool
				if err = pki.PublishHostTrustPolicy(r.dir, &policy, true); err != nil {
					t.Fatal(err)
				}
				if err = pki.PublishHostTrustPolicy(r.dir, &policy, false); err != nil {
					t.Fatal(err)
				}
			}
			var cancel context.CancelFunc
			if mode == "cancel" {
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
			}
			r.seams = &localCommitSeams{beforeCommit: func(tx *sql.Tx) error {
				switch mode {
				case "held-inert":
					time.Sleep(11 * time.Second)
				case "cancel":
					cancel()
				case "expired-attempt":
					a.notAfter = time.Now().Add(-time.Second)
				case "selection":
					_, err := tx.Exec(`UPDATE local_automation_receiver_current SET attempt='superseded'`)
					return err
				case "rollback":
					return errors.New("injected audit commit failure")
				}
				return nil
			}}
			started := time.Now()
			err = r.AuditSource(ctx, a, "a")
			if mode == "held-inert" {
				if err != nil || time.Since(started) < 11*time.Second {
					t.Fatal("long inert audit refused", err)
				}
				if receiverAudited(t, r.client) == derived {
					t.Fatal("long audit did not persist inert evidence")
				}
			} else {
				if err == nil {
					t.Fatal("final guard bypassed", mode)
				}
				if receiverAudited(t, r.client) != derived {
					t.Fatal("failed audit committed partial derived evidence")
				}
			}
			if receiverActive(t, r.client) != active {
				t.Fatal("audit changed active state")
			}
		})
	}
}
