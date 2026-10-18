package corrosion

import (
	"context"
	"encoding/hex"
	"github.com/litevirt/litevirt/internal/pki"
	"path/filepath"
	"testing"
)

func TestReceiverReestablishAllPriorJobsAndPartialArtifacts(t *testing.T) {
	for _, mode := range []string{"all-legacy", "partial-legacy", "peer-original"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			f := currentProofFixture(t)
			old, err := f.receiver.VerifyCurrent(ctx, f.attempt)
			if err != nil {
				t.Fatal(err)
			}
			if err = pki.GenerateCRL(f.ca.cert, f.ca.key, filepath.Join(f.local.pki, "crl.pem"), []string{"a98e"}); err != nil {
				t.Fatal(err)
			}
			prior, err := f.receiver.Begin(ctx, f.attempt.request, nil)
			if err != nil {
				t.Fatal(err)
			}
			intent := prior.request
			intent.Revision++
			current, err := f.receiver.Begin(ctx, intent, prior)
			if err != nil {
				t.Fatal(err)
			}
			q := `DELETE FROM local_automation_receiver_established`
			if mode == "partial-legacy" {
				q = `DELETE FROM local_automation_receiver_established WHERE attempt=(SELECT MIN(id) FROM local_automation_receiver_jobs)`
			}
			result, err := f.local.c.db.Exec(q)
			if err != nil {
				t.Fatal(err)
			}
			n, err := result.RowsAffected()
			if err != nil || n == 0 {
				t.Fatal("legacy absence setup", n, err)
			}
			if mode == "peer-original" {
				peer, err := pki.CaptureHostTrust(ctx, f.voters[0].pki, f.voters[0].name)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := peer.PublicEvidence()
				if err != nil {
					t.Fatal(err)
				}
				digest := peer.EvidenceDigest()
				if _, err = f.local.c.db.Exec(`INSERT INTO local_automation_receiver_validations(attempt,digest,evidence) VALUES(?,?,?)`, current.id, hex.EncodeToString(digest[:]), raw); err != nil {
					t.Fatal(err)
				}
			}
			active, spool := receiverActive(t, f.local.c), receiverStored(t, f.local.c)
			err = f.receiver.Reestablish(ctx, intent)
			if mode == "peer-original" {
				if err == nil {
					t.Fatal("peer evidence established receiver ownership")
				}
				rows, e := f.local.c.Query(ctx, `SELECT COUNT(*) AS n FROM local_automation_receiver_established`)
				if e != nil || len(rows) != 1 || rows[0].Int64("n") != 0 {
					t.Fatal("partial artifact set after peer refusal", rows, e)
				}
				if receiverActive(t, f.local.c) != active || receiverStored(t, f.local.c) != spool {
					t.Fatal("peer refusal changed original spool/ACTIVE")
				}
				return
			}
			if err != nil {
				t.Fatal("all retained jobs repair", err)
			}
			rows, err := f.local.c.Query(ctx, `SELECT (SELECT COUNT(*) FROM local_automation_receiver_jobs) AS jobs,(SELECT COUNT(*) FROM local_automation_receiver_validations) AS originals,(SELECT COUNT(*) FROM local_automation_receiver_established) AS established`)
			if err != nil || len(rows) != 1 || rows[0].Int64("jobs") != 2 || rows[0].Int64("originals") != 3 || rows[0].Int64("established") != 3 {
				t.Fatal("all-job exact coverage", rows, err)
			}
			if err = f.receiver.consumeCurrent(ctx, old); err == nil {
				t.Fatal("prior process proof revived after repair")
			}
			if _, err = f.receiver.Begin(ctx, intent, nil); err != nil {
				t.Fatal("repaired current selection", err)
			}
			if receiverActive(t, f.local.c) != active || receiverStored(t, f.local.c) != spool {
				t.Fatal("repair changed original spool/ACTIVE")
			}
		})
	}
}
