package corrosion

import (
	"context"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/pki"
)

func TestReceiverEstablishedAllOriginalInventory(t *testing.T) {
	for _, mode := range []string{"complete", "missing-initial", "orphan", "digest", "peer", "type", "mutation"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Heads: []int{1, 1}})
			if err := pki.GenerateCRL(f.ca.cert, f.ca.key, filepath.Join(f.local.pki, "crl.pem"), []string{"ab10"}); err != nil {
				t.Fatal(err)
			}
			fresh, err := f.receiver.Begin(ctx, f.attempt.request, nil)
			if err != nil {
				t.Fatal(err)
			}
			var q string
			var args []any
			switch mode {
			case "missing-initial":
				old := f.attempt.view.EvidenceDigest()
				q = `DELETE FROM local_automation_receiver_validations WHERE attempt=? AND digest=?`
				args = []any{f.attempt.id, hex.EncodeToString(old[:])}
			case "orphan":
				q = `UPDATE local_automation_receiver_validations SET attempt='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'`
			case "digest":
				q = `UPDATE local_automation_receiver_validations SET digest='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' WHERE digest=(SELECT MIN(digest) FROM local_automation_receiver_validations)`
			case "peer":
				view, e := pki.CaptureHostTrust(ctx, f.voters[0].pki, f.voters[0].name)
				if e != nil {
					t.Fatal(e)
				}
				raw, e := view.PublicEvidence()
				if e != nil {
					t.Fatal(e)
				}
				digest := view.EvidenceDigest()
				q = `INSERT INTO local_automation_receiver_validations(attempt,digest,evidence) VALUES(?,?,?)`
				args = []any{fresh.id, hex.EncodeToString(digest[:]), raw}
			case "type":
				q = `UPDATE local_automation_receiver_validations SET evidence=CAST(evidence AS TEXT)`
			}
			if q != "" {
				if _, err = f.local.c.db.Exec(q, args...); err != nil {
					t.Fatal(err)
				}
			}
			visits := 0
			digest, err := f.receiver.scanEstablishmentOriginals(ctx, func(_ *receiverPredecessor, _ string, _ []byte, e *pki.HostTrustEvidence) error {
				visits++
				if mode == "mutation" && visits == 1 {
					if _, err := f.local.c.db.Exec(`UPDATE local_automation_receiver_jobs SET revision=revision+1`); err != nil {
						t.Fatal(err)
					}
				}
				_, err := e.RecordedLocalHost(f.local.name)
				return err
			})
			if mode != "complete" && mode != "mutation" {
				if err == nil {
					t.Fatal("incomplete/foreign original inventory accepted", mode)
				}
				return
			}
			if mode == "mutation" {
				if err != nil {
					return
				}
				var after string
				err = f.local.c.ExecuteLocal(ctx, func(tx *LocalTx) error { after, err = receiverOriginalDigestTx(ctx, tx); return err })
				if err != nil {
					t.Fatal(err)
				}
				if digest == after {
					t.Fatal("concurrent original mutation disappeared")
				}
				return
			}
			if err != nil || visits != 2 {
				t.Fatal("all genuine original validations not covered", visits, err)
			}
			var final string
			err = f.local.c.ExecuteLocal(ctx, func(tx *LocalTx) error { final, err = receiverOriginalDigestTx(ctx, tx); return err })
			if err != nil || final != digest {
				t.Fatal("bounded outside/inside SQL inventories differ", digest, final, err)
			}
		})
	}
}
