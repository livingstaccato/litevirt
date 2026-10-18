package corrosion

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/pki"
)

func TestReceiverEstablishedLegacyPreparationAllJobs(t *testing.T) {
	for _, mode := range []string{"complete", "missing-floor-repair", "peer", "mutation"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Heads: []int{1, 1}})
			oldID := f.attempt.id
			crlpath := filepath.Join(f.local.pki, "crl.pem")
			if err := pki.GenerateCRL(f.ca.cert, f.ca.key, crlpath, []string{"cd12"}); err != nil {
				t.Fatal(err)
			}
			crl, err := os.ReadFile(crlpath)
			if err != nil {
				t.Fatal(err)
			}
			a, err := f.receiver.Begin(ctx, f.attempt.request, nil)
			if err != nil {
				t.Fatal(err)
			}
			intent := a.request
			intent.Revision++
			a, err = f.receiver.Begin(ctx, intent, a)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "missing-floor-repair" {
				if err = os.Remove(crlpath); err != nil {
					t.Fatal(err)
				}
				if _, err = f.receiver.reconcileLegacyOriginals(ctx, a); err == nil {
					t.Fatal("missing installed required floor accepted")
				}
				if _, _, err = pki.InstallCRLs(f.local.pki, [][]byte{crl}); err != nil {
					t.Fatal(err)
				}
				a, err = f.receiver.Begin(ctx, intent, nil)
				if err != nil {
					t.Fatal("supported PKI repair could not reauthenticate", err)
				}
			}
			if mode == "peer" {
				v, e := pki.CaptureHostTrust(ctx, f.voters[0].pki, f.voters[0].name)
				if e != nil {
					t.Fatal(e)
				}
				raw, e := v.PublicEvidence()
				if e != nil {
					t.Fatal(e)
				}
				digest := v.EvidenceDigest()
				if _, e = f.local.c.db.Exec(`INSERT INTO local_automation_receiver_validations(attempt,digest,evidence) VALUES(?,?,?)`, a.id, hex.EncodeToString(digest[:]), raw); e != nil {
					t.Fatal(e)
				}
			}
			original, err := f.receiver.reconcileLegacyOriginals(ctx, a)
			if mode == "peer" {
				if err == nil {
					t.Fatal("peer original became receiver floor ownership")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			// Genuine recapture/revalidation after the existing PKI owner reconciles ALL
			// originals; no historical evidence can be substituted for this fresh step.
			a, err = f.receiver.Begin(ctx, intent, nil)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "mutation" {
				if _, err = f.local.c.db.Exec(`UPDATE local_automation_receiver_jobs SET revision=revision+10 WHERE id=?`, oldID); err != nil {
					t.Fatal(err)
				}
			}
			spool, err := f.receiver.prepareLegacyEstablishments(ctx, a, original)
			if mode == "mutation" {
				if spool != nil {
					spool.close()
				}
				if err == nil {
					t.Fatal("mutated prior job omitted from preparation")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer spool.close()
			count := 0
			err = spool.replay(ctx, func(attempt, digest string, raw []byte) error {
				count++
				binding, _, err := f.receiver.establishmentJob(ctx, attempt)
				if err != nil {
					return err
				}
				rows, err := f.local.c.Query(ctx, `SELECT evidence FROM local_automation_receiver_validations WHERE attempt=? AND digest=?`, attempt, digest)
				if err != nil {
					return err
				}
				if len(rows) != 1 {
					t.Fatal("prepared frame lost its original")
				}
				_, err = decodeReceiverEstablished(raw, binding, rows[0].Bytes("evidence"), f.local.name)
				return err
			})
			if err != nil || count != 3 {
				t.Fatal("all prior/current job originals not prepared", count, err)
			}
		})
	}
}
