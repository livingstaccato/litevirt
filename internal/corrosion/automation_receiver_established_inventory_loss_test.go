package corrosion

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/litevirt/litevirt/internal/pki"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestReceiverEstablishedMatchedLossFreshProcess(t *testing.T) {
	ctx := context.Background()
	if dir := os.Getenv("LITEVIRT_RECEIVER_LOSS_DB"); dir != "" {
		var intent AutomationSourceRequest
		if err := json.Unmarshal([]byte(os.Getenv("LITEVIRT_RECEIVER_LOSS_INTENT")), &intent); err != nil {
			t.Fatal(err)
		}
		c, err := NewLocalClient(dir, intent.Target)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		r := NewAutomationReceiver(c, os.Getenv("LITEVIRT_RECEIVER_LOSS_PKI"))
		defer r.Close()
		if os.Getenv("LITEVIRT_RECEIVER_LOSS_ACTION") == "current" {
			a, e := r.Begin(ctx, intent, nil)
			if e != nil {
				t.Fatal("restored original/floor startup", e)
			}
			proof, e := r.VerifyCurrent(ctx, a)
			if e != nil {
				t.Fatal("restored fresh current proof", e)
			}
			if e = r.consumeCurrent(ctx, proof); e != nil {
				t.Fatal(e)
			}
			return
		}
		if os.Getenv("LITEVIRT_RECEIVER_LOSS_ACTION") == "repair" {
			err = r.Reestablish(ctx, intent)
		} else {
			_, err = r.Begin(ctx, intent, nil)
		}
		if err == nil {
			t.Fatal("matched noninitial validation/artifact loss accepted weaker installed signed floor")
		}
		return
	}
	for _, action := range []string{"begin", "repair"} {
		t.Run(action, func(t *testing.T) {
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Heads: []int{2, 1}, Initial: func(t *testing.T, v *claimTestVoter, ca claimTestCA) {
				if v.name == "receiver" {
					if err := pki.GenerateCRL(ca.cert, ca.key, filepath.Join(v.pki, "crl.pem"), nil); err != nil {
						t.Fatal(err)
					}
				}
			}})
			for i := range f.producers {
				f.stage(t, i, 11, true)
			}
			oldProof, err := f.receiver.VerifyCurrent(ctx, f.attempt)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(f.local.pki, "crl.pem")
			oldCRL, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err = pki.GenerateCRL(f.ca.cert, f.ca.key, path, []string{"ff9123"}); err != nil {
				t.Fatal(err)
			}
			later, err := f.receiver.Begin(ctx, f.attempt.request, nil)
			if err != nil {
				t.Fatal(err)
			}
			digest := later.view.EvidenceDigest()
			key := hex.EncodeToString(digest[:])
			retained, err := f.local.c.Query(ctx, `SELECT v.evidence,a.artifact FROM local_automation_receiver_validations v JOIN local_automation_receiver_established a ON a.attempt=v.attempt AND a.digest=v.digest WHERE v.attempt=? AND v.digest=?`, later.id, key)
			if err != nil || len(retained) != 1 {
				t.Fatal("genuine retained restore bytes", retained, err)
			}
			strongCRL, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, table := range []string{"local_automation_receiver_validations", "local_automation_receiver_established"} {
				result, err := f.local.c.db.Exec(`DELETE FROM `+table+` WHERE attempt=? AND digest=?`, later.id, key)
				if err != nil {
					t.Fatal(err)
				}
				n, err := result.RowsAffected()
				if err != nil || n != 1 {
					t.Fatal("matched loss setup", table, n, err)
				}
			}
			rows, err := f.local.c.Query(ctx, `SELECT (SELECT COUNT(*) FROM local_automation_receiver_jobs) AS jobs,(SELECT COUNT(*) FROM local_automation_receiver_current) AS selected,(SELECT COUNT(*) FROM local_automation_receiver_validations) AS originals,(SELECT COUNT(*) FROM local_automation_receiver_established) AS artifacts`)
			if err != nil || len(rows) != 1 || rows[0].Int64("jobs") != 1 || rows[0].Int64("selected") != 1 || rows[0].Int64("originals") != 1 || rows[0].Int64("artifacts") != 1 {
				t.Fatal("surviving original/current/E0 altered", rows, err)
			}
			f.receiver.Close()
			if err = os.WriteFile(path, oldCRL, 0600); err != nil {
				t.Fatal(err)
			}
			intent, err := json.Marshal(f.attempt.request)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestReceiverEstablishedMatchedLossFreshProcess$", "-test.v")
			cmd.Env = append(os.Environ(), "LITEVIRT_RECEIVER_LOSS_DB="+f.dir, "LITEVIRT_RECEIVER_LOSS_PKI="+f.local.pki, "LITEVIRT_RECEIVER_LOSS_INTENT="+string(intent), "LITEVIRT_RECEIVER_LOSS_ACTION="+action)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("actual fresh process %s: %v\n%s", action, err, out)
			}
			// Restore the actual missing originals and signed floor. Repair may
			// not invent these bytes from the weaker surviving subset.
			if _, err = f.local.c.db.Exec(`INSERT INTO local_automation_receiver_validations(attempt,digest,evidence) VALUES(?,?,?)`, later.id, key, retained[0].Bytes("evidence")); err != nil {
				t.Fatal(err)
			}
			if _, err = f.local.c.db.Exec(`INSERT INTO local_automation_receiver_established(attempt,digest,artifact) VALUES(?,?,?)`, later.id, key, retained[0].Bytes("artifact")); err != nil {
				t.Fatal(err)
			}
			if _, _, err = pki.InstallCRLs(f.local.pki, [][]byte{strongCRL}); err != nil {
				t.Fatal("supported signed floor restoration", err)
			}
			restored := exec.Command(os.Args[0], "-test.run=^TestReceiverEstablishedMatchedLossFreshProcess$", "-test.v")
			restored.Env = append(os.Environ(), "LITEVIRT_RECEIVER_LOSS_DB="+f.dir, "LITEVIRT_RECEIVER_LOSS_PKI="+f.local.pki, "LITEVIRT_RECEIVER_LOSS_INTENT="+string(intent), "LITEVIRT_RECEIVER_LOSS_ACTION=current")
			if out, e := restored.CombinedOutput(); e != nil {
				t.Fatalf("actual restored fresh process: %v\n%s", e, out)
			}
			if err = f.receiver.consumeCurrent(ctx, oldProof); err == nil {
				t.Fatal("old proof revived after missing-original restoration")
			}

		})
	}
}
