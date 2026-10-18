package corrosion

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/pki"
)

func TestReceiverEstablishedStartupAllOriginals(t *testing.T) {
	for _, mode := range []string{"signature", "subset", "orphan", "original", "job", "initial", "type", "oversize", "schema"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			f := currentProofFixture(t)
			if err := pki.GenerateCRL(f.ca.cert, f.ca.key, filepath.Join(f.local.pki, "crl.pem"), []string{"cd21"}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.receiver.Begin(ctx, f.attempt.request, nil); err != nil {
				t.Fatal(err)
			}
			var q string
			var args []any
			switch mode {
			case "signature":
				q = `UPDATE local_automation_receiver_established SET artifact=x'00' WHERE digest=(SELECT MIN(digest) FROM local_automation_receiver_established)`
			case "subset":
				q = `DELETE FROM local_automation_receiver_established WHERE digest=(SELECT MIN(digest) FROM local_automation_receiver_established)`
			case "orphan":
				q = `INSERT INTO local_automation_receiver_established(attempt,digest,artifact) VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',x'00')`
			case "original":
				q = `UPDATE local_automation_receiver_validations SET evidence=x'00' WHERE digest=(SELECT MIN(digest) FROM local_automation_receiver_validations)`
			case "job":
				q = `UPDATE local_automation_receiver_jobs SET revision=revision+1`
			case "initial":
				q = `UPDATE local_automation_receiver_jobs SET evidence=x'00'`
			case "type":
				q = `UPDATE local_automation_receiver_established SET artifact=CAST(artifact AS TEXT)`
			case "oversize":
				q = `UPDATE local_automation_receiver_established SET artifact=zeroblob(?) WHERE digest=(SELECT MIN(digest) FROM local_automation_receiver_established)`
				args = []any{maxReceiverEstablishedBytes + 1}
			case "schema":
				q = `ALTER TABLE local_automation_receiver_established ADD COLUMN ignored TEXT`
			}
			if _, err := f.local.c.db.Exec(q, args...); err != nil {
				t.Fatal(err)
			}
			f.receiver.Close()
			reopened := NewAutomationReceiver(f.local.c, f.local.pki)
			defer reopened.Close()
			active, spool := receiverActive(t, f.local.c), receiverStored(t, f.local.c)
			if a, err := reopened.Begin(ctx, f.attempt.request, nil); a != nil || err == nil {
				t.Fatal("startup accepted corrupt/incomplete original establishment", mode, err)
			}
			if mode != "subset" && mode != "schema" {
				if err := reopened.Reestablish(ctx, f.attempt.request); err == nil {
					t.Fatal("explicit repair silently discarded corrupt original", mode)
				}
			}
			if active != receiverActive(t, f.local.c) || spool != receiverStored(t, f.local.c) {
				t.Fatal("startup refusal changed ACTIVE/spool")
			}
		})
	}
}

func TestReceiverEstablishedRestartFloors(t *testing.T) {
	ctx := context.Background()
	if dir := os.Getenv("LITEVIRT_RECEIVER_RESTART_DB"); dir != "" {
		var intent AutomationSourceRequest
		if err := json.Unmarshal([]byte(os.Getenv("LITEVIRT_RECEIVER_RESTART_INTENT")), &intent); err != nil {
			t.Fatal(err)
		}
		c, err := NewLocalClient(dir, intent.Target)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		r := NewAutomationReceiver(c, os.Getenv("LITEVIRT_RECEIVER_RESTART_PKI"))
		defer r.Close()
		a, err := r.Begin(ctx, intent, nil)
		if os.Getenv("LITEVIRT_RECEIVER_RESTART_EXPECT") == "refuse" {
			if err == nil || a != nil {
				t.Fatal("new process selected weaker retained floor subset")
			}
			return
		}
		if err != nil {
			t.Fatal("repaired process startup", err)
		}
		proof, err := r.VerifyCurrent(ctx, a)
		if err != nil {
			t.Fatal("new process fresh proof", err)
		}
		if err = r.consumeCurrent(ctx, proof); err != nil {
			t.Fatal(err)
		}
		return
	}
	f := currentProofFixture(t)
	old, err := f.receiver.VerifyCurrent(ctx, f.attempt)
	if err != nil {
		t.Fatal(err)
	}
	crlpath := filepath.Join(f.local.pki, "crl.pem")
	if err = pki.GenerateCRL(f.ca.cert, f.ca.key, crlpath, []string{"ef31"}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.receiver.Begin(ctx, f.attempt.request, nil); err != nil {
		t.Fatal(err)
	}
	crl, err := os.ReadFile(crlpath)
	if err != nil {
		t.Fatal(err)
	}
	f.receiver.Close()
	if err = os.Remove(crlpath); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(f.attempt.request)
	if err != nil {
		t.Fatal(err)
	}
	run := func(expect string) {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestReceiverEstablishedRestartFloors$", "-test.v")
		cmd.Env = append(os.Environ(), "LITEVIRT_RECEIVER_RESTART_DB="+f.dir, "LITEVIRT_RECEIVER_RESTART_PKI="+f.local.pki, "LITEVIRT_RECEIVER_RESTART_INTENT="+string(raw), "LITEVIRT_RECEIVER_RESTART_EXPECT="+expect)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("actual new process %s: %v\n%s", expect, err, out)
		}
	}
	run("refuse")
	if _, _, err = pki.InstallCRLs(f.local.pki, [][]byte{crl}); err != nil {
		t.Fatal(err)
	}
	run("current")
	if err = f.receiver.consumeCurrent(ctx, old); err == nil {
		t.Fatal("old closed-process-owner proof revived after repair")
	}
}
