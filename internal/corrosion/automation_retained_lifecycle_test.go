package corrosion

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/litevirt/litevirt/internal/pki"
)

func TestRetainedRemoteHolderCurrentLifecycle(t *testing.T) {
	for _, mode := range []string{"remote-live", "final-donor-admission", "trust-toggle-back", "copied-attempt", "closed-owner"} {
		t.Run(mode, func(t *testing.T) {
			producer, r, q, _, _ := receiverFixture(t)
			ctx := context.Background()
			a, err := r.Begin(ctx, q.Intent, nil)
			if err != nil {
				t.Fatal(err)
			}
			raw, entries := retainedPendingPages(t, a)
			holder, err := decodeRetainedHolder(raw)
			if err != nil {
				t.Fatal(err)
			}
			body := holder.body
			member, ok := a.facts.Next.Member("a")
			if !ok {
				t.Fatal("remote successor absent")
			}
			read, err := r.client.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			host, err := sourceReadHost(ctx, &LocalTx{tx: read}, "a")
			if err != nil {
				read.Rollback()
				t.Fatal(err)
			}
			if err = read.Rollback(); err != nil {
				t.Fatal(err)
			}
			admission, _ := json.Marshal(host)
			pair, err := pki.ServedHostKeyPair(producer.dir)
			if err != nil {
				t.Fatal(err)
			}
			fingerprint := sha256.Sum256(pair.Certificate[0])
			body.Donor, body.DonorIncarnation, body.Signer = "a", member.Incarnation, hex.EncodeToString(fingerprint[:])
			body.AdmissionDigest = sourceDigest([]byte("litevirt/retained-admission/v1"), admission)
			var digest retainedDirectoryDigest
			for i, raw := range entries {
				var entry retainedDirectoryEntry
				if err := retainedCanonical(raw, maxAutomationCutMetadataBytes, &entry); err != nil {
					t.Fatal(err)
				}
				entry.Descriptor.Source, entry.Descriptor.Incarnation = body.Donor, body.DonorIncarnation
				descriptor, _ := json.Marshal(entry.Descriptor)
				if err = digest.add(int64(i+1), descriptor); err != nil {
					t.Fatal(err)
				}
				entries[i], _ = json.Marshal(entry)
			}
			body.DirectoryRoot, _, body.DirectoryObjects, _, _, _, err = digest.finish()
			if err != nil {
				t.Fatal(err)
			}
			body.DirectoryBytes = digest.descriptorBytes
			raw = retainedSignAdversarial(t, pair, body, retainedHolderDomain)
			first := retainedPage{Records: entries[:1]}
			if _, err = r.stageRetained(ctx, a, raw, first); err != nil {
				t.Fatal("actual remote current holder raw stage", err)
			}
			before, stored := receiverActive(t, r.client), receiverStored(t, r.client)
			reached := false
			switch mode {
			case "final-donor-admission":
				r.seams = &localCommitSeams{beforeCommit: func(tx *sql.Tx) error {
					reached = true
					_, e := tx.Exec(`UPDATE hosts SET cert_serial='changed' WHERE name='a'`)
					return e
				}}
			case "trust-toggle-back":
				var policy atomic.Bool
				if err = pki.PublishHostTrustPolicy(r.dir, &policy, true); err != nil {
					t.Fatal(err)
				}
				if err = pki.PublishHostTrustPolicy(r.dir, &policy, false); err != nil {
					t.Fatal(err)
				}
			case "copied-attempt":
				copy := *a
				a = &copy
			case "closed-owner":
				r.Close()
			}
			_, err = r.stageRetained(ctx, a, raw, retainedPage{Position: 1, Records: entries[1:2]})
			if mode == "remote-live" {
				if err != nil {
					t.Fatal("remote current continuation", err)
				}
			} else {
				if err == nil {
					t.Fatal("stale/changed retained holder continued", mode)
				}
				if receiverStored(t, r.client) != stored {
					t.Fatal("refused retained delivery changed stored progress")
				}
			}
			if mode == "final-donor-admission" && (!reached || !strings.Contains(err.Error(), "admission changed")) {
				t.Fatal("did not reach final remote donor guard", reached, err)
			}
			if receiverActive(t, r.client) != before {
				t.Fatal("retained lifecycle changed ACTIVE")
			}
			rows, e := r.client.Query(ctx, `SELECT COUNT(*) AS n FROM local_automation_retained_completions`)
			if e != nil || rows[0].Int64("n") != 0 {
				t.Fatal("raw holder created completion", e)
			}
		})
	}
}
