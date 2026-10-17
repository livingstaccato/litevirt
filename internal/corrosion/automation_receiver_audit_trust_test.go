package corrosion

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

func receiverAuditShortCertificate(t *testing.T, dir string, after time.Time) {
	t.Helper()
	read := func(name string) []byte {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			t.Fatal(name)
		}
		return block.Bytes
	}
	ca, err := x509.ParseCertificate(read("ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParseECPrivateKey(read("ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(read("host.crt"))
	if err != nil {
		t.Fatal(err)
	}
	leaf.NotAfter = after
	raw, err := x509.CreateCertificate(rand.Reader, leaf, ca, leaf.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "host.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestReceiverSourceAuditRenewedOverExpiredNativeAnchor(t *testing.T) {
	var original ClaimCertificate
	expires := time.Now().Truncate(time.Second).Add(15 * time.Second)
	p, r, q, peer, _ := receiverAuditFixtureOptions(t, 3, receiverAuditOptions{
		initial: func(a *claimTestVoter, _ []*claimTestVoter) {
			receiverAuditShortCertificate(t, a.pki, expires)
			var err error
			a.signer, err = LoadClaimSigner(a.pki, "a")
			if err != nil {
				t.Fatal(err)
			}
		},
		beforeFreeze: func(a *claimTestVoter, _ []*claimTestVoter) {
			rows, err := a.c.Query(context.Background(), `SELECT certificate FROM local_automation_history WHERE sequence=1`)
			if err != nil || len(rows) != 1 {
				t.Fatal(err)
			}
			original, err = sourceCertificate(rows[0].String("certificate"))
			if err != nil {
				t.Fatal(err)
			}
		},
	})
	ctx := context.Background()
	if _, _, err := pki.RenewLocal(filepath.Join(p.dir, "ca.crt"), filepath.Join(p.dir, "ca.key"), p.dir, "a"); err != nil {
		t.Fatal(err)
	}
	signer, err := LoadClaimSigner(p.dir, "a")
	if err != nil {
		t.Fatal(err)
	}
	// Preserve the decided values and other original voters. Re-attest a's exact
	// votes using its real renewed host identity; both current ordinary chains
	// are genuinely complete, while the signed frozen evidence remains original.
	for g := int64(1); g <= 2; g++ {
		cfg, err := GetVoterConfig(ctx, p.client, g)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := sourceCertificate(cfg.Certificate)
		if err != nil {
			t.Fatal(err)
		}
		for i, accept := range cert.Accepts {
			if accept.Voter == "a" {
				cert.Accepts[i], err = signer.Sign(cert.Key, cert.ConfigGeneration, cert.Ballot, cert.ValueDigest, accept.VoterIncarnation)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		raw, _ := cert.Encode()
		for _, client := range []*Client{p.client, r.client} {
			if _, err = client.db.Exec(`UPDATE voter_configs SET certificate=? WHERE generation=?`, raw, g); err != nil {
				t.Fatal(err)
			}
		}
	}
	time.Sleep(time.Until(expires) + 50*time.Millisecond)
	historical, err := LoadClaimVerifier(p.dir)
	if err != nil {
		t.Fatal(err)
	}
	// One expired original accept cannot independently verify. Historical is
	// still a current verifier, not an established-anchor provenance shortcut.
	one := original
	one.Accepts = []ClaimAccept{original.Accepts[0]}
	if err = historical.Historical().Verify(one, CertExpectation{Key: one.Key, ConfigGeneration: 1, ValueDigest: one.ValueDigest, Electorate: q.Intent.Sources, Quorum: 1}); err == nil {
		t.Fatal("standalone expired Historical verification succeeded")
	}
	q.Intent.Revision++
	candidate, err := p.Prepare(ctx, q.Intent)
	if err != nil {
		t.Fatal("renewed source current preparation", err)
	}
	q.Publication, err = p.Publish(ctx, candidate)
	if err != nil {
		t.Fatal(err)
	}
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal("renewed ordinary receiver", err)
	}
	receiverThrough(t, p, r, a, q, peer, 11)
	active := receiverActive(t, r.client)
	if err = r.AuditSource(ctx, a, "a"); err != nil {
		t.Fatal("renewed source over expired established native anchor", err)
	}
	rows, err := r.client.Query(ctx, `SELECT record FROM local_automation_receiver_records WHERE attempt=? AND source='a' AND component=5 AND ordinal=1`, a.id)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	row, err := decodeSourceCutRow(2, 1, rows[0].Bytes("record"))
	if err != nil {
		t.Fatal(err)
	}
	retained, err := sourceCertificate(row.String("certificate"))
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(original)
	after, _ := json.Marshal(retained)
	if string(before) != string(after) {
		t.Fatal("original expired certificate metadata rewritten")
	}
	if receiverActive(t, r.client) != active {
		t.Fatal("renewed inert audit changed active state")
	}
}

func TestReceiverSourceAuditActualSourceLeaseExpiry(t *testing.T) {
	p, r, q, peer, _ := receiverFixture(t)
	expires := time.Now().Truncate(time.Second).Add(12 * time.Second)
	receiverAuditShortCertificate(t, p.dir, expires)
	ctx := context.Background()
	q.Intent.Revision++
	candidate, err := p.Prepare(ctx, q.Intent)
	if err != nil {
		t.Fatal(err)
	}
	q.Publication, err = p.Publish(ctx, candidate)
	if err != nil {
		t.Fatal(err)
	}
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverThrough(t, p, r, a, q, peer, 11)
	active, derived := receiverActive(t, r.client), receiverAudited(t, r.client)
	reached := false
	r.seams = &localCommitSeams{beforeCommit: func(*sql.Tx) error { reached = true; time.Sleep(time.Until(expires) + 50*time.Millisecond); return nil }}
	err = r.AuditSource(ctx, a, "a")
	if !reached || err == nil || !strings.Contains(err.Error(), "host certificate not currently valid") {
		t.Fatal("actual source certificate expiry did not refuse final commit", err)
	}
	if receiverActive(t, r.client) != active || receiverAudited(t, r.client) != derived {
		t.Fatal("expired source committed partial audit")
	}
}
