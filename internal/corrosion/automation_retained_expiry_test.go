package corrosion

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

// Real publication is made and staged while its actual source leaf is current.
// Only after wall-clock expiry do we exercise the inert original-byte adapter.
// This is not an adopted-holder or completed private-proof fixture.
func TestRetainedOriginalExpiredLeafProvenance(t *testing.T) {
	ctx := context.Background()
	var expiry time.Time
	producer, r, q, exportCtx, _ := receiverFixtureSeed(t, func(v *claimTestVoter) {
		read := func(name string) []byte {
			raw, err := os.ReadFile(filepath.Join(v.pki, name))
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(raw)
			if block == nil {
				t.Fatal("missing fixture PEM")
			}
			return block.Bytes
		}
		leaf, err := x509.ParseCertificate(read("host.crt"))
		if err != nil {
			t.Fatal(err)
		}
		ca, err := x509.ParseCertificate(read("ca.crt"))
		if err != nil {
			t.Fatal(err)
		}
		key, err := x509.ParseECPrivateKey(read("ca.key"))
		if err != nil {
			t.Fatal(err)
		}
		expiry = time.Now().Add(12 * time.Second).Truncate(time.Second)
		leaf.NotAfter = expiry
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, leaf.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(v.pki, "host.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
	})
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverThrough(t, producer, r, a, q, exportCtx, 11)
	publication := a.publications["a"]
	if _, _, err := a.view.VerifyHostCertificate(publication.chain, "a"); err != nil {
		t.Fatal("genuine source was not staged before expiry", err)
	}
	before := receiverActive(t, r.client)
	if remaining := time.Until(expiry.Add(20 * time.Millisecond)); remaining > 0 {
		time.Sleep(remaining)
	}
	if _, _, err := a.view.VerifyHostCertificate(publication.chain, "a"); err == nil {
		t.Fatal("actual original leaf did not expire")
	}
	for _, mode := range []string{"expired-original", "expired-original-now-revoked"} {
		t.Run(mode, func(t *testing.T) {
			view := a.view
			if mode == "expired-original-now-revoked" {
				leaf, err := x509.ParseCertificate(publication.chain[0])
				if err != nil {
					t.Fatal(err)
				}
				if err = pki.GenerateCRL(filepath.Join(producer.dir, "ca.crt"), filepath.Join(producer.dir, "ca.key"), filepath.Join(r.dir, "crl.pem"), []string{leaf.SerialNumber.Text(16)}); err != nil {
					t.Fatal(err)
				}
				view, err = pki.CaptureHostTrust(ctx, r.dir, r.client.hostName)
				if err != nil {
					t.Fatal(err)
				}
			}
			tx0, err := r.client.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx0.Rollback()
			tx := &LocalTx{tx: tx0}
			m := publication.manifest
			address, err := retainedAddress(strings.Repeat("e", 64), 1, m.Source, publication.id, retainedSourceStream)
			if err != nil {
				t.Fatal(err)
			}
			d := retainedObjectDescriptor{1, "source", retainedObjectLayout("source"), publication.id, m.Source, m.Incarnation, nil}
			sections, _, _ := retainedObjectSections("source")
			for i := 0; i < 3; i++ {
				n := publication.metadataBytes[i]
				sum := publication.metadataDigests[i]
				d.ComponentInventories = append(d.ComponentInventories, automationCutInventory{sections[i], 1, (n + AutomationExportChunkBytes - 1) / AutomationExportChunkBytes, n, hex.EncodeToString(sum[:])})
			}
			d.ComponentInventories = append(d.ComponentInventories, m.Cut.Inventory...)
			if err = walkAutomationStoredFrames(ctx, tx, "local_automation_receiver_records", "attempt=? AND source=?", []any{a.id, m.Source}, "component", maxAutomationCutRecordBytes, func(c int, n int64, body []byte) error { return address.save(ctx, tx, c, n, body) }); err != nil {
				t.Fatal(err)
			}
			original, err := decodeReceiverBinding(a.id, a.request.Job, a.request.Revision, a.binding)
			if err != nil {
				t.Fatal(err)
			}
			roster := aggregateRosterEntry{m.Source, m.Incarnation, sourceDigest([]byte("litevirt/receiver-source-audit/v1"), []byte(a.id), []byte(m.Source), []byte(publication.id), []byte(m.Root)), publication.id, m.Root, m.Cut.ID, strings.Repeat("a", 64)}
			got, err := address.publication(ctx, tx, d, original, roster, view)
			if err != nil {
				t.Fatalf("genuine expired original provenance refused: %v", err)
			}
			if got.id != publication.id || sha256.Sum256(got.chain[0]) != sha256.Sum256(publication.chain[0]) {
				t.Fatal("original signed identity was rewritten")
			}
			if err = tx0.Rollback(); err != nil {
				t.Fatal(err)
			}
			if receiverActive(t, r.client) != before {
				t.Fatal("expired provenance changed ACTIVE")
			}
		})
	}
}
