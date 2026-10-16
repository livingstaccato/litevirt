package corrosion

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// This storage fixture supplies real certificate bytes via a synthetic context;
// it is NOT transport evidence. Real direct TLS lives in the fleet tests.
func exportFixture(t *testing.T) (*AutomationSourcePreparer, AutomationExportRequest, context.Context) {
	t.Helper()
	return exportFixtureAt(t, "")
}
func exportFixtureAt(t *testing.T, dir string) (*AutomationSourcePreparer, AutomationExportRequest, context.Context) {
	t.Helper()
	p, intent := sourcePreparationFixtureAt(t, dir)
	ctx := context.Background()
	if err := p.InitializePublication(ctx); err != nil {
		t.Fatal(err)
	}
	candidate, err := p.Prepare(ctx, intent)
	if err != nil {
		t.Fatal(err)
	}
	id, err := p.Publish(ctx, candidate)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := pki.ServedHostKeyPair(p.dir)
	if err != nil {
		t.Fatal(err)
	}
	var chain []*x509.Certificate
	for _, raw := range pair.Certificate {
		cert, e := x509.ParseCertificate(raw)
		if e != nil {
			t.Fatal(e)
		}
		chain = append(chain, cert)
	}
	ctx = peer.NewContext(ctx, &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{HandshakeComplete: true, PeerCertificates: chain}}})
	return p, AutomationExportRequest{Intent: intent, Publication: id, MaxRecords: 1}, ctx
}

// A missing count/digest/cursor-binding check must fail these actual immutable
// reads. Expectations come directly from the committed SQL bytes, not exporter
// digest or pagination helpers.
func TestSourceExportExactAllSections(t *testing.T) {
	p, r, ctx := exportFixture(t)
	rows, err := p.client.Query(ctx, `SELECT artifact,evidence,membership FROM local_automation_publications WHERE id=?`, r.Publication)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	original := rows[0]
	for component := uint32(0); component < 12; component++ {
		r.Component = component
		r.Cursor = ""
		var all []byte
		var count int64
		for n := 0; n < 100; n++ {
			page, e := p.ExportAutomationSource(ctx, r)
			if e != nil {
				t.Fatalf("component %d page %d: %v", component, n, e)
			}
			retry, e := p.ExportAutomationSource(ctx, r)
			if e != nil {
				t.Fatal(e)
			}
			a, _ := json.Marshal(page)
			b, _ := json.Marshal(retry)
			if !bytes.Equal(a, b) {
				t.Fatal("immutable retry changed page/cursor bytes")
			}
			if len(page.Records) > 1 {
				t.Fatal("requested record count ignored")
			}
			if component < 3 {
				all = append(all, page.Chunk...)
				count++
			} else {
				for _, raw := range page.Records {
					all = append(all, raw...)
					count++
				}
			}
			if page.Terminal {
				if page.TerminalRecords != count || page.TerminalBytes != int64(len(all)) {
					t.Fatal("terminal count/bytes differs from received bytes")
				}
				if component < 3 {
					column := []string{"artifact", "evidence", "membership"}[component]
					if !bytes.Equal(all, original.Bytes(column)) {
						t.Fatal("changed committed evidence")
					}
					sum := sha256.Sum256(all)
					if page.TerminalDigest != hex.EncodeToString(sum[:]) {
						t.Fatal("evidence terminal digest differs")
					}
				}
				break
			}
			if page.Cursor == "" || len(page.Cursor) > 1024 {
				t.Fatal("missing bounded cursor")
			}
			if component >= 3 {
				bad := r
				bad.Cursor = page.Cursor
				bad.Component = (component-3+1)%9 + 3
				if _, e := p.ExportAutomationSource(ctx, bad); e == nil {
					t.Fatal("cursor crossed section")
				}
				bad = r
				bad.Cursor = page.Cursor
				bad.Intent.Revision++
				if _, e := p.ExportAutomationSource(ctx, bad); e == nil {
					t.Fatal("cursor crossed revision")
				}
				bad = r
				bad.Cursor = page.Cursor[:len(page.Cursor)-1] + "!"
				if _, e := p.ExportAutomationSource(ctx, bad); e == nil {
					t.Fatal("tampered cursor accepted")
				}
			}
			r.Cursor = page.Cursor
			if n == 99 {
				t.Fatal("export never reached authenticated terminal")
			}
		}
		if component >= 3 {
			records, e := p.client.Query(ctx, `SELECT record FROM local_automation_cut_records WHERE cut_id=(SELECT id FROM local_automation_cuts WHERE generation=1) AND section=? ORDER BY ordinal`, int(component)-3)
			if e != nil {
				t.Fatal(e)
			}
			var expected []byte
			for _, row := range records {
				expected = append(expected, row.Bytes("record")...)
			}
			if !bytes.Equal(all, expected) {
				t.Fatal("export differs from complete immutable rows")
			}
		}
	}
}

func TestSourceExportRefusesChangedAuthorityAndCorruption(t *testing.T) {
	for _, kind := range []string{"missing-publication", "wrong-job", "wrong-target", "wrong-source-incarnation", "missing-adoption", "forced-intermediate", "record-bit", "record-gap", "record-extra", "oversize-cursor"} {
		t.Run(kind, func(t *testing.T) {
			p, r, ctx := exportFixture(t)
			r.Component = 3
			r.MaxRecords = 64
			exec := func(q string, args ...any) {
				t.Helper()
				if err := p.client.ExecOutOfProcessForTest(q, args...); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "missing-publication":
				exec(`DELETE FROM local_automation_publications`)
			case "wrong-job":
				r.Intent.Job = "another"
			case "wrong-target":
				r.Intent.Target = "b"
			case "wrong-source-incarnation":
				exec(`UPDATE local_voter_incarnation SET incarnation='replacement'`)
			case "missing-adoption":
				exec(`DELETE FROM local_voter_adoption WHERE generation=1`)
			case "forced-intermediate":
				exec(`UPDATE voter_configs SET change='force:a' WHERE generation=1`)
			case "record-bit":
				exec(`UPDATE local_automation_cut_records SET record=substr(record,1,length(record)-1)||X'01' WHERE section=0 AND ordinal=1`)
			case "record-gap":
				exec(`DELETE FROM local_automation_cut_records WHERE section=0 AND ordinal=1`)
			case "record-extra":
				exec(`INSERT INTO local_automation_cut_records(cut_id,section,ordinal,record) SELECT cut_id,section,999,record FROM local_automation_cut_records WHERE section=0 AND ordinal=1`)
			case "oversize-cursor":
				r.Cursor = strings.Repeat("x", 1025)
			}
			if _, err := p.ExportAutomationSource(ctx, r); err == nil {
				t.Fatal("changed source/context/cut was exported")
			}
		})
	}
}

// A blocked Client writer must not keep a cancelled exporter and its actual
// PKI lease alive. The timing seam only pauses; it supplies no trusted facts.
func TestSourceExportCancelLateDatabaseWait(t *testing.T) {
	p, r, ctx := exportFixture(t)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	reached := make(chan struct{})
	done := make(chan error, 1)
	p.client.automationExportBeforeRead = func() { p.client.mu.Lock(); close(reached) }
	go func() { _, err := p.ExportAutomationSource(ctx, r); done <- err }()
	select {
	case <-reached:
	case <-time.After(3 * time.Second):
		t.Fatal("export did not reach actual late database wait")
	}
	cancel()
	returned := false
	select {
	case err := <-done:
		returned = true
		if err == nil {
			t.Error("cancelled export succeeded")
		}
	case <-time.After(300 * time.Millisecond):
		t.Error("cancelled export retained lease while blocked on Client writer")
	}
	// Capture must progress while the unrelated SQL writer STILL owns mu.
	trustDone := make(chan error, 1)
	go func() {
		_, err := pki.CaptureHostTrust(context.Background(), p.dir, p.client.hostName)
		trustDone <- err
	}()
	select {
	case err := <-trustDone:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(300 * time.Millisecond):
		t.Error("cancelled export retained actual PKI owner lease")
	}
	p.client.mu.Unlock()
	if !returned {
		if err := <-done; err == nil {
			t.Error("cancelled export succeeded after writer release")
		}
	}
	p.client.automationExportBeforeRead = nil
	if _, err := p.ExportAutomationSource(peer.NewContext(context.Background(), mustExportPeer(t, p)), r); err != nil {
		t.Fatal("cancelled export prevented later progress", err)
	}
}
func mustExportPeer(t *testing.T, p *AutomationSourcePreparer) *peer.Peer {
	t.Helper()
	pair, err := pki.ServedHostKeyPair(p.dir)
	if err != nil {
		t.Fatal(err)
	}
	var chain []*x509.Certificate
	for _, raw := range pair.Certificate {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, cert)
	}
	return &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{HandshakeComplete: true, PeerCertificates: chain}}}
}

func TestSourceExportCurrentServedAuthority(t *testing.T) {
	for _, kind := range []string{"revoked", "expired-replacement", "renewed"} {
		t.Run(kind, func(t *testing.T) {
			p, r, ctx := exportFixture(t)
			r.Component = 3
			first, e := p.ExportAutomationSource(ctx, r)
			if e != nil || first.Cursor == "" {
				t.Fatal(e)
			}
			r.Cursor = first.Cursor
			pair, e := pki.ServedHostKeyPair(p.dir)
			if e != nil {
				t.Fatal(e)
			}
			leaf, e := x509.ParseCertificate(pair.Certificate[0])
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "revoked":
				e = pki.GenerateCRL(filepath.Join(p.dir, "ca.crt"), filepath.Join(p.dir, "ca.key"), filepath.Join(p.dir, "crl.pem"), []string{leaf.SerialNumber.Text(16)})
			case "expired-replacement":
				caRaw, err := os.ReadFile(filepath.Join(p.dir, "ca.crt"))
				if err != nil {
					t.Fatal(err)
				}
				block, _ := pem.Decode(caRaw)
				ca, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				keyRaw, err := os.ReadFile(filepath.Join(p.dir, "ca.key"))
				if err != nil {
					t.Fatal(err)
				}
				block, _ = pem.Decode(keyRaw)
				key, err := x509.ParseECPrivateKey(block.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				leaf.NotAfter = time.Now().Add(-time.Second)
				raw, err := x509.CreateCertificate(rand.Reader, leaf, ca, leaf.PublicKey, key)
				if err != nil {
					t.Fatal(err)
				}
				e = os.WriteFile(filepath.Join(p.dir, "host.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), 0600)
			case "renewed":
				_, _, e = pki.RenewLocal(filepath.Join(p.dir, "ca.crt"), filepath.Join(p.dir, "ca.key"), p.dir, "a")
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, e = p.ExportAutomationSource(ctx, r); e == nil {
				t.Fatal("historical publication supplied current source authority")
			}
			if kind == "renewed" {
				freshCtx := peer.NewContext(context.Background(), mustExportPeer(t, p))
				if _, e = p.ExportAutomationSource(freshCtx, r); e == nil {
					t.Fatal("old cursor survived new served signer")
				}
				fresh := r
				fresh.Publication = ""
				fresh.Cursor = ""
				page, e := p.ExportAutomationSource(freshCtx, fresh)
				if e != nil {
					t.Fatal("fresh actual reattestation did not progress", e)
				}
				if page.Publication == r.Publication {
					t.Fatal("renewal reused earlier publication")
				}
				fresh.Publication = page.Publication
				fresh.Cursor = r.Cursor
				if _, e = p.ExportAutomationSource(freshCtx, fresh); e == nil {
					t.Fatal("stale cursor spliced new attestation")
				}
			}
		})
	}
}

func TestSourceExportTerminalDigestDetectsStructurallyValidCorruption(t *testing.T) {
	p, r, ctx := exportFixture(t)
	r.Component = 3
	r.MaxRecords = 64
	rows, e := p.client.Query(ctx, `SELECT ordinal,record FROM local_automation_cut_records WHERE section=0 ORDER BY ordinal DESC LIMIT 1`)
	if e != nil || len(rows) != 1 {
		t.Fatal(e)
	}
	raw := append([]byte(nil), rows[0].Bytes("record")...)
	found := false
	for i := len(raw) - 1; i >= 0; i-- {
		raw[i] ^= 1
		if _, e = decodeSourceCutRow(0, rows[0].Int64("ordinal"), raw); e == nil {
			found = true
			break
		}
		raw[i] ^= 1
	}
	if !found {
		t.Fatal("fixture could not make structurally valid changed frame")
	}
	if e = p.client.ExecOutOfProcessForTest(`UPDATE local_automation_cut_records SET record=? WHERE section=0 AND ordinal=?`, raw, rows[0].Int64("ordinal")); e != nil {
		t.Fatal(e)
	}
	if _, e = p.ExportAutomationSource(ctx, r); e == nil || !strings.Contains(e.Error(), "terminal count/bytes/digest") {
		t.Fatal("signed terminal did not detect valid-frame corruption", e)
	}
}

func TestSourceExportActualServedCertificateExpires(t *testing.T) {
	p, intent := sourcePreparationFixture(t)
	ctx := context.Background()
	pair, e := pki.ServedHostKeyPair(p.dir)
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	caRaw, e := os.ReadFile(filepath.Join(p.dir, "ca.crt"))
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode(caRaw)
	ca, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	keyRaw, e := os.ReadFile(filepath.Join(p.dir, "ca.key"))
	if e != nil {
		t.Fatal(e)
	}
	block, _ = pem.Decode(keyRaw)
	key, e := x509.ParseECPrivateKey(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	leaf.NotAfter = time.Now().Truncate(time.Second).Add(4 * time.Second)
	raw, e := x509.CreateCertificate(rand.Reader, leaf, ca, leaf.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(p.dir, "host.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), 0600); e != nil {
		t.Fatal(e)
	}
	served, e := pki.ServedHostKeyPair(p.dir)
	if e != nil || !bytes.Equal(served.Certificate[0], raw) {
		t.Fatal("short-lived actual served identity not adopted", e)
	}
	if e = p.InitializePublication(ctx); e != nil {
		t.Fatal(e)
	}
	candidate, e := p.Prepare(ctx, intent)
	if e != nil {
		t.Fatal(e)
	}
	id, e := p.Publish(ctx, candidate)
	if e != nil {
		t.Fatal(e)
	}
	ctx = peer.NewContext(ctx, mustExportPeer(t, p))
	r := AutomationExportRequest{Intent: intent, Publication: id, Component: 3, MaxRecords: 1}
	first, e := p.ExportAutomationSource(ctx, r)
	if e != nil || first.Cursor == "" {
		t.Fatal("real short-lived serving positive", e)
	}
	time.Sleep(time.Until(leaf.NotAfter) + 30*time.Millisecond)
	r.Cursor = first.Cursor
	if _, e = p.ExportAutomationSource(ctx, r); e == nil {
		t.Fatal("actually expired served identity continued export")
	}
	t.Logf("actual admitted serving certificate expired at %s after successful publish/export", leaf.NotAfter.UTC())
}
