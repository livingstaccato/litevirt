package fleet

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// This bounded observer belongs only to the expired-history diagnostic. It
// records public progress/error metadata, never requests, values, PEM or keys.
type automationHistoryDiagnostic struct {
	started, expiry time.Time
	cluster         *Cluster
	mu              sync.Mutex
	events          [256]string
	written, calls  uint64
}

func (d *automationHistoryDiagnostic) record(detail string) {
	at := time.Now()
	if len(detail) > 2048 {
		detail = detail[:2048] + " [truncated]"
	}
	d.mu.Lock()
	d.events[d.written%uint64(len(d.events))] = fmt.Sprintf("at=%s elapsed=%s remaining_expiry=%s %s", at.Format(time.RFC3339Nano), at.Sub(d.started), d.expiry.Sub(at), detail)
	d.written++
	d.mu.Unlock()
}

func historyDiagnosticError(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	if len(text) > 512 {
		return text[:512] + " [truncated]"
	}
	return text
}

func historyDiagnosticRecord(raw []byte) string {
	if len(raw) == 0 || len(raw) > corrosion.MaxAutomationRecordBytes {
		return "record_decode=invalid-size"
	}
	var r corrosion.AutomationRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Sprintf("record_decode=%q", historyDiagnosticError(err))
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(canonical, raw) || r.Value.Automation == nil {
		return "record_decode=noncanonical-or-nonautomation"
	}
	decision, err := contract.DecodeDecision(r.Value.Automation.Envelope)
	if err != nil {
		return fmt.Sprintf("decision_decode=%q", historyDiagnosticError(err))
	}
	digest, err := r.Value.Digest()
	return fmt.Sprintf("sequence=%d digest=%s digest_error=%q", decision.Sequence, digest, historyDiagnosticError(err))
}

func (d *automationHistoryDiagnostic) observe(c *Cluster) {
	d.cluster = c
	for _, n := range c.Nodes {
		source := n.Name
		network := c.networkRPCClient()
		n.Server.SetPeerUnaryInterceptor(func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoke grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			switch methodName(method) {
			case "GetAutomationDecision", "InstallAutomationDecision", "PrepareRecoveryClaim", "AcceptRecoveryClaim":
			default:
				return network(ctx, method, req, reply, cc, invoke, opts...)
			}
			started := time.Now()
			deadline, hasDeadline := ctx.Deadline()
			d.mu.Lock()
			d.calls++
			call := d.calls
			d.mu.Unlock()
			requested := uint64(0)
			if r, ok := req.(*pb.GetAutomationDecisionRequest); ok {
				requested = r.GetSequence()
			}
			d.record(fmt.Sprintf("rpc-start call=%d source=%s target=%s method=%s requested_sequence=%d has_deadline=%v deadline=%s deadline_remaining=%s", call, source, cc.Target(), methodName(method), requested, hasDeadline, deadline.Format(time.RFC3339Nano), deadline.Sub(started)))
			// Preserve the real interceptor chain, arguments, deadline and result.
			err := network(ctx, method, req, reply, cc, invoke, opts...)
			ended := time.Now()
			detail := ""
			if err == nil {
				switch r := reply.(type) {
				case *pb.GetAutomationDecisionResponse:
					detail = fmt.Sprintf("found=%v", r.GetFound())
					if r.GetFound() {
						detail += " " + historyDiagnosticRecord(r.GetRecordJson())
					}
				case *pb.InstallAutomationDecisionResponse:
					detail = fmt.Sprintf("applied_sequence=%d", r.GetAppliedSequence())
				case *pb.PrepareRecoveryClaimResponse:
					detail = fmt.Sprintf("promised=%v refusal=%q", r.GetPromised(), r.GetRefusalReason())
				case *pb.AcceptRecoveryClaimResponse:
					detail = fmt.Sprintf("accepted=%v refusal=%q", r.GetAccepted(), r.GetRefusalReason())
				}
			}
			d.record(fmt.Sprintf("rpc-end call=%d source=%s target=%s method=%s ended=%s duration=%s code=%s error=%q context_error=%q %s", call, source, cc.Target(), methodName(method), ended.Format(time.RFC3339Nano), ended.Sub(started), status.Code(err), historyDiagnosticError(err), historyDiagnosticError(ctx.Err()), detail))
			return err
		})
	}
}

func (d *automationHistoryDiagnostic) snapshot(stage string) {
	d.record("stage=" + stage)
	if d.cluster == nil {
		return
	}
	for _, n := range d.cluster.Nodes {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		rows, err := n.DB.Query(ctx, `SELECT (SELECT count(*) FROM local_automation_prefix WHERE id=1) AS prefix_rows, p.cluster_uid, p.sequence, p.digest, (SELECT count(*) FROM local_automation_recovery) AS recovery_rows, (SELECT sequence FROM local_automation_recovery WHERE id=1) AS recovery_target, (SELECT next_sequence FROM local_automation_recovery WHERE id=1) AS recovery_next, (SELECT count(*) FROM local_automation_staging) AS staging_rows FROM (SELECT 1) LEFT JOIN local_automation_prefix p ON p.id=1`)
		cancel()
		if err != nil || len(rows) != 1 {
			d.record(fmt.Sprintf("snapshot stage=%s node=%s rows=%d error=%q", stage, n.Name, len(rows), historyDiagnosticError(err)))
		} else {
			r := rows[0]
			d.record(fmt.Sprintf("snapshot stage=%s node=%s prefix_rows=%d cluster=%s sequence=%d digest=%s recovery_rows=%d recovery_target=%d recovery_next=%d staging_rows=%d", stage, n.Name, r.Int64("prefix_rows"), r.String("cluster_uid"), r.Int64("sequence"), r.String("digest"), r.Int64("recovery_rows"), r.Int64("recovery_target"), r.Int64("recovery_next"), r.Int64("staging_rows")))
		}
		certPEM, err := os.ReadFile(filepath.Join(n.PKIDir, "host.crt"))
		if err != nil {
			d.record(fmt.Sprintf("certificate node=%s error=%q", n.Name, historyDiagnosticError(err)))
			continue
		}
		block, _ := pem.Decode(certPEM)
		if block == nil {
			d.record("certificate node=" + n.Name + " error=invalid-PEM")
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			d.record(fmt.Sprintf("certificate node=%s error=%q", n.Name, historyDiagnosticError(err)))
			continue
		}
		d.record(fmt.Sprintf("certificate node=%s serial=%s not_after=%s remaining=%s", n.Name, cert.SerialNumber.Text(16), cert.NotAfter.Format(time.RFC3339Nano), time.Until(cert.NotAfter)))
	}
}

func (d *automationHistoryDiagnostic) dump(t *testing.T) {
	d.mu.Lock()
	count := d.written
	first := uint64(0)
	if count > uint64(len(d.events)) {
		first = count - uint64(len(d.events))
	}
	events := make([]string, 0, len(d.events))
	for i := first; i < count; i++ {
		events = append(events, d.events[i%uint64(len(d.events))])
	}
	d.mu.Unlock()
	t.Logf("HISTORY-DIAGNOSTIC retained=%d overwritten=%d", len(events), first)
	for _, event := range events {
		t.Log(event)
	}
}

func shortAutomationCertificates(t *testing.T, c *Cluster, deadline time.Time) {
	t.Helper()
	caPEM, err := os.ReadFile(c.caCert)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	caKeyPEM, err := os.ReadFile(c.caKey)
	if err != nil {
		t.Fatal(err)
	}
	block, _ = pem.Decode(caKeyPEM)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range c.Nodes {
		// The harness already loaded the original signer during startup. Mint a
		// CA-authenticated successor so production hot reload observes this pair.
		if _, _, err := pki.RenewLocal(c.caCert, c.caKey, n.PKIDir, n.Name); err != nil {
			t.Fatal(err)
		}
		pair, err := tls.LoadX509KeyPair(filepath.Join(n.PKIDir, "host.crt"), filepath.Join(n.PKIDir, "host.key"))
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		cert.NotAfter = deadline
		cert.ExtraExtensions = cert.Extensions
		der, err := x509.CreateCertificate(rand.Reader, cert, ca, &pair.PrivateKey.(*ecdsa.PrivateKey).PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(n.PKIDir, "host.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// Globally relaxing Historical would admit untrusted expired material; replay
// instead trusts locally persisted anchors, and new replicas need a fresh head.
func TestAutomationReplayExpiredHistoryAndRenewedHead(t *testing.T) {
	var expiry time.Time
	diagnostic := &automationHistoryDiagnostic{started: time.Now()}
	defer func() {
		diagnostic.snapshot("test-exit")
		diagnostic.dump(t)
	}()
	f := newAutomationFixtureWith(t, 3, true, func(c *Cluster) {
		issuanceStart := time.Now()
		expiry = issuanceStart.Add(12 * time.Second).Truncate(time.Second)
		diagnostic.expiry = expiry
		diagnostic.observe(c)
		diagnostic.record("stage=before-short-certificates")
		shortAutomationCertificates(t, c, expiry)
		caPEM, err := os.ReadFile(c.caCert)
		if err != nil {
			t.Fatal("issuance-window CA read failed", err)
		}
		block, _ := pem.Decode(caPEM)
		if block == nil {
			t.Fatal("issuance-window CA PEM invalid")
		}
		ca, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal("issuance-window CA parse failed", err)
		}
		var facts []string
		credentialsValid := len(c.Nodes) == 3
		windowValid := true
		for _, n := range c.Nodes {
			pair, err := tls.LoadX509KeyPair(filepath.Join(n.PKIDir, "host.crt"), filepath.Join(n.PKIDir, "host.key"))
			if err != nil {
				credentialsValid = false
				facts = append(facts, fmt.Sprintf("node=%s key_pair_error=%q", n.Name, historyDiagnosticError(err)))
				continue
			}
			cert, err := x509.ParseCertificate(pair.Certificate[0])
			if err != nil {
				credentialsValid = false
				facts = append(facts, fmt.Sprintf("node=%s key_pair_valid=true certificate_error=%q", n.Name, historyDiagnosticError(err)))
				continue
			}
			signatureErr := cert.CheckSignatureFrom(ca)
			commonExpiry := cert.NotAfter.Equal(expiry)
			window := cert.NotAfter.Sub(issuanceStart)
			credentialsValid = credentialsValid && signatureErr == nil && commonExpiry
			windowValid = windowValid && window > 11*time.Second && window <= 12*time.Second
			facts = append(facts, fmt.Sprintf("node=%s key_pair_valid=true serial=%s not_after=%s common_expiry=%v signature_error=%q window=%s", n.Name, cert.SerialNumber.Text(16), cert.NotAfter.Format(time.RFC3339Nano), commonExpiry, historyDiagnosticError(signatureErr), window))
		}
		diagnostic.record(fmt.Sprintf("issuance-window issuance_start=%s facts=%v", issuanceStart.Format(time.RFC3339Nano), facts))
		if !credentialsValid {
			t.Fatalf("issuance-window actual credentials invalid: issuance_start=%s facts=%v", issuanceStart.Format(time.RFC3339Nano), facts)
		}
		if !windowValid {
			t.Fatalf("HISTORY_WINDOW_PRECONDITION_RED issuance_start=%s expected=11s<window<=12s facts=%v", issuanceStart.Format(time.RFC3339Nano), facts)
		}
		diagnostic.snapshot("after-short-certificates")
	})
	f.historyDiagnostic = diagnostic
	diagnostic.snapshot("initialized-fixture-return")
	original, ok, err := f.cluster.Nodes[0].DB.AutomationRecord(f.Context(), 1)
	if err != nil || !ok {
		t.Fatal(err)
	}
	for _, a := range original.Certificate.Accepts {
		block, _ := pem.Decode([]byte(a.CertPEM))
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.NotAfter.Equal(expiry) {
			t.Fatalf("fixture did not use expiring accept: %v", err)
		}
	}
	diagnostic.snapshot("before-renewal-submit-start")
	if _, err := f.Engine(0).Submit(f.Context(), f.Barrier(0, "before-renewal")); err != nil {
		diagnostic.record(fmt.Sprintf("before-renewal-submit error=%q", historyDiagnosticError(err)))
		t.Fatal(err)
	}
	diagnostic.snapshot("before-renewal-submit-return")
	f.Converge(t)
	// Renewal is CA-authenticated continuity, not a peer-provided replacement root.
	for _, n := range f.cluster.Nodes {
		serial, err := pki.CertSerial(filepath.Join(n.PKIDir, "host.crt"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := corrosion.RecordOwnCertSerial(f.Context(), n.DB, n.Name, serial); err != nil {
			t.Fatal(err)
		}
	}
	f.cluster.WaitConverged(t, convergeTimeout)
	for _, n := range f.cluster.Nodes {
		installRenewal(t, f.cluster, n)
	}
	time.Sleep(time.Until(expiry.Add(100 * time.Millisecond)))
	verifier, err := corrosion.LoadClaimVerifier(f.cluster.Nodes[0].PKIDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := corrosion.AdoptedVoterConfig(f.Context(), f.cluster.Nodes[0].DB)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Historical().Verify(original.Certificate, corrosion.CertExpectation{Key: original.Certificate.Key, ValueDigest: original.Value.MustDigest(), ConfigGeneration: cfg.Generation, Electorate: cfg.Members, Quorum: 2}); err == nil {
		t.Fatal("global historical verifier accepted expired leaf")
	}
	n := f.cluster.Nodes[2]
	for _, table := range []string{"local_automation_requests", "local_automation_prefix"} {
		if err := localExec(f.Context(), n.DB, "DELETE FROM "+table); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Engine(2).Recover(f.Context()); err != nil {
		t.Fatalf("locally anchored expired replay failed: %v", err)
	}
	if _, err := f.cluster.PeerClient(n, f.cluster.Nodes[0]).GetAutomationDecision(f.Context(), &pb.GetAutomationDecisionRequest{}); err != nil {
		t.Fatalf("renewed prefix transport failed: %v", err)
	}
	// Remove all history and anchors from one voter. It must obtain a fresh
	// current quorum head and verify the backwards bytes before applying them.
	beforeLoss := f.Head(t, 0)
	f.resetReplicaHistory(t, 2)
	if err := f.Engine(2).Recover(f.Context()); err != nil {
		t.Fatalf("fresh head did not authenticate expired predecessors: %v", err)
	}
	if recovered, found, err := n.DB.AutomationRecord(f.Context(), 1); err != nil || !found || !bytes.Equal(recovered.Value.Automation.Envelope, original.Value.Automation.Envelope) {
		t.Fatalf("fresh head recovery changed expired original bytes: found=%v err=%v", found, err)
	}
	fresh, found, err := n.DB.AutomationRecord(f.Context(), beforeLoss.Sequence)
	if err != nil || !found || fresh.Value.MustDigest() != beforeLoss.Digest {
		t.Fatalf("fresh head recovery changed the recorded head: found=%v err=%v", found, err)
	}
	if err := verifier.Verify(fresh.Certificate, corrosion.CertExpectation{Key: fresh.Certificate.Key, ValueDigest: beforeLoss.Digest, ConfigGeneration: cfg.Generation, Electorate: cfg.Members, Quorum: 2}); err != nil {
		t.Fatalf("recovered head lacks a current normally verified certificate: %v", err)
	}
	f.Converge(t)
	if _, err := f.Engine(2).Submit(f.Context(), f.Barrier(2, "after-expiry")); err != nil {
		t.Fatalf("renewed quorum did not progress: %v", err)
	}

	f.Converge(t)
	source := f.cluster.Nodes[0]
	current, err := corrosion.AdoptedVoterConfig(f.Context(), source.DB)
	if err != nil {
		t.Fatal(err)
	}
	if err = source.DB.SealVoterGeneration(f.Context(), current.Generation, "expired-history-cut"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.Engine(0).FreezeMembershipCut(f.Context(), current.Generation); err != nil {
		t.Fatalf("owned expired history could not form inert source cut: %v", err)
	}
}

// A peer cannot substitute a CA while preserving names, incarnations, digest,
// ballot, generation and even a complete quorum-shaped certificate.
func TestAutomationReplayRejectsUnauthenticatedRootReplacement(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	r, ok, err := f.cluster.Nodes[0].DB.AutomationRecord(f.Context(), 1)
	if err != nil || !ok {
		t.Fatal(err)
	}
	fake := t.TempDir()
	caCert := filepath.Join(fake, "ca.crt")
	caKey := filepath.Join(fake, "ca.key")
	if err := pki.GenerateCA(caCert, caKey); err != nil {
		t.Fatal(err)
	}
	for i, a := range r.Certificate.Accepts {
		dir := filepath.Join(fake, a.Voter)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := pki.GenerateHostCert(caCert, caKey, filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"), a.Voter, nil); err != nil {
			t.Fatal(err)
		}
		signer, err := corrosion.LoadClaimSigner(dir, a.Voter)
		if err != nil {
			t.Fatal(err)
		}
		r.Certificate.Accepts[i], err = signer.Sign(a.Key, a.ConfigGeneration, a.Ballot, a.ValueDigest, a.VoterIncarnation)
		if err != nil {
			t.Fatal(err)
		}
	}
	before := f.Head(t, 1)
	if err := f.Engine(1).Install(f.Context(), r); err == nil {
		t.Fatal("unauthenticated root replacement admitted")
	}
	if f.Head(t, 1) != before {
		t.Fatal("fake root changed applied prefix")
	}
	rows, err := f.cluster.Nodes[1].DB.Query(f.Context(), `SELECT count(*) AS n FROM local_automation_recovery`)
	if err != nil || rows[0].Int64("n") != 0 {
		t.Fatalf("fake root acquired staging authority: %v", err)
	}
}
