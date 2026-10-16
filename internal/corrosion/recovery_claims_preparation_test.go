package corrosion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/litevirt/litevirt/internal/pki"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProofComparisonFactoryRunsOutsideDatabase(t *testing.T) {
	for _, merge := range []bool{false, true} {
		t.Run(map[bool]string{false: "writer", true: "anti-entropy"}[merge], func(t *testing.T) {
			f := newCertFixture(t)
			a, b := f.voters[0].c, f.voters[1].c
			a.SetRecoveryClaimGate(func() bool { return true })
			b.SetRecoveryClaimGate(func() bool { return true })
			genuine, err := f.cert.Encode()
			if err != nil {
				t.Fatal(err)
			}
			forged := f.cert
			forged.Accepts = nil
			bad, err := forged.Encode()
			if err != nil {
				t.Fatal(err)
			}
			p := *f.value.Proof
			p.ClaimCertificate = genuine
			if err := WriteActionProof(context.Background(), a, p); err != nil {
				t.Fatal(err)
			}
			calls, underDB := 0, false
			a.SetClaimCertificateVerifier(func() *ClaimVerifier {
				calls++
				if a.mu.TryLock() {
					a.mu.Unlock()
				} else {
					underDB = true
				}
				return f.verifier
			})
			p.ClaimCertificate = bad
			if merge {
				if err := WriteActionProof(context.Background(), b, p); err != nil {
					t.Fatal(err)
				}
				if err := a.MergeSensitiveStateBytesLWW(b.DumpSensitiveStateBytes()); err != nil {
					t.Fatal(err)
				}
			} else if err := SetProofClaimCertificate(context.Background(), a, p); !errors.Is(err, ErrNoRowsAffected) {
				t.Fatal(err)
			}
			if calls == 0 {
				t.Fatal("comparison did not consult real verifier factory")
			}
			if underDB {
				t.Fatal("proof comparison invoked PKI-capable verifier factory while holding database mutex")
			}
			got, ok, err := GetActionProof(context.Background(), a, p.ID)
			if err != nil || !ok || got.ClaimCertificate != genuine {
				t.Fatal("forged evidence replaced genuine proof", err)
			}
		})
	}
}

func TestPreparedProofEvidenceProcess(t *testing.T) {
	dir := os.Getenv("LITEVIRT_PROOF_TRUST_DIR")
	if dir == "" {
		t.Skip("subprocess only")
	}
	for _, pair := range strings.Split(os.Getenv("LITEVIRT_PROOF_PREDECESSORS"), ",") {
		fields := strings.Split(pair, ":")
		if _, ok := pki.SupersededBy(dir, fields[0], fields[1]); !ok {
			t.Fatal("eligible candidate observation did not survive process restart", fields[0])
		}
	}
}

func TestProofPreparationLearnsBothEligibleCandidates(t *testing.T) {
	f := newCertFixture(t)
	a := f.voters[0].c
	ctx := context.Background()
	a.SetRecoveryClaimGate(func() bool { return true })
	a.SetClaimCertificateVerifier(func() *ClaimVerifier { return f.verifier.WithoutSerialPin() })
	variants := []ClaimCertificate{f.cert, f.cert}
	var predecessors []string
	for i, voter := range f.voters[:2] {
		previous, _, err := pki.RenewLocal(f.ca.cert, f.ca.key, voter.pki, voter.name)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(voter.pki, "host.crt"))
		if err != nil {
			t.Fatal(err)
		}
		variants[i].Accepts = append(append([]ClaimAccept(nil), f.cert.Accepts...), ClaimAccept{Voter: "not-a-member", CertPEM: string(raw)})
		predecessors = append(predecessors, voter.name+":"+previous)
	}
	proof := *f.value.Proof
	proof.ClaimCertificate, _ = variants[0].Encode()
	if err := WriteActionProof(ctx, a, proof); err != nil {
		t.Fatal(err)
	}
	proof.ClaimCertificate, _ = variants[1].Encode()
	if err := SetProofClaimCertificate(ctx, a, proof); !errors.Is(err, ErrNoRowsAffected) {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestPreparedProofEvidenceProcess$")
	child.Env = append(os.Environ(), "LITEVIRT_PROOF_TRUST_DIR="+f.verifier.pkiDir, "LITEVIRT_PROOF_PREDECESSORS="+strings.Join(predecessors, ","))
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("durable candidate learning: %v\n%s", err, output)
	}
}

func TestProofPreparationRechecksDiscovery(t *testing.T) {
	for _, churn := range []bool{false, true} {
		t.Run(map[bool]string{false: "retry", true: "bounded-churn"}[churn], func(t *testing.T) {
			f := newCertFixture(t)
			a := f.voters[0].c
			ctx := context.Background()
			a.SetRecoveryClaimGate(func() bool { return true })
			good, _ := f.cert.Encode()
			forged := f.cert
			forged.Accepts = nil
			bad, _ := forged.Encode()
			proof := *f.value.Proof
			proof.ClaimCertificate = good
			if err := WriteActionProof(ctx, a, proof); err != nil {
				t.Fatal(err)
			}
			calls := 0
			a.SetClaimCertificateVerifier(func() *ClaimVerifier {
				calls++
				if calls == 1 || churn {
					raw := bad
					if calls%2 == 0 {
						raw = good
					}
					a.mu.Lock()
					_, err := a.db.Exec(`UPDATE runtime_action_proofs SET claim_certificate=? WHERE id=?`, raw, proof.ID)
					a.mu.Unlock()
					if err != nil {
						t.Fatal(err)
					}
				}
				return f.verifier
			})
			proof.ClaimCertificate = good
			err := SetProofClaimCertificate(ctx, a, proof)
			if churn {
				if !errors.Is(err, ErrProofPreparationChanged) || calls != proofPreparationAttempts {
					t.Fatalf("churn escaped bounded exact-discovery retry: calls=%d err=%v", calls, err)
				}
				a.SetClaimCertificateVerifier(func() *ClaimVerifier { return f.verifier })
				if err := SetProofClaimCertificate(ctx, a, proof); err != nil {
					t.Fatal("stable retry after bounded churn did not progress", err)
				}
			} else if err != nil || calls != 2 {
				t.Fatalf("changed exact certificate was not rediscovered: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestProofPreparationCancellationReleasesOwner(t *testing.T) {
	f := newCertFixture(t)
	a := f.voters[0].c
	a.SetRecoveryClaimGate(func() bool { return true })
	good, _ := f.cert.Encode()
	proof := *f.value.Proof
	proof.ClaimCertificate = good
	if err := WriteActionProof(context.Background(), a, proof); err != nil {
		t.Fatal(err)
	}
	locked := make(chan struct{})
	a.SetClaimCertificateVerifier(func() *ClaimVerifier { a.mu.Lock(); close(locked); return f.verifier })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- SetProofClaimCertificate(ctx, a, proof) }()
	<-locked
	// The existing DB mutex is intentionally not cancellable. The prepared
	// caller must notice cancellation once its holder allows progress.
	time.Sleep(40 * time.Millisecond)
	cancel()
	a.mu.Unlock()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled proof leaked its lease")
	}
	writer := make(chan error, 1)
	go func() {
		writer <- pki.GenerateCRL(f.ca.cert, f.ca.key, filepath.Join(f.verifier.pkiDir, "crl.pem"), []string{"abc"})
	}()
	select {
	case err := <-writer:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("trust writer could not progress after proof cancellation")
	}
}

func TestProofPreparationJSONBounds(t *testing.T) {
	for _, n := range []int{maxPreparedAccepts, maxPreparedAccepts + 1} {
		raw := `{"accepts":[` + strings.Repeat(`{},`, n-1) + `{}]}`
		err := preflightProofJSON(raw, false)
		if (n > maxPreparedAccepts) != errors.Is(err, ErrProofPreparationSize) {
			t.Fatalf("accept count %d: %v", n, err)
		}
	}
	for _, n := range []int{maxPreparedAcceptPEMBytes, maxPreparedAcceptPEMBytes + 1} {
		raw := `{"accepts":[{"cert_pem":"` + strings.Repeat("a", n) + `"}]}`
		err := preflightProofJSON(raw, false)
		if (n > maxPreparedAcceptPEMBytes) != errors.Is(err, ErrProofPreparationSize) {
			t.Fatalf("PEM bytes %d: %v", n, err)
		}
	}
	for _, n := range []int{maxPreparedMembers, maxPreparedMembers + 1} {
		raw := `[` + strings.Repeat(`{},`, n-1) + `{}]`
		err := preflightProofJSON(raw, true)
		if (n > maxPreparedMembers) != errors.Is(err, ErrProofPreparationSize) {
			t.Fatalf("member count %d: %v", n, err)
		}
	}
	raw := `{"ACCEPTS":[{"cert_pem":"` + strings.Repeat(`\u0061`, maxPreparedAcceptPEMBytes+1) + `"}]}`
	if !errors.Is(preflightProofJSON(raw, false), ErrProofPreparationSize) {
		t.Fatal("escaped PEM bypassed decoded-byte preflight")
	}
}

func TestProofPreparationDecodedUnicodePEMBound(t *testing.T) {
	for name, body := range map[string]string{
		"unpaired-surrogates": strings.Repeat(`\ud800\ud800`, maxPreparedAcceptPEMBytes/4),
		"invalid-utf8":        strings.Repeat(string([]byte{0xff}), maxPreparedAcceptPEMBytes/2),
	} {
		t.Run(name, func(t *testing.T) {
			raw := `{"accepts":[{"cert_pem":"` + body + `"}]}`
			if !errors.Is(preflightProofJSON(raw, false), ErrProofPreparationSize) {
				t.Fatal("decoded oversized PEM bypassed preallocation bound")
			}
		})
	}
}

func TestProofPreparationRealSignatureAtFinalComparison(t *testing.T) {
	f := newCertFixture(t)
	ctx := context.Background()
	a, b := f.voters[0].c, f.voters[1].c
	adoptHandBuilt(t, 2, membersOf(f.voters...), f.voters...)
	for _, c := range []*Client{a, b} {
		c.SetRecoveryClaimGate(func() bool { return true })
		c.SetClaimCertificateVerifier(func() *ClaimVerifier { return f.verifier })
	}
	good, _ := f.cert.Encode()
	bad := f.cert
	bad.ConfigGeneration = 2
	bad.Accepts = append([]ClaimAccept(nil), f.cert.Accepts...)
	for i := range bad.Accepts {
		bad.Accepts[i].ConfigGeneration = 2
	} // signatures remain for generation 1
	forged, _ := bad.Encode()
	proof := *f.value.Proof
	proof.ClaimCertificate = good
	if err := WriteActionProof(ctx, a, proof); err != nil {
		t.Fatal(err)
	}
	proof.ClaimCertificate = forged
	if err := SetProofClaimCertificate(ctx, a, proof); !errors.Is(err, ErrNoRowsAffected) {
		t.Fatalf("final writer accepted forged later-generation signatures: %v", err)
	}
	if err := WriteActionProof(ctx, b, proof); err != nil {
		t.Fatal(err)
	}
	if err := a.MergeSensitiveStateBytesLWW(b.DumpSensitiveStateBytes()); err != nil {
		t.Fatal(err)
	}
	if err := b.MergeSensitiveStateBytesLWW(a.DumpSensitiveStateBytes()); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*Client{a, b} {
		got, ok, err := GetActionProof(ctx, c, proof.ID)
		if err != nil || !ok || got.ClaimCertificate != good {
			t.Fatal("final AE comparison accepted forged later-generation signatures", err)
		}
	}
}

func TestPreparedProofMergeDropsRolledBackConflict(t *testing.T) {
	ctx := context.Background()
	a, b := testClient(t), testClient(t)
	proof := claimProof("rollback-conflict")
	for _, c := range []*Client{a, b} {
		if err := WriteActionProof(ctx, c, proof); err != nil {
			t.Fatal(err)
		}
	}
	a.mu.Lock()
	_, err := a.db.Exec(`UPDATE runtime_action_proofs SET status='completed' WHERE id=?`, proof.ID)
	a.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	_, err = b.db.Exec(`UPDATE runtime_action_proofs SET status='failed' WHERE id=?`, proof.ID)
	b.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	dump := b.DumpSensitiveStateBytes()
	mergeChunkFailHook = func() bool { return true }
	t.Cleanup(func() { mergeChunkFailHook = nil })
	if err := a.MergeSensitiveStateBytesLWW(dump); err == nil {
		t.Fatal("injected chunk failure reported success")
	}
	if n := a.UnresolvedTieCount(); n != 0 {
		t.Fatalf("rolled-back proof chunk leaked %d conflict effects", n)
	}
	mergeChunkFailHook = nil
	if err := a.MergeSensitiveStateBytesLWW(dump); err != nil {
		t.Fatal(err)
	}
	if n := a.UnresolvedTieCount(); n != 1 {
		t.Fatalf("committed terminal conflict missing: %d", n)
	}
}

func TestPreparedProofMergeRestoresPristineDuplicateRows(t *testing.T) {
	f := newCertFixture(t)
	ctx := context.Background()
	a, b := f.voters[0].c, f.voters[1].c
	for _, c := range []*Client{a, b} {
		c.SetRecoveryClaimGate(func() bool { return true })
		c.SetClaimCertificateVerifier(func() *ClaimVerifier { return f.verifier })
	}
	good, _ := f.cert.Encode()
	bad := f.cert
	bad.Accepts = nil
	forged, _ := bad.Encode()
	proof := *f.value.Proof
	proof.ClaimCertificate = good
	if err := WriteActionProof(ctx, a, proof); err != nil {
		t.Fatal(err)
	}
	proof.ClaimCertificate = forged
	if err := WriteActionProof(ctx, b, proof); err != nil {
		t.Fatal(err)
	}
	payload, err := decompressPayload(b.DumpSensitiveStateBytes())
	if err != nil {
		t.Fatal(err)
	}
	table := &payload.Tables[0]
	table.Rows = append(table.Rows, append([]interface{}(nil), table.Rows[0]...))
	step := indexOf(table.Columns, "step_state")
	cert := indexOf(table.Columns, "claim_certificate")
	table.Rows[0][step] = "disk_built"
	table.Rows[1][step] = "started"
	table.Rows[1][cert] = good
	mergeChunkFailHook = func() bool { return true }
	t.Cleanup(func() { mergeChunkFailHook = nil })
	if err := a.mergeStatePayloadLWWWithAllowlist(payload, sensitiveTableSet); err == nil {
		t.Fatal("failed duplicate-PK chunk reported success")
	}
	if table.Rows[0][step] != "disk_built" || table.Rows[1][step] != "started" || table.Rows[0][cert] != forged {
		t.Fatal("failed merge mutated caller's pristine rows")
	}
	got, _, err := GetActionProof(ctx, a, proof.ID)
	if err != nil || got.StepState != "" {
		t.Fatal("rolled-back step union reached database", err)
	}
	mergeChunkFailHook = nil
	if err := a.mergeStatePayloadLWWWithAllowlist(payload, sensitiveTableSet); err != nil {
		t.Fatal(err)
	}
	got, _, err = GetActionProof(ctx, a, proof.ID)
	if err != nil || !ProofStepDone(got.StepState, "disk_built") || !ProofStepDone(got.StepState, "started") || got.ClaimCertificate != good {
		t.Fatalf("duplicate-PK merge lost steps or genuine certificate: %+v %v", got, err)
	}
}

func TestProofPreparationRechecksAllDatabaseDependencies(t *testing.T) {
	for _, kind := range []string{"insert", "delete", "binding", "adoption", "forced", "members", "config-delete", "factory"} {
		t.Run(kind, func(t *testing.T) {
			f := newCertFixture(t)
			a := f.voters[0].c
			ctx := context.Background()
			a.SetRecoveryClaimGate(func() bool { return true })
			adoptHandBuilt(t, 2, membersOf(f.voters...), f.voters...)
			good, _ := f.cert.Encode()
			bad := f.cert
			bad.Accepts = nil
			forged, _ := bad.Encode()
			proof := *f.value.Proof
			proof.ClaimCertificate = forged
			if kind != "insert" {
				if err := WriteActionProof(ctx, a, proof); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			a.SetClaimCertificateVerifier(func() *ClaimVerifier {
				calls++
				if calls == 1 {
					if kind == "factory" {
						a.SetClaimCertificateVerifier(func() *ClaimVerifier { calls++; return nil })
					} else if kind == "insert" {
						if err := WriteActionProof(ctx, a, proof); err != nil {
							t.Fatal(err)
						}
					} else {
						var query string
						var args []interface{}
						switch kind {
						case "delete":
							query = `DELETE FROM runtime_action_proofs WHERE id=?`
							args = []interface{}{proof.ID}
						case "binding":
							query = `UPDATE runtime_action_proofs SET dest_host='someone-else' WHERE id=?`
							args = []interface{}{proof.ID}
						case "adoption":
							query = `INSERT INTO local_voter_adoption(generation,imported_from,adopted_at) VALUES(3,'','test')`
						case "forced":
							query = `UPDATE voter_configs SET change='force:test' WHERE generation=2`
						case "members":
							query = `UPDATE voter_configs SET members_json='[]' WHERE generation=1`
						case "config-delete":
							query = `DELETE FROM voter_configs WHERE generation=1`
						}
						a.mu.Lock()
						_, err := a.db.Exec(query, args...)
						a.mu.Unlock()
						if err != nil {
							t.Fatal(err)
						}
					}
				}
				return f.verifier
			})
			incoming := proof
			incoming.ClaimCertificate = good
			err := SetProofClaimCertificate(ctx, a, incoming)
			if calls != 2 {
				t.Fatalf("%s dependency not rediscovered: calls=%d err=%v", kind, calls, err)
			}
			switch kind {
			case "insert", "adoption":
				if err != nil {
					t.Fatal(err)
				}
			case "binding":
				if !errors.Is(err, ErrProofDiverges) {
					t.Fatal(err)
				}
			default:
				if !errors.Is(err, ErrNoRowsAffected) {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestPreparedProofSingleOversizeDoesNotSubdivideAndCommitSiblings(t *testing.T) {
	f := newCertFixture(t)
	ctx := context.Background()
	a := f.voters[0].c
	a.SetRecoveryClaimGate(func() bool { return true })
	a.SetClaimCertificateVerifier(func() *ClaimVerifier { return f.verifier })
	good, _ := f.cert.Encode()
	proof := *f.value.Proof
	proof.ClaimCertificate = good
	if err := WriteActionProof(ctx, a, proof); err != nil {
		t.Fatal(err)
	}
	payload, err := decompressPayload(a.DumpSensitiveStateBytes())
	if err != nil {
		t.Fatal(err)
	}
	table := &payload.Tables[0]
	table.Rows = append(table.Rows, append([]interface{}(nil), table.Rows[0]...))
	table.Rows[0][indexOf(table.Columns, "step_state")] = "must-rollback"
	table.Rows[1][indexOf(table.Columns, "claim_certificate")] = strings.Repeat("x", maxPreparedCertificateBytes+1)
	if err := a.mergeStatePayloadLWWWithAllowlist(payload, sensitiveTableSet); !errors.Is(err, ErrProofPreparationSize) {
		t.Fatal("individual bound did not surface unsupported size", err)
	}
	got, _, err := GetActionProof(ctx, a, proof.ID)
	if err != nil || got.StepState != "" {
		t.Fatal("individual oversize was treated as aggregate subdivision and committed a sibling", err)
	}
}

func TestPreparedProofAggregateBudgetSubdividesPristineRows(t *testing.T) {
	f := newCertFixture(t)
	ctx := context.Background()
	a := f.voters[0].c
	a.SetRecoveryClaimGate(func() bool { return true })
	a.SetClaimCertificateVerifier(func() *ClaimVerifier { return f.verifier })
	good, _ := f.cert.Encode()
	proof := *f.value.Proof
	proof.ClaimCertificate = good
	if err := WriteActionProof(ctx, a, proof); err != nil {
		t.Fatal(err)
	}
	payload, err := decompressPayload(a.DumpSensitiveStateBytes())
	if err != nil {
		t.Fatal(err)
	}
	table := &payload.Tables[0]
	template := table.Rows[0]
	table.Rows = nil
	step, cert := indexOf(table.Columns, "step_state"), indexOf(table.Columns, "claim_certificate")
	suffixes := []string{"  ", " \t", " \n", " \r"}
	for i, suffix := range suffixes {
		row := append([]interface{}(nil), template...)
		row[step] = fmt.Sprintf("step%d", i)
		row[cert] = good + strings.Repeat(" ", maxPreparedCertificateBytes-len(good)-len(suffix)) + suffix
		table.Rows = append(table.Rows, row)
	}
	if err := a.mergeStatePayloadLWWWithAllowlist(payload, sensitiveTableSet); err != nil {
		t.Fatal("supported aggregate could not subdivide", err)
	}
	got, _, err := GetActionProof(ctx, a, proof.ID)
	if err != nil {
		t.Fatal(err)
	}
	for i := range suffixes {
		stepName := fmt.Sprintf("step%d", i)
		if !ProofStepDone(got.StepState, stepName) {
			t.Fatal("subdivision omitted supported row", stepName)
		}
		if table.Rows[i][step] != stepName {
			t.Fatal("subdivision mutated pristine incoming row")
		}
	}
}

func TestPreparedProofStoredOversizeAndOwnerErrorsAreOperational(t *testing.T) {
	for _, kind := range []string{"stored-certificate", "config", "owner"} {
		t.Run(kind, func(t *testing.T) {
			f := newCertFixture(t)
			ctx := context.Background()
			a := f.voters[0].c
			a.SetRecoveryClaimGate(func() bool { return true })
			a.SetClaimCertificateVerifier(func() *ClaimVerifier { return f.verifier })
			good, _ := f.cert.Encode()
			bad := f.cert
			bad.Accepts = nil
			forged, _ := bad.Encode()
			proof := *f.value.Proof
			proof.ClaimCertificate = forged
			if err := WriteActionProof(ctx, a, proof); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "stored-certificate":
				a.mu.Lock()
				_, err := a.db.Exec(`UPDATE runtime_action_proofs SET claim_certificate=? WHERE id=?`, strings.Repeat("x", maxPreparedCertificateBytes+1), proof.ID)
				a.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			case "config":
				a.mu.Lock()
				_, err := a.db.Exec(`UPDATE voter_configs SET members_json=? WHERE generation=1`, strings.Repeat("x", maxPreparedConfigBytes+1))
				a.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			case "owner":
				if err := os.Mkdir(filepath.Join(f.verifier.pkiDir, ".trust.lock"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			proof.ClaimCertificate = good
			err := SetProofClaimCertificate(ctx, a, proof)
			if err == nil || errors.Is(err, ErrNoRowsAffected) {
				t.Fatal("preparation failure became success or ordinary negative verdict", err)
			}
			if kind != "owner" && !errors.Is(err, ErrProofPreparationSize) {
				t.Fatal("stored individual bound was not explicit", err)
			}
		})
	}
}

func TestPreparedProofMultiChunkFailureReleasesTrustAndResumes(t *testing.T) {
	f := newCertFixture(t)
	a := f.voters[0].c
	a.SetRecoveryClaimGate(func() bool { return true })
	a.SetClaimCertificateVerifier(func() *ClaimVerifier { return f.verifier })
	proof := *f.value.Proof
	proof.ClaimCertificate, _ = f.cert.Encode()
	if err := WriteActionProof(context.Background(), a, proof); err != nil {
		t.Fatal(err)
	}
	payload, err := decompressPayload(a.DumpSensitiveStateBytes())
	if err != nil {
		t.Fatal(err)
	}
	table := &payload.Tables[0]
	template := table.Rows[0]
	table.Rows = nil
	step := indexOf(table.Columns, "step_state")
	for _, name := range []string{"first", "second", "third"} {
		row := append([]interface{}(nil), template...)
		row[step] = name
		table.Rows = append(table.Rows, row)
	}
	oldSize, oldHook := mergeApplyChunkRows, mergeChunkHook
	defer func() { mergeApplyChunkRows, mergeChunkHook = oldSize, oldHook }()
	mergeApplyChunkRows = 2
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	boundaries := 0
	mergeChunkHook = func() {
		boundaries++
		progressCtx, done := context.WithTimeout(context.Background(), time.Second)
		defer done()
		_, lease, err := pki.AcquireOrdinaryClaimTrust(progressCtx, f.verifier.pkiDir, nil, nil, maxProofPreparationBytes)
		if err != nil {
			t.Fatal("chunk retained trust lease", err)
		}
		lease.Release()
		if _, _, err := GetActionProof(progressCtx, a, proof.ID); err != nil {
			t.Fatal("chunk retained database lock", err)
		}
		cancel()
	}
	if err := a.mergeStatePayloadLWWWithAllowlistContext(ctx, payload, sensitiveTableSet); !errors.Is(err, context.Canceled) {
		t.Fatal("later chunk failure was not reported", err)
	}
	if boundaries != 1 {
		t.Fatal("failed chunk exposed success boundary", boundaries)
	}
	got, _, err := GetActionProof(context.Background(), a, proof.ID)
	if err != nil || !ProofStepDone(got.StepState, "first") || !ProofStepDone(got.StepState, "second") || ProofStepDone(got.StepState, "third") {
		t.Fatal("wrong partial chunk state", got.StepState, err)
	}
	mergeChunkHook = nil
	if err := a.mergeStatePayloadLWWWithAllowlist(payload, sensitiveTableSet); err != nil {
		t.Fatal("fresh cycle could not resume", err)
	}
	got, _, err = GetActionProof(context.Background(), a, proof.ID)
	if err != nil || !ProofStepDone(got.StepState, "third") {
		t.Fatal("retry omitted remaining chunk", err)
	}
	for i, name := range []string{"first", "second", "third"} {
		if table.Rows[i][step] != name {
			t.Fatal("retry mutated source row")
		}
	}
}

func TestProofDiscoveryPreflightsStoredBodies(t *testing.T) {
	for _, kind := range []string{"aggregate", "binding"} {
		t.Run(kind, func(t *testing.T) {
			f := newCertFixture(t)
			c := f.voters[0].c
			ctx := context.Background()
			c.SetRecoveryClaimGate(func() bool { return true })
			good, _ := f.cert.Encode()
			var ids []string
			count := 4
			if kind == "binding" {
				count = 1
			}
			for i := 0; i < count; i++ {
				proof := *f.value.Proof
				proof.ID = fmt.Sprintf("bounded-stored-%d", i)
				if kind == "binding" {
					proof.ID = f.value.Proof.ID
				}
				proof.ClaimCertificate = good
				if kind == "aggregate" {
					proof.ClaimCertificate = good + strings.Repeat(" ", maxPreparedCertificateBytes-len(good)-i) + strings.Repeat("\t", i)
				}
				if err := WriteActionProof(ctx, c, proof); err != nil {
					t.Fatal(err)
				}
				ids = append(ids, proof.ID)
			}
			if kind == "binding" {
				c.mu.Lock()
				_, err := c.db.Exec(`UPDATE runtime_action_proofs SET relocation_token=? WHERE id=?`, strings.Repeat("x", maxProofPreparationBytes+1), ids[0])
				c.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			}
			var fetched []string
			proofRowBodyReadSeam = func(id string) { fetched = append(fetched, id) }
			defer func() { proofRowBodyReadSeam = nil }()
			_, err := c.discoverProofPreparation(ctx, ids, nil)
			if kind == "aggregate" {
				if !errors.Is(err, errProofPreparationAggregate) {
					t.Fatal("stored aggregate not refused", err)
				}
				if len(fetched) > 3 {
					t.Fatalf("fetched over-budget stored row body: %v", fetched)
				}
				p, err := c.discoverProofPreparation(ctx, ids[:2], nil)
				if err != nil {
					t.Fatal("supported subdivision did not progress", err)
				}
				p.release()
				peer := f.voters[1].c
				peer.SetRecoveryClaimGate(func() bool { return true })
				c.SetClaimCertificateVerifier(func() *ClaimVerifier { return f.verifier })
				for _, id := range ids {
					proof := *f.value.Proof
					proof.ID = id
					proof.ClaimCertificate = good
					if err := WriteActionProof(ctx, peer, proof); err != nil {
						t.Fatal(err)
					}
				}
				payload, err := decompressPayload(peer.DumpSensitiveStateBytes())
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range payload.Tables[0].Rows {
					row[indexOf(payload.Tables[0].Columns, "step_state")] = "progress"
				}
				before, err := json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				if err := c.mergeStatePayloadLWWWithAllowlist(payload, sensitiveTableSet); err != nil {
					t.Fatal("stored aggregate subdivision failed", err)
				}
				after, err := json.Marshal(payload)
				if err != nil || string(before) != string(after) {
					t.Fatal("subdivision changed incoming rows", err)
				}
				for _, id := range ids {
					got, _, err := GetActionProof(ctx, c, id)
					if err != nil || !ProofStepDone(got.StepState, "progress") {
						t.Fatal("subdivision omitted row", id, err)
					}
				}
			} else {
				if !errors.Is(err, ErrProofPreparationSize) || errors.Is(err, errProofPreparationAggregate) {
					t.Fatal("oversized binding not individual operational error", err)
				}
				if len(fetched) != 0 {
					t.Fatal("oversized binding materialized before refusal", fetched)
				}
				proof := *f.value.Proof
				proof.ID = ids[0]
				proof.ClaimCertificate = good
				if err := SetProofClaimCertificate(ctx, c, proof); !errors.Is(err, ErrProofPreparationSize) || errors.Is(err, ErrNoRowsAffected) {
					t.Fatal("oversized binding became ranking verdict", err)
				}
			}
		})
	}
}

func TestProofDiscoverySharesOneOwnedMemberSet(t *testing.T) {
	f := newCertFixture(t)
	c := f.voters[0].c
	ctx := context.Background()
	members := []VoterMember{{Name: "host", Incarnation: strings.Repeat("i", 2<<20)}}
	rawMembers, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	_, err = c.db.Exec(`UPDATE voter_configs SET members_json=? WHERE generation=1`, string(rawMembers))
	c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var incoming []string
	for i := 0; i < 24; i++ {
		cert := f.cert
		cert.Ballot.Round = uint64(i + 1)
		raw, err := cert.Encode()
		if err != nil {
			t.Fatal(err)
		}
		incoming = append(incoming, raw)
	}
	p, err := c.discoverProofPreparation(ctx, nil, incoming)
	if err != nil {
		t.Fatal(err)
	}
	defer p.release()
	var first *VoterMember
	for _, candidate := range p.candidates {
		if len(candidate.members) != 1 || candidate.members[0].Incarnation != members[0].Incarnation {
			t.Fatal("lost decoded members")
		}
		if first == nil {
			first = &candidate.members[0]
		} else if first != &candidate.members[0] {
			t.Fatal("shared config materialized multiple retained member sets")
		}
	}
	members[0].Name = "caller-mutated"
	rawMembers[0] = '!'
	if first.Name != "host" {
		t.Fatal("prepared member set aliases caller storage")
	}
}

func TestProofRecheckRejectsOversizedBindingBeforeMaterialization(t *testing.T) {
	f := newCertFixture(t)
	c := f.voters[0].c
	ctx := context.Background()
	c.SetRecoveryClaimGate(func() bool { return true })
	proof := *f.value.Proof
	proof.ClaimCertificate, _ = f.cert.Encode()
	if err := WriteActionProof(ctx, c, proof); err != nil {
		t.Fatal(err)
	}
	calls, fetches := 0, 0
	proofRowBodyReadSeam = func(string) { fetches++ }
	defer func() { proofRowBodyReadSeam = nil }()
	c.SetClaimCertificateVerifier(func() *ClaimVerifier {
		calls++
		c.mu.Lock()
		_, err := c.db.Exec(`UPDATE runtime_action_proofs SET target_name=? WHERE id=?`, strings.Repeat("x", maxProofPreparationBytes+1), proof.ID)
		c.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		return f.verifier
	})
	err := SetProofClaimCertificate(ctx, c, proof)
	if !errors.Is(err, ErrProofPreparationSize) || errors.Is(err, errProofPreparationAggregate) {
		t.Fatal("recheck did not refuse oversized changed binding", err)
	}
	if calls != 1 || fetches != 1 {
		t.Fatalf("recheck fetched changed body or retried oversized row: factory=%d body=%d", calls, fetches)
	}
	c.mu.Lock()
	_, err = c.db.Exec(`UPDATE runtime_action_proofs SET target_name=? WHERE id=?`, proof.TargetName, proof.ID)
	c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	c.SetClaimCertificateVerifier(func() *ClaimVerifier { return f.verifier })
	if err := SetProofClaimCertificate(ctx, c, proof); !errors.Is(err, ErrNoRowsAffected) {
		t.Fatal("repair after oversized recheck failed to progress", err)
	}
}

func TestProofStoredTailIndividualLimitPrecedesSubdivision(t *testing.T) {
	for _, kind := range []string{"binding", "decoded-pem", "members"} {
		t.Run(kind, func(t *testing.T) {
			f := newCertFixture(t)
			c, peer := f.voters[0].c, f.voters[1].c
			ctx := context.Background()
			c.SetRecoveryClaimGate(func() bool { return true })
			peer.SetRecoveryClaimGate(func() bool { return true })
			c.SetClaimCertificateVerifier(func() *ClaimVerifier { return f.verifier })
			if kind == "members" {
				adoptHandBuilt(t, 2, membersOf(f.voters...), f.voters...)
			}
			good, _ := f.cert.Encode()
			for i := 0; i < 5; i++ {
				proof := *f.value.Proof
				proof.ID = fmt.Sprintf("stored-tail-%d", i)
				proof.ClaimCertificate = good
				if err := WriteActionProof(ctx, peer, proof); err != nil {
					t.Fatal(err)
				}
				if i < 4 {
					proof.ClaimCertificate = good + strings.Repeat(" ", maxPreparedCertificateBytes-len(good)-i) + strings.Repeat("\t", i)
				}
				if err := WriteActionProof(ctx, c, proof); err != nil {
					t.Fatal(err)
				}
			}
			var err error
			c.mu.Lock()
			switch kind {
			case "binding":
				_, err = c.db.Exec(`UPDATE runtime_action_proofs SET relocation_token=? WHERE id='stored-tail-4'`, strings.Repeat("x", maxProofPreparationBytes+1))
			case "decoded-pem":
				_, err = c.db.Exec(`UPDATE runtime_action_proofs SET claim_certificate=? WHERE id='stored-tail-4'`, `{"config_generation":1,"accepts":[{"cert_pem":"`+strings.Repeat("a", maxPreparedAcceptPEMBytes+1)+`"}]}`)
			case "members":
				_, err = c.db.Exec(`UPDATE voter_configs SET members_json=? WHERE generation=2`, `[`+strings.Repeat(`{},`, maxPreparedMembers)+`{}]`)
				if err == nil {
					_, err = c.db.Exec(`UPDATE runtime_action_proofs SET claim_certificate=? WHERE id='stored-tail-4'`, `{"config_generation":2,"accepts":[]}`)
				}
			}
			c.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			payload, err := decompressPayload(peer.DumpSensitiveStateBytes())
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range payload.Tables[0].Rows {
				row[indexOf(payload.Tables[0].Columns, "step_state")] = "must-not-commit"
			}
			fetches := 0
			proofRowBodyReadSeam = func(string) { fetches++ }
			defer func() { proofRowBodyReadSeam = nil }()
			err = c.mergeStatePayloadLWWWithAllowlist(payload, sensitiveTableSet)
			if !errors.Is(err, ErrProofPreparationSize) || errors.Is(err, errProofPreparationAggregate) {
				t.Fatal("stored individual limit became splittable", err)
			}
			c.mu.Lock()
			var written int
			err = c.db.QueryRow(`SELECT COUNT(*) FROM runtime_action_proofs WHERE step_state<>''`).Scan(&written)
			c.mu.Unlock()
			if err != nil || written != 0 {
				t.Fatalf("late individually oversized stored value committed siblings: %d, %v", written, err)
			}
			if kind == "binding" && fetches != 0 {
				t.Fatal("fetched bodies before checking all individual stored lengths", fetches)
			}
		})
	}
}
