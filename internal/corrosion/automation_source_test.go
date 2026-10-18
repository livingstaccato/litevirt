package corrosion

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

// This fixture chooses both values with real persisted accepts, verifies their
// ordinary certificates, and invokes the actual import/adoption storage owner.
// It is intentionally small; later-joined and remote targets live in fleet.
func sourcePreparationFixture(t *testing.T) (*AutomationSourcePreparer, AutomationSourceRequest) {
	return sourcePreparationFixtureAt(t, "")
}
func sourcePreparationFixtureAt(t *testing.T, dataDir string) (*AutomationSourcePreparer, AutomationSourceRequest) {
	p, r, _ := sourcePreparationFixtureWithPeer(t, dataDir)
	return p, r
}
func sourcePreparationFixtureWithPeer(t *testing.T, dataDir string) (*AutomationSourcePreparer, AutomationSourceRequest, *claimTestVoter) {
	return sourcePreparationFixtureWithSeed(t, dataDir, nil)
}
func sourcePreparationFixtureWithSeed(t *testing.T, dataDir string, seed func(*claimTestVoter)) (*AutomationSourcePreparer, AutomationSourceRequest, *claimTestVoter) {
	return sourcePreparationFixtureWithInitialSeed(t, dataDir, nil, seed)
}

func sourcePreparationFixtureWithInitialSeed(t *testing.T, dataDir string, initial, seed func(*claimTestVoter)) (*AutomationSourcePreparer, AutomationSourceRequest, *claimTestVoter) {
	t.Helper()
	ctx := context.Background()
	ca := newClaimTestCA(t)
	a, b := newClaimTestVoter(t, ca, "a"), newClaimTestVoter(t, ca, "b")
	if dataDir != "" {
		c, err := NewLocalClient(dataDir, "a")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		if err := InitSchema(ctx, c); err != nil {
			t.Fatal(err)
		}
		c.SetVoterConfigGate(func() bool { return true })
		a.c = c
		a.inc, err = c.VoterIncarnation(ctx)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := copyTestFile(ca.key, filepath.Join(a.pki, "ca.key")); err != nil {
		t.Fatal(err)
	}
	if initial != nil {
		initial(a)
	}
	choose := func(prev *VoterConfig, value VoterConfigValue) *VoterConfig {
		key := ClaimKey{TargetKind: ClaimKindVoterConfig, OwnerEpoch: value.Generation - 1}
		ballot := testBallot(1, "a")
		result, err := a.c.ClaimAccept(ctx, key, ballot, ClaimValue{Config: &value}, key.OwnerEpoch, a.signer, nil)
		if err != nil || !result.Accepted || result.Accept == nil {
			t.Fatal("real membership accept", result, err)
		}
		digest, _ := (ClaimValue{Config: &value}).Digest()
		cert := ClaimCertificate{Key: key, ConfigGeneration: key.OwnerEpoch, Ballot: ballot, ValueDigest: digest, Accepts: []ClaimAccept{*result.Accept}}
		raw, err := cert.Encode()
		if err != nil {
			t.Fatal(err)
		}
		row := &VoterConfig{VoterConfigValue: value, MembersHash: MembersHash(value.Members), Certificate: raw}
		view, err := pki.CaptureHostTrust(ctx, a.pki, "a")
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyVoterConfigRow(&ClaimVerifier{sourceTrust: view, pinned: true}, prev, row); err != nil {
			t.Fatal("chosen ordinary certificate", err)
		}
		return row
	}
	first := choose(nil, VoterConfigValue{Generation: 1, Members: membersOf(a), Change: VoterChangeGenesis, CreatedBy: "a", CreatedAt: "t"})
	cert, _ := DecodeClaimCertificate(first.Certificate)
	if err := WriteVoterConfig(ctx, a.c, first.VoterConfigValue, cert); err != nil {
		t.Fatal(err)
	}
	if err := RecordVoterAdoption(ctx, a.c, 1); err != nil {
		t.Fatal(err)
	}
	if seed != nil {
		seed(a)
	}
	second := choose(first, VoterConfigValue{Generation: 2, Members: membersOf(a, b), Change: "add:b", CreatedBy: "a", CreatedAt: "t2"})
	if _, err := a.c.FreezeAutomationCut(ctx, 1, nil); err != nil {
		t.Fatal(err)
	}
	cert, _ = DecodeClaimCertificate(second.Certificate)
	if err := WriteVoterConfig(ctx, a.c, second.VoterConfigValue, cert); err != nil {
		t.Fatal(err)
	}
	state, found, err := a.c.ClaimState(ctx, ClaimKey{TargetKind: ClaimKindVoterConfig, OwnerEpoch: 1})
	if err != nil || !found {
		t.Fatal(err)
	}
	if _, err := a.c.ImportClaimsAndAdopt(ctx, 2, []string{"a"}, []ClaimVoterState{state}); err != nil {
		t.Fatal(err)
	}
	pair, err := pki.ServedHostKeyPair(a.pki)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := InsertHost(ctx, a.c, HostRecord{Name: "a", Address: "127.0.0.1", SSHUser: "test", GRPCPort: 50051, CertSerial: leaf.SerialNumber.Text(16), State: "active"}); err != nil {
		t.Fatal(err)
	}
	return NewAutomationSourcePreparer(a.c, a.pki), AutomationSourceRequest{Generation: 1, Target: "a", Job: "owned", Revision: 1, Sources: first.Members}, b
}

func TestSourcePreparationBindings(t *testing.T) {
	producer, request := sourcePreparationFixture(t)
	fresh := func(t *testing.T) *AutomationSourcePreparation {
		t.Helper()
		p, err := producer.Prepare(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { p.owner = producer; p.Discard() })
		return p
	}
	good := fresh(t)
	if err := good.checkPrepared(); err != nil {
		t.Fatal(err)
	}
	pair, err := pki.ServedHostKeyPair(producer.dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pair.Certificate[0], good.chain[0]) {
		t.Fatal("manifest did not use actual served certificate")
	}
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	hash, _ := hex.DecodeString(sourceDigest([]byte(sourceManifestDomain), good.body))
	if !ecdsa.VerifyASN1(leaf.PublicKey.(*ecdsa.PublicKey), hash, good.signature) {
		t.Fatal("actual served signature invalid")
	}
	wrong, _ := hex.DecodeString(sourceDigest([]byte("different-domain"), good.body))
	if ecdsa.VerifyASN1(leaf.PublicKey.(*ecdsa.PublicKey), wrong, good.signature) {
		t.Fatal("cross-domain signature")
	}
	fp := sha256.Sum256(pair.Certificate[0])
	if good.manifest.Signer != hex.EncodeToString(fp[:]) {
		t.Fatal("wrong signer binding")
	}
	for _, mode := range []string{"zero", "copied", "foreign-client", "discarded", "body", "signature", "chain", "target-chain", "manifest", "request", "dependency", "transition", "expired", "future"} {
		t.Run(mode, func(t *testing.T) {
			p := fresh(t)
			switch mode {
			case "zero":
				p = &AutomationSourcePreparation{}
			case "copied":
				p = &AutomationSourcePreparation{self: p, owner: p.owner, ctx: p.ctx}
			case "foreign-client":
				p.owner = &AutomationSourcePreparer{client: &Client{}, dir: producer.dir}
			case "discarded":
				p.Discard()
			case "body":
				p.body = append(p.body, ' ')
			case "signature":
				p.signature[0] ^= 1
			case "chain":
				p.chain[0] = []byte("invalid")
			case "target-chain":
				p.targetChain[0][0] ^= 1
			case "manifest":
				p.manifest.Request.Job = "changed"
			case "request":
				p.request.Job = "changed"
			case "dependency":
				p.dependency = "changed"
			case "transition":
				p.transitionEvidence = "changed"
			case "expired":
				p.expires = time.Now().Add(-time.Second)
			case "future":
				p.at = time.Now().Add(time.Hour)
			}
			if err := p.checkPrepared(); err == nil {
				body, _ := json.Marshal(p.manifest)
				t.Fatalf("changed %s binding accepted (%d manifest bytes)", mode, len(body))
			}
		})
	}
}

func TestSourceProducerRejectsChangedEvidence(t *testing.T) {
	for _, mode := range []string{"source-incarnation", "missing-adoption", "changed-config", "changed-cut", "missing-cut", "admission-serial", "revoked-source", "expired-source", "wrong-source-key"} {
		t.Run(mode, func(t *testing.T) {
			producer, request := sourcePreparationFixture(t)
			ctx := context.Background()
			positive := func() {
				t.Helper()
				p, err := producer.Prepare(ctx, request)
				if err != nil {
					t.Fatal("unchanged real producer refused", err)
				}
				p.Discard()
			}
			positive()
			var restore func()
			update := func(query string, args ...any) {
				t.Helper()
				if err := producer.client.ExecOutOfProcessForTest(query, args...); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "source-incarnation":
				old, err := producer.client.VoterIncarnation(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := producer.client.ReplaceVoterIncarnationForTest(ctx); err != nil {
					t.Fatal(err)
				}
				restore = func() { update(`UPDATE local_voter_incarnation SET incarnation=? WHERE id=1`, old) }
			case "missing-adoption":
				update(`UPDATE local_voter_adoption SET generation=100 WHERE generation=1`)
				restore = func() { update(`UPDATE local_voter_adoption SET generation=1 WHERE generation=100`) }
			case "changed-config":
				update(`UPDATE voter_configs SET created_at='changed' WHERE generation=2`)
				restore = func() { update(`UPDATE voter_configs SET created_at='t2' WHERE generation=2`) }
			case "changed-cut":
				rows, err := producer.client.Query(ctx, `SELECT cut_id,section,ordinal,record FROM local_automation_cut_records WHERE section=0 AND ordinal=1 LIMIT 1`)
				if err != nil || len(rows) != 1 {
					t.Fatal(err)
				}
				r := rows[0]
				corrupt := bytes.Clone(r.Bytes("record"))
				corrupt[len(corrupt)-1] ^= 1
				update(`UPDATE local_automation_cut_records SET record=? WHERE cut_id=? AND section=? AND ordinal=?`, corrupt, r.String("cut_id"), r.Int("section"), r.Int64("ordinal"))
				restore = func() {
					update(`UPDATE local_automation_cut_records SET record=? WHERE cut_id=? AND section=? AND ordinal=?`, r.Bytes("record"), r.String("cut_id"), r.Int("section"), r.Int64("ordinal"))
				}
			case "missing-cut":
				update(`UPDATE local_automation_cuts SET generation=99 WHERE generation=1`)
				restore = func() { update(`UPDATE local_automation_cuts SET generation=1 WHERE generation=99`) }
			case "admission-serial":
				rows, err := producer.client.Query(ctx, `SELECT cert_serial FROM hosts WHERE name='a'`)
				if err != nil || len(rows) != 1 {
					t.Fatal(err)
				}
				old := rows[0].String("cert_serial")
				update(`UPDATE hosts SET cert_serial='unadmitted' WHERE name='a'`)
				restore = func() { update(`UPDATE hosts SET cert_serial=? WHERE name='a'`, old) }
			case "revoked-source":
				pair, err := pki.ServedHostKeyPair(producer.dir)
				if err != nil {
					t.Fatal(err)
				}
				leaf, _ := x509.ParseCertificate(pair.Certificate[0])
				path := filepath.Join(producer.dir, "crl.pem")
				if err := pki.GenerateCRL(filepath.Join(producer.dir, "ca.crt"), filepath.Join(producer.dir, "ca.key"), path, []string{leaf.SerialNumber.Text(16)}); err != nil {
					t.Fatal(err)
				}
				restore = func() {
					if _, _, err := pki.RenewLocal(filepath.Join(producer.dir, "ca.crt"), filepath.Join(producer.dir, "ca.key"), producer.dir, "a"); err != nil {
						t.Fatal(err)
					}
				}
			case "expired-source":
				path := filepath.Join(producer.dir, "host.crt")
				original, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				block, _ := pem.Decode(original)
				leaf, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				caPEM, err := os.ReadFile(filepath.Join(producer.dir, "ca.crt"))
				if err != nil {
					t.Fatal(err)
				}
				block, _ = pem.Decode(caPEM)
				ca, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				keyPEM, err := os.ReadFile(filepath.Join(producer.dir, "ca.key"))
				if err != nil {
					t.Fatal(err)
				}
				block, _ = pem.Decode(keyPEM)
				key, err := x509.ParseECPrivateKey(block.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				leaf.NotAfter = time.Now().Add(-time.Second)
				raw, err := x509.CreateCertificate(rand.Reader, leaf, ca, leaf.PublicKey, key)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), 0600); err != nil {
					t.Fatal(err)
				}
				restore = func() {
					if err := os.WriteFile(path, original, 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "wrong-source-key":
				path := filepath.Join(producer.dir, "host.key")
				original, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				other := testPKI(t, "unrelated")
				replacement, err := os.ReadFile(filepath.Join(other, "host.key"))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, replacement, 0600); err != nil {
					t.Fatal(err)
				}
				restore = func() {
					if err := os.WriteFile(path, original, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			p, err := producer.Prepare(ctx, request)
			if p != nil {
				p.Discard()
			}
			if err == nil {
				t.Error("changed actual evidence prepared")
			}
			restore()
			positive()
		})
	}
}

func TestSourceSnapshotOrdinaryQuorum(t *testing.T) {
	// Actual storage accepts from the existing ordinary voter fixture. This
	// test covers the pure predicate, never treats its local setup as a source.
	f := newCertFixture(t)
	view, err := pki.CaptureHostTrust(context.Background(), f.voters[0].pki, "a")
	if err != nil {
		t.Fatal(err)
	}
	verifier := &ClaimVerifier{sourceTrust: view, pinned: true}
	if err := verifier.Verify(f.cert, f.want); err != nil {
		t.Fatal("actual majority refused", err)
	}
	for _, mode := range []string{"signature", "duplicate", "incarnation", "voter", "digest", "generation", "ballot", "old-electorate"} {
		t.Run(mode, func(t *testing.T) {
			cert := f.cert
			cert.Accepts = append([]ClaimAccept(nil), f.cert.Accepts...)
			want := f.want
			switch mode {
			case "signature":
				cert.Accepts[0].Signature = []byte("forged")
			case "duplicate":
				cert.Accepts[1] = cert.Accepts[0]
			case "incarnation":
				cert.Accepts[0].VoterIncarnation = "reimaged"
			case "voter":
				cert.Accepts[0].Voter = "other"
			case "digest":
				cert.Accepts[0].ValueDigest = "changed"
			case "generation":
				cert.Accepts[0].ConfigGeneration++
			case "ballot":
				cert.Accepts[0].Ballot.Round++
			case "old-electorate":
				want.Electorate = []VoterMember{{Name: "other", Incarnation: "other"}, {Name: "b", Incarnation: f.voters[1].inc}, {Name: "c", Incarnation: f.voters[2].inc}}
			}
			if err := verifier.Verify(cert, want); err == nil {
				t.Fatal("invalid ordinary majority verified")
			}
		})
	}
}

func TestSourcePreparationCloseReleases(t *testing.T) {
	producer, request := sourcePreparationFixture(t)
	p, err := producer.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := producer.client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.checkPrepared(); err == nil {
		t.Fatal("closed client's preparation remained active")
	}
	if len(p.body) != 0 || len(p.artifact) != 0 || len(p.chain) != 0 || len(p.targetChain) != 0 || p.targetChainDigest != "" || p.trust != nil || p.discovery.old != nil {
		t.Fatal("discard retains source evidence")
	}
	if _, err := producer.Prepare(context.Background(), request); err == nil {
		t.Fatal("closed source client prepared")
	}
}
