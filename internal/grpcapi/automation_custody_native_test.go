package grpcapi

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/litevirt/litevirt/internal/automation"
	"github.com/litevirt/litevirt/internal/automation/custody"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var custodyTestAddress = flag.String("custody-test-address", "", "assigned same-host private address for native custody TLS fixtures")

// Only established authority and certified genesis are seeded prerequisites.
// Every custody operation uses actual production RPC/auth/PKI/storage owners.
func custodyNativeServers(t *testing.T) []*Server {
	t.Helper()
	address := *custodyTestAddress
	if address == "" {
		t.Skip("requires an explicitly selected assigned same-host private fixture address")
	}
	ip := net.ParseIP(address)
	if ip == nil || ip.IsLoopback() || !ip.IsPrivate() {
		t.Fatal("fixture requires an assigned private non-loopback address")
	}
	assigned := false
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		addrs, e := iface.Addrs()
		if e != nil {
			t.Fatal(e)
		}
		for _, addr := range addrs {
			a, _, e := net.ParseCIDR(addr.String())
			if e == nil && a.Equal(ip) {
				assigned = true
				t.Logf("same-host fixture interface=%s address=%s", iface.Name, address)
			}
		}
	}
	if !assigned {
		t.Fatal("fixture address is not assigned on this host")
	}
	ctx := context.Background()
	caDir := t.TempDir()
	ca, key := filepath.Join(caDir, "ca.crt"), filepath.Join(caDir, "ca.key")
	if err = pki.GenerateCA(ca, key); err != nil {
		t.Fatal(err)
	}
	caBody, err := os.ReadFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	var servers []*Server
	var members []corrosion.VoterMember
	var signers []*corrosion.ClaimSigner
	var hosts []corrosion.HostRecord
	for _, name := range []string{"a", "b", "c"} {
		data, pd := t.TempDir(), t.TempDir()
		if err = os.Chmod(data, 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(pd, "ca.crt"), caBody, 0600); err != nil {
			t.Fatal(err)
		}
		if err = pki.GenerateHostCert(ca, key, filepath.Join(pd, "host.crt"), filepath.Join(pd, "host.key"), name, ip); err != nil {
			t.Fatal(err)
		}
		db, e := corrosion.NewLocalClient(data, name)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { db.Close() })
		if err = corrosion.InitSchema(ctx, db); err != nil {
			t.Fatal(err)
		}
		db.SetVoterConfigGate(func() bool { return true })
		inc, e := db.VoterIncarnation(ctx)
		if e != nil {
			t.Fatal(e)
		}
		members = append(members, corrosion.VoterMember{Name: name, Incarnation: inc})
		signer, e := corrosion.LoadClaimSigner(pd, name)
		if e != nil {
			t.Fatal(e)
		}
		signers = append(signers, signer)
		s := NewServer(name, data, pd, db, nil, nil)
		servers = append(servers, s)
		t.Cleanup(func() { s.CloseAutomationCustody() })
		tlsConfig, e := pki.ServerTLSConfig(pd)
		if e != nil {
			t.Fatal(e)
		}
		listener, e := net.Listen("tcp", net.JoinHostPort(address, "0"))
		if e != nil {
			t.Fatal(e)
		}
		t.Logf("same-host custody endpoint %s=%s", name, listener.Addr())
		gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)), grpc.ChainUnaryInterceptor(s.UnaryAuthInterceptor), grpc.ChainStreamInterceptor(s.StreamAuthInterceptor))
		s.RegisterServices(gs)
		done := make(chan struct{})
		go func() { defer close(done); _ = gs.Serve(listener) }()
		t.Cleanup(func() { gs.Stop(); listener.Close(); <-done })
		pair, e := pki.ServedHostKeyPair(pd)
		if e != nil {
			t.Fatal(e)
		}
		leaf, e := x509.ParseCertificate(pair.Certificate[0])
		if e != nil {
			t.Fatal(e)
		}
		hosts = append(hosts, corrosion.HostRecord{Name: name, Address: address, GRPCPort: listener.Addr().(*net.TCPAddr).Port, State: "up", CertSerial: leaf.SerialNumber.Text(16)})
	}
	assignment, _ := json.Marshal(contract.Assignment{Version: 1, ClusterUID: "custody-test-cluster", OperationID: "seeded-genesis", RecordedAt: "2026-10-17T00:00:00Z"})
	envelope, err := contract.EncodeDecision(contract.Decision{Sequence: 1, Command: contract.Command{Kind: "initialize_cluster", PrincipalID: "fixture", RequestID: "initialize", Body: []byte(`{"version":1}`)}, Assignment: assignment})
	if err != nil {
		t.Fatal(err)
	}
	value := corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: envelope}}
	claimKey, _ := corrosion.AutomationClaimKey(1)
	ballot := corrosion.Ballot{Round: 2, Coordinator: "a", Nonce: []byte{1}}
	record := corrosion.AutomationRecord{Value: value, Certificate: corrosion.ClaimCertificate{Key: claimKey, Ballot: ballot, ConfigGeneration: 1, ValueDigest: value.MustDigest()}}
	for i, signer := range signers[:2] {
		vote, e := signer.Sign(claimKey, 1, ballot, value.MustDigest(), members[i].Incarnation)
		if e != nil {
			t.Fatal(e)
		}
		record.Certificate.Accepts = append(record.Certificate.Accepts, vote)
	}
	for i, s := range servers {
		if err = corrosion.WriteVoterConfig(ctx, s.db, corrosion.VoterConfigValue{Generation: 1, Members: members, Change: corrosion.VoterChangeGenesis, CreatedBy: "fixture", CreatedAt: "fixture"}, corrosion.ClaimCertificate{}); err != nil {
			t.Fatal(err)
		}
		if err = corrosion.RecordVoterAdoption(ctx, s.db, 1); err != nil {
			t.Fatal(err)
		}
		if err = s.db.ExecuteLocal(ctx, func(tx *corrosion.LocalTx) error {
			_, e := tx.Exec(ctx, `INSERT INTO local_automation_authority(id,generation,members_hash,incarnation,bootstrap_principal,bootstrap_request,provenance) VALUES(1,1,?,?,'fixture','initialize','test-only:custody-established-prerequisites')`, corrosion.MembersHash(members), members[i].Incarnation)
			return e
		}); err != nil {
			t.Fatal(err)
		}
		verifier, e := corrosion.LoadClaimVerifier(s.pkiDir)
		if e != nil {
			t.Fatal(e)
		}
		if receipt, e := s.db.AutomationApply(ctx, record, verifier, contract.Reduce); e != nil || receipt.Code != "" {
			t.Fatalf("seeded genesis: %v %v", receipt, e)
		}
		for _, host := range hosts {
			if err = corrosion.InsertHost(ctx, s.db, host); err != nil {
				t.Fatal(err)
			}
			if _, e := s.db.DB().ExecContext(ctx, `UPDATE hosts SET created_at=? WHERE name=?`, "2026-10-01T00:00:00Z", host.Name); e != nil {
				t.Fatal(e)
			}
		}
	}
	return servers
}

func TestAutomationCustodyNativeProvisionAllMembersSeededPrerequisites(t *testing.T) {
	servers := custodyNativeServers(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	producer, err := servers[0].custodyProducer()
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := producer.PrepareInitialEpoch(ctx)
	if err != nil {
		t.Fatal("prepare", err)
	}
	defer attempt.Release()
	ready, err := producer.ProvisionInitialEpoch(ctx, attempt)
	if err != nil || ready == nil {
		t.Fatalf("complete native physical provisioning unavailable: %v", err)
	}
	defer ready.Release()
	for _, s := range servers {
		head, e := s.db.AutomationHead(ctx)
		if e != nil || head.Sequence != 1 {
			t.Fatal("physical provisioning changed certified history")
		}
		count := 0
		err = filepath.WalkDir(filepath.Join(s.dataDir, "automation-custody"), func(path string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if !d.IsDir() && d.Name() == "completion" {
				count++
			}
			return nil
		})
		if err != nil || count == 0 {
			t.Fatalf("host %s lacks durable completion: %v", s.hostName, err)
		}
	}
}

func TestAutomationCustodyNativeFirstAcceptSeededPrerequisites(t *testing.T) {
	servers := custodyNativeServers(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	p, err := servers[0].custodyProducer()
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := p.PrepareInitialEpoch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer attempt.Release()
	ready, err := p.ProvisionInitialEpoch(ctx, attempt)
	if err != nil {
		t.Fatal(err)
	}
	defer ready.Release()
	command, err := ready.ImportCommand()
	if err != nil {
		t.Fatal(err)
	}
	head, err := servers[0].db.AutomationHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	base := contract.Decision{Sequence: head.Sequence + 1, ParentDigest: head.Digest, Command: command}
	value, admission, err := p.PrepareCustodyValue(ctx, ready, base)
	if err != nil || admission == nil {
		t.Fatalf("native key admission unavailable: %v", err)
	}
	defer admission.Release()
	key, _ := corrosion.AutomationClaimKey(base.Sequence)
	ballot := corrosion.Ballot{Round: 3, Coordinator: "a", Nonce: []byte{2}}
	signer, _, err := servers[0].claimIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if result, e := servers[0].db.ClaimAccept(ctx, key, ballot, value, 1, signer, nil); e != nil || result.Accepted || result.Refusal != corrosion.RefusalAutomationUnavailable {
		t.Fatalf("naked key accept: %+v %v", result, e)
	}
	result, err := servers[0].db.ClaimAcceptKeyNative(ctx, key, ballot, value, 1, signer, admission)
	if err != nil || !result.Accepted || result.Accept == nil {
		t.Fatalf("native first FULL acceptance unavailable: %+v %v", result, err)
	}
	if again, e := servers[0].db.ClaimAcceptKeyNative(ctx, key, ballot, value, 1, signer, admission); e != nil || again.Accepted {
		t.Fatalf("consumed native key admission reusable: %+v %v", again, e)
	}
	state, found, err := servers[0].db.ClaimState(ctx, key)
	if err != nil || !found || state.Accept == nil || state.ValueDigest != value.MustDigest() {
		t.Fatalf("native acceptance not durably stored: %v", err)
	}
	remote, err := (serverClaimTransport{servers[0]}).Accept(ctx, "b", key, ballot, value, 1)
	if err != nil || !remote.Accepted || remote.Accept == nil {
		t.Fatalf("remote stored key evidence did not induce actual vote: %+v %v", remote, err)
	}
	record := corrosion.AutomationRecord{Value: value, Certificate: corrosion.ClaimCertificate{Key: key, Ballot: ballot, ConfigGeneration: 1, ValueDigest: value.MustDigest(), Accepts: []corrosion.ClaimAccept{*result.Accept, *remote.Accept}}}
	for _, s := range servers {
		_, verifier, e := s.claimIdentity()
		if e != nil {
			t.Fatal(e)
		}
		owned := record
		receipt, e := s.db.AutomationApplyOwned(ctx, &owned, verifier, contract.Reduce)
		if e != nil || receipt.Code != "" || receipt.Sequence != 2 {
			t.Fatalf("actual certified import apply failed: %+v %v", receipt, e)
		}
	}

	imported := contract.HistoryReference{Sequence: 2, Digest: value.MustDigest()}
	activationCommand, err := ready.ActivationCommand(imported)
	if err != nil {
		t.Fatal(err)
	}
	// A successful typed import receipt is causal evidence. A rejected receipt
	// cannot be treated as an acknowledgment merely because the history exists.
	receipts, err := servers[0].db.Query(ctx, `SELECT receipt_json FROM local_automation_history WHERE sequence=2`)
	if err != nil || len(receipts) != 1 {
		t.Fatal("original import receipt", err)
	}
	originalReceipt := receipts[0].String("receipt_json")
	var rejected contract.Receipt
	if json.Unmarshal([]byte(originalReceipt), &rejected) != nil {
		t.Fatal("receipt decode")
	}
	rejected.Code = contract.CodeValidation
	rejectedJSON, _ := json.Marshal(rejected)
	if _, err = servers[0].db.DB().ExecContext(ctx, `UPDATE local_automation_history SET receipt_json=? WHERE sequence=2`, string(rejectedJSON)); err != nil {
		t.Fatal(err)
	}
	if _, cap, e := p.PrepareInitialActivation(ctx, ready, imported, contract.Decision{Sequence: 3, ParentDigest: imported.Digest, Command: activationCommand}); e == nil || cap != nil {
		t.Fatal("rejected import receipt issued native activation")
	}
	if _, err = servers[0].db.DB().ExecContext(ctx, `UPDATE local_automation_history SET receipt_json=? WHERE sequence=2`, originalReceipt); err != nil {
		t.Fatal(err)
	}
	activation, activationAdmission, err := p.PrepareInitialActivation(ctx, ready, imported, contract.Decision{Sequence: 3, ParentDigest: imported.Digest, Command: activationCommand})
	if err != nil || activationAdmission == nil {
		t.Fatalf("initial activation native admission unavailable: %v", err)
	}
	defer activationAdmission.Release()
	activationKey, _ := corrosion.AutomationClaimKey(3)
	first, err := servers[0].db.ClaimAcceptKeyNative(ctx, activationKey, ballot, activation, 1, signer, activationAdmission)
	if err != nil || !first.Accepted || first.Accept == nil {
		t.Fatalf("initial activation native vote: %+v %v", first, err)
	}
	second, err := (serverClaimTransport{servers[0]}).Accept(ctx, "b", activationKey, ballot, activation, 1)
	if err != nil || !second.Accepted || second.Accept == nil {
		t.Fatalf("initial activation remote vote: %+v %v", second, err)
	}
	activationRecord := corrosion.AutomationRecord{Value: activation, Certificate: corrosion.ClaimCertificate{Key: activationKey, Ballot: ballot, ConfigGeneration: 1, ValueDigest: activation.MustDigest(), Accepts: []corrosion.ClaimAccept{*first.Accept, *second.Accept}}}
	for _, s := range servers {
		_, verifier, e := s.claimIdentity()
		if e != nil {
			t.Fatal(e)
		}
		owned := activationRecord
		receipt, e := s.db.AutomationApplyOwned(ctx, &owned, verifier, contract.Reduce)
		if e != nil || receipt.Code != "" || receipt.Sequence != 3 {
			t.Fatalf("genuine initial activation apply: %+v %v", receipt, e)
		}
		rows, e := s.db.Query(ctx, `SELECT count(*) AS n FROM local_automation_key_epochs WHERE stage=''`)
		if e != nil || len(rows) != 1 || rows[0].Int64("n") != 1 {
			t.Fatalf("host %s lacks initial active epoch: %v", s.hostName, e)
		}
	}

}

func TestAutomationCustodyNativeFirstAcceptCurrentness(t *testing.T) {
	for _, change := range []string{"trust-revision", "final-host-lifetime", "origin-canceled", "equality-loss", "root-loss", "completion-loss"} {
		t.Run(change, func(t *testing.T) {
			servers := custodyNativeServers(t)
			s := servers[0]
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			p, err := s.custodyProducer()
			if err != nil {
				t.Fatal(err)
			}
			attempt, err := p.PrepareInitialEpoch(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer attempt.Release()
			ready, err := p.ProvisionInitialEpoch(ctx, attempt)
			if err != nil {
				t.Fatal(err)
			}
			defer ready.Release()
			command, err := ready.ImportCommand()
			if err != nil {
				t.Fatal(err)
			}
			head, err := s.db.AutomationHead(ctx)
			if err != nil {
				t.Fatal(err)
			}
			value, admission, err := p.PrepareCustodyValue(ctx, ready, contract.Decision{Sequence: head.Sequence + 1, ParentDigest: head.Digest, Command: command})
			if err != nil {
				t.Fatal(err)
			}
			defer admission.Release()
			signer, _, err := s.claimIdentity()
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "trust-revision":
				// This real writer must finish: preparation cannot hold a PKI lease across
				// its caller. Even a later permissive policy invalidates the captured view.
				if err = pki.PublishHostTrustPolicy(s.pkiDir, &s.trustRotatedPeerCerts, true); err != nil {
					t.Fatal(err)
				}
			case "final-host-lifetime":
				// The actual vote write changes the admitted lifetime inside the same SQL
				// transaction, after initial native admission and before final COMMIT.
				if _, err = s.db.DB().ExecContext(ctx, `CREATE TRIGGER custody_lifetime_at_vote AFTER INSERT ON local_recovery_claims BEGIN UPDATE hosts SET created_at='2026-10-02T00:00:00Z' WHERE name='a'; END`); err != nil {
					t.Fatal(err)
				}
			case "root-loss":
				root := filepath.Join(s.dataDir, "automation-custody")
				if err = os.Rename(root, root+"-lost"); err != nil {
					t.Fatal(err)
				}
			case "equality-loss", "completion-loss":
				removed := 0
				err = filepath.WalkDir(filepath.Join(s.dataDir, "automation-custody"), func(path string, entry os.DirEntry, walkErr error) error {
					if walkErr != nil {
						return walkErr
					}
					if entry.IsDir() {
						return nil
					}
					remove := change == "completion-loss" && entry.Name() == "completion"
					if change == "equality-loss" && entry.Name() == "material" {
						raw, e := os.ReadFile(path)
						if e != nil {
							return e
						}
						var record struct{ Purpose string }
						if json.Unmarshal(raw, &record) != nil {
							return fmt.Errorf("fixture material record malformed")
						}
						remove = record.Purpose == "equality"
					}
					if remove {
						if e := os.Remove(path); e != nil {
							return e
						}
						removed++
					}
					return nil
				})
				if err != nil || removed == 0 {
					t.Fatalf("material loss fixture: removed=%d err=%v", removed, err)
				}
			case "origin-canceled":
				cancel()
			}
			key, _ := corrosion.AutomationClaimKey(2)
			ballot := corrosion.Ballot{Round: 3, Coordinator: "a", Nonce: []byte{2}}
			result, err := s.db.ClaimAcceptKeyNative(context.Background(), key, ballot, value, 1, signer, admission)
			if result.Accepted || result.Accept != nil {
				t.Fatalf("changed predicate published first acceptance: %v", err)
			}
			state, found, e := s.db.ClaimState(context.Background(), key)
			if e != nil || found && state.Accept != nil {
				t.Fatalf("refused native vote survived rollback: %v", e)
			}
			again, e := s.db.ClaimAcceptKeyNative(context.Background(), key, ballot, value, 1, signer, admission)
			if e != nil || again.Accepted {
				t.Fatal("failed native call restored its consumed capability")
			}
		})
	}
}

func TestAutomationCustodyEngineInitialActivationSeededPrerequisites(t *testing.T) {
	servers := custodyNativeServers(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	p, err := servers[0].custodyProducer()
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := p.PrepareInitialEpoch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer attempt.Release()
	ready, err := p.ProvisionInitialEpoch(ctx, attempt)
	if err != nil {
		t.Fatal(err)
	}
	defer ready.Release()
	engine, err := servers[0].AutomationEngine()
	if err != nil {
		t.Fatal(err)
	}
	receipt, decision, err := engine.SubmitInitialKeyEpoch(ctx, ready)
	if err != nil || receipt.Code != "" || receipt.Sequence != 3 || decision.Sequence != 3 || decision.Command.Kind != "activate_key_epoch" {
		t.Fatalf("engine native two-decision activation: %+v %+v %v", receipt, decision, err)
	}
	for _, server := range servers {
		head, e := server.db.AutomationHead(ctx)
		if e != nil || head.Sequence != 3 {
			t.Fatalf("host %s did not install actual certified activation: %+v %v", server.hostName, head, e)
		}
		for seq, kind := range map[uint64]string{2: contract.CustodyImportCommand, 3: "activate_key_epoch"} {
			record, found, e := server.db.AutomationRecord(ctx, seq)
			if e != nil || !found || len(record.Certificate.Accepts) < 2 {
				t.Fatalf("missing actual majority for %s: %v", kind, e)
			}
			d, e := contract.DecodeDecision(record.Value.Automation.Envelope)
			if e != nil || d.Command.Kind != kind {
				t.Fatalf("wrong certified decision: %v", e)
			}
			original, e := server.db.AutomationRequest(ctx, corrosion.AutomationScope(d), d.Command.RequestID)
			if e != nil || original == nil || original.Receipt.Code != "" || original.Receipt.Sequence != seq {
				t.Fatalf("missing successful original: %+v %v", original, e)
			}
		}
	}
	again, original, err := engine.SubmitInitialKeyEpoch(ctx, ready)
	if err != nil || again != receipt || original.Sequence != decision.Sequence || string(original.Assignment) != string(decision.Assignment) {
		t.Fatalf("exact original retry: %+v %+v %v", again, original, err)
	}
}

// Drop only the result AFTER the real native FULL commit has completed.
type custodyLostReplyTransport struct {
	serverAutomationTransport
	nativeCalls map[int64]int
	lost        bool
}

func (t *custodyLostReplyTransport) PrepareKeyPhase2(ctx context.Context, key corrosion.ClaimKey, b corrosion.Ballot, value corrosion.ClaimValue, cfg *corrosion.VoterConfig, native *corrosion.AutomationKeyAdmission) (corrosion.Ballot, error) {
	if native != nil {
		t.nativeCalls[key.OwnerEpoch]++
	}
	stale, err := t.serverAutomationTransport.PrepareKeyPhase2(ctx, key, b, value, cfg, native)
	if err == nil && native != nil && !t.lost {
		state, found, e := t.s.db.ClaimState(ctx, key)
		if e != nil || !found || state.Accept == nil || state.ValueDigest != value.MustDigest() {
			return stale, fmt.Errorf("missing real committed first vote")
		}
		t.lost = true
		return corrosion.Ballot{}, fmt.Errorf("fixture lost native FULL reply")
	}
	return stale, err
}
func TestAutomationCustodyEngineActualLostFirstVoteReply(t *testing.T) {
	servers := custodyNativeServers(t)
	s := servers[0]
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	p, err := s.custodyProducer()
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := p.PrepareInitialEpoch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer attempt.Release()
	ready, err := p.ProvisionInitialEpoch(ctx, attempt)
	if err != nil {
		t.Fatal(err)
	}
	defer ready.Release()
	_, verifier, err := s.claimIdentity()
	if err != nil {
		t.Fatal(err)
	}
	transport := &custodyLostReplyTransport{serverAutomationTransport: serverAutomationTransport{s}, nativeCalls: map[int64]int{}}
	engine := automation.NewEngine(s.hostName, s.db, verifier, transport)
	receipt, _, err := engine.SubmitInitialKeyEpoch(ctx, ready)
	if err == nil || !transport.lost || transport.nativeCalls[2] != 1 {
		t.Fatalf("lost FULL reply must leave uncertain first call: %+v %v", receipt, err)
	}
	receipt, _, err = engine.SubmitInitialKeyEpoch(ctx, ready)
	if err != nil || receipt.Sequence != 3 || !transport.lost || transport.nativeCalls[2] != 1 || transport.nativeCalls[3] != 1 {
		t.Fatalf("real lost FULL reply recovery: %+v calls=%v lost=%v err=%v", receipt, transport.nativeCalls, transport.lost, err)
	}
	for _, server := range servers {
		h, e := server.db.AutomationHead(ctx)
		if e != nil || h.Sequence != 3 {
			t.Fatalf("missing installed activation after lost reply: %+v %v", h, e)
		}
	}
}
func TestAutomationCustodyEngineSelectedOtherBeforeImport(t *testing.T) {
	servers := custodyNativeServers(t)
	s := servers[0]
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	p, err := s.custodyProducer()
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := p.PrepareInitialEpoch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer attempt.Release()
	ready, err := p.ProvisionInitialEpoch(ctx, attempt)
	if err != nil {
		t.Fatal(err)
	}
	defer ready.Release()
	head, err := s.db.AutomationHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assignment, _ := json.Marshal(contract.Assignment{Version: 1, ClusterUID: head.ClusterUID, OperationID: "other-operation", RecordedAt: time.Now().UTC().Format(time.RFC3339Nano)})
	body, _ := contract.EncodeDecision(contract.Decision{Sequence: 2, ParentDigest: head.Digest, Command: contract.Command{Kind: "read_barrier", ClusterUID: head.ClusterUID, PrincipalID: s.hostName, RequestID: "other-original", Body: []byte(`{"version":1}`)}, Assignment: assignment})
	value := corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: body}}
	key, _ := corrosion.AutomationClaimKey(2)
	signer, _, err := s.claimIdentity()
	if err != nil {
		t.Fatal(err)
	}
	vote, err := s.db.ClaimAccept(ctx, key, corrosion.Ballot{Round: 1, Coordinator: s.hostName, Nonce: []byte{1}}, value, 1, signer, nil)
	if err != nil || !vote.Accepted || vote.Accept == nil {
		t.Fatalf("real other-value first vote: %+v %v", vote, err)
	}
	engine, err := s.AutomationEngine()
	if err != nil {
		t.Fatal(err)
	}
	receipt, _, err := engine.SubmitInitialKeyEpoch(ctx, ready)
	if err != nil || receipt.Sequence != 4 {
		t.Fatalf("selected other then original custody/activation: %+v %v", receipt, err)
	}
	original, e := s.db.AutomationRequest(ctx, corrosion.AutomationScope(contract.Decision{Command: contract.Command{Kind: "read_barrier", ClusterUID: head.ClusterUID, PrincipalID: s.hostName}}), "other-original")
	if e != nil || original == nil || original.Receipt.Sequence != 2 {
		t.Fatalf("selected other original absent: %+v %v", original, e)
	}
}

type custodyRestartFixture struct {
	ExpectedReceipt   contract.Receipt
	ExpectedDigest    string
	Material          map[string]string
	UncertainRequests []string
	Mode              string
	Data, PKI         string
	Ref               custody.CustodyProvisionRef
	Command           contract.Command
}

func TestAutomationCustodyNativeProcessRestart(t *testing.T) {
	if raw := os.Getenv("LITEVIRT_CUSTODY_NATIVE_RESTART"); raw != "" {
		var fixture custodyRestartFixture
		if err := json.Unmarshal([]byte(raw), &fixture); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		db, err := corrosion.NewLocalClient(fixture.Data, "a")
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		db.SetVoterConfigGate(func() bool { return true }) // same explicitly seeded fixture prerequisite
		server := NewServer("a", fixture.Data, fixture.PKI, db, nil, nil)
		defer server.CloseAutomationCustody()
		producer, err := server.custodyProducer()
		if err != nil {
			t.Fatal(err)
		}
		attempt, err := producer.ResumeInitialEpoch(ctx, fixture.Ref)
		if err != nil {
			t.Fatalf("native process continuation reopen: %v", err)
		}
		defer attempt.Release()
		ready, err := producer.ProvisionInitialEpoch(ctx, attempt)
		if err != nil {
			t.Fatalf("current authenticated completion after restart: %v", err)
		}
		defer ready.Release()
		command, err := ready.ImportCommand()
		if err != nil {
			t.Fatal(err)
		}
		expected, _ := contract.CanonicalCommand(fixture.Command)
		actual, _ := contract.CanonicalCommand(command)
		if command.RequestID != fixture.Command.RequestID || string(actual) != string(expected) {
			t.Fatal("restart changed immutable import request")
		}
		if fixture.Mode == "lost-plan-advanced-activation" {
			head, e := db.AutomationHead(ctx)
			if e != nil {
				t.Fatal(e)
			}
			candidate, e := ready.ActivationCommand(contract.HistoryReference{Sequence: head.Sequence, Digest: head.Digest})
			if e != nil {
				t.Fatal(e)
			}
			for _, old := range fixture.UncertainRequests {
				if candidate.RequestID == old {
					t.Fatal("restart recreated an uncertain prior activation request identity")
				}
			}
		}
		_, verifier, err := server.claimIdentity()
		if err != nil {
			t.Fatal(err)
		}
		counter := &custodyNativeCounter{serverAutomationTransport: serverAutomationTransport{server}, calls: map[int64]int{}}
		engine := automation.NewEngine(server.hostName, db, verifier, counter)
		receipt, decision, err := engine.SubmitInitialKeyEpoch(ctx, ready)
		wantSequence := uint64(3)
		if fixture.Mode == "lost-advanced-activation" || fixture.Mode == "lost-plan-advanced-activation" || fixture.Mode == "certified-advanced-activation" {
			wantSequence = 4
		}
		if err != nil || receipt.Sequence != wantSequence {
			t.Fatalf("native process restart activation: %+v %v", receipt, err)
		}
		assignment, err := contract.DecodeAssignment(decision)
		if err != nil || assignment.KeyTransition == nil || len(assignment.KeyTransition.Recipients) == 0 {
			t.Fatal("selected original assignment missing")
		}
		imported := assignment.KeyTransition.Recipients[0].RecipientAck
		altered := decision
		altered.Command.RequestID += "-forged"
		if err = ready.ConfirmActivationOriginal(ctx, imported, receipt, altered); err == nil {
			t.Fatal("caller supplied decision became original authority")
		}
		wantImport, wantActivation := 1, 1
		if fixture.Mode != "physical" {
			wantImport = 0
		}
		if strings.HasPrefix(fixture.Mode, "certified-") || fixture.Mode == "lost-activation" || (fixture.Mode == "lost-advanced-activation" || fixture.Mode == "lost-plan-advanced-activation" || fixture.Mode == "certified-advanced-activation") {
			wantActivation = 0
		}
		if counter.calls[2] != wantImport || counter.calls[int64(wantSequence)] != wantActivation {
			t.Fatalf("restart refreshed native authority: calls=%v expected=%d/%d", counter.calls, wantImport, wantActivation)
		}
		again, original, err := engine.SubmitInitialKeyEpoch(ctx, ready)
		if err != nil || again != receipt || original.Command.RequestID != decision.Command.RequestID {
			t.Fatalf("restarted selected original retry: %+v %v", again, err)
		}

		if strings.HasPrefix(fixture.Mode, "certified-") {
			if len(counter.calls) != 0 {
				t.Fatalf("historical recovery issued native votes: %v", counter.calls)
			}
			encoded, e := contract.EncodeDecision(decision)
			if e != nil || receipt != fixture.ExpectedReceipt || contract.CiphertextDigest(encoded) != fixture.ExpectedDigest {
				t.Fatal("certified original changed across fresh process", e)
			}
			if !reflect.DeepEqual(custodyMaterialHashes(t, fixture.Data), fixture.Material) {
				t.Fatal("historical recovery changed physical material or inert refs")
			}
			if fresh, e := producer.PrepareInitialEpoch(ctx); e == nil || fresh != nil {
				t.Fatal("certified historical recovery became fresh preparation")
			}
		}
		return
	}
	for _, mode := range []string{"physical", "after-import", "lost-activation", "lost-advanced-activation", "lost-plan-advanced-activation", "certified-activation", "certified-advanced-activation"} {
		t.Run(mode, func(t *testing.T) {
			wantSequence := uint64(3)
			if mode == "lost-advanced-activation" || mode == "lost-plan-advanced-activation" || mode == "certified-advanced-activation" {
				wantSequence = 4
			}
			servers := custodyNativeServers(t)
			server := servers[0]
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			producer, err := server.custodyProducer()
			if err != nil {
				t.Fatal(err)
			}
			attempt, err := producer.PrepareInitialEpoch(ctx)
			if err != nil {
				t.Fatal(err)
			}
			ref, err := attempt.Continuation()
			if err != nil {
				t.Fatal(err)
			}
			ready, err := producer.ProvisionInitialEpoch(ctx, attempt)
			if err != nil {
				t.Fatal(err)
			}
			command, err := ready.ImportCommand()
			if err != nil {
				t.Fatal(err)
			}
			var certifiedReceipt contract.Receipt
			var certifiedDigest string
			if mode != "physical" {
				_, verifier, e := server.claimIdentity()
				if e != nil {
					t.Fatal(e)
				}
				transport := &custodyStopActivationTransport{serverAutomationTransport: serverAutomationTransport{server}, lose: mode == "lost-activation"}
				engine := automation.NewEngine(server.hostName, server.db, verifier, transport)
				var advanced *custodyAdvancedLostTransport
				if mode == "lost-advanced-activation" || mode == "lost-plan-advanced-activation" || mode == "certified-advanced-activation" {
					advanced = &custodyAdvancedLostTransport{custodyOtherActivationTransport: custodyOtherActivationTransport{serverAutomationTransport: serverAutomationTransport{server}, ready: ready, scenario: ctx, trace: t}}
					engine = automation.NewEngine(server.hostName, server.db, verifier, advanced)
				}

				callCtx := ctx
				var lost *custodyCertifiedLostTransport
				if strings.HasPrefix(mode, "certified-") {
					var cancelReply context.CancelFunc
					callCtx, cancelReply = context.WithCancel(ctx)
					defer cancelReply()
					lost = &custodyCertifiedLostTransport{custodyOtherActivationTransport: custodyOtherActivationTransport{serverAutomationTransport: serverAutomationTransport{server}, ready: ready, scenario: ctx, trace: t}, advanced: mode == "certified-advanced-activation", cancel: cancelReply}
					engine = automation.NewEngine(server.hostName, server.db, verifier, lost)
				}
				_, _, submitErr := engine.SubmitInitialKeyEpoch(callCtx, ready)
				if submitErr == nil {
					t.Fatal("fixture did not stop at activation boundary")
				}
				t.Logf("custody restart mode=%s submit=%v scenario=(%s) call=(%s)", mode, submitErr, custodyScenarioContext(ctx), custodyScenarioContext(callCtx))
				if lost != nil {
					t.Logf("custody certified cut installed=%d injection=%v failure=%v", lost.installed, lost.injected, lost.failure)
				} else if advanced != nil {
					t.Logf("custody advanced cut reached=%v injection=%v failure=%v", advanced.cutReached, advanced.injected, advanced.failure)
				} else {
					t.Logf("custody activation cut reached=%v", transport.cutReached)
				}
				head, e := server.db.AutomationHead(ctx)

				expectedHead := wantSequence - 1
				if lost != nil {
					expectedHead = wantSequence
				}
				if e != nil || head.Sequence != expectedHead {
					t.Fatalf("import was not certified before restart: %+v %v; actual submit=%v scenario=(%s)", head, e, submitErr, custodyScenarioContext(ctx))
				}

				if lost == nil && ((advanced != nil && (!advanced.cutReached || advanced.failure != nil)) || (advanced == nil && !transport.cutReached)) {
					t.Fatalf("restart did not reach intended activation cut: %v", submitErr)
				}
				if lost != nil {
					if lost.failure != nil {
						t.Fatalf("certified restart intervening setup failed: %v", lost.failure)
					}
					if lost.installed != 2 {
						t.Fatal("did not lose reply after local and both remote FULL installs")
					}
					record, found, e := server.db.AutomationRecord(ctx, wantSequence)
					if e != nil || !found {
						t.Fatal("certified activation missing", e)
					}
					decision, e := contract.DecodeDecision(record.Value.Automation.Envelope)
					if e != nil {
						t.Fatal(e)
					}
					original, e := server.db.AutomationRequest(ctx, corrosion.AutomationScope(decision), decision.Command.RequestID)
					if e != nil || original == nil || original.Receipt.Code != "" {
						t.Fatal("certified original missing", e)
					}
					certifiedReceipt = original.Receipt
					encoded, e := contract.EncodeDecision(decision)
					if e != nil {
						t.Fatal(e)
					}
					certifiedDigest = contract.CiphertextDigest(encoded)
				}
				key, _ := corrosion.AutomationClaimKey(wantSequence)
				state, found, e := server.db.ClaimState(ctx, key)
				if e != nil {
					t.Fatal(e)
				}
				committed := found && state.Accept != nil
				if committed != (strings.HasPrefix(mode, "certified-") || mode == "lost-activation" || (mode == "lost-advanced-activation" || mode == "lost-plan-advanced-activation" || mode == "certified-advanced-activation")) {
					t.Fatalf("actual activation FULL boundary differs: committed=%v", committed)
				}
			}
			var uncertain []string
			if mode == "lost-plan-advanced-activation" {
				err = filepath.WalkDir(filepath.Join(server.dataDir, "automation-custody"), func(path string, entry os.DirEntry, walkErr error) error {
					if walkErr != nil {
						return walkErr
					}
					if entry.IsDir() || entry.Name() != "plan" {
						return nil
					}
					raw, e := os.ReadFile(path)
					if e != nil {
						return e
					}
					var record struct{ Body []byte }
					if json.Unmarshal(raw, &record) != nil {
						return fmt.Errorf("fixture invalid plan")
					}
					var command contract.Command
					if json.Unmarshal(record.Body, &command) == nil && command.Kind == "activate_key_epoch" {
						uncertain = append(uncertain, command.RequestID)
						return os.Remove(path)
					}
					return nil
				})
				if err != nil || len(uncertain) != 2 {
					t.Fatalf("activation intent loss fixture: %d %v", len(uncertain), err)
				}
			}
			ready.Release()
			attempt.Release()
			if err = producer.Close(); err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(custodyRestartFixture{ExpectedReceipt: certifiedReceipt, ExpectedDigest: certifiedDigest, Material: custodyMaterialHashes(t, server.dataDir), UncertainRequests: uncertain, Mode: mode, Data: server.dataDir, PKI: server.pkiDir, Ref: ref, Command: command})
			if err != nil {
				t.Fatal(err)
			}
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAutomationCustodyNativeProcessRestart$", "-test.timeout=18s")
			child.Env = append(os.Environ(), "LITEVIRT_CUSTODY_NATIVE_RESTART="+string(raw))
			if out, err := child.CombinedOutput(); err != nil {
				t.Fatalf("native child restart failed: %v %s", err, out)
			}
			for _, s := range servers {
				head, e := s.db.AutomationHead(ctx)
				if e != nil || head.Sequence != wantSequence {
					t.Fatalf("process restart did not install actual activation on %s: %+v %v", s.hostName, head, e)
				}
			}
		})
	}
}

type custodyOtherActivationTransport struct {
	serverAutomationTransport
	ready                 *corrosion.AutomationCustodyReady
	old                   contract.Command
	injected              bool
	failure               error
	scenario              context.Context
	cancelInstalled       bool
	installedThenCanceled bool
	trace                 *testing.T
}

func custodyScenarioContext(ctx context.Context) string {
	deadline, ok := ctx.Deadline()
	if !ok {
		return fmt.Sprintf("err=%v deadline=absent", ctx.Err())
	}
	return fmt.Sprintf("err=%v remaining=%s", ctx.Err(), time.Until(deadline))
}

func (t *custodyOtherActivationTransport) observe(phase, voter string, sequence int64, started time.Time, ctx context.Context, err error) {
	if t.trace != nil {
		t.trace.Logf("custody stage=%s voter=%s sequence=%d elapsed=%s context=(%s) error=%v", phase, voter, sequence, time.Since(started), custodyScenarioContext(ctx), err)
	}
}

func (t *custodyOtherActivationTransport) Prepare(ctx context.Context, voter string, key corrosion.ClaimKey, ballot corrosion.Ballot, generation int64, evidence *corrosion.SupersedeEvidence) (corrosion.PrepareResult, error) {
	started := time.Now()
	result, err := t.serverAutomationTransport.Prepare(ctx, voter, key, ballot, generation, evidence)
	t.observe("prepare", voter, key.OwnerEpoch, started, ctx, err)
	return result, err
}

func (t *custodyOtherActivationTransport) Accept(ctx context.Context, voter string, key corrosion.ClaimKey, ballot corrosion.Ballot, value corrosion.ClaimValue, generation int64) (corrosion.AcceptResult, error) {
	started := time.Now()
	result, err := t.serverAutomationTransport.Accept(ctx, voter, key, ballot, value, generation)
	t.observe("accept", voter, key.OwnerEpoch, started, ctx, err)
	if t.trace != nil {
		t.trace.Logf("custody accept voter=%s sequence=%d accepted=%v refusal=%s", voter, key.OwnerEpoch, result.Accepted, result.Refusal)
	}
	return result, err
}

func (t *custodyOtherActivationTransport) PrepareKeyPhase2(ctx context.Context, key corrosion.ClaimKey, ballot corrosion.Ballot, value corrosion.ClaimValue, cfg *corrosion.VoterConfig, native *corrosion.AutomationKeyAdmission) (corrosion.Ballot, error) {
	started := time.Now()
	stale, err := t.serverAutomationTransport.PrepareKeyPhase2(ctx, key, ballot, value, cfg, native)
	t.observe("key-phase2", t.s.hostName, key.OwnerEpoch, started, ctx, err)
	if t.trace != nil {
		t.trace.Logf("custody phase2 sequence=%d native=%v", key.OwnerEpoch, native != nil)
	}
	return stale, err
}

func (t *custodyOtherActivationTransport) Install(ctx context.Context, voter string, record corrosion.AutomationRecord) error {
	var cancelInstalled context.CancelFunc
	if t.cancelInstalled {
		ctx, cancelInstalled = context.WithCancel(ctx)
		defer cancelInstalled()
	}
	started := time.Now()
	installErr := t.serverAutomationTransport.Install(ctx, voter, record)
	t.observe("install", voter, record.Certificate.Key.OwnerEpoch, started, ctx, installErr)
	if installErr != nil {
		return installErr
	}
	d, err := contract.DecodeDecision(record.Value.Automation.Envelope)
	if err != nil || d.Sequence != 2 || d.Command.Kind != contract.CustodyImportCommand || t.injected {
		return err
	}
	t.injected = true
	if cancelInstalled != nil {
		cancelInstalled()
		t.installedThenCanceled = ctx.Err() == context.Canceled
	}
	t.old, err = t.ready.ActivationCommand(contract.HistoryReference{Sequence: 2, Digest: record.Value.MustDigest()})
	if err != nil {
		t.failure = err
		return err
	}
	assignment, _ := json.Marshal(contract.Assignment{Version: 1, ClusterUID: d.Command.ClusterUID, OperationID: "between-import-activation", RecordedAt: time.Now().UTC().Format(time.RFC3339Nano)})
	body, err := contract.EncodeDecision(contract.Decision{Sequence: 3, ParentDigest: record.Value.MustDigest(), Command: contract.Command{Kind: "read_barrier", ClusterUID: d.Command.ClusterUID, PrincipalID: t.s.hostName, RequestID: "between-original", Body: []byte(`{"version":1}`)}, Assignment: assignment})
	if err != nil {
		t.failure = err
		return err
	}
	value := corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: body}}
	key, _ := corrosion.AutomationClaimKey(3)
	signer, _, err := t.s.claimIdentity()
	if err != nil {
		t.failure = err
		return err
	}
	// This is a distinct local competing proposal after the real Install RPC.
	// Its existing scenario deadline owns it; the completed RPC cannot cancel it.
	if t.scenario == nil {
		t.failure = fmt.Errorf("intervening fixture requires bounded scenario context")
		return t.failure
	}
	if _, bounded := t.scenario.Deadline(); !bounded {
		t.failure = fmt.Errorf("intervening fixture requires bounded scenario context")
		return t.failure
	}
	started = time.Now()
	vote, err := t.s.db.ClaimAccept(t.scenario, key, corrosion.Ballot{Round: 1, Coordinator: t.s.hostName, Nonce: []byte{1}}, value, 1, signer, nil)
	t.observe("intervening-local-accept", t.s.hostName, key.OwnerEpoch, started, t.scenario, err)
	if err != nil || !vote.Accepted || vote.Accept == nil {
		t.failure = fmt.Errorf("actual intervening first vote: %+v %v", vote, err)
		return t.failure
	}
	return nil
}

// The competing proposal belongs to the scenario, after a completed real RPC.
// Canceling that completed RPC must not cancel the independent local first vote.
func TestAutomationCustodyInterveningSetupContext(t *testing.T) {
	servers := custodyNativeServers(t)
	s := servers[0]
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	p, err := s.custodyProducer()
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := p.PrepareInitialEpoch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer attempt.Release()
	ready, err := p.ProvisionInitialEpoch(ctx, attempt)
	if err != nil {
		t.Fatal(err)
	}
	defer ready.Release()
	_, verifier, err := s.claimIdentity()
	if err != nil {
		t.Fatal(err)
	}
	transport := &custodyOtherActivationTransport{serverAutomationTransport: serverAutomationTransport{s}, ready: ready, scenario: ctx, trace: t, cancelInstalled: true}
	engine := automation.NewEngine(s.hostName, s.db, verifier, transport)
	receipt, decision, submitErr := engine.SubmitInitialKeyEpoch(ctx, ready)
	if !transport.installedThenCanceled || ctx.Err() != nil {
		t.Fatalf("control did not complete real Install then cancel only its child context: installed=%v scenario=%v", transport.installedThenCanceled, ctx.Err())
	}
	if transport.failure != nil {
		t.Fatalf("completed Install context canceled independent intervening vote: %v", transport.failure)
	}
	key, _ := corrosion.AutomationClaimKey(3)
	state, found, err := s.db.ClaimState(ctx, key)
	if err != nil || !found || state.Accept == nil || state.Value == nil {
		t.Fatalf("independent intervening FULL vote absent: found=%v err=%v", found, err)
	}
	intervening, err := contract.DecodeDecision(state.Value.Automation.Envelope)
	if err != nil || intervening.Command.Kind != "read_barrier" || intervening.Command.RequestID != "between-original" {
		t.Fatal("independent intervening vote changed", err)
	}
	remote, err := servers[1].db.AutomationHead(ctx)
	if err != nil || remote.Sequence < 2 {
		t.Fatalf("real delegated import Install absent: %+v %v", remote, err)
	}
	if submitErr != nil || receipt.Sequence != 4 || decision.Command.RequestID == transport.old.RequestID {
		t.Fatalf("activation after independently committed intervening vote: %+v %v", receipt, submitErr)
	}
}

func TestAutomationCustodyEngineActivationPrefixChange(t *testing.T) {
	servers := custodyNativeServers(t)
	s := servers[0]
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	p, err := s.custodyProducer()
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := p.PrepareInitialEpoch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer attempt.Release()
	ready, err := p.ProvisionInitialEpoch(ctx, attempt)
	if err != nil {
		t.Fatal(err)
	}
	defer ready.Release()
	_, verifier, err := s.claimIdentity()
	if err != nil {
		t.Fatal(err)
	}
	transport := &custodyOtherActivationTransport{serverAutomationTransport: serverAutomationTransport{s}, ready: ready, scenario: ctx, trace: t}
	engine := automation.NewEngine(s.hostName, s.db, verifier, transport)
	receipt, decision, err := engine.SubmitInitialKeyEpoch(ctx, ready)
	if transport.failure != nil || !transport.injected {
		t.Fatalf("intervening value setup: %v", transport.failure)
	}
	if err != nil || receipt.Sequence != 4 || decision.Command.RequestID == transport.old.RequestID {
		t.Fatalf("activation must resolve old intent then use a new identity at changed prefix: %+v %v", receipt, err)
	}
	old, err := s.db.AutomationRequest(ctx, corrosion.AutomationScope(contract.Decision{Command: transport.old}), transport.old.RequestID)
	if err != nil || old != nil {
		t.Fatalf("retired unchosen activation request acquired original: %+v %v", old, err)
	}
	var body contract.ActivateKeyEpochBody
	if json.Unmarshal(decision.Command.Body, &body) != nil || body.Prefix.Sequence != 3 {
		t.Fatal("activation did not bind actual new prefix")
	}
	again, original, err := engine.SubmitInitialKeyEpoch(ctx, ready)
	if err != nil || again != receipt || original.Command.RequestID != decision.Command.RequestID {
		t.Fatalf("changed-prefix original retry: %+v %v", again, err)
	}
}
func TestAutomationCustodyNativeResumeRefusals(t *testing.T) {
	for _, mode := range []string{"missing-root", "symlink-root", "wrong-reference", "uncertain-source"} {
		t.Run(mode, func(t *testing.T) {
			servers := custodyNativeServers(t)
			s := servers[0]
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			p, err := s.custodyProducer()
			if err != nil {
				t.Fatal(err)
			}
			attempt, err := p.PrepareInitialEpoch(ctx)
			if err != nil {
				t.Fatal(err)
			}
			ref, err := attempt.Continuation()
			if err != nil {
				t.Fatal(err)
			}
			if mode != "uncertain-source" {
				ready, e := p.ProvisionInitialEpoch(ctx, attempt)
				if e != nil {
					t.Fatal(e)
				}
				ready.Release()
			}
			attempt.Release()
			if err = p.Close(); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(s.dataDir, "automation-custody")
			switch mode {
			case "missing-root", "symlink-root":
				old := filepath.Join(s.dataDir, "old-custody")
				if err = os.Rename(root, old); err != nil {
					t.Fatal(err)
				}
				if mode == "symlink-root" {
					if err = os.Symlink(old, root); err != nil {
						t.Fatal(err)
					}
				}
			case "wrong-reference":
				ref.Attempt += "-wrong"
			}
			reopened, err := corrosion.NewAutomationCustodyProducer(s.db, s.pkiDir, root)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			resumed, err := reopened.ResumeInitialEpoch(ctx, ref)
			if err == nil || resumed != nil {
				t.Fatal("unsafe continuation resumed")
			}
			if mode == "missing-root" {
				if _, err = os.Lstat(root); !os.IsNotExist(err) {
					t.Fatal("missing root was regenerated")
				}
			}
			head, e := s.db.AutomationHead(ctx)
			if e != nil || head.Sequence != 1 {
				t.Fatal("restart refusal changed semantic authority")
			}
		})
	}
}

type custodyNativeCounter struct {
	serverAutomationTransport
	calls map[int64]int
}

func (t *custodyNativeCounter) PrepareKeyPhase2(ctx context.Context, key corrosion.ClaimKey, b corrosion.Ballot, value corrosion.ClaimValue, cfg *corrosion.VoterConfig, native *corrosion.AutomationKeyAdmission) (corrosion.Ballot, error) {
	if native != nil {
		t.calls[key.OwnerEpoch]++
	}
	return t.serverAutomationTransport.PrepareKeyPhase2(ctx, key, b, value, cfg, native)
}

type custodyStopActivationTransport struct {
	serverAutomationTransport
	lose       bool
	cutReached bool
}

func (t *custodyStopActivationTransport) PrepareKeyPhase2(ctx context.Context, key corrosion.ClaimKey, b corrosion.Ballot, value corrosion.ClaimValue, cfg *corrosion.VoterConfig, native *corrosion.AutomationKeyAdmission) (corrosion.Ballot, error) {
	d, err := contract.DecodeDecision(value.Automation.Envelope)
	if err != nil {
		return corrosion.Ballot{}, err
	}
	if d.Command.Kind != "activate_key_epoch" {
		return t.serverAutomationTransport.PrepareKeyPhase2(ctx, key, b, value, cfg, native)
	}
	if !t.lose {
		t.cutReached = true
		return corrosion.Ballot{}, fmt.Errorf("fixture stop before activation vote")
	}
	stale, err := t.serverAutomationTransport.PrepareKeyPhase2(ctx, key, b, value, cfg, native)
	if err != nil {
		return stale, err
	}
	t.cutReached = true
	return corrosion.Ballot{}, fmt.Errorf("fixture lost committed activation vote reply")
}

func TestAutomationCustodyNativeResumePreservesOriginalExpiry(t *testing.T) {
	servers := custodyNativeServers(t)
	s := servers[0]
	original, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	p, err := s.custodyProducer()
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := p.PrepareInitialEpoch(original)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := attempt.Continuation()
	if err != nil {
		t.Fatal(err)
	}
	ready, err := p.ProvisionInitialEpoch(original, attempt)
	if err != nil {
		t.Fatal(err)
	}
	ready.Release()
	attempt.Release()
	if err = p.Close(); err != nil {
		t.Fatal(err)
	}
	<-original.Done()
	resumedOwner, err := corrosion.NewAutomationCustodyProducer(s.db, s.pkiDir, filepath.Join(s.dataDir, "automation-custody"))
	if err != nil {
		t.Fatal(err)
	}
	defer resumedOwner.Close()
	fresh, cancelFresh := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFresh()
	resumed, err := resumedOwner.ResumeInitialEpoch(fresh, ref)
	if err == nil || resumed != nil {
		t.Fatal("restart extended original expiry")
	}
}

func TestAutomationCustodyNativeCertifiedResumePreservesOriginalExpiry(t *testing.T) {
	servers := custodyNativeServers(t)
	s := servers[0]
	original, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	p, err := s.custodyProducer()
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := p.PrepareInitialEpoch(original)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := attempt.Continuation()
	if err != nil {
		t.Fatal(err)
	}
	ready, err := p.ProvisionInitialEpoch(original, attempt)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := s.AutomationEngine()
	if err != nil {
		t.Fatal(err)
	}
	receipt, decision, err := engine.SubmitInitialKeyEpoch(original, ready)
	if err != nil || receipt.Sequence != 3 {
		t.Fatalf("certified expiry fixture did not activate: receipt=%+v error=%v original=(%s)", receipt, err, custodyScenarioContext(original))
	}
	ready.Release()
	attempt.Release()
	if err = p.Close(); err != nil {
		t.Fatal(err)
	}
	<-original.Done()
	resumedOwner, err := corrosion.NewAutomationCustodyProducer(s.db, s.pkiDir, filepath.Join(s.dataDir, "automation-custody"))
	if err != nil {
		t.Fatal(err)
	}
	defer resumedOwner.Close()
	fresh, cancelFresh := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFresh()
	resumed, err := resumedOwner.ResumeInitialEpoch(fresh, ref)
	if err == nil || resumed != nil {
		t.Fatal("certified history renewed expired continuation")
	}
	recorded, err := s.db.AutomationRequest(fresh, corrosion.AutomationScope(decision), decision.Command.RequestID)
	if err != nil || recorded == nil || recorded.Receipt != receipt {
		t.Fatal("expired preparation erased historical original", err)
	}
	if attempt, err := resumedOwner.PrepareInitialEpoch(fresh); err == nil || attempt != nil {
		t.Fatal("expired certified result became fresh initial issuance")
	}

}

type custodyAdvancedLostTransport struct {
	custodyOtherActivationTransport
	cutReached bool
}

func (t *custodyAdvancedLostTransport) PrepareKeyPhase2(ctx context.Context, key corrosion.ClaimKey, b corrosion.Ballot, value corrosion.ClaimValue, cfg *corrosion.VoterConfig, native *corrosion.AutomationKeyAdmission) (corrosion.Ballot, error) {
	stale, err := t.custodyOtherActivationTransport.PrepareKeyPhase2(ctx, key, b, value, cfg, native)
	if err != nil {
		return stale, err
	}
	d, err := contract.DecodeDecision(value.Automation.Envelope)
	if err != nil {
		return stale, err
	}
	if d.Command.Kind == "activate_key_epoch" {
		t.cutReached = true
		return corrosion.Ballot{}, fmt.Errorf("fixture lost advanced activation FULL reply")
	}
	return stale, nil
}

// Every activation Install follows the engine's local certified FULL apply.
// Cancel only after both real remote installs: the caller gets no receipt.
type custodyCertifiedLostTransport struct {
	custodyOtherActivationTransport
	advanced  bool
	cancel    context.CancelFunc
	installed int
}

func (t *custodyCertifiedLostTransport) Install(ctx context.Context, voter string, record corrosion.AutomationRecord) error {
	var err error
	if t.advanced {
		err = t.custodyOtherActivationTransport.Install(ctx, voter, record)
	} else {
		err = t.serverAutomationTransport.Install(ctx, voter, record)
	}
	if err != nil {
		return err
	}
	d, err := contract.DecodeDecision(record.Value.Automation.Envelope)
	if err != nil {
		return err
	}
	if d.Command.Kind == "activate_key_epoch" {
		t.installed++
		if t.installed == 2 {
			t.cancel()
		}
	}
	return nil
}
func custodyMaterialHashes(t *testing.T, data string) map[string]string {
	t.Helper()
	root := filepath.Join(data, "automation-custody")
	out := map[string]string{}
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		out[rel] = fmt.Sprintf("%x", sha256.Sum256(raw))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAutomationCustodyKeyEvidenceFinalAuthority(t *testing.T) {
	servers := custodyNativeServers(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	p, err := servers[0].custodyProducer()
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := p.PrepareInitialEpoch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer attempt.Release()
	ready, err := p.ProvisionInitialEpoch(ctx, attempt)
	if err != nil {
		t.Fatal(err)
	}
	defer ready.Release()
	command, err := ready.ImportCommand()
	if err != nil {
		t.Fatal(err)
	}
	head, err := servers[0].db.AutomationHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	base := contract.Decision{Sequence: head.Sequence + 1, ParentDigest: head.Digest, Command: command}
	value, admission, err := p.PrepareCustodyValue(ctx, ready, base)
	if err != nil || admission == nil {
		t.Fatalf("native key admission unavailable: %v", err)
	}
	defer admission.Release()
	key, _ := corrosion.AutomationClaimKey(base.Sequence)
	ballot := corrosion.Ballot{Round: 3, Coordinator: "a", Nonce: []byte{2}}
	signer, _, err := servers[0].claimIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if result, e := servers[0].db.ClaimAccept(ctx, key, ballot, value, 1, signer, nil); e != nil || result.Accepted || result.Refusal != corrosion.RefusalAutomationUnavailable {
		t.Fatalf("naked key accept: %+v %v", result, e)
	}
	result, err := servers[0].db.ClaimAcceptKeyNative(ctx, key, ballot, value, 1, signer, admission)
	if err != nil || !result.Accepted || result.Accept == nil {
		t.Fatalf("native first FULL acceptance unavailable: %+v %v", result, err)
	}
	if again, e := servers[0].db.ClaimAcceptKeyNative(ctx, key, ballot, value, 1, signer, admission); e != nil || again.Accepted {
		t.Fatalf("consumed native key admission reusable: %+v %v", again, e)
	}
	state, found, err := servers[0].db.ClaimState(ctx, key)
	if err != nil || !found || state.Accept == nil || state.ValueDigest != value.MustDigest() {
		t.Fatalf("native acceptance not durably stored: %v", err)
	}
	// Change actual authority only when the remote vote is being saved, after
	// initial evidence admission. Final revalidation must roll back both writes.
	remoteDB := servers[1].db
	if _, err = remoteDB.DB().ExecContext(ctx, `CREATE TRIGGER custody_evidence_authority_at_vote AFTER INSERT ON local_recovery_claims BEGIN UPDATE local_automation_authority SET generation=2 WHERE id=1; END`); err != nil {
		t.Fatal(err)
	}
	remote, err := (serverClaimTransport{servers[0]}).Accept(ctx, "b", key, ballot, value, 1)
	if remote.Accepted || remote.Accept != nil {
		t.Fatalf("changed final evidence authority published vote: %+v %v", remote, err)
	}
	retained, found, e := remoteDB.ClaimState(ctx, key)
	if e != nil || found && retained.Accept != nil {
		t.Fatalf("refused evidence vote survived rollback: %+v %v", retained, e)
	}
	authority, e := remoteDB.Query(ctx, `SELECT generation FROM local_automation_authority WHERE id=1`)
	if e != nil || len(authority) != 1 || authority[0].Int64("generation") != 1 {
		t.Fatal("authority mutation escaped rollback", e)
	}
	if _, err = remoteDB.DB().ExecContext(ctx, `DROP TRIGGER custody_evidence_authority_at_vote`); err != nil {
		t.Fatal(err)
	}
	// The same actual stored first vote is sufficient once the fault is removed.
	remote, err = (serverClaimTransport{servers[0]}).Accept(ctx, "b", key, ballot, value, 1)
	if err != nil || !remote.Accepted || remote.Accept == nil {
		t.Fatalf("restored real evidence did not commit: %+v %v", remote, err)
	}
	retained, found, e = remoteDB.ClaimState(ctx, key)
	if e != nil || !found || retained.Accept == nil || retained.ValueDigest != value.MustDigest() {
		t.Fatal("restored remote committed vote missing", e)
	}
}
