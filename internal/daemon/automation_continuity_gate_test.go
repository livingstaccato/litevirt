package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/pki"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type continuityNode struct {
	d              *Daemon
	s              *grpcapi.Server
	signer         *corrosion.ClaimSigner
	verifier       *corrosion.ClaimVerifier
	grpc           *grpc.Server
	listener       net.Listener
	done           chan struct{}
	inc            string
	dbdir, ca, key string
	pings, acks    atomic.Int32
}

func (n *continuityNode) stop() { n.grpc.Stop(); _ = n.listener.Close(); <-n.done }

// Only the initial certified identity/custody is a prerequisite fixture. The
// continuity lineage below starts at real Login, native gate, and FULL Accept.
func continuityDaemonCluster(t *testing.T) []*continuityNode {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	ca, key := filepath.Join(root, "ca.crt"), filepath.Join(root, "ca.key")
	if err := pki.GenerateCA(ca, key); err != nil {
		t.Fatal(err)
	}
	caBytes, err := os.ReadFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	var nodes []*continuityNode
	for _, name := range []string{"a", "b", "c"} {
		dir := filepath.Join(root, name)
		if err = os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, "ca.crt"), caBytes, 0600); err != nil {
			t.Fatal(err)
		}
		if err = pki.GenerateHostCert(ca, key, filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"), name, net.ParseIP("127.0.0.1")); err != nil {
			t.Fatal(err)
		}
		dbdir := t.TempDir()
		db, err := corrosion.NewLocalClient(dbdir, name)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		if err = corrosion.InitSchema(ctx, db); err != nil {
			t.Fatal(err)
		}
		db.SetVoterConfigGate(func() bool { return true })
		db.SetUserIncarnationGate(func() bool { return true })
		db.SetClusterPolicyGate(func() bool { return true })
		inc, err := db.VoterIncarnation(ctx)
		if err != nil {
			t.Fatal(err)
		}
		n := &continuityNode{inc: inc, dbdir: dbdir, ca: ca, key: key}
		n.signer, err = corrosion.LoadClaimSigner(dir, name)
		if err != nil {
			t.Fatal(err)
		}
		n.verifier, err = corrosion.LoadClaimVerifier(dir)
		if err != nil {
			t.Fatal(err)
		}
		data := t.TempDir()
		checker := health.NewChecker(name, dir, db)
		checker.SetActivationMarker(health.ActivationMarkerBase(data))
		n.d = &Daemon{cfg: &Config{HostName: name, PKIDir: dir, DataDir: data, AdvertiseAddress: "127.0.0.1"}, db: db, checker: checker}
		n.d.buildServer = func() *grpcapi.Server {
			return grpcapi.NewServerForTests(grpcapi.TestServerOpts{HostName: name, PKIDir: dir, DataDir: data, DB: n.d.db})
		}
		n.s = n.d.newServer() // actual production wiring of gate AND typed restorer
		tls, err := pki.ServerTLSConfig(dir)
		if err != nil {
			t.Fatal(err)
		}
		n.listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		n.grpc = grpc.NewServer(grpc.Creds(credentials.NewTLS(tls)), grpc.ChainUnaryInterceptor(n.s.UnaryAuthInterceptor), grpc.ChainStreamInterceptor(n.s.StreamAuthInterceptor))
		n.s.RegisterServices(n.grpc)
		n.done = make(chan struct{})
		go func() { defer close(n.done); _ = n.grpc.Serve(n.listener) }()
		t.Cleanup(n.stop)
		nodes = append(nodes, n)
	}
	members := make([]corrosion.VoterMember, 0, 3)
	for _, n := range nodes {
		members = append(members, corrosion.VoterMember{Name: n.d.cfg.HostName, Incarnation: n.inc})
	}
	for _, n := range nodes {
		for _, peer := range nodes {
			port := peer.listener.Addr().(*net.TCPAddr).Port
			if err := corrosion.InsertHost(ctx, n.d.db, corrosion.HostRecord{Name: peer.d.cfg.HostName, Address: "127.0.0.1", GRPCPort: port, State: "active", Role: "worker", CertSerial: peer.signer.Serial()}); err != nil {
				t.Fatal(err)
			}
		}
		n.d.db.SetMembersForTests(func() []corrosion.PeerInfo { return []corrosion.PeerInfo{{Name: "a"}, {Name: "b"}, {Name: "c"}} })
		if err := corrosion.WriteVoterConfig(ctx, n.d.db, corrosion.VoterConfigValue{Generation: 1, Members: members, Change: corrosion.VoterChangeGenesis, CreatedBy: "fixture", CreatedAt: "fixture"}, corrosion.ClaimCertificate{}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.RecordVoterAdoption(ctx, n.d.db, 1); err != nil {
			t.Fatal(err)
		}
		if err := n.d.db.ExecuteLocal(ctx, func(tx *corrosion.LocalTx) error {
			_, err := tx.Exec(ctx, `INSERT INTO local_automation_authority(id,generation,members_hash,incarnation,bootstrap_principal,bootstrap_request,provenance) VALUES(1,1,?,?,'fixture','initialize','test-only:existing-custody')`, corrosion.MembersHash(members), n.inc)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		n.d.checker.SetPeerPinger(func(ctx context.Context, host string) ([]string, time.Time, error) {
			n.pings.Add(1)
			cl, conn, err := n.s.PeerClientForTests(ctx, host)
			if err != nil {
				return nil, time.Time{}, err
			}
			defer conn.Close()
			response, err := cl.Ping(ctx, &pb.PingRequest{})
			if err != nil {
				return nil, time.Time{}, err
			}
			return response.GetCapabilities(), time.Time{}, nil
		})
		n.d.checker.SetReleaseUseConfirmer(func(ctx context.Context, host, token, feature string) (bool, error) {
			n.acks.Add(1)
			// Controlled delivery of the actual originating used mutation. ACKED is
			// deliberately not delivered. Confirmation itself uses the real peer RPC.
			var target *continuityNode
			for _, p := range nodes {
				if p.d.cfg.HostName == host {
					target = p
				}
			}
			if target == nil {
				return false, fmt.Errorf("unknown recipient")
			}
			rows, err := n.d.db.Query(ctx, `SELECT seq,hlc,origin,stmts FROM mutation_log WHERE stmts LIKE ? ORDER BY seq`, "%release_feature/"+token+"/"+feature+"%")
			if err != nil {
				return false, err
			}
			var entries []*pb.MutationEntry
			for _, r := range rows {
				entries = append(entries, &pb.MutationEntry{Seq: r.Int64("seq"), Hlc: r.String("hlc"), Origin: r.String("origin"), Stmts: r.String("stmts")})
			}
			if len(entries) == 0 {
				return false, fmt.Errorf("no actual used record")
			}
			replicator := corrosion.NewReplicator(target.d.db, target.d.cfg.PKIDir, corrosion.RelayConfig{})
			if _, err = replicator.ApplyRemoteMutations(ctx, entries); err != nil {
				return false, err
			}
			return n.s.PeerHoldsReleaseFeatureUse(ctx, host, token, feature)
		})
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err = corrosion.InsertUser(ctx, nodes[0].d.db, "alice", "operator", string(hash)); err != nil {
		t.Fatal(err)
	}
	origin, err := corrosion.AutomationLifetime(ctx, nodes[0].d.db, "principal", "alice")
	if err != nil {
		t.Fatal(err)
	}
	apply := func(d contract.Decision) string {
		t.Helper()
		raw, err := contract.EncodeDecision(d)
		if err != nil {
			t.Fatal(err)
		}
		value := corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: raw}}
		key, _ := corrosion.AutomationClaimKey(d.Sequence)
		ballot := corrosion.Ballot{Round: 2, Coordinator: "a", Nonce: []byte{1}}
		r := corrosion.AutomationRecord{Value: value, Certificate: corrosion.ClaimCertificate{Key: key, ConfigGeneration: 1, Ballot: ballot, ValueDigest: value.MustDigest()}}
		for _, n := range nodes[:2] {
			vote, err := n.signer.Sign(key, 1, ballot, value.MustDigest(), n.inc)
			if err != nil {
				t.Fatal(err)
			}
			r.Certificate.Accepts = append(r.Certificate.Accepts, vote)
		}
		for _, n := range nodes {
			if receipt, err := n.d.db.AutomationApply(ctx, r, n.verifier, contract.Reduce); err != nil || receipt.Code != "" {
				t.Fatalf("historical prerequisite: %+v %v", receipt, err)
			}
		}
		return value.MustDigest()
	}
	assignment, _ := json.Marshal(contract.Assignment{Version: 1, ClusterUID: "continuity-cluster", OperationID: "initialize-op", RecordedAt: "2026-10-17T00:00:00Z"})
	parent := apply(contract.Decision{Sequence: 1, Command: contract.Command{Kind: "initialize_cluster", PrincipalID: "fixture", RequestID: "initialize", Body: []byte(`{"version":1}`)}, Assignment: assignment})
	body, _ := json.Marshal(contract.IdentityEnrollment{Version: 1, Kind: "principal", Alias: "alice", Witness: origin.Witness, EvidenceID: "closed-cutover"})
	assignment, _ = json.Marshal(contract.Assignment{Version: 1, ClusterUID: "continuity-cluster", OperationID: "principal-op", RecordedAt: "2026-10-17T00:00:00Z", Identity: &contract.IdentityAssignment{UID: "principal-uid", Generation: 1, Enrollment: &contract.IdentityEnrollmentFacts{Version: 1, EvidenceID: "closed-cutover", ClusterUID: "continuity-cluster", Kind: "principal", Alias: "alice", Witness: origin.Witness, CoverageDigest: strings.Repeat("b", 64), FenceSequence: 1}}})
	apply(contract.Decision{Sequence: 2, ParentDigest: parent, Command: contract.Command{Kind: "assign_identity", ClusterUID: "continuity-cluster", PrincipalID: "host", RequestID: "principal-request", Body: body}, Assignment: assignment})
	for _, n := range nodes {
		if cfg, err := n.d.db.AutomationMembership(ctx); err != nil || cfg.Generation != 1 {
			t.Fatalf("actual current membership: %+v %v", cfg, err)
		}
	}
	return nodes
}

func continuityDaemonPreparation(t *testing.T, n *continuityNode) (*corrosion.AutomationIdentityContinuity, corrosion.ClaimValue) {
	t.Helper()
	ctx := context.Background()
	login, err := n.s.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "correct-password", Realm: "local"})
	if err != nil {
		t.Fatal(err)
	}
	_, session, err := corrosion.AuthenticateAutomationOwnerSession(ctx, n.d.db, strings.TrimPrefix(login.GetToken(), "lvs_"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	p, err := corrosion.PrepareAutomationIdentityContinuity(ctx, n.d.db, session, "principal", "principal-uid", "retained-request")
	if err != nil {
		t.Fatal(err)
	}
	h, err := n.d.db.AutomationHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	facts := p.Facts()
	assignment, _ := json.Marshal(contract.Assignment{Version: 1, ClusterUID: facts.ClusterUID, OperationID: "original-continuity-op", RecordedAt: time.Now().UTC().Format(time.RFC3339Nano), Continuity: &facts})
	raw, err := contract.EncodeDecision(contract.Decision{Sequence: h.Sequence + 1, ParentDigest: h.Digest, Command: p.Command(), Assignment: assignment})
	if err != nil {
		t.Fatal(err)
	}
	return p, corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: raw}}
}

func continuityDaemonAccept(t *testing.T, from, to *continuityNode, value corrosion.ClaimValue, round uint64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cl, conn, err := from.s.PeerClientForTests(ctx, to.d.cfg.HostName)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	result, err := cl.AcceptRecoveryClaim(ctx, &pb.AcceptRecoveryClaimRequest{Key: &pb.RecoveryClaimKey{TargetKind: "automation", TargetName: "cluster", OwnerEpoch: 3}, Ballot: &pb.ClaimBallot{Round: round, Coordinator: from.d.cfg.HostName, BootNonce: []byte{7}}, ConfigGeneration: 1, Value: &pb.RecoveryClaimValue{Automation: &pb.AutomationClaimValue{Envelope: value.Automation.Envelope}}})
	if err != nil || !result.GetAccepted() {
		t.Fatalf("actual peer continuity Accept: %+v %v", result, err)
	}
}

func TestContinuityDaemonUsedOnlyRecoveryWithoutOrigin(t *testing.T) {
	nodes := continuityDaemonCluster(t)
	a, b, c := nodes[0], nodes[1], nodes[2]
	ctx := context.Background()
	prepared, value := continuityDaemonPreparation(t, a)
	key, _ := corrosion.AutomationClaimKey(3)
	ballot := corrosion.Ballot{Round: 7, Coordinator: "a", Nonce: []byte{7}}
	result, err := a.d.db.ClaimAcceptContinuityNative(ctx, key, ballot, value, 1, a.signer, prepared)
	if err != nil || !result.Accepted {
		t.Fatalf("native checked first use: %+v %v", result, err)
	}
	if a.acks.Load() != 2 {
		t.Fatalf("native vote without all actual used ACKs: %d", a.acks.Load())
	}
	continuityDaemonAccept(t, a, b, value, 7)
	present, acked, err := corrosion.ReleaseFeatureState(ctx, c.d.db, capabilities.Release202702V1, string(capabilities.FeatureAutomationIdentityContinuity))
	if err != nil || !present || acked || c.d.checker.DurablyLatched(capabilities.Release202702V1) {
		t.Fatalf("C prerequisite must be used-only with no local marker: %v %v %v", present, acked, err)
	}
	a.stop()
	if err = a.d.db.Execute(ctx, `UPDATE sessions SET revoked_at = ? WHERE username = ?`, a.d.db.NowTS(), "alice"); err != nil {
		t.Fatal(err)
	}
	bp, ba, cp, ca := b.pings.Load(), b.acks.Load(), c.pings.Load(), c.acks.Load()
	continuityDaemonAccept(t, b, c, value, 8) // C obtains B's stored acceptance over mTLS.
	bballot := corrosion.Ballot{Round: 8, Coordinator: "b", Nonce: []byte{7}}
	renewed, err := b.d.db.ClaimAccept(ctx, key, bballot, value, 1, b.signer, nil)
	if err != nil || !renewed.Accepted {
		t.Fatalf("own signed-row recovery: %+v %v", renewed, err)
	}
	cert := corrosion.ClaimCertificate{Key: key, ConfigGeneration: 1, Ballot: bballot, ValueDigest: value.MustDigest()}
	for _, n := range []*continuityNode{b, c} {
		state, found, err := n.d.db.ClaimState(ctx, key)
		if err != nil || !found || state.Accept == nil {
			t.Fatal("missing actual B/C acceptance", err)
		}
		cert.Accepts = append(cert.Accepts, *state.Accept)
	}
	record := corrosion.AutomationRecord{Value: value, Certificate: cert}
	receipt, err := c.d.db.AutomationApplyOwned(ctx, &record, c.verifier, contract.Reduce)
	if err != nil || receipt.Code != "" || receipt.OperationID != "original-continuity-op" || receipt.ResourceUID != "principal-uid" {
		t.Fatalf("B/C certified FULL apply: %+v %v", receipt, err)
	}
	if b.pings.Load() != bp || b.acks.Load() != ba || c.pings.Load() != cp || c.acks.Load() != ca {
		t.Fatal("recovery required an all-host readiness/ACK round")
	}
	if !c.d.checker.DurablyLatched(capabilities.Release202702V1) {
		t.Fatal("new vote without durable local marker")
	}
	_, acked, err = corrosion.ReleaseFeatureState(ctx, c.d.db, capabilities.Release202702V1, string(capabilities.FeatureAutomationIdentityContinuity))
	if err != nil || !acked {
		t.Fatal("new vote without own acknowledged use", err)
	}
	for _, n := range []*continuityNode{b, c} {
		for _, table := range []string{"sessions", "local_automation_lifetimes", "local_automation_credential_issuance"} {
			rows, err := n.d.db.Query(ctx, "SELECT count(*) AS n FROM "+table)
			if err != nil || rows[0].Int64("n") != 0 {
				t.Fatal("recovery copied private origin/session rows", table, err)
			}
		}
	}
}

func TestContinuityDaemonEngineOriginalNeedsCurrentQuorumAndFinalAuth(t *testing.T) {
	for _, mode := range []string{"surviving-quorum", "no-quorum", "revoked-during-quorum", "reopen-original"} {
		t.Run(mode, func(t *testing.T) {
			nodes := continuityDaemonCluster(t)
			a, b, c := nodes[0], nodes[1], nodes[2]
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			prepared, _ := continuityDaemonPreparation(t, a)
			engine, err := a.s.AutomationEngine()
			if err != nil {
				t.Fatal(err)
			}
			original, err := engine.CertifyIdentityContinuity(ctx, prepared)
			if err != nil || original.ResourceUID != "principal-uid" || original.Sequence != 3 {
				t.Fatalf("real engine certification: %+v %v", original, err)
			}
			c.stop()
			var changed atomic.Bool
			if mode == "no-quorum" {
				b.stop()
			}
			if mode == "revoked-during-quorum" {
				b.s.SetClaimVoteObserverForTest(func(v grpcapi.ClaimVote) {
					if v.Phase == "accept" && v.Key.OwnerEpoch == 3 && changed.CompareAndSwap(false, true) {
						if err := a.d.db.Execute(context.Background(), `UPDATE sessions SET revoked_at = ? WHERE username = ?`, a.d.db.NowTS(), "alice"); err != nil {
							t.Error(err)
						}
					}
				})
			}
			if mode == "reopen-original" {
				a.stop()
				a.d.db.Close()
				encoded, e := json.Marshal(original)
				if e != nil {
					t.Fatal(e)
				}
				child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestContinuityDaemonReopenProcess$", "-test.v")
				child.Env = append(os.Environ(), "LITEVIRT_CONTINUITY_REOPEN_DB="+a.dbdir, "LITEVIRT_CONTINUITY_REOPEN_PKI="+a.d.cfg.PKIDir, "LITEVIRT_CONTINUITY_REOPEN_DATA="+a.d.cfg.DataDir, "LITEVIRT_CONTINUITY_REOPEN_RECEIPT="+string(encoded))
				output, e := child.CombinedOutput()
				if e != nil {
					t.Fatalf("real process reopen: %v\n%s", e, output)
				}
				return
			}
			retry, retryErr := engine.CertifyIdentityContinuity(ctx, prepared)
			if mode == "surviving-quorum" || mode == "reopen-original" {
				if retryErr != nil || retry != original {

					t.Fatalf("exact original with A/B quorum: %+v %v", retry, retryErr)
				}
			} else {
				if retryErr == nil || retry.OperationID != "" {
					t.Fatalf("original disclosed without current authority/quorum: %+v %v", retry, retryErr)
				}
				if mode == "revoked-during-quorum" && !changed.Load() {
					t.Fatal("final auth control never reached actual network Accept")
				}
			}
			head, err := a.d.db.AutomationHead(context.Background())
			if err != nil || head.Sequence != 3 {
				t.Fatalf("retry changed head: %+v %v", head, err)
			}
			stored, err := a.d.db.AutomationRequest(context.Background(), contract.Scope(contract.Decision{Command: prepared.Command()}), prepared.Command().RequestID)
			if err != nil || stored == nil || stored.Receipt != original {
				t.Fatalf("retry changed original receipt: %+v %v", stored, err)
			}
		})
	}
}

func TestContinuityDaemonRecoveryRefusalsAndRestart(t *testing.T) {
	for _, mode := range []string{"nil-restorer", "missing-marker", "marker-write-failure", "use-write-failure", "bad-signature", "wrong-source", "wrong-envelope", "wrong-config", "unsigned-cycle", "restart", "factory-replaced", "revoked-source", "revoked-local-signer"} {
		t.Run(mode, func(t *testing.T) {
			nodes := continuityDaemonCluster(t)
			a, c := nodes[0], nodes[2]
			ctx := context.Background()
			prepared, value := continuityDaemonPreparation(t, a)
			key, _ := corrosion.AutomationClaimKey(3)
			accepted, err := a.d.db.ClaimAcceptContinuityNative(ctx, key, corrosion.Ballot{Round: 7, Coordinator: "a", Nonce: []byte{7}}, value, 1, a.signer, prepared)
			if err != nil || !accepted.Accepted {
				t.Fatalf("native prerequisite: %+v %v", accepted, err)
			}
			state, found, err := a.d.db.ClaimState(ctx, key)
			if err != nil || !found {
				t.Fatal(err)
			}
			a.stop()
			source := "a"
			switch mode {
			case "nil-restorer":
				c.d.db.SetAutomationContinuityReleaseRestorer(nil)
			case "missing-marker":
				c.d.checker.SetActivationMarker("")
			case "marker-write-failure":
				block := filepath.Join(t.TempDir(), "file")
				if err = os.WriteFile(block, []byte("blocked"), 0600); err != nil {
					t.Fatal(err)
				}
				c.d.checker.SetActivationMarker(filepath.Join(block, "marker"))
			case "use-write-failure":
				c.d.db.SetClusterPolicyGate(func() bool { return false })
			case "revoked-source", "revoked-local-signer":
				serial := a.signer.Serial()
				if mode == "revoked-local-signer" {
					serial = c.signer.Serial()
				}
				if e := pki.GenerateCRL(c.ca, c.key, filepath.Join(c.d.cfg.PKIDir, "crl.pem"), []string{serial}); e != nil {
					t.Fatal(e)
				}
			case "bad-signature":
				state.Accept.Signature[0] ^= 1
			case "wrong-source":
				source = "b"
			case "wrong-envelope":
				state.Value.Automation.Envelope = append(state.Value.Automation.Envelope, byte(' '))
			case "wrong-config":
				state.ConfigGeneration = 2
			case "unsigned-cycle":
				state.Accept = nil
			case "factory-replaced":
				c.d.db.SetAutomationContinuityReleaseRestorer(func(ctx context.Context, p *corrosion.AutomationContinuityReleaseEvidence) error {
					if err := c.d.checker.RestoreAutomationContinuityReleaseUse(ctx, p); err != nil {
						return err
					}
					c.d.db.SetClaimCertificateVerifier(func() *corrosion.ClaimVerifier { return c.verifier })
					return nil
				})
			case "restart":
				checker := health.NewChecker("c", c.d.cfg.PKIDir, c.d.db)
				checker.SetActivationMarker(health.ActivationMarkerBase(c.d.cfg.DataDir))
				c.d.checker = checker
				c.d.wireServer(c.s)
			}
			beforeP, beforeA := c.pings.Load(), c.acks.Load()
			result, err := c.d.db.ClaimAcceptContinuityEvidence(ctx, key, corrosion.Ballot{Round: 8, Coordinator: "c", Nonce: []byte{8}}, value, 1, c.signer, source, state)
			if mode == "restart" {
				if err != nil || !result.Accepted || !c.d.checker.DurablyLatched(capabilities.Release202702V1) {
					t.Fatalf("restart stored evidence recovery: %+v %v", result, err)
				}
				again := health.NewChecker("c", c.d.cfg.PKIDir, c.d.db)
				again.SetActivationMarker(health.ActivationMarkerBase(c.d.cfg.DataDir))
				if !again.DurablyLatched(capabilities.Release202702V1) {
					t.Fatal("marker missing on next restart")
				}
			} else {
				if err == nil && result.Accepted {
					t.Fatalf("invalid recovery accepted: %+v", result)
				}
				row, found, readErr := c.d.db.ClaimState(ctx, key)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if found && (row.Value != nil || row.Accept != nil) {
					t.Fatalf("refusal left accepted bytes: %+v", row)
				}
			}
			if c.pings.Load() != beforeP || c.acks.Load() != beforeA {
				t.Fatal("restoration attempted all-host first use")
			}
		})
	}
}

func TestContinuityDaemonFirstMaterialization(t *testing.T) {
	for _, mode := range []string{"apply-only", "begin-recovery", "staged-predecessor", "altered-predecessor", "bad-certificate", "signed-import", "unsigned-import"} {
		t.Run(mode, func(t *testing.T) {
			nodes := continuityDaemonCluster(t)
			a, b, c := nodes[0], nodes[1], nodes[2]
			ctx := context.Background()
			prepared, value := continuityDaemonPreparation(t, a)
			key, _ := corrosion.AutomationClaimKey(3)
			ballot := corrosion.Ballot{Round: 7, Coordinator: "a", Nonce: []byte{7}}
			accepted, err := a.d.db.ClaimAcceptContinuityNative(ctx, key, ballot, value, 1, a.signer, prepared)
			if err != nil || !accepted.Accepted {
				t.Fatalf("native prerequisite: %+v %v", accepted, err)
			}
			continuityDaemonAccept(t, a, b, value, 7)
			cert := corrosion.ClaimCertificate{Key: key, ConfigGeneration: 1, Ballot: ballot, ValueDigest: value.MustDigest()}
			var states []corrosion.ClaimVoterState
			for _, n := range []*continuityNode{a, b} {
				state, found, err := n.d.db.ClaimState(ctx, key)
				if err != nil || !found || state.Accept == nil {
					t.Fatal(err)
				}
				cert.Accepts = append(cert.Accepts, *state.Accept)
				states = append(states, state)
			}
			record := corrosion.AutomationRecord{Value: value, Certificate: cert}
			a.stop()
			if c.d.checker.DurablyLatched(capabilities.Release202702V1) {
				t.Fatal("C already protected before first materialization")
			}
			cp, ca := c.pings.Load(), c.acks.Load()
			switch mode {
			case "apply-only":
				_, err = c.d.db.AutomationApplyOwned(ctx, &record, c.verifier, contract.Reduce)
			case "bad-certificate":
				record.Certificate.Accepts[0].Signature[0] ^= 1
				_, err = c.d.db.AutomationApplyOwned(ctx, &record, c.verifier, contract.Reduce)
			case "begin-recovery":
				err = c.d.db.AutomationBeginRecovery(ctx, record, c.verifier)
				if err == nil {
					err = c.d.db.AutomationFinishRecovery(ctx, contract.Reduce, 4)
				}
			case "staged-predecessor", "altered-predecessor":
				// A later ordinary certified anchor is the existing recovery prerequisite;
				// its linked continuity predecessor is the real A/B native accepted value.
				assignment, _ := json.Marshal(contract.Assignment{Version: 1, ClusterUID: "continuity-cluster", OperationID: "later-barrier", RecordedAt: time.Now().UTC().Format(time.RFC3339Nano)})
				raw, e := contract.EncodeDecision(contract.Decision{Sequence: 4, ParentDigest: value.MustDigest(), Command: contract.Command{Kind: "read_barrier", ClusterUID: "continuity-cluster", PrincipalID: "b", RequestID: "later-barrier", Body: []byte(`{"version":1}`)}, Assignment: assignment})
				if e != nil {
					t.Fatal(e)
				}
				next := corrosion.AutomationRecord{Value: corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: raw}}}
				anchorKey, _ := corrosion.AutomationClaimKey(4)
				next.Certificate = corrosion.ClaimCertificate{Key: anchorKey, ConfigGeneration: 1, Ballot: ballot, ValueDigest: next.Value.MustDigest()}
				for _, n := range []*continuityNode{a, b} {
					vote, e := n.signer.Sign(anchorKey, 1, ballot, next.Value.MustDigest(), n.inc)
					if e != nil {
						t.Fatal(e)
					}
					next.Certificate.Accepts = append(next.Certificate.Accepts, vote)
				}
				if e = c.d.db.AutomationBeginRecovery(ctx, next, c.verifier); e != nil {
					t.Fatal(e)
				}
				if c.d.checker.DurablyLatched(capabilities.Release202702V1) {
					t.Fatal("ordinary anchor falsely restored continuity")
				}
				if mode == "altered-predecessor" {
					d, e := contract.DecodeDecision(record.Value.Automation.Envelope)
					if e != nil {
						t.Fatal(e)
					}
					d.Command.RequestID = "altered"
					record.Value.Automation.Envelope, e = contract.EncodeDecision(d)
					if e != nil {
						t.Fatal(e)
					}
				}
				err = c.d.db.AutomationStagePredecessor(ctx, record)
				if err == nil {
					err = c.d.db.AutomationFinishRecovery(ctx, contract.Reduce, 5)
				}
			case "signed-import", "unsigned-import":
				if mode == "unsigned-import" {
					for i := range states {
						states[i].Accept = nil
					}
					c.d.db.SetReleaseFeatureGate(nil)
				}
				_, err = c.d.db.ImportClaimsAndAdopt(ctx, 2, []string{"a", "b"}, states)
				if mode == "signed-import" && err == nil {
					row, found, e := c.d.db.ClaimState(ctx, key)
					if e != nil || !found || row.Accept != nil || row.ValueDigest != value.MustDigest() || !row.Accepted.Equal(ballot) {
						t.Fatalf("import altered bytes or manufactured own signature: %+v %v", row, e)
					}
				}
			}
			refused := mode == "bad-certificate" || mode == "altered-predecessor" || mode == "unsigned-import"
			if refused {
				if err == nil {
					t.Fatal("invalid first materialization succeeded")
				}
				if c.d.checker.DurablyLatched(capabilities.Release202702V1) {
					t.Fatal("unverified input restored release state")
				}
				head, e := c.d.db.AutomationHead(ctx)
				if e != nil || head.Sequence != 2 {
					t.Fatalf("refused materialization changed head: %+v %v", head, e)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if !c.d.checker.DurablyLatched(capabilities.Release202702V1) {
					t.Fatal("first materialization unprotected")
				}
				_, acked, e := corrosion.ReleaseFeatureState(ctx, c.d.db, capabilities.Release202702V1, string(capabilities.FeatureAutomationIdentityContinuity))
				if e != nil || !acked {
					t.Fatal("materialized before own acknowledged use", e)
				}
				if mode == "apply-only" {
					resigned, e := c.d.db.ClaimAccept(ctx, key, corrosion.Ballot{Round: 8, Coordinator: "c", Nonce: []byte{8}}, value, 1, c.signer, nil)
					if e != nil || !resigned.Accepted {
						t.Fatalf("anchored-history resign: %+v %v", resigned, e)
					}
				}
			}
			if c.pings.Load() != cp || c.acks.Load() != ca {
				t.Fatal("materialization required all-host readiness")
			}
		})
	}
}

// The ordinary PKI owner deliberately rejects a second policy source within a
// process. A true restart uses a new process, preserving that guard unchanged.
func TestContinuityDaemonReopenProcess(t *testing.T) {
	dbdir := os.Getenv("LITEVIRT_CONTINUITY_REOPEN_DB")
	if dbdir == "" {
		t.Skip("subprocess-only real reopen control")
	}
	db, err := corrosion.NewLocalClient(dbdir, "a")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err = corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	db.SetVoterConfigGate(func() bool { return true })
	db.SetUserIncarnationGate(func() bool { return true })
	db.SetClusterPolicyGate(func() bool { return true })
	db.SetMembersForTests(func() []corrosion.PeerInfo { return []corrosion.PeerInfo{{Name: "a"}, {Name: "b"}, {Name: "c"}} })
	dir, data := os.Getenv("LITEVIRT_CONTINUITY_REOPEN_PKI"), os.Getenv("LITEVIRT_CONTINUITY_REOPEN_DATA")
	checker := health.NewChecker("a", dir, db)
	checker.SetActivationMarker(health.ActivationMarkerBase(data))
	n := &continuityNode{d: &Daemon{cfg: &Config{HostName: "a", PKIDir: dir, DataDir: data, AdvertiseAddress: "127.0.0.1"}, db: db, checker: checker}}
	n.d.buildServer = func() *grpcapi.Server {
		return grpcapi.NewServerForTests(grpcapi.TestServerOpts{HostName: "a", PKIDir: dir, DataDir: data, DB: db})
	}
	n.s = n.d.newServer()
	prepared, _ := continuityDaemonPreparation(t, n)
	engine, err := n.s.AutomationEngine()
	if err != nil {
		t.Fatal(err)
	}
	var original contract.Receipt
	if err = json.Unmarshal([]byte(os.Getenv("LITEVIRT_CONTINUITY_REOPEN_RECEIPT")), &original); err != nil {
		t.Fatal(err)
	}
	retry, err := engine.CertifyIdentityContinuity(ctx, prepared)
	if err != nil || retry != original {
		t.Fatalf("real restarted original with current A/B quorum: %+v %v", retry, err)
	}
	head, err := db.AutomationHead(ctx)
	if err != nil || head.Sequence != 3 {
		t.Fatalf("restart retry changed head: %+v %v", head, err)
	}
}
