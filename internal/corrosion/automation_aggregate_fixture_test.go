package corrosion

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type aggregateFixtureOptions struct {
	Initial       func(t *testing.T, v *claimTestVoter, ca claimTestCA)
	Old           int
	Sources       int
	Heads         []int
	LocalHead     int
	Continuing    bool
	Remove        string // Explicit ordinary removal; seven voters require this path.
	BeforeFreeze  func(t *testing.T, voters []*claimTestVoter, receiver *claimTestVoter)
	BeforePublish func(t *testing.T, f *aggregateFixture)
}
type aggregateFixture struct {
	ca        claimTestCA
	receiver  *AutomationReceiver
	attempt   *AutomationReceiverAttempt
	voters    []*claimTestVoter
	local     *claimTestVoter
	producers []*AutomationSourcePreparer
	requests  []AutomationExportRequest
	exportCtx context.Context
	dir       string
}

// Each voter starts as its own FULL file-backed replica and host key. The sole
// authority fixture premise is native G1 bootstrap, as in receiverAuditFixture;
// ordinary membership and every published source are verified by real owners.
// BeforeFreeze can install already-certified historical fixtures, never a fresh
// business-class issuer or a replacement semantic/authorization callback.
func newAggregateFixture(t *testing.T, options aggregateFixtureOptions) *aggregateFixture {
	t.Helper()
	if options.Old == 0 {
		options.Old = 3
	}
	if options.Old != 3 && options.Old != 5 && !(options.Old == 7 && options.Remove != "") {
		t.Fatal("aggregate fixture old electorate must be 3 or 5, or 7 with explicit removal")
	}
	if options.Remove != "" && !options.Continuing {
		t.Fatal("removal requires a continuing receiver")
	}
	if options.Sources == 0 {
		options.Sources = MajorityOf(options.Old)
	}
	if options.Sources < MajorityOf(options.Old) || options.Sources > options.Old {
		t.Fatal("aggregate fixture requires a whole-old majority source roster")
	}
	if len(options.Heads) > options.Old || options.LocalHead < 0 {
		t.Fatal("invalid aggregate fixture head inventory")
	}
	ctx := context.Background()
	ca := newClaimTestCA(t)
	newVoter := func(name string) *claimTestVoter {
		t.Helper()
		c, err := NewLocalClient(t.TempDir(), name)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		if err = InitSchema(ctx, c); err != nil {
			t.Fatal(err)
		}
		c.SetVoterConfigGate(func() bool { return true })
		inc, err := c.VoterIncarnation(ctx)
		if err != nil {
			t.Fatal(err)
		}
		dir := ca.pkiDir(t, name)
		signer, err := LoadClaimSigner(dir, name)
		if err != nil {
			t.Fatal(err)
		}
		v := &claimTestVoter{name: name, c: c, signer: signer, pki: dir, inc: inc}
		if options.Initial != nil {
			options.Initial(t, v, ca)
		}
		return v
	}
	f := &aggregateFixture{ca: ca}
	for i := 0; i < options.Old; i++ {
		f.voters = append(f.voters, newVoter(fmt.Sprintf("old-%d", i)))
	}
	var joined *claimTestVoter
	if options.Remove == "" {
		joined = newVoter("receiver")
	}
	f.local = joined
	if options.Continuing {
		f.local = f.voters[len(f.voters)-1]
	}
	f.dir = f.local.c.dataDir
	choose := func(prev *VoterConfig, value VoterConfigValue) *VoterConfig {
		t.Helper()
		key := ClaimKey{TargetKind: ClaimKindVoterConfig, OwnerEpoch: value.Generation - 1}
		ballot := testBallot(1, f.voters[0].name)
		cert := ClaimCertificate{Key: key, ConfigGeneration: key.OwnerEpoch, Ballot: ballot, ValueDigest: (ClaimValue{Config: &value}).MustDigest()}
		for _, v := range f.voters {
			reply, err := v.c.ClaimAccept(ctx, key, ballot, ClaimValue{Config: &value}, key.OwnerEpoch, v.signer, nil)
			if err != nil || !reply.Accepted || reply.Accept == nil {
				t.Fatalf("ordinary membership %s: %+v %v", v.name, reply, err)
			}
			cert.Accepts = append(cert.Accepts, *reply.Accept)
		}
		raw, err := cert.Encode()
		if err != nil {
			t.Fatal(err)
		}
		cfg := &VoterConfig{VoterConfigValue: value, MembersHash: MembersHash(value.Members), Certificate: raw}
		view, err := pki.CaptureHostTrust(ctx, f.voters[0].pki, f.voters[0].name)
		if err != nil {
			t.Fatal(err)
		}
		if err = VerifyVoterConfigRow(&ClaimVerifier{sourceTrust: view, pinned: true}, prev, cfg); err != nil {
			t.Fatal("ordinary membership verification", err)
		}
		return cfg
	}
	write := func(v *claimTestVoter, cfg *VoterConfig) {
		t.Helper()
		cert, err := DecodeClaimCertificate(cfg.Certificate)
		if err != nil {
			t.Fatal(err)
		}
		if err = WriteVoterConfig(ctx, v.c, cfg.VoterConfigValue, cert); err != nil {
			t.Fatal(err)
		}
	}
	first := choose(nil, VoterConfigValue{Generation: 1, Members: membersOf(f.voters...), Change: VoterChangeGenesis, CreatedBy: f.voters[0].name, CreatedAt: "t1"})
	for _, v := range f.voters {
		write(v, first)
		if err := RecordVoterAdoption(ctx, v.c, 1); err != nil {
			t.Fatal(err)
		}
	}
	if joined != nil {
		write(joined, first)
	}
	heads := make([]int, options.Old)
	copy(heads, options.Heads)
	if options.Continuing {
		heads[options.Old-1] = options.LocalHead
	} else if options.LocalHead != 0 {
		t.Fatal("new receiver cannot have a native old history")
	}
	maxHead := 0
	for _, h := range heads {
		if h < 0 {
			t.Fatal("negative aggregate history height")
		}
		if h > maxHead {
			maxHead = h
		}
	}
	for i, v := range f.voters {
		if heads[i] > 0 {
			key, _ := AutomationClaimKey(1)
			installAutomationEvidence(t, v.c, key, "", 1)
		}
	}
	parent := ""
	for seq := 1; seq <= maxHead; seq++ {
		request, operation := "req", "op"
		if seq > 1 {
			request, operation = fmt.Sprintf("barrier-%d", seq), fmt.Sprintf("barrier-op-%d", seq)
		}
		record := sharedAutomationRecord(t, uint64(seq), parent, request, operation, f.voters...)
		for i, v := range f.voters {
			if heads[i] < seq {
				continue
			}
			verifier, err := LoadClaimVerifier(v.pki)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = v.c.AutomationApply(ctx, record, verifier, contract.Reduce); err != nil {
				t.Fatalf("native shared history %s/%d: %v", v.name, seq, err)
			}
		}
		parent = record.Value.MustDigest()
	}
	if options.BeforeFreeze != nil {
		options.BeforeFreeze(t, f.voters, f.local)
	}
	var successor []*claimTestVoter
	change := ""
	if options.Remove == "" {
		successor = append(append([]*claimTestVoter(nil), f.voters...), joined)
		change = "add:" + joined.name
	} else {
		for _, v := range f.voters {
			if v.name != options.Remove {
				successor = append(successor, v)
			} else if v == f.local {
				t.Fatal("removal cannot remove the continuing receiver")
			}
		}
		if len(successor) != options.Old-1 {
			t.Fatal("removal must name exactly one actual old member")
		}
		change = VoterChangeRm(options.Remove)
	}
	second := choose(first, VoterConfigValue{Generation: 2, Members: membersOf(successor...), Change: change, CreatedBy: f.voters[0].name, CreatedAt: "t2"})
	// Choosing the successor seals each actual old standing. Freeze before any
	// adoption rewrites claims, and retain the continuing receiver at adopted G.
	for _, v := range f.voters {
		if _, err := v.c.FreezeAutomationCut(ctx, 1, contract.Reduce); err != nil {
			t.Fatalf("freeze independent %s: %v", v.name, err)
		}
		write(v, second)
	}
	if joined != nil {
		write(joined, second)
	}
	var states []ClaimVoterState
	var sourceNames []string
	for _, v := range f.voters {
		state, found, err := v.c.ClaimState(ctx, ClaimKey{TargetKind: ClaimKindVoterConfig, OwnerEpoch: 1})
		if err != nil || !found {
			t.Fatal("actual successor vote missing", err)
		}
		states = append(states, state)
		sourceNames = append(sourceNames, v.name)
	}
	for _, v := range f.voters {
		if v == f.local || v.name == options.Remove {
			continue
		}
		if _, err := v.c.ImportClaimsAndAdopt(ctx, 2, sourceNames, states); err != nil {
			t.Fatal("ordinary successor adoption", v.name, err)
		}
	}
	all := append([]*claimTestVoter(nil), f.voters...)
	if joined != nil {
		all = append(all, joined)
	}
	// Real loopback TLS returns each owner's live incarnation; currentPKI and
	// source/target admission still run in Prepare, Publish, Export, Stage, Audit.
	for _, v := range all {
		host := receiverServe(t, v.c, v.pki)
		for _, db := range all {
			if err := InsertHost(ctx, db.c, host); err != nil {
				t.Fatal(err)
			}
		}
	}
	intent := AutomationSourceRequest{Generation: 1, Target: f.local.name, Job: "aggregate-fixture", Revision: 1, Sources: membersOf(f.voters[:options.Sources]...)}
	if options.BeforePublish != nil {
		options.BeforePublish(t, f)
	}
	for _, v := range f.voters[:options.Sources] {
		producer := NewAutomationSourcePreparer(v.c, v.pki)
		if err := producer.InitializePublication(ctx); err != nil {
			t.Fatal(err)
		}
		candidate, err := producer.Prepare(ctx, intent)
		if err != nil {
			t.Fatalf("prepare %s: %v", v.name, err)
		}
		id, err := producer.Publish(ctx, candidate)
		candidate.Discard()
		if err != nil {
			t.Fatalf("publish %s: %v", v.name, err)
		}
		f.producers = append(f.producers, producer)
		f.requests = append(f.requests, AutomationExportRequest{Intent: intent, Publication: id, MaxRecords: 1})
	}
	pair, err := pki.ServedHostKeyPair(f.local.pki)
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
	f.exportCtx = peer.NewContext(ctx, &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{HandshakeComplete: true, PeerCertificates: chain}}})
	f.receiver = NewAutomationReceiver(f.local.c, f.local.pki)
	f.attempt, err = f.receiver.Begin(ctx, intent, nil)
	if err != nil {
		t.Fatal("begin aggregate fixture", err)
	}
	return f
}

// through is inclusive (0..11). Construction publishes but stages no pages.
func (f *aggregateFixture) stage(t *testing.T, sourceIndex int, through uint32, audit bool) {
	t.Helper()
	if sourceIndex < 0 || sourceIndex >= len(f.producers) || through >= 12 {
		t.Fatal("invalid aggregate source/component")
	}
	producer, request := f.producers[sourceIndex], f.requests[sourceIndex]
	source := producer.client.hostName
	for component := uint32(0); component <= through; component++ {
		request.Component, request.Cursor = component, ""
		for {
			page, err := producer.ExportAutomationSource(f.exportCtx, request)
			if err != nil {
				t.Fatalf("export %s/%d: %v", source, component, err)
			}
			if _, err = f.receiver.Stage(context.Background(), f.attempt, source, request, page); err != nil {
				t.Fatalf("stage %s/%d: %v", source, component, err)
			}
			if page.Terminal {
				break
			}
			request.Cursor = page.Cursor
		}
	}
	if audit {
		if err := f.receiver.AuditSource(context.Background(), f.attempt, source); err != nil {
			t.Fatalf("audit %s: %v", source, err)
		}
	}
}

func TestAggregateFixtureIndependentProducers(t *testing.T) {
	for _, tc := range []struct {
		name         string
		old, sources int
		heads        []int
		continuing   bool
		localHead    int
	}{
		{"whole3-fixed2", 3, 2, []int{3, 1}, false, 0},
		{"whole5-fixed3", 5, 3, []int{3, 2, 1}, false, 0},
		{"whole5-fixed4", 5, 4, []int{3, 2, 1, 0}, false, 0},
		{"continuing-owned-cut", 3, 2, []int{2, 1}, true, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: tc.old, Sources: tc.sources, Heads: tc.heads, Continuing: tc.continuing, LocalHead: tc.localHead})
			seenDB, seenKey, seenPublication, seenCut := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
			for i, p := range f.producers {
				if _, err := os.Stat(filepath.Join(p.client.dataDir, "state.db")); err != nil {
					t.Fatal("producer is not file backed", err)
				}
				pair, err := pki.ServedHostKeyPair(p.dir)
				if err != nil {
					t.Fatal(err)
				}
				cert, err := x509.ParseCertificate(pair.Certificate[0])
				if err != nil {
					t.Fatal(err)
				}
				key, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
				if err != nil {
					t.Fatal(err)
				}
				cuts, err := p.client.Query(context.Background(), `SELECT id,metadata FROM local_automation_cuts WHERE generation=1`)
				if err != nil || len(cuts) != 1 {
					t.Fatal("independent cut missing", err)
				}
				if seenDB[p.client.dsn] || seenKey[string(key)] || seenPublication[f.requests[i].Publication] || seenCut[cuts[0].String("id")] {
					t.Fatal("producer identity was cloned")
				}
				seenDB[p.client.dsn], seenKey[string(key)], seenPublication[f.requests[i].Publication], seenCut[cuts[0].String("id")] = true, true, true, true
				f.stage(t, i, 11, true)
				audits, err := f.receiver.client.Query(context.Background(), `SELECT head,publication FROM local_automation_receiver_audits WHERE attempt=? AND source=?`, f.attempt.id, p.client.hostName)
				if err != nil || len(audits) != 1 {
					t.Fatal("real source audit missing", err)
				}
				var head AutomationPrefix
				if err = json.Unmarshal(audits[0].Bytes("head"), &head); err != nil {
					t.Fatal(err)
				}
				if head.Sequence != uint64(tc.heads[i]) || audits[0].String("publication") != f.requests[i].Publication {
					t.Fatalf("independent audited head/publication differs: %+v", head)
				}
			}
			if tc.continuing {
				adopted, err := AdoptedVoterConfig(context.Background(), f.local.c)
				if err != nil || adopted.Generation != 1 {
					t.Fatal("continuing receiver adopted successor", err)
				}
				cuts, err := f.local.c.Query(context.Background(), `SELECT id FROM local_automation_cuts WHERE generation=1 AND incarnation=?`, f.local.inc)
				if err != nil || len(cuts) != 1 {
					t.Fatal("continuing receiver lacks genuine own cut", err)
				}
				head, err := f.local.c.AutomationHead(context.Background())
				if err != nil || head.Sequence != uint64(tc.localHead) {
					t.Fatal("staging changed continuing history", err)
				}
			}
		})
	}
}
