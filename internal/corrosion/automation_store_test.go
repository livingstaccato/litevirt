package corrosion

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// Mutation: omit automation key recognition or discard the new JSON alternative.
func TestAutomationRepresentation(t *testing.T) {
	k := ClaimKey{TargetKind: "automation", TargetName: "cluster", OwnerEpoch: 1}
	if err := k.Validate(); err != nil {
		t.Fatal(err)
	}
	if !k.IsGenerationScoped() {
		t.Fatal("automation must transfer with the voter generation")
	}
	var v ClaimValue
	if err := json.Unmarshal([]byte(`{"automation":{"version":1,"sequence":1,"envelope":"invalid"}}`), &v); err == nil {
		if _, err := v.Digest(); err == nil {
			t.Fatal("malformed durable envelope accepted")
		}
	}
}

// Mutation: admit a structurally valid automation request without certified readiness.
func TestAutomationDefaultClosed(t *testing.T) {
	_, a, _, _ := threeVoters(t)
	key, v := automationFixture(t, 1, "")
	ctx := context.Background()
	before := localTestMutationLogCount(t, a.c)
	p, err := a.c.ClaimPrepare(ctx, key, testBallot(1, "a"), 1)
	if err != nil || p.Promised || p.Refusal != RefusalAutomationUnavailable {
		t.Fatal("prepare did not fail closed", err, p.Refusal)
	}
	r, err := a.c.ClaimAccept(ctx, key, testBallot(1, "a"), v, 1, a.signer, nil)
	if err != nil || r.Accepted || r.Accept != nil || r.Refusal != RefusalAutomationUnavailable {
		t.Fatal("accept did not fail closed", err)
	}
	_, found, err := a.c.ClaimState(ctx, key)
	if err != nil || found {
		t.Fatal("closed admission wrote promise", err)
	}
	if localTestMutationLogCount(t, a.c) != before {
		t.Fatal("automation relayed")
	}
}

func automationFixture(t *testing.T, seq uint64, parent string) (ClaimKey, ClaimValue) {
	t.Helper()
	kind := "read_barrier"
	cluster := "established-cluster"
	if seq == 1 {
		kind = "initialize_cluster"
		cluster = ""
	}
	d := contract.Decision{Sequence: seq, ParentDigest: parent, Command: contract.Command{Kind: kind, ClusterUID: cluster, RequestID: "req", PrincipalID: "fixture", Body: []byte("{\n\"version\":1}")}, Assignment: []byte(`{"version":1,"cluster_uid":"established-cluster","operation_id":"op","recorded_at":"2026-10-15T00:00:00Z"}`)}
	b, err := contract.EncodeDecision(d)
	if err != nil {
		t.Fatal(err)
	}
	key, err := AutomationClaimKey(seq)
	if err != nil {
		t.Fatal(err)
	}
	return key, ClaimValue{Automation: &AutomationClaimValue{Envelope: b}}
}

func installAutomationEvidence(t *testing.T, c *Client, key ClaimKey, parent string, gen int64) {
	t.Helper()
	cfg, err := AdoptedVoterConfig(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	incarnation, err := c.VoterIncarnation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.db.Exec(`INSERT OR REPLACE INTO local_automation_authority (id,generation,members_hash,incarnation,bootstrap_principal,bootstrap_request,provenance) VALUES (1,?,?,?,?,?,?)`, gen, MembersHash(cfg.Members), incarnation, "fixture", "req", "test-only:storage-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if key.OwnerEpoch > 1 {
		_, err = c.db.Exec(`INSERT OR REPLACE INTO local_automation_prefix (id,cluster_uid,sequence,digest) VALUES (1,?,?,?)`, "established-cluster", key.OwnerEpoch-1, parent)
		if err != nil {
			t.Fatal(err)
		}
	}
}

// Mutation: weaken exclusive alternatives, key binding, complete digest or bounds.
func TestAutomationValueValidation(t *testing.T) {
	key, v := automationFixture(t, 1, "")
	digest := v.MustDigest()
	for _, other := range []ClaimValue{{Proof: &ActionProof{}}, {Config: &VoterConfigValue{}}, {LUN: &LUNAllocation{}}, {SourceHost: "host"}} {
		other.Automation = v.Automation
		if _, err := other.Digest(); err == nil {
			t.Fatal("mixed alternative accepted")
		}
	}
	for _, bad := range []ClaimKey{{TargetKind: "automation", TargetName: "cluster"}, {TargetKind: "automation", TargetName: "cluster", OwnerEpoch: 1, Attempt: 1}, key.WithIncarnation("x")} {
		if bad.Validate() == nil {
			t.Fatal("bad key accepted")
		}
	}
	if _, err := AutomationClaimKey(uint64(math.MaxInt64) + 1); err == nil {
		t.Fatal("sequence overflow")
	}
	if r, _ := validateGenerationClaimValue(workloadKey(), &v); r == "" {
		t.Fatal("wrong key accepted")
	}
	for name, mutate := range map[string]func(*contract.Decision){
		"session":        func(d *contract.Decision) { d.Command.Session++ },
		"ciphertext":     func(d *contract.Decision) { d.Command.Ciphertext = []byte{1, 255} },
		"body":           func(d *contract.Decision) { d.Command.Body = []byte(`{"version":1}`) },
		"assignment":     func(d *contract.Decision) { d.Assignment = []byte(`{"version":1,"operation":"other"}`) },
		"equality tag":   func(d *contract.Decision) { d.Command.SecretIntentTag = []byte{7}; d.Command.SecretKeyEpoch = "e" },
		"equality epoch": func(d *contract.Decision) { d.Command.SecretIntentTag = []byte{7}; d.Command.SecretKeyEpoch = "other" },
	} {
		d, err := contract.DecodeDecision(v.Automation.Envelope)
		if err != nil {
			t.Fatal(err)
		}
		mutate(&d)
		b, err := contract.EncodeDecision(d)
		if err != nil {
			t.Fatal(err)
		}
		if (ClaimValue{Automation: &AutomationClaimValue{Envelope: b}}).MustDigest() == digest {
			t.Fatal(name + " unbound")
		}
	}

}

// Mutation: inspect synchronous on a different connection, or ignore it.
func TestAutomationRequiresFullTransaction(t *testing.T) {
	_, a, _, _ := threeVoters(t)
	key, v := automationFixture(t, 1, "")
	installAutomationEvidence(t, a.c, key, "", 1)
	a.c.db.SetMaxOpenConns(1)
	if _, err := a.c.db.Exec("PRAGMA synchronous=NORMAL"); err != nil {
		t.Fatal(err)
	}
	p, err := a.c.ClaimPrepare(context.Background(), key, testBallot(1, "a"), 1)
	if err == nil || p.Promised {
		t.Fatal("non-FULL promise")
	}
	r, err := a.c.ClaimAccept(context.Background(), key, testBallot(1, "a"), v, 1, a.signer, nil)
	if err == nil || r.Accept != nil {
		t.Fatal("non-FULL acceptance")
	}
}

// Mutation: omit payload from the atomic row or return a vote after save/commit failure.
func TestAutomationAcceptDurabilityAndFailures(t *testing.T) {
	for _, mode := range []string{"success", "sign", "save", "commit"} {
		t.Run(mode, func(t *testing.T) {
			_, a, _, _ := threeVoters(t)
			key, v := automationFixture(t, 1, "")
			installAutomationEvidence(t, a.c, key, "", 1)
			before := localTestMutationLogCount(t, a.c)
			switch mode {
			case "sign":
				a.signer.key = nil
			case "save":
				_, err := a.c.db.Exec(`CREATE TRIGGER deny_automation BEFORE INSERT ON local_recovery_claims WHEN NEW.target_kind='automation' BEGIN SELECT RAISE(ABORT,'injected save failure'); END`)
				if err != nil {
					t.Fatal(err)
				}
			case "commit":
				a.c.automationSeams = &localCommitSeams{beforeCommit: func(tx *sql.Tx) error { _ = tx.Rollback(); return nil }}
			}
			result, err := a.c.ClaimAccept(context.Background(), key, testBallot(1, "a"), v, 1, a.signer, nil)
			if mode != "success" {
				if err == nil || result.Accept != nil || result.Accepted {
					t.Fatal("failure disclosed acceptance", err)
				}
				_, found, e := a.c.ClaimState(context.Background(), key)
				if e != nil || found {
					t.Fatal("failed transaction persisted", e)
				}
			} else {
				if err != nil || !result.Accepted || result.Accept == nil {
					t.Fatal("accept failed", err, result.Refusal)
				}
				state, found, e := a.c.ClaimState(context.Background(), key)
				if e != nil || !found || !reflect.DeepEqual(state.Value, &v) {
					t.Fatal("accepted bytes missing", e)
				}
				second, e := a.c.ClaimAccept(context.Background(), key, testBallot(2, "a"), v, 1, a.signer, nil)
				if e != nil || !second.Accepted || second.Accept.ValueDigest != result.Accept.ValueDigest {
					t.Fatal("recertification changed chain", e)
				}
			}
			if localTestMutationLogCount(t, a.c) != before {
				t.Fatal("local state relayed")
			}
		})
	}
}

func TestAutomationCorruptionNeverAbsence(t *testing.T) {
	for _, damage := range []string{
		"value_json=''", "value_digest='wrong'", "accepted_round=0,accepted_coord='',accepted_nonce=x''",
		"value_json='{}'", "value_json=replace(value_json,'envelope','unknown')", "accept_json='{}'",
		"config_generation=7",
	} {
		t.Run(damage, func(t *testing.T) {
			_, a, _, _ := threeVoters(t)
			key, v := automationFixture(t, 1, "")
			installAutomationEvidence(t, a.c, key, "", 1)
			r, err := a.c.ClaimAccept(context.Background(), key, testBallot(1, "a"), v, 1, a.signer, nil)
			if err != nil || !r.Accepted {
				t.Fatal(err)
			}
			if _, err = a.c.db.Exec("UPDATE local_recovery_claims SET " + damage + " WHERE target_kind='automation'"); err != nil {
				t.Fatal(err)
			}
			if _, _, err = a.c.ClaimState(context.Background(), key); err == nil {
				t.Fatal("corruption hidden by load")
			}
			if _, err = a.c.ClaimPrepare(context.Background(), key, testBallot(2, "a"), 1); err == nil {
				t.Fatal("corruption hidden by prepare")
			}
			if _, err = a.c.ClaimStatesForImport(context.Background(), 1); err == nil {
				t.Fatal("corruption hidden by export")
			}
		})
	}
}

// Every verification runs in a different OS process from the abrupt writer.
func TestAutomationCrashRecovery(t *testing.T) {
	for _, stage := range []string{"before_commit", "after_commit", "before_reply"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			ca := newClaimTestCA(t)
			pkiDir := ca.pkiDir(t, "a")
			c, err := NewLocalClient(dir, "a")
			if err != nil {
				t.Fatal(err)
			}
			if err = InitSchema(context.Background(), c); err != nil {
				t.Fatal(err)
			}
			inc, err := c.VoterIncarnation(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			c.SetVoterConfigGate(func() bool { return true })
			voter := &claimTestVoter{c: c, name: "a", inc: inc}
			adoptHandBuilt(t, 1, []VoterMember{{Name: "a", Incarnation: inc}, {Name: "b", Incarnation: "fixture-b"}, {Name: "c", Incarnation: "fixture-c"}}, voter)
			if err = c.Close(); err != nil {
				t.Fatal(err)
			}
			run := func(mode string) error {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAutomationCrashProcess$", "-test.timeout=25s")
				cmd.Env = append(os.Environ(), "AUTOMATION_CRASH_DIR="+dir, "AUTOMATION_CRASH_PKI="+pkiDir, "AUTOMATION_CRASH_STAGE="+stage, "AUTOMATION_CRASH_MODE="+mode)
				out, err := cmd.CombinedOutput()
				if len(out) > 0 && err != nil {
					t.Log(string(out))
				}
				return err
			}
			err = run("write")
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 91 {
				t.Fatalf("writer did not hit crash seam: %v", err)
			}
			if err = run("verify"); err != nil {
				t.Fatal("reopen process", err)
			}
		})
	}
}

func TestAutomationCrashProcess(t *testing.T) {
	dir := os.Getenv("AUTOMATION_CRASH_DIR")
	if dir == "" {
		t.Skip("subprocess only")
	}
	ctx := context.Background()
	c, err := NewLocalClient(dir, "a")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetVoterConfigGate(func() bool { return true })
	key, v := automationFixture(t, 1, "")
	if os.Getenv("AUTOMATION_CRASH_MODE") == "verify" {
		state, found, err := c.ClaimState(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		if os.Getenv("AUTOMATION_CRASH_STAGE") == "before_commit" {
			if found {
				t.Fatal("uncommitted acceptance survived")
			}
			return
		}
		if !found || !reflect.DeepEqual(state.Value, &v) || state.ValueDigest != v.MustDigest() ||
			!state.Accepted.Equal(testBallot(1, "a")) || !state.Promised.Equal(testBallot(1, "a")) || state.Accept == nil {
			t.Fatal("complete committed recovery state missing")
		}
		return
	}
	rows, err := c.Query(ctx, "PRAGMA journal_mode")
	if err != nil || len(rows) != 1 || rows[0].Values[0] != "wal" {
		t.Fatal("file-backed WAL required", err)
	}
	installAutomationEvidence(t, c, key, "", 1)
	signer, err := LoadClaimSigner(os.Getenv("AUTOMATION_CRASH_PKI"), "a")
	if err != nil {
		t.Fatal(err)
	}
	crash := func() { os.Exit(91) }
	seams := &localCommitSeams{}
	switch os.Getenv("AUTOMATION_CRASH_STAGE") {
	case "before_commit":
		seams.beforeCommit = func(*sql.Tx) error { crash(); return nil }
	case "after_commit":
		seams.afterCommit = crash
	case "before_reply":
		seams.beforeReply = crash
	default:
		t.Fatal("unknown crash stage")
	}
	c.automationSeams = seams
	_, err = c.ClaimAccept(ctx, key, testBallot(1, "a"), v, 1, signer, nil)
	t.Fatal("crash seam not reached", err)
}

func TestAutomationImportCompletePromiseAndAccepted(t *testing.T) {
	_, a, b, c := threeVoters(t)
	ctx := context.Background()
	key, v := automationFixture(t, 1, "")
	installAutomationEvidence(t, a.c, key, "", 1)
	installAutomationEvidence(t, b.c, key, "", 1)
	if r, err := a.c.ClaimAccept(ctx, key, testBallot(2, "a"), v, 1, a.signer, nil); err != nil || !r.Accepted {
		t.Fatal(err)
	}
	if r, err := b.c.ClaimPrepare(ctx, key, testBallot(9, "a"), 1); err != nil || !r.Promised {
		t.Fatal(err)
	}
	accepted, err := a.c.ClaimStatesForImport(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	promised, err := b.c.ClaimStatesForImport(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(accepted.States) != 1 || len(promised.States) != 1 {
		t.Fatal("export omitted automation history")
	}
	both := append(accepted.States, promised.States...)
	if n, err := c.c.ImportClaimsAndAdopt(ctx, 2, []string{"a", "b"}, both); err != nil || n != 1 {
		t.Fatal("import failed", n, err)
	}
	state, found, err := c.c.ClaimState(ctx, key)
	if err != nil || !found || !state.Promised.Equal(testBallot(9, "a")) ||
		!state.Accepted.Equal(testBallot(2, "a")) || !reflect.DeepEqual(state.Value, &v) || state.Accept != nil {
		t.Fatal("import lost promise or complete value", err)
	}
}

// Invalid transport/history must fail the whole import before adoption.
func TestAutomationImportRejectsCorruption(t *testing.T) {
	for _, damage := range []func(*ClaimVoterState){
		func(s *ClaimVoterState) { s.Value = nil },
		func(s *ClaimVoterState) { s.ValueDigest = "bad" },
		func(s *ClaimVoterState) { s.Accepted = Ballot{} },
		func(s *ClaimVoterState) { s.Key.TargetName = "other" },
		func(s *ClaimVoterState) { s.Accept = &ClaimAccept{} },
	} {
		_, _, _, c := threeVoters(t)
		key, v := automationFixture(t, 1, "")
		state := ClaimVoterState{Key: key, Promised: testBallot(1, "a"), Accepted: testBallot(1, "a"), Value: &v, ValueDigest: v.MustDigest(), ConfigGeneration: 1}
		damage(&state)
		if _, err := c.c.ImportClaimsAndAdopt(context.Background(), 2, []string{"a"}, []ClaimVoterState{state}); err == nil {
			t.Fatal("corrupt import succeeded")
		}
		cfg, err := AdoptedVoterConfig(context.Background(), c.c)
		if err != nil || cfg.Generation != 1 {
			t.Fatal("failed import adopted")
		}
	}
}

func TestAutomationInvalidLoadKey(t *testing.T) {
	c := NewTestClientT(t)
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	for _, k := range []ClaimKey{{TargetKind: "automation", TargetName: "other", OwnerEpoch: 1}, {TargetKind: "automation", TargetName: "cluster", OwnerEpoch: 1, Incarnation: "forbidden"}} {
		if _, _, err := c.ClaimState(context.Background(), k); err == nil {
			t.Fatal("invalid key reported as absence")
		}
	}
}

// Mutation: retain the previous generation's signature when importing a higher
// promise over a local accepted value, or discard the value to repair it.
func TestAutomationImportHigherPromiseOverLocalAcceptance(t *testing.T) {
	_, a, _, _ := threeVoters(t)
	ctx := context.Background()
	key, v := automationFixture(t, 1, "")
	installAutomationEvidence(t, a.c, key, "", 1)
	if r, err := a.c.ClaimAccept(ctx, key, testBallot(2, "a"), v, 1, a.signer, nil); err != nil || !r.Accepted {
		t.Fatal("initial acceptance", err)
	}
	promise := ClaimVoterState{Key: key, Promised: testBallot(9, "b"), ConfigGeneration: 1}
	if _, err := a.c.ImportClaimsAndAdopt(ctx, 2, []string{"b"}, []ClaimVoterState{promise}); err != nil {
		t.Fatal("import promise over local acceptance", err)
	}
	st, found, err := a.c.ClaimState(ctx, key)
	if err != nil || !found || !st.Promised.Equal(promise.Promised) || !st.Accepted.Equal(testBallot(2, "a")) || !reflect.DeepEqual(st.Value, &v) || st.Accept != nil {
		t.Fatal("import lost local complete decision or retained stale signature", err)
	}
}

// Mutation: retain an old-generation signature when Prepare advances a healthy
// accepted row that an unchanged import left at its original generation.
func TestAutomationPrepareAndRecertifyAfterUnchangedImport(t *testing.T) {
	for _, identicalState := range []bool{false, true} {
		name := "empty-import"
		if identicalState {
			name = "equal-state-import"
		}
		t.Run(name, func(t *testing.T) {
			_, a, b, c := threeVoters(t)
			ctx := context.Background()
			key, value := automationFixture(t, 1, "")
			installAutomationEvidence(t, a.c, key, "", 1)
			oldBallot := testBallot(2, "a")
			accepted, err := a.c.ClaimAccept(ctx, key, oldBallot, value, 1, a.signer, nil)
			if err != nil || !accepted.Accepted || accepted.Accept == nil {
				t.Fatal("initial acceptance", err)
			}
			before, found, err := a.c.ClaimState(ctx, key)
			if err != nil || !found {
				t.Fatal("initial state", err)
			}
			next := VoterConfigValue{Generation: 2, Members: membersOf(a, b, c), Change: VoterChangeGenesis, CreatedBy: "t", CreatedAt: "t"}
			if err := WriteVoterConfig(ctx, a.c, next, ClaimCertificate{}); err != nil {
				t.Fatal(err)
			}
			var states []ClaimVoterState
			if identicalState {
				states = []ClaimVoterState{before}
			}
			if n, err := a.c.ImportClaimsAndAdopt(ctx, 2, []string{"a", "b"}, states); err != nil || n != 0 {
				t.Fatal("unchanged import", n, err)
			}
			installAutomationEvidence(t, a.c, key, "", 2)
			newBallot := testBallot(3, "a")
			prepared, err := a.c.ClaimPrepare(ctx, key, newBallot, 2)
			if err != nil || !prepared.Promised {
				t.Fatal("prepare after unchanged import", prepared.Refusal, err)
			}
			preparedState, found, err := a.c.ClaimState(ctx, key)
			if err != nil || !found || !preparedState.Promised.Equal(newBallot) || !preparedState.Accepted.Equal(oldBallot) ||
				!reflect.DeepEqual(preparedState.Value, &value) || preparedState.ValueDigest != before.ValueDigest ||
				preparedState.ConfigGeneration != 2 || preparedState.Accept != nil {
				t.Fatal("prepare lost the accepted decision or retained a stale signature", err)
			}
			recertified, err := a.c.ClaimAccept(ctx, key, newBallot, value, 2, a.signer, nil)
			if err != nil || !recertified.Accepted || recertified.Accept == nil ||
				recertified.Accept.ConfigGeneration != 2 || recertified.Accept.ValueDigest != before.ValueDigest {
				t.Fatal("re-certification after unchanged import", err)
			}
			final, found, err := a.c.ClaimState(ctx, key)
			if err != nil || !found || !final.Accepted.Equal(newBallot) || !reflect.DeepEqual(final.Value, &value) ||
				final.ValueDigest != before.ValueDigest || !reflect.DeepEqual(final.Accept, recertified.Accept) {
				t.Fatal("re-certified decision not durable", err)
			}
		})
	}
}

// Mutation: change a legacy domain, field order or optional-field framing while
// adding automation. These literals were independently framed and SHA-256 hashed.
func TestAutomationPreservesLegacyDigests(t *testing.T) {
	for _, tc := range []struct {
		value ClaimValue
		want  string
	}{
		{ClaimValue{Proof: &ActionProof{ID: "id", Action: "recover", TargetKind: "vm", TargetName: "vm", DestHost: "dest", Coordinator: "coord", RelocationToken: "token", FenceEpoch: "fence", OwnerEpoch: "owner", LeaseTerm: 3, LeaseKey: "lease"}, SourceHost: "source"}, "0f6fd9da42c6b6225d8a424fd0a8a1321d71be5325ca23c83144b8e31ded679f"},
		{ClaimValue{LUN: &LUNAllocation{LUN: "lun", Generation: 1, ClaimID: "claim", VMID: "vmid", VMName: "vm", Disk: "disk", Host: "host"}}, "0f82128db6ff968a274a1e776e8e5956f98cef3713b6d95aaf00ed265d36e788"},
		{ClaimValue{Config: &VoterConfigValue{Generation: 1, Members: []VoterMember{{Name: "host", Incarnation: "inc"}}, Change: "genesis", CreatedBy: "actor", CreatedAt: "time"}}, "4a6dfda90ac4cfb4701318033523cce1ddc99676139037673aaf1510e431efa2"},
	} {
		if got, err := tc.value.Digest(); err != nil || got != tc.want {
			t.Fatal("legacy digest changed", got, err)
		}
	}
}

// Mutation: allow oversized complete envelopes or unbounded ballot metadata to
// create durable promises/acceptances. The gate is explicitly open in this test.
func TestAutomationRejectsOversizedBeforeWrite(t *testing.T) {
	_, a, _, _ := threeVoters(t)
	key, v := automationFixture(t, 1, "")
	installAutomationEvidence(t, a.c, key, "", 1)
	v.Automation.Envelope = make([]byte, MaxAutomationClaimBytes+1)
	if r, err := a.c.ClaimAccept(context.Background(), key, testBallot(1, "a"), v, 1, a.signer, nil); err != nil || r.Accepted || r.Accept != nil || r.Refusal != RefusalInvalidValue {
		t.Fatal("oversized accept", err)
	}
	ballot := testBallot(1, "a")
	ballot.Nonce = make([]byte, 257)
	if r, err := a.c.ClaimPrepare(context.Background(), key, ballot, 1); err != nil || r.Promised || r.Refusal != RefusalInvalidValue {
		t.Fatal("oversized ballot promise", err)
	}
	if _, found, err := a.c.ClaimState(context.Background(), key); err != nil || found {
		t.Fatal("oversized request wrote state", err)
	}
}
