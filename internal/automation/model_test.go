package automation_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/automation"
	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// This test must fail if phase one stops reporting highest accepted values,
// including when the first proposer lost every acceptance reply.
func TestModelRecoversChosenButUnlearnedAfterRestart(t *testing.T) {
	m := newProtocolModel(t)
	a := automation.Decision{Sequence: 1, Command: command()}
	first := m.begin("p", 1, a)
	m.deliverPhase(m.phase(), []string{"c", "a", "b"}, false)
	m.deliverPhase(m.phase(), []string{"b", "c", "a"}, true)
	if result := <-first; result.err == nil {
		t.Fatal("lost replies produced a certificate")
	}
	if err := m.safety(); err != nil {
		t.Fatal(err)
	}
	for _, voter := range []string{"a", "b", "c"} {
		m.restart(voter)
	}
	b := a
	b.Command.RequestID = "competing"
	second := m.round("q", 2, b, []string{"a", "c", "b"})
	if err := m.safety(); err != nil {
		t.Fatal(err)
	}
	if m.decision(second).Command.RequestID != "read-1" {
		t.Fatal("chosen request was not recovered")
	}
	for _, voter := range []string{"b", "a", "c"} {
		if err := m.learn(voter, second); err != nil {
			t.Fatal(err)
		}
		if err := m.learn(voter, second); err != nil {
			t.Fatal(err)
		}
	}
	m.assertPrefixes(t, 1, 1)
}

func TestModelReorderedProposersAndDuplicateRequests(t *testing.T) {
	for _, order := range [][]string{{"a", "b", "c"}, {"a", "c", "b"}, {"b", "a", "c"}, {"b", "c", "a"}, {"c", "a", "b"}, {"c", "b", "a"}} {
		t.Run(order[0]+order[1]+order[2], func(t *testing.T) {
			m := newProtocolModel(t)
			a := automation.Decision{Sequence: 1, Command: command()}
			low := m.begin("p", 1, a)
			m.deliverPhase(m.phase(), order, false)
			pending := m.phase()
			m.deliver(pending["a"], false) // accepted, not yet chosen
			b := a
			b.Command.RequestID = "competitor"
			high := m.begin("q", 2, b)
			m.deliverPhase(m.phase(), order, false)
			m.deliverPhase(m.phase(), order, false)
			winner := <-high
			if winner.err != nil {
				t.Fatal(winner.err)
			}
			m.deliver(pending["c"], false)
			m.deliver(pending["b"], false)
			if result := <-low; result.err == nil {
				t.Fatal("stale accepts certified")
			}
			if m.decision(winner.out).Command.RequestID != "read-1" {
				t.Fatal("partial highest acceptance lost")
			}
			for _, voter := range order {
				if err := m.learn(voter, winner.out); err != nil {
					t.Fatal(err)
				}
			}
			retry := a
			retry.Sequence, retry.ParentDigest = 2, winner.out.Digest
			retry.Command.Session++
			out := m.round("q", 3, retry, order)
			for _, voter := range order {
				if err := m.learn(voter, out); err != nil {
					t.Fatal(err)
				}
			}
			if err := m.safety(); err != nil {
				t.Fatal(err)
			}
			m.assertPrefixes(t, 2, 1) // two slots, one immutable request result
		})
	}
}

func TestModelRejectsUncertifiedAndConflictingPrefix(t *testing.T) {
	m := newProtocolModel(t)
	a := automation.Decision{Sequence: 1, Command: command()}
	out := m.round("p", 1, a, []string{"a", "b", "c"})
	bad := out
	bad.Certificate.Accepts = bad.Certificate.Accepts[:1]
	if err := m.learn("a", bad); err == nil {
		t.Fatal("minority certificate applied")
	}
	if err := m.learn("a", out); err != nil {
		t.Fatal(err)
	}
	b := a
	b.Sequence, b.ParentDigest = 2, "wrong-parent"
	failed := m.begin("p", 2, b)
	m.deliverPhase(m.phase(), []string{"a", "b", "c"}, false)
	m.deliverPhase(m.phase(), []string{"a", "b", "c"}, false)
	if result := <-failed; result.err == nil {
		t.Fatal("gap or conflicting predecessor was accepted")
	}
	if len(m.nodes["a"].applied) != 1 || len(m.nodes["b"].applied) != 0 {
		t.Fatal("rejected command changed a prefix")
	}
}

// This schedule matches the production preflight: ABC -> ABCD -> BCD, then
// a delayed import from removed A. Accepted-only transfer loses B's promise-only
// floor and allows an old high acceptance to overwrite a newer chosen value.
func TestModelMembershipCarriesPromiseFloorAndPartialAcceptance(t *testing.T) {
	m := newProtocolModel(t)
	low := automation.Decision{Sequence: 1, Command: command()}
	high := low
	high.Command.RequestID = "high"
	m.partial("p", 1, low, []string{"b", "c"}, "c")
	m.partial("q", 10, high, []string{"a", "b"}, "a")
	old := m.freeze(1, []string{"a", "b", "c"})
	m.members[2] = []string{"a", "b", "c", "d"}
	m.generation = 2
	m.nodes["d"] = &modelNode{states: map[corrosion.ClaimKey]corrosion.ClaimVoterState{}, receipts: map[string]string{}, generation: 1}
	for _, n := range []string{"a", "b", "c", "d"} {
		sources := []string{"b", "c"}
		if n == "a" {
			sources = []string{"a", "b"}
		}
		if err := m.adopt(n, 2, sources, old); err != nil {
			t.Fatal(err)
		}
	}
	frozen := m.freeze(2, []string{"b", "c", "d"})
	m.members[3] = []string{"b", "c", "d"}
	m.generation = 3
	for _, n := range []string{"c", "d"} {
		if err := m.adopt(n, 3, []string{"b", "c", "d"}, frozen); err != nil {
			t.Fatal(err)
		}
	}
	first := m.reachableRound("p", 2, low, []string{"c", "d"})
	if first.err != nil {
		first = m.reachableRound("p", 11, low, []string{"c", "d"})
	}
	if first.err != nil {
		t.Fatal(first.err)
	}
	for _, n := range []string{"c", "d"} {
		if err := m.learn(n, first.out); err != nil {
			t.Fatal(err)
		}
	}
	late := m.freeze(2, []string{"a", "b", "c"})
	if err := m.adopt("b", 3, []string{"a", "b", "c"}, late); err != nil {
		t.Fatal(err)
	}
	second := m.reachableRound("q", 12, high, []string{"b", "c"})
	if second.err != nil {
		t.Fatal(second.err)
	}
	if err := m.safety(); err != nil {
		t.Fatal(err)
	}
	if first.out.Digest != second.out.Digest {
		t.Fatal("membership changed chosen value")
	}
	for _, n := range []string{"b", "c", "d"} {
		if err := m.learn(n, second.out); err != nil {
			t.Fatal(err)
		}
	}
	// A higher-ballot certificate for the SAME value must not change the
	// predecessor link. Chain to the first value digest, not certificate bytes.
	next := low
	next.Sequence, next.ParentDigest, next.Command.RequestID = 2, first.out.Digest, "next"
	out := m.round("p", 13, next, []string{"d", "b", "c"})
	for _, n := range []string{"b", "c", "d"} {
		if err := m.learn(n, out); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.safety(); err != nil {
		t.Fatal(err)
	}
}

func TestModelMembershipRefusesMissingOldQuorum(t *testing.T) {
	m := newProtocolModel(t)
	m.members[2] = []string{"b", "c", "d"}
	frozen := m.freeze(1, []string{"a"})
	if err := m.adopt("b", 2, []string{"a", "a"}, frozen); err == nil {
		t.Fatal("forced membership discarded required recovery quorum")
	}
	if m.nodes["b"].generation != 1 {
		t.Fatal("failed import adopted new generation")
	}
}

// The model uses the production proposer and ballot ordering. Only the transport,
// stable store, certificate authenticity and deterministic request projection are
// abstracted. It is not the future automation voter or reducer implementation.
type protocolModel struct {
	t          *testing.T
	ctx        context.Context
	messages   chan *modelMessage
	nodes      map[string]*modelNode
	decisions  map[string]automation.Decision
	history    []corrosion.ClaimAccept
	members    map[int64][]string
	generation int64
}
type modelNode struct {
	generation int64
	states     map[corrosion.ClaimKey]corrosion.ClaimVoterState
	applied    []string
	receipts   map[string]string
	sealed     bool
}
type modelMessage struct {
	voter      string
	key        corrosion.ClaimKey
	ballot     corrosion.Ballot
	generation int64
	value      *corrosion.ClaimValue
	reply      chan modelReply
}
type modelReply struct {
	prepare corrosion.PrepareResult
	accept  corrosion.AcceptResult
	err     error
}
type modelOutcome struct {
	out claims.Outcome
	err error
}

func newProtocolModel(t *testing.T) *protocolModel {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	m := &protocolModel{t: t, ctx: ctx, messages: make(chan *modelMessage, 16), nodes: map[string]*modelNode{}, decisions: map[string]automation.Decision{}, members: map[int64][]string{1: {"a", "b", "c"}}, generation: 1}
	for _, n := range m.members[1] {
		m.nodes[n] = &modelNode{states: map[corrosion.ClaimKey]corrosion.ClaimVoterState{}, receipts: map[string]string{}, generation: 1}
	}
	return m
}
func (m *protocolModel) Prepare(ctx context.Context, voter string, key corrosion.ClaimKey, b corrosion.Ballot, gen int64, _ *corrosion.SupersedeEvidence) (corrosion.PrepareResult, error) {
	r := m.send(ctx, &modelMessage{voter: voter, key: key, ballot: b, generation: gen})
	return r.prepare, r.err
}
func (m *protocolModel) Accept(ctx context.Context, voter string, key corrosion.ClaimKey, b corrosion.Ballot, value corrosion.ClaimValue, gen int64) (corrosion.AcceptResult, error) {
	r := m.send(ctx, &modelMessage{voter: voter, key: key, ballot: b, generation: gen, value: &value})
	return r.accept, r.err
}
func (m *protocolModel) send(ctx context.Context, msg *modelMessage) modelReply {
	msg.reply = make(chan modelReply, 1)
	select {
	case m.messages <- msg:
	case <-ctx.Done():
		return modelReply{err: ctx.Err()}
	}
	select {
	case r := <-msg.reply:
		return r
	case <-ctx.Done():
		return modelReply{err: ctx.Err()}
	}
}
func (m *protocolModel) begin(name string, round uint64, d automation.Decision) <-chan modelOutcome {
	// ClaimValue has no automation alternative yet. Bind a complete model decision
	// digest in an existing value's ID solely to exercise the real proposer.
	data, err := json.Marshal(d)
	if err != nil {
		m.t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	value := corrosion.ClaimValue{Proof: &corrosion.ActionProof{ID: hex.EncodeToString(hash[:])}}
	m.decisions[value.MustDigest()] = d
	result := make(chan modelOutcome, 1)
	members := append([]string(nil), m.members[m.generation]...)
	spec := claims.Spec{Key: corrosion.ClaimKey{TargetKind: "automation", TargetName: "cluster", OwnerEpoch: int64(d.Sequence)}, Generation: m.generation, Voters: members, PrepareQuorum: len(members)/2 + 1, StartRound: round, MaxRounds: 1,
		Propose: func(map[string]corrosion.PrepareResult) (corrosion.ClaimValue, error) { return value, nil }}
	p := claims.NewProposer(name, m)
	p.CallTimeout = 5 * time.Second
	p.Backoff = func(int) time.Duration { return 0 }
	go func() { out, err := p.Decide(m.ctx, spec); result <- modelOutcome{out, err} }()
	return result
}
func (m *protocolModel) phase() map[string]*modelMessage {
	messages := map[string]*modelMessage{}
	for len(messages) < len(m.members[m.generation]) {
		select {
		case msg := <-m.messages:
			if messages[msg.voter] != nil {
				m.t.Fatal("unexpected duplicate phase target")
			}
			messages[msg.voter] = msg
		case <-m.ctx.Done():
			m.t.Fatal("model schedule stalled")
		}
	}
	return messages
}
func (m *protocolModel) deliverPhase(messages map[string]*modelMessage, order []string, loseReply bool) {
	for _, voter := range order {
		m.deliver(messages[voter], loseReply)
	}
}
func (m *protocolModel) deliver(msg *modelMessage, loseReply bool) modelReply {
	reply := m.transition(msg)
	// Re-delivery is idempotent; the history records duplicates intentionally so
	// the chosen-value oracle has to count distinct voters.
	duplicate := m.transition(msg)
	if !reflect.DeepEqual(reply, duplicate) {
		m.t.Fatal("message redelivery changed its result")
	}
	if loseReply {
		reply = modelReply{err: errors.New("model dropped reply")}
	}
	msg.reply <- reply
	return reply
}
func (m *protocolModel) transition(msg *modelMessage) modelReply {
	n := m.nodes[msg.voter]
	s := n.states[msg.key]
	if n.sealed || msg.generation != n.generation {
		return modelReply{err: errors.New("sealed generation")}
	}
	if corrosion.CompareBallots(msg.ballot, s.Promised) < 0 {
		return modelReply{prepare: corrosion.PrepareResult{Refusal: corrosion.RefusalBallotStale, PromisedBallot: s.Promised}, accept: corrosion.AcceptResult{Refusal: corrosion.RefusalBallotStale, PromisedBallot: s.Promised}}
	}
	s.Key, s.ConfigGeneration = msg.key, msg.generation
	if msg.value == nil {
		s.Promised = msg.ballot
		n.states[msg.key] = s // stable before response
		if os.Getenv("AUTOMATION_MODEL_IGNORE_ACCEPTED") == "1" {
			s.Value = nil
			s.Accepted = corrosion.Ballot{}
		}
		return modelReply{prepare: corrosion.PrepareResult{Promised: true, State: s, PromisedBallot: s.Promised, Voter: msg.voter}}
	}
	digest := msg.value.MustDigest()
	d := m.decisions[digest]
	if d.Sequence > 1 && (uint64(len(n.applied)) < d.Sequence-1 || n.applied[d.Sequence-2] != d.ParentDigest) {
		return modelReply{err: errors.New("uncertified predecessor")}
	}
	if s.Accepted.Equal(msg.ballot) && s.Value != nil && s.ValueDigest != digest {
		return modelReply{err: errors.New("ballot already bound")}
	}
	accept := corrosion.ClaimAccept{Voter: msg.voter, Key: msg.key, Ballot: msg.ballot, ValueDigest: digest, ConfigGeneration: msg.generation}
	s.Promised, s.Accepted, s.Value, s.ValueDigest, s.Accept = msg.ballot, msg.ballot, msg.value, digest, &accept
	n.states[msg.key] = s // stable before signing; cryptography abstracted
	m.history = append(m.history, accept)
	return modelReply{accept: corrosion.AcceptResult{Accepted: true, Accept: &accept, Voter: msg.voter}}
}
func (m *protocolModel) round(name string, ballot uint64, d automation.Decision, order []string) claims.Outcome {
	result := m.begin(name, ballot, d)
	m.deliverPhase(m.phase(), order, false)
	m.deliverPhase(m.phase(), order, false)
	r := <-result
	if r.err != nil {
		m.t.Fatal(r.err)
	}
	return r.out
}
func (m *protocolModel) decision(out claims.Outcome) automation.Decision {
	return m.decisions[out.Digest]
}
func (m *protocolModel) restart(voter string) {
	// A process restart loses caches, not stable promises, values or projections.
	// Round-trip through storage bytes instead of retaining the same map pointers.
	n := m.nodes[voter]
	states := make([]corrosion.ClaimVoterState, 0, len(n.states))
	for _, s := range n.states {
		states = append(states, s)
	}
	data, err := json.Marshal(states)
	if err != nil {
		m.t.Fatal(err)
	}
	var restored []corrosion.ClaimVoterState
	if err := json.Unmarshal(data, &restored); err != nil {
		m.t.Fatal(err)
	}
	copy := &modelNode{states: map[corrosion.ClaimKey]corrosion.ClaimVoterState{}, applied: append([]string(nil), n.applied...), receipts: maps.Clone(n.receipts), sealed: n.sealed, generation: n.generation}
	for _, s := range restored {
		copy.states[s.Key] = s
	}
	m.nodes[voter] = copy
}
func (m *protocolModel) learn(voter string, out claims.Outcome) error {
	c := out.Certificate
	seen := map[string]bool{}
	for _, a := range c.Accepts {
		if a.Key != c.Key || !a.Ballot.Equal(c.Ballot) || a.ConfigGeneration != c.ConfigGeneration || a.ValueDigest != out.Digest || !slices.Contains(m.members[c.ConfigGeneration], a.Voter) {
			return errors.New("invalid certificate")
		}
		exists := false
		for _, actual := range m.history {
			if reflect.DeepEqual(a, actual) {
				exists = true
				break
			}
		}
		if !exists {
			return errors.New("acceptance not authentic")
		}
		seen[a.Voter] = true
	}
	if len(seen) < len(m.members[c.ConfigGeneration])/2+1 {
		return errors.New("no certificate quorum")
	}
	d := m.decision(out)
	n := m.nodes[voter]
	if d.Sequence <= uint64(len(n.applied)) {
		if n.applied[d.Sequence-1] == out.Digest {
			return nil
		}
		return errors.New("conflicting prefix")
	}
	if d.Sequence != uint64(len(n.applied))+1 || (d.Sequence > 1 && n.applied[d.Sequence-2] != d.ParentDigest) {
		return errors.New("prefix gap")
	}
	immutable, err := automation.CanonicalCommand(d.Command)
	if err != nil {
		return err
	}
	// Abstract request projection, not the future VM reducer: unchanged retries
	// recover one result; conflicting retries leave the original result intact.
	requestKey := d.Command.OwnerID + "\x00" + d.Command.RequestID
	if _, exists := n.receipts[requestKey]; !exists {
		n.receipts[requestKey] = string(immutable)
	}
	n.applied = append(n.applied, out.Digest)
	return nil
}
func (m *protocolModel) safety() error {
	// Count historical accepts, not just present state: a lost certificate or
	// later overwrite must not conceal an already chosen conflicting value.
	groups := map[string]map[string]bool{}
	values := map[string]string{}
	slots := map[string]int64{}
	generations := map[string]int64{}
	for _, a := range m.history {
		k := fmt.Sprintf("%d/%d/%s/%s", a.Key.OwnerEpoch, a.ConfigGeneration, a.Ballot.String(), a.ValueDigest)
		if groups[k] == nil {
			groups[k] = map[string]bool{}
		}
		groups[k][a.Voter] = true
		values[k] = a.ValueDigest
		slots[k] = a.Key.OwnerEpoch
		generations[k] = a.ConfigGeneration
	}
	chosen := map[int64]string{}
	for k, voters := range groups {
		if len(voters) >= len(m.members[generations[k]])/2+1 {
			if prior := chosen[slots[k]]; prior != "" && prior != values[k] {
				return fmt.Errorf("conflicting chosen values at slot %d", slots[k])
			}
			chosen[slots[k]] = values[k]
		}
	}
	for _, a := range m.nodes {
		for _, b := range m.nodes {
			for i := 0; i < min(len(a.applied), len(b.applied)); i++ {
				if a.applied[i] != b.applied[i] {
					return errors.New("applied prefixes diverged")
				}
			}
		}
	}
	return nil
}
func (m *protocolModel) assertPrefixes(t *testing.T, slots, requests int) {
	t.Helper()
	for voter, n := range m.nodes {
		if len(n.applied) != slots || len(n.receipts) != requests {
			t.Fatalf("voter %s has %d applied slots and %d receipts", voter, len(n.applied), len(n.receipts))
		}
		if !reflect.DeepEqual(n.receipts, m.nodes["a"].receipts) {
			t.Fatal("equal applied prefixes produced different request projections")
		}
	}
	if err := m.safety(); err != nil {
		t.Fatal(err)
	}
}

func (m *protocolModel) drop(msg *modelMessage) {
	msg.reply <- modelReply{err: errors.New("model dropped request")}
}
func (m *protocolModel) partial(proposer string, ballot uint64, d automation.Decision, prepare []string, accept string) {
	result := m.begin(proposer, ballot, d)
	messages := m.phase()
	for _, n := range m.members[m.generation] {
		if slices.Contains(prepare, n) {
			m.deliver(messages[n], false)
		} else {
			m.drop(messages[n])
		}
	}
	messages = m.phase()
	for _, n := range m.members[m.generation] {
		if n == accept {
			m.deliver(messages[n], false)
		} else {
			m.drop(messages[n])
		}
	}
	if r := <-result; r.err == nil {
		m.t.Fatal("partial acceptance unexpectedly certified")
	}
}
func (m *protocolModel) reachableRound(proposer string, ballot uint64, d automation.Decision, reachable []string) modelOutcome {
	result := m.begin(proposer, ballot, d)
	messages := m.phase()
	promises := 0
	for _, n := range m.members[m.generation] {
		if slices.Contains(reachable, n) {
			if m.deliver(messages[n], false).prepare.Promised {
				promises++
			}
		} else {
			m.drop(messages[n])
		}
	}
	if promises >= len(m.members[m.generation])/2+1 {
		messages = m.phase()
		for _, n := range m.members[m.generation] {
			if slices.Contains(reachable, n) {
				m.deliver(messages[n], false)
			} else {
				m.drop(messages[n])
			}
		}
	}
	return <-result
}

type modelSnapshot struct {
	generation int64
	states     map[corrosion.ClaimKey]corrosion.ClaimVoterState
}

func (m *protocolModel) freeze(old int64, voters []string) map[string]modelSnapshot {
	snapshots := map[string]modelSnapshot{}
	for _, voter := range voters {
		n := m.nodes[voter]
		if n.generation < old {
			m.t.Fatal("unadopted source")
		}
		if n.generation == old {
			n.sealed = true
		}
		snapshots[voter] = modelSnapshot{generation: n.generation, states: maps.Clone(n.states)}
	}
	return snapshots
}
func (m *protocolModel) adopt(voter string, generation int64, sources []string, snapshots map[string]modelSnapshot) error {
	n := m.nodes[voter]
	if n.generation != generation-1 {
		return errors.New("nonconsecutive adoption")
	}
	seen := map[string]bool{}
	for _, source := range sources {
		snapshot, ok := snapshots[source]
		if !ok || snapshot.generation < generation-1 || !slices.Contains(m.members[generation-1], source) {
			return errors.New("unverified source")
		}
		seen[source] = true
	}
	if len(seen) < len(m.members[generation-1])/2+1 {
		return errors.New("unavailable: old recovery quorum missing")
	}
	// This is the candidate full-state transfer rule, NOT today's production
	// importer. A certified normal change supplies an old frozen quorum. Every
	// old phase-two ballot first prepared such a quorum, so its promise floor
	// intersects each import quorum even if its acceptance was only a minority.
	for _, source := range sources {
		for key, in := range snapshots[source].states {
			current := n.states[key]
			current.Key = key
			if os.Getenv("AUTOMATION_MODEL_ACCEPTED_ONLY") == "1" {
				if in.Value == nil {
					continue
				}
			} else if corrosion.CompareBallots(in.Promised, current.Promised) > 0 {
				current.Promised = in.Promised
			}
			if in.Value != nil && corrosion.CompareBallots(in.Accepted, current.Accepted) > 0 {
				current.Accepted, current.Value, current.ValueDigest = in.Accepted, in.Value, in.ValueDigest
				current.Accept = nil
			}
			if corrosion.CompareBallots(current.Accepted, current.Promised) > 0 {
				current.Promised = current.Accepted
			}
			current.ConfigGeneration = generation
			n.states[key] = current
		}
	}
	n.generation, n.sealed = generation, false // atomic with durable import
	return nil
}
