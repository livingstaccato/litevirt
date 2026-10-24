package corrosion

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/automation/custody"
	"github.com/litevirt/litevirt/internal/pki"
)

// Construction binds actual daemon owners. It creates neither authority nor a
// missing custody root; only explicit initial preparation may reserve a root.
type AutomationCustodyProducer struct {
	mu           sync.Mutex
	client       *Client
	pkiDir, root string
	store        *custody.LocalCustody
	scope        custody.CustodyScope
	closed       bool
}
type custodyObservedHost struct {
	binding  contract.CustodyHost
	endpoint sourceHost
}
type custodyInitialPlan struct {
	Candidates                       []contract.CustodyCandidate
	ImportRequest, ActivationRequest string
}

type custodySnapshot struct {
	head      contract.Prefix
	genesis   contract.HistoryReference
	principal string
	cfg       *VoterConfig
	hosts     map[string]custodyObservedHost
}

// AutomationInitialEpoch is process-local intent under an original deadline,
// never a first-vote capability or a caller-constructible authority record.
type AutomationInitialEpoch struct {
	mu                               sync.Mutex
	self                             *AutomationInitialEpoch
	owner                            *AutomationCustodyProducer
	ctx                              context.Context
	expires                          time.Time
	snapshot                         custodySnapshot
	candidates                       []contract.CustodyCandidate
	plan                             custody.CustodyProvisionRef
	importRequest, activationRequest string
	sourceStarted                    bool
	resumed                          bool
	historical                       *AutomationCustodyReady
}

func NewAutomationCustodyProducer(c *Client, pkiDir, custodyRoot string) (*AutomationCustodyProducer, error) {
	if c == nil || c.hostName == "" || !filepath.IsAbs(pkiDir) || !filepath.IsAbs(custodyRoot) || filepath.Clean(custodyRoot) != custodyRoot || custodyRoot == "/" {
		return nil, errAutomationAuthority
	}
	return &AutomationCustodyProducer{client: c, pkiDir: pkiDir, root: custodyRoot}, nil
}
func (p *AutomationCustodyProducer) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.store != nil {
		return p.store.Close()
	}
	return nil
}
func (p *AutomationInitialEpoch) Release() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.self = nil
	p.owner = nil
	p.ctx = nil
}
func custodyRandomID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}
func custodyScope(cluster string, h contract.CustodyHost) custody.CustodyScope {
	return custody.CustodyScope{ClusterUID: cluster, HostID: h.Host, HostIncarnation: h.HostIncarnation, AdmittedAt: h.AdmittedAt}
}
func custodyRefs(c contract.CustodyCandidate) (custody.CustodyKeyRef, custody.CustodyKeyRef, custody.CustodyKeyRef) {
	return custody.CustodyKeyRef{Epoch: c.RecipientEpoch, KeyID: c.VoterKeyID, Generation: c.MembershipGeneration, ConfigDigest: c.ConfigDigest}, custody.CustodyKeyRef{Epoch: c.EqualityEpoch, KeyID: c.SourceEqualityKeyID, Generation: c.MembershipGeneration, ConfigDigest: c.ConfigDigest}, custody.CustodyKeyRef{Epoch: c.EqualityEpoch, KeyID: c.EqualityKeyID, Generation: c.MembershipGeneration, ConfigDigest: c.ConfigDigest}
}
func custodyProvisionRef(c contract.CustodyCandidate) custody.CustodyProvisionRef {
	voter, _, equality := custodyRefs(c)
	return custody.CustodyProvisionRef{Attempt: c.Attempt, Voter: voter, Equality: equality}
}

// snapshotTx is the strict fresh-issuance gate. Historical continuation uses
// currentSnapshotTx only, then authenticates an exact certified original.
func (p *AutomationCustodyProducer) snapshotTx(ctx context.Context, tx *LocalTx) (custodySnapshot, error) {
	if err := custodyEmptyInventoryTx(ctx, tx); err != nil {
		return custodySnapshot{}, err
	}
	return p.currentSnapshotTx(ctx, tx)
}
func custodyEmptyInventoryTx(ctx context.Context, tx *LocalTx) error {
	for _, table := range []string{"local_automation_key_epochs", "local_automation_key_recipients", "local_automation_payload_wrappings"} {
		rows, err := automationKeyRowsTx(ctx, tx, table, "")
		if err != nil {
			return err
		}
		if len(rows) != 0 {
			return errAutomationAuthority
		}
	}
	rows, err := tx.Query(ctx, `SELECT count(*) AS n FROM local_automation_admissions WHERE stage='' AND payload_id<>''`)
	if err != nil || len(rows) != 1 || rows[0].Int64("n") != 0 {
		return errAutomationAuthority
	}
	return nil
}
func (p *AutomationCustodyProducer) currentSnapshotTx(ctx context.Context, tx *LocalTx) (custodySnapshot, error) {
	var s custodySnapshot
	if p == nil || p.client == nil || ctx.Err() != nil {
		return s, errAutomationAuthority
	}
	standing, err := readStandingTx(ctx, tx, p.client.hostName)
	if err != nil {
		return s, err
	}
	cfg, err := automationAuthorityTx(ctx, tx, p.client.hostName, standing.adopted)
	if err != nil {
		return s, err
	}
	if cfg.MembersHash != MembersHash(cfg.Members) || len(cfg.Members) > contract.MaxKeyRecipients {
		return s, errAutomationAuthority
	}
	head, err := automationHeadTx(ctx, tx)
	if err != nil {
		return s, err
	}
	retained, err := automationRetainedHeadTx(ctx, tx)
	if err != nil || head.Sequence == 0 || head != retained {
		return s, errAutomationAuthority
	}
	genesis, err := (localAutomationKeySource{tx}).keyHistory(ctx, 1)
	if err != nil || genesis.Kind != "initialize_cluster" || genesis.ClusterUID != head.ClusterUID || genesis.MembershipGeneration != uint64(cfg.Generation) || genesis.PrincipalID == "" {
		return s, errAutomationAuthority
	}
	trusted, found, err := automationTrustedDigestTx(ctx, tx, 1)
	if err != nil || !found || trusted != genesis.Digest {
		return s, errAutomationAuthority
	}
	s = custodySnapshot{head: head, genesis: contract.HistoryReference{Sequence: 1, Digest: genesis.Digest}, principal: genesis.PrincipalID, cfg: cfg, hosts: map[string]custodyObservedHost{}}
	for _, member := range cfg.Members {
		endpoint, err := sourceReadHost(ctx, tx, member.Name)
		if err != nil {
			return custodySnapshot{}, err
		}
		key, found, err := localHostKey(ctx, tx.tx, member.Name)
		if err != nil || !found || key.deleted || key.n < 0 || len(key.at) > contract.MaxStringBytes || key.serial != endpoint.Serial {
			return custodySnapshot{}, errAutomationAuthority
		}
		if _, err = time.Parse(time.RFC3339Nano, key.at); err != nil {
			return custodySnapshot{}, errAutomationAuthority
		}
		s.hosts[member.Name] = custodyObservedHost{binding: contract.CustodyHost{Host: member.Name, HostIncarnation: uint64(key.n), AdmittedAt: key.at, AdmissionSerial: key.serial, VoterIncarnation: member.Incarnation}, endpoint: endpoint}
	}
	if s.hosts[p.client.hostName].binding.VoterIncarnation != standing.incarnation {
		return custodySnapshot{}, errAutomationAuthority
	}
	return s, requireAutomationFull(ctx, tx)
}

func (p *AutomationCustodyProducer) localTrust(ctx context.Context) (*pki.HostTrust, *tls.Certificate, *pki.HostCertificateValidation, error) {
	pair, err := pki.ServedHostKeyPair(p.pkiDir)
	if err != nil {
		return nil, nil, nil, err
	}
	view, err := pki.CaptureHostTrust(ctx, p.pkiDir, p.client.hostName)
	if err != nil {
		return nil, nil, nil, err
	}
	cap, err := view.ValidateServedHost(ctx, pair)
	if err != nil {
		return nil, nil, nil, err
	}
	return view, pair, cap, nil
}
func (p *AutomationCustodyProducer) openStore(scope custody.CustodyScope, create bool) (*custody.LocalCustody, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, errAutomationAuthority
	}
	if p.store != nil {
		if p.scope != scope {
			return nil, errAutomationAuthority
		}
		return p.store, nil
	}
	var store *custody.LocalCustody
	var err error
	if create {
		store, err = custody.CreateLocalCustody(p.root, scope)
		if errors.Is(err, custody.ErrCustodyConflict) {
			store, err = custody.OpenLocalCustody(p.root, scope)
		}
	} else {
		store, err = custody.OpenLocalCustody(p.root, scope)
	}
	if err != nil {
		return nil, err
	}
	p.store, p.scope = store, scope
	return store, nil
}

func (p *AutomationCustodyProducer) PrepareInitialEpoch(ctx context.Context) (*AutomationInitialEpoch, error) {
	if p == nil || p.client == nil || ctx.Err() != nil {
		return nil, errAutomationAuthority
	}
	expires := time.Now().Add(sourcePreparationLifetime)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	view, pair, cap, err := p.localTrust(ctx)
	if err != nil {
		return nil, err
	}
	defer cap.Discard()
	lease, err := pki.AcquireHostCertificateLease(ctx, p.pkiDir, cap)
	if err != nil {
		return nil, err
	}
	var snap custodySnapshot
	err = p.client.executeLocal(ctx, func(tx *LocalTx) error {
		var err error
		snap, err = p.snapshotTx(ctx, tx)
		if err != nil {
			return err
		}
		return sourceAdmission(view, snap.hosts[p.client.hostName].endpoint, pair.Certificate[0])
	}, &localCommitSeams{beforeCommit: func(tx *sql.Tx) error {
		if ctx.Err() != nil || !time.Now().Before(expires) {
			return errAutomationAuthority
		}
		return lease.Check()
	}})
	lease.Release()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 7+2*len(snap.cfg.Members))
	for i := range ids {
		ids[i], err = custodyRandomID()
		if err != nil {
			return nil, err
		}
	}
	attempt := &AutomationInitialEpoch{owner: p, ctx: ctx, expires: expires, snapshot: snap, importRequest: ids[3], activationRequest: ids[4]}
	attempt.self = attempt
	source := snap.hosts[p.client.hostName].binding
	sourceEquality := ""
	for i, member := range snap.cfg.Members {
		if member.Name == p.client.hostName {
			sourceEquality = ids[7+2*i+1]
		}
	}
	for i, member := range snap.cfg.Members {
		candidate := contract.CustodyCandidate{ClusterUID: snap.head.ClusterUID, Attempt: ids[0], MembershipGeneration: uint64(snap.cfg.Generation), ConfigDigest: snap.cfg.MembersHash, RecipientEpoch: ids[1], EqualityEpoch: ids[2], ExpiresAt: expires.UTC().Format(time.RFC3339Nano), Genesis: snap.genesis, Source: source, Target: snap.hosts[member.Name].binding, VoterKeyID: ids[7+2*i], SourceEqualityKeyID: sourceEquality, EqualityKeyID: ids[7+2*i+1]}
		if err = contract.ValidateCustodyCandidate(candidate); err != nil {
			return nil, err
		}
		attempt.candidates = append(attempt.candidates, candidate)
	}
	store, err := p.openStore(custodyScope(snap.head.ClusterUID, source), true)
	if err != nil {
		return nil, err
	}
	_, sourceRef, _ := custodyRefs(attempt.candidates[0])
	attempt.plan = custody.CustodyProvisionRef{Attempt: ids[0], Voter: custody.CustodyKeyRef{Epoch: ids[1], KeyID: ids[5], Generation: uint64(snap.cfg.Generation), ConfigDigest: snap.cfg.MembersHash}, Equality: sourceRef}
	body, err := json.Marshal(custodyInitialPlan{attempt.candidates, attempt.importRequest, attempt.activationRequest})
	if err != nil {
		return nil, err
	}
	if err = store.SaveProvisionRecord(attempt.plan, "plan", body); err != nil {
		return nil, err
	}
	if ctx.Err() != nil || !time.Now().Before(expires) {
		return nil, errAutomationAuthority
	}
	return attempt, nil
}

// Continuation is inert metadata identifying existing files; it carries no
// authorization and contains neither recipient identity nor equality material.
func (a *AutomationInitialEpoch) Continuation() (custody.CustodyProvisionRef, error) {
	if a == nil {
		return custody.CustodyProvisionRef{}, errAutomationAuthority
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.self != a || a.owner == nil {
		return custody.CustodyProvisionRef{}, errAutomationAuthority
	}
	return a.plan, nil
}
func (p *AutomationCustodyProducer) ResumeInitialEpoch(ctx context.Context, ref custody.CustodyProvisionRef) (*AutomationInitialEpoch, error) {
	if p == nil || p.client == nil || ctx.Err() != nil {
		return nil, errAutomationAuthority
	}
	view, pair, cap, err := p.localTrust(ctx)
	if err != nil {
		return nil, err
	}
	defer cap.Discard()
	lease, err := pki.AcquireHostCertificateLease(ctx, p.pkiDir, cap)
	if err != nil {
		return nil, err
	}
	var snap custodySnapshot
	err = p.client.executeLocal(ctx, func(tx *LocalTx) error {
		var e error
		snap, e = p.currentSnapshotTx(ctx, tx)
		if e != nil {
			return e
		}
		return sourceAdmission(view, snap.hosts[p.client.hostName].endpoint, pair.Certificate[0])
	}, &localCommitSeams{beforeCommit: func(tx *sql.Tx) error {
		if ctx.Err() != nil {
			return errAutomationAuthority
		}
		return lease.Check()
	}})
	lease.Release()
	if err != nil {
		return nil, err
	}
	own := snap.hosts[p.client.hostName].binding
	store, err := p.openStore(custodyScope(snap.head.ClusterUID, own), false)
	if err != nil {
		return nil, err
	}
	raw, err := store.ReadProvisionRecord(ref, "plan")
	if err != nil {
		return nil, err
	}
	var plan custodyInitialPlan
	if custodyProtocolDecode(raw, &plan) != nil || len(plan.Candidates) != len(snap.cfg.Members) || len(plan.Candidates) == 0 {
		return nil, errAutomationAuthority
	}
	for _, id := range []string{plan.ImportRequest, plan.ActivationRequest} {
		decoded, e := hex.DecodeString(id)
		if e != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != id {
			return nil, errAutomationAuthority
		}
	}
	if plan.ImportRequest == plan.ActivationRequest {
		return nil, errAutomationAuthority
	}
	first := plan.Candidates[0]
	expires, err := time.Parse(time.RFC3339Nano, first.ExpiresAt)
	if err != nil || !time.Now().Before(expires) || time.Until(expires) > sourcePreparationLifetime {
		return nil, errAutomationAuthority
	}
	_, sourceRef, _ := custodyRefs(first)
	if first.Source != own || ref.Attempt != first.Attempt || ref.Equality != sourceRef || ref.Voter.Epoch != first.RecipientEpoch || ref.Voter.Generation != first.MembershipGeneration || ref.Voter.ConfigDigest != first.ConfigDigest {
		return nil, errAutomationAuthority
	}
	voters, equalities := map[string]bool{}, map[string]bool{}
	for i, candidate := range plan.Candidates {
		if contract.ValidateCustodyCandidate(candidate) != nil || !custodyCandidateMatches(snap, candidate) || candidate.Target.Host != snap.cfg.Members[i].Name || candidate.Source != first.Source || candidate.Attempt != first.Attempt || candidate.RecipientEpoch != first.RecipientEpoch || candidate.EqualityEpoch != first.EqualityEpoch || candidate.SourceEqualityKeyID != first.SourceEqualityKeyID || candidate.ExpiresAt != first.ExpiresAt || voters[candidate.VoterKeyID] || equalities[candidate.EqualityKeyID] {
			return nil, errAutomationAuthority
		}
		voters[candidate.VoterKeyID] = true
		equalities[candidate.EqualityKeyID] = true
		if candidate.Target.Host == own.Host && candidate.EqualityKeyID != first.SourceEqualityKeyID {
			return nil, errAutomationAuthority
		}
	}
	// A restart cannot distinguish absent original material from a lost create.
	// Only reopen it; a new process never regenerates this reserved identity.
	if _, err = store.OpenEqualityKey(sourceRef); err != nil {
		return nil, err
	}
	attempt := &AutomationInitialEpoch{owner: p, ctx: ctx, expires: expires, snapshot: snap, candidates: plan.Candidates, plan: ref, importRequest: plan.ImportRequest, activationRequest: plan.ActivationRequest, sourceStarted: true, resumed: true}
	attempt.self = attempt
	historical, err := p.recoverCertifiedInitialEpoch(ctx, attempt)
	if err != nil {
		return nil, err
	}
	if historical == nil {
		if err = p.client.ExecuteLocal(ctx, func(tx *LocalTx) error { _, e := p.snapshotTx(ctx, tx); return e }); err != nil {
			return nil, err
		}
	} else {
		attempt.historical = historical
	}
	return attempt, nil
}
