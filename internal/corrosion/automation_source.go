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
	"errors"
	"math"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/litevirt/litevirt/internal/pki"
)

const maxSourcePreparations = 8
const sourcePreparationLifetime = 30 * time.Second
const sourceManifestDomain = "litevirt/automation-source-publication/v1"

// AutomationSourceRequest is bounded intent, never content, a predecessor,
// source lifetime or a caller verification/completion assertion.
type AutomationSourceRequest struct {
	Generation int64
	Target     string
	Job        string
	Revision   int64
	Sources    []VoterMember
}

type sourceManifest struct {
	Version                                                                                        int
	Purpose, Stream, TrustDomain, TrustEvidence                                                    string
	Request                                                                                        AutomationSourceRequest
	Source, Incarnation, OldValue, NextValue, OldMembers, NextMembers, Lineage, MembershipEvidence string
	Cut                                                                                            automationCutMetadata
	Root                                                                                           string
	Target                                                                                         sourceTargetManifest
	Signer                                                                                         string
}
type sourceTargetManifest struct {
	Host, Incarnation, Endpoint, Connected, Certificate string
	Local                                               bool
}

// AutomationSourcePreparation is process-only, explicitly unpublishable
// preparation. It is neither a durable job pin nor commit authority. Its signed
// bytes are private; a later typed FULL owner must independently recheck facts.
type AutomationSourcePreparation struct {
	mu                               sync.Mutex
	self                             *AutomationSourcePreparation
	owner                            *AutomationSourcePreparer
	ctx                              context.Context
	stopContext                      func() bool
	timer                            *time.Timer
	request                          AutomationSourceRequest
	discovery                        sourceDiscovery
	dependency                       string
	transitionEvidence               string
	manifest                         sourceManifest
	body, signature, artifact        []byte
	chain                            [][]byte
	trust                            *pki.HostTrust
	validations                      []*pki.HostCertificateValidation
	at, notBefore, notAfter, expires time.Time
}

func (p *AutomationSourcePreparation) Discard() {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.self != p || p.owner == nil {
		p.mu.Unlock()
		return
	}
	c := p.owner.client
	c.automationSourceMu.Lock()
	delete(c.automationSourcePreparations, p)
	c.automationSourceMu.Unlock()
	if p.stopContext != nil {
		p.stopContext()
	}
	if p.timer != nil {
		p.timer.Stop()
	}
	caps := p.validations
	p.validations = nil
	p.self = nil
	p.owner = nil
	p.ctx = nil
	p.stopContext = nil
	p.timer = nil
	p.body = nil
	p.signature = nil
	p.artifact = nil
	p.chain = nil
	p.trust = nil
	p.transitionEvidence = ""
	p.discovery = sourceDiscovery{}
	p.manifest = sourceManifest{}
	p.request = AutomationSourceRequest{}
	p.dependency = ""
	p.mu.Unlock()
	for _, cap := range caps {
		cap.Discard()
	}
}

type AutomationSourcePreparer struct {
	client *Client
	dir    string
}

// NewAutomationSourcePreparer binds actual application configuration. It does
// not reconcile completed floors or enable publication/readiness.
func NewAutomationSourcePreparer(c *Client, dir string) *AutomationSourcePreparer {
	return &AutomationSourcePreparer{client: c, dir: dir}
}

func sourceRequest(r AutomationSourceRequest) (AutomationSourceRequest, error) {
	if r.Generation <= 0 || r.Generation == math.MaxInt64 || r.Revision <= 0 || r.Job == "" || len(r.Job) > 128 || !utf8.ValidString(r.Job) || r.Target == "" || len(r.Target) > 253 || !utf8.ValidString(r.Target) || sourceMembers(r.Sources) != nil {
		return r, errors.New("invalid source request")
	}
	r.Sources = append([]VoterMember(nil), r.Sources...)
	sort.Slice(r.Sources, func(i, j int) bool { return r.Sources[i].Name < r.Sources[j].Name })
	return r, nil
}
func sourceRoster(r AutomationSourceRequest, d sourceDiscovery, source string) error {
	if len(r.Sources) < MajorityOf(len(d.old.Members)) {
		return errors.New("requested source roster is not a whole-old majority")
	}
	found := false
	for _, m := range r.Sources {
		old, ok := d.old.Member(m.Name)
		if !ok || old != m {
			return errors.New("requested source is not an exact old member")
		}
		found = found || m.Name == source
	}
	if !found {
		return errors.New("requested source roster excludes this source")
	}
	if _, ok := d.next.Member(r.Target); !ok {
		return errors.New("target is not a successor member")
	}
	return nil
}
func (producer *AutomationSourcePreparer) Prepare(ctx context.Context, request AutomationSourceRequest) (candidate *AutomationSourcePreparation, err error) {
	if producer == nil || producer.client == nil {
		return nil, errors.New("missing source owner")
	}
	request, err = sourceRequest(request)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	c := producer.client
	p := &AutomationSourcePreparation{owner: producer, ctx: ctx, request: request, at: time.Now()}
	p.self = p
	c.automationSourceMu.Lock()
	if c.automationSourceClosed {
		c.automationSourceMu.Unlock()
		return nil, errors.New("source client is closed")
	}
	if len(c.automationSourcePreparations) >= maxSourcePreparations {
		c.automationSourceMu.Unlock()
		return nil, errors.New("source preparation capacity reached")
	}
	if c.automationSourcePreparations == nil {
		c.automationSourcePreparations = make(map[*AutomationSourcePreparation]bool)
	}
	c.automationSourcePreparations[p] = true
	c.automationSourceMu.Unlock()
	defer func() {
		if err != nil {
			p.Discard()
		}
	}()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.self != p {
		return nil, errors.New("source attempt was discarded")
	}
	// Reserve a finite attempt before key acquisition. The first key is the
	// actual served pair, before any database discovery or network exchange.
	pair, err := pki.ServedHostKeyPair(producer.dir)
	if err != nil {
		return nil, err
	}
	attemptCtx, cancel := context.WithTimeout(ctx, sourcePreparationLifetime)
	defer cancel()
	d, err := c.discoverSource(attemptCtx, request)
	if err != nil {
		return nil, err
	}
	if err = sourceRoster(request, d, c.hostName); err != nil {
		return nil, err
	}
	cert, err := sourceCertificate(d.next.Certificate)
	if err != nil {
		return nil, err
	}
	sourceLearnMembership(producer.dir, cert)
	var target sourceTarget
	if request.Target == c.hostName {
		target = sourceTarget{Host: d.target, Incarnation: d.incarnation, Local: true}
		for _, raw := range pair.Certificate {
			target.Chain = append(target.Chain, bytes.Clone(raw))
		}
		fp := sha256.Sum256(target.Chain[0])
		target.Fingerprint = hex.EncodeToString(fp[:])
	} else {
		_, target, err = sourceQueryPeer(attemptCtx, producer.dir, d.target, request.Generation, false)
		if err != nil {
			return nil, err
		}
	}
	member, _ := d.next.Member(request.Target)
	if member.Incarnation != target.Incarnation {
		return nil, errors.New("observed target storage lifetime differs from successor")
	}
	view, err := pki.CaptureHostTrust(attemptCtx, producer.dir, c.hostName)
	if err != nil {
		return nil, err
	}
	signer, err := ClaimSignerFromKeyPair(c.hostName, pair)
	if err != nil {
		return nil, err
	}
	verifiedNext := d.next
	before, after, err := verifySourceTransition(view, d.old, verifiedNext)
	if err != nil {
		verifiedNext, err = producer.reattestSourceTransition(attemptCtx, d, signer)
		if err != nil {
			return nil, err
		}
		view, err = pki.CaptureHostTrust(attemptCtx, producer.dir, c.hostName)
		if err != nil {
			return nil, err
		}
		before, after, err = verifySourceTransition(view, d.old, verifiedNext)
		if err != nil {
			return nil, err
		}
	}
	p.transitionEvidence = verifiedNext.Certificate
	if err = sourceAdmission(view, d.source, pair.Certificate[0]); err != nil {
		return nil, err
	}
	if err = sourceAdmission(view, d.target, target.Chain[0]); err != nil {
		return nil, err
	}
	if !signer.AutomationTransportEligible() {
		return nil, errors.New("source signer exceeds supported size")
	}
	domain := view.RootDigest()
	evidence := view.EvidenceDigest()
	fingerprint := sha256.Sum256(pair.Certificate[0])
	p.manifest = sourceManifest{Version: 1, Purpose: "automation-membership-source", Stream: "automation", TrustDomain: hex.EncodeToString(domain[:]), TrustEvidence: hex.EncodeToString(evidence[:]), Request: request, Source: c.hostName, Incarnation: d.incarnation, OldValue: sourceConfigDigest(d.old), NextValue: sourceConfigDigest(d.next), OldMembers: d.old.MembersHash, NextMembers: d.next.MembersHash, Lineage: d.lineage, MembershipEvidence: sourceDigest([]byte(verifiedNext.Certificate)), Cut: d.cut, Root: d.root, Target: sourceTargetManifest{Host: request.Target, Incarnation: target.Incarnation, Endpoint: target.Endpoint, Connected: target.Connected, Certificate: target.Fingerprint, Local: target.Local}, Signer: hex.EncodeToString(fingerprint[:])}
	if err = p.signSourceManifest(signer, pair.Certificate); err != nil {
		return nil, err
	}
	// Re-read exact DB dependencies after network/signing, outside PKI ownership.
	// Durable consumption must perform this independently again in its FULL tx.
	current, err := c.discoverSource(attemptCtx, request)
	if err != nil {
		return nil, err
	}
	p.dependency = sourceDiscoveryDigest(d)
	if sourceDiscoveryDigest(current) != p.dependency {
		return nil, errors.New("source dependencies changed during preparation")
	}
	// Reconcile cross-process files before registering the old exact snapshot.
	// Registration refuses changed revision, including policy toggle-back.
	if _, err = pki.CaptureHostTrust(attemptCtx, producer.dir, c.hostName); err != nil {
		return nil, err
	}
	sourceCap, err := view.ValidateServedHost(attemptCtx, pair)
	if err != nil {
		return nil, err
	}
	p.validations = append(p.validations, sourceCap)
	targetCap, err := view.ValidateHostCertificate(attemptCtx, target.Chain, request.Target)
	if err != nil {
		return nil, err
	}
	p.validations = append(p.validations, targetCap)
	p.discovery = d
	p.trust = view
	p.notBefore = before
	p.notAfter = after
	p.expires = p.at.Add(sourcePreparationLifetime)
	if err = p.checkPreparedLocked(); err != nil {
		return nil, err
	}
	p.stopContext = context.AfterFunc(ctx, p.Discard)
	p.timer = time.AfterFunc(time.Until(p.expires), p.Discard)
	return p, nil
}

// signSourceManifest accepts only this constructor's privately built typed
// manifest, never a generic byte string or fabricated claim vote.
func (p *AutomationSourcePreparation) signSourceManifest(signer *ClaimSigner, chain [][]byte) error {
	body, err := json.Marshal(p.manifest)
	if err != nil || len(body) > maxSourceManifestBytes {
		return errors.New("source manifest exceeds bound")
	}
	digest := sourceDigest([]byte(sourceManifestDomain), body)
	hash, _ := hex.DecodeString(digest)
	signature, err := ecdsa.SignASN1(rand.Reader, signer.key, hash)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return err
	}
	public, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !ecdsa.VerifyASN1(public, hash, signature) {
		return errors.New("source key does not match captured signer")
	}
	p.body = body
	p.signature = signature
	size := 0
	for _, raw := range chain {
		size += len(raw)
		if size > 1<<20 || len(p.chain) >= 8 {
			return errors.New("source chain exceeds bound")
		}
		p.chain = append(p.chain, bytes.Clone(raw))
	}
	artifact, err := json.Marshal(sourceSignedArtifact{Manifest: json.RawMessage(body), Signature: signature, Chain: p.chain})
	if err != nil || len(artifact) > maxSourceArtifactBytes {
		return errors.New("source artifact exceeds bound")
	}
	p.artifact = artifact
	return nil
}

type sourceSignedArtifact struct {
	Manifest  json.RawMessage
	Signature []byte
	Chain     [][]byte
}

const maxSourceArtifactBytes = 2 << 20

// checkPrepared checks only this process's exact signed preparation. It does
// not replace PKI lease acquisition or independent transaction-local rechecks.
func (p *AutomationSourcePreparation) checkPrepared() error {
	if p == nil {
		return errors.New("nil source preparation")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.checkPreparedLocked()
}
func (p *AutomationSourcePreparation) checkPreparedLocked() error {
	if p.self != p || p.owner == nil {
		return errors.New("foreign or discarded source preparation")
	}
	c := p.owner.client
	if c == nil {
		return errors.New("missing preparation client")
	}
	c.automationSourceMu.Lock()
	active := c.automationSourcePreparations[p] && !c.automationSourceClosed
	c.automationSourceMu.Unlock()
	if !active {
		return errors.New("inactive source preparation")
	}
	if err := p.ctx.Err(); err != nil {
		return err
	}
	now := time.Now()
	if now.Before(p.at) || now.Before(p.notBefore) || !now.Before(p.notAfter) || !now.Before(p.expires) {
		return errors.New("source preparation expired")
	}
	if p.discovery.old == nil || p.discovery.next == nil || p.trust == nil {
		return errors.New("missing preparation facts")
	}
	request, _ := json.Marshal(p.request)
	boundRequest, _ := json.Marshal(p.manifest.Request)
	cut, _ := json.Marshal(p.discovery.cut)
	boundCut, _ := json.Marshal(p.manifest.Cut)
	domain := p.trust.RootDigest()
	evidence := p.trust.EvidenceDigest()
	if !bytes.Equal(request, boundRequest) || !bytes.Equal(cut, boundCut) || p.manifest.Source != c.hostName || p.manifest.Incarnation != p.discovery.incarnation || p.manifest.Root != p.discovery.root || p.manifest.Lineage != p.discovery.lineage || p.manifest.OldValue != sourceConfigDigest(p.discovery.old) || p.manifest.NextValue != sourceConfigDigest(p.discovery.next) || p.dependency != sourceDiscoveryDigest(p.discovery) || p.manifest.MembershipEvidence != sourceDigest([]byte(p.transitionEvidence)) || p.manifest.TrustDomain != hex.EncodeToString(domain[:]) || p.manifest.TrustEvidence != hex.EncodeToString(evidence[:]) {
		return errors.New("source preparation facts changed")
	}
	body, err := json.Marshal(p.manifest)
	if err != nil || !bytes.Equal(body, p.body) || len(p.chain) == 0 {
		return errors.New("source preparation binding changed")
	}
	artifact, err := json.Marshal(sourceSignedArtifact{Manifest: json.RawMessage(p.body), Signature: p.signature, Chain: p.chain})
	if err != nil || len(artifact) > maxSourceArtifactBytes || !bytes.Equal(artifact, p.artifact) {
		return errors.New("source artifact binding changed")
	}
	fingerprint := sha256.Sum256(p.chain[0])
	if p.manifest.Signer != hex.EncodeToString(fingerprint[:]) {
		return errors.New("source signer binding changed")
	}
	leaf, err := x509.ParseCertificate(p.chain[0])
	if err != nil {
		return err
	}
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	digest, _ := hex.DecodeString(sourceDigest([]byte(sourceManifestDomain), p.body))
	if !ok || !ecdsa.VerifyASN1(key, digest, p.signature) {
		return errors.New("invalid source preparation signature")
	}
	return nil
}
