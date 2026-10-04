package corrosion

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"
)

// Forced reconfiguration (docs/design/recovery-claims.md §4.6): the
// break-glass for a voter generation g whose majority is gone for good, so
// that neither `voter rm` nor any recovery claim can ever succeed under it.
//
// The survivors — the members of g not named lost, fewer than a majority of g
// — each seal g, sign the new generation unanimously, and adopt it after
// importing every value any of them accepted and every certificate any
// reachable host holds. What that gives up, and why the named lost hosts must
// be fenced proof-grade first, is §4.6's "What safety is given up".

// ForcedSignature is one survivor's signature over a forced generation.
type ForcedSignature struct {
	Voter       string `json:"voter"`
	Incarnation string `json:"incarnation"`
	CertPEM     string `json:"cert_pem"`
	Signature   []byte `json:"signature"`
}

// ForcedFence is the proof-grade fence of one lost host the forced generation
// rests on.
type ForcedFence struct {
	Host      string `json:"host"`
	FenceID   string `json:"fence_id"`
	Method    string `json:"method"`
	Result    string `json:"result"`
	Timestamp string `json:"timestamp"`
}

// ForcedVoterEvidence is what a forced generation's certificate column holds
// in place of a claim certificate.
type ForcedVoterEvidence struct {
	FromGeneration int64             `json:"from_generation"`
	Lost           []string          `json:"lost"`
	Fences         []ForcedFence     `json:"fences"`
	Signatures     []ForcedSignature `json:"signatures"`
}

// Encode is the evidence's stored form.
func (e ForcedVoterEvidence) Encode() (string, error) {
	b, err := json.Marshal(e)
	return string(b), err
}

// DecodeForcedVoterEvidence parses a forced generation's evidence.
func DecodeForcedVoterEvidence(s string) (ForcedVoterEvidence, error) {
	var e ForcedVoterEvidence
	if err := json.Unmarshal([]byte(s), &e); err != nil {
		return e, fmt.Errorf("forced-generation evidence does not parse: %w", err)
	}
	return e, nil
}

// VoterChangeForce names a forced reconfiguration that dropped lost.
func VoterChangeForce(lost []string) string {
	l := append([]string(nil), lost...)
	sort.Strings(l)
	return voterChangeForcePfx + strings.Join(l, ",")
}

// ForcedLost returns the lost hosts a force: change names.
func ForcedLost(change string) []string {
	if !IsForcedChange(change) {
		return nil
	}
	return strings.Split(strings.TrimPrefix(change, voterChangeForcePfx), ",")
}

const voterForceDomain = "litevirt-voter-force-v1"

// forcedPayload is what each survivor signs:
// "litevirt-voter-force-v1" || g || members || lost, over the full value so a
// signature cannot be replayed onto another forced generation.
func forcedPayload(from int64, v VoterConfigValue, voter, incarnation string) []byte {
	h := sha256.New()
	claimField(h, voterForceDomain)
	claimField(h, i64(from))
	claimField(h, i64(v.Generation))
	claimField(h, MembersHash(SortMembers(v.Members)))
	claimField(h, v.Change)
	claimField(h, v.CreatedBy)
	claimField(h, v.CreatedAt)
	claimField(h, voter)
	claimField(h, incarnation)
	return h.Sum(nil)
}

// SignForced signs this survivor's part of a forced generation.
func (s *ClaimSigner) SignForced(from int64, v VoterConfigValue, incarnation string) (ForcedSignature, error) {
	if s == nil || s.key == nil {
		return ForcedSignature{}, fmt.Errorf("no claim signing key loaded")
	}
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, forcedPayload(from, v, s.name, incarnation))
	if err != nil {
		return ForcedSignature{}, fmt.Errorf("sign forced generation: %w", err)
	}
	return ForcedSignature{Voter: s.name, Incarnation: incarnation, CertPEM: s.certPEM, Signature: sig}, nil
}

// ValidateForcedChange checks a forced generation against the one it replaces
// (§4.6 "Adopting a forced row"), everything but the probes: the named lost
// hosts and the members partition prev exactly, the members keep their
// entries, they are FEWER than a majority of prev, every lost host has a
// proof-grade fence recorded, and every member signed. It is what every voter
// checks before it signs and every node before it adopts.
func (v *ClaimVerifier) ValidateForcedChange(prev *VoterConfig, next VoterConfigValue, ev ForcedVoterEvidence) error {
	if err := ValidateForcedShape(prev, next, ev); err != nil {
		return err
	}
	return v.verifyForcedSignatures(prev, next, ev)
}

// ValidateForcedShape is ValidateForcedChange without the signatures: what a
// survivor checks before it signs.
func ValidateForcedShape(prev *VoterConfig, next VoterConfigValue, ev ForcedVoterEvidence) error {
	if !prev.Explicit() {
		return fmt.Errorf("a forced reconfiguration replaces a generation with members")
	}
	if next.Generation != prev.Generation+1 || ev.FromGeneration != prev.Generation {
		return fmt.Errorf("forced generation %d does not follow %d", next.Generation, prev.Generation)
	}
	lost := append([]string(nil), ev.Lost...)
	sort.Strings(lost)
	if len(lost) == 0 || next.Change != VoterChangeForce(lost) {
		return fmt.Errorf("change %q does not name the lost hosts %v", next.Change, lost)
	}
	old := map[string]string{}
	for _, m := range prev.Members {
		old[m.Name] = m.Incarnation
	}
	seen := map[string]bool{}
	for _, l := range lost {
		if _, ok := old[l]; !ok {
			return fmt.Errorf("%s is named lost but is not a member of generation %d", l, prev.Generation)
		}
		seen[l] = true
	}
	for _, m := range next.Members {
		inc, ok := old[m.Name]
		if !ok || seen[m.Name] {
			return fmt.Errorf("member %s is not a surviving member of generation %d", m.Name, prev.Generation)
		}
		if inc != m.Incarnation {
			return fmt.Errorf("member %s's incarnation changed across the forced generation", m.Name)
		}
		seen[m.Name] = true
	}
	if len(seen) != len(prev.Members) {
		return fmt.Errorf("members and lost hosts do not cover generation %d exactly", prev.Generation)
	}
	if len(next.Members) == 0 || len(next.Members) >= MajorityOf(len(prev.Members)) {
		return fmt.Errorf("%d survivors of %d are a majority, or none: `lv cluster voter rm` is the change, not a forced one",
			len(next.Members), len(prev.Members))
	}
	fenced := map[string]bool{}
	for _, f := range ev.Fences {
		if FenceProofGrade(f.Method, f.Result) && f.FenceID != "" {
			fenced[f.Host] = true
		}
	}
	for _, l := range lost {
		if !fenced[l] {
			return fmt.Errorf("the forced generation carries no proof-grade fence of %s", l)
		}
	}
	return nil
}

func (v *ClaimVerifier) verifyForcedSignatures(prev *VoterConfig, next VoterConfigValue, ev ForcedVoterEvidence) error {
	old := map[string]string{}
	for _, m := range prev.Members {
		old[m.Name] = m.Incarnation
	}
	signed := map[string]bool{}
	for _, sgn := range ev.Signatures {
		if !isMember(next.Members, sgn.Voter) {
			return fmt.Errorf("%s signed but is not a survivor", sgn.Voter)
		}
		inc := old[sgn.Voter]
		if sgn.Incarnation != inc {
			return fmt.Errorf("%s signed as incarnation %s, admitted as %s", sgn.Voter, short(sgn.Incarnation), short(inc))
		}
		if err := v.verifySigned(sgn.CertPEM, sgn.Voter, forcedPayload(ev.FromGeneration, next, sgn.Voter, sgn.Incarnation), sgn.Signature); err != nil {
			return fmt.Errorf("%s's signature: %w", sgn.Voter, err)
		}
		signed[sgn.Voter] = true
	}
	for _, m := range next.Members {
		if !signed[m.Name] {
			return fmt.Errorf("survivor %s did not sign; a forced generation is unanimous among its survivors", m.Name)
		}
	}
	return nil
}

func isMember(ms []VoterMember, name string) bool {
	for _, m := range ms {
		if m.Name == name {
			return true
		}
	}
	return false
}

// verifySigned checks a signature by name's CA-issued, unrevoked certificate.
func (v *ClaimVerifier) verifySigned(certPEM, name string, payload, sig []byte) error {
	if v == nil {
		return fmt.Errorf("no claim verifier loaded")
	}
	c, err := parseCertPEM([]byte(certPEM))
	if err != nil {
		return err
	}
	if _, err := c.Verify(x509.VerifyOptions{Roots: v.roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("certificate does not chain to the cluster CA: %w", err)
	}
	if c.Subject.CommonName != name {
		return fmt.Errorf("signed with %q's certificate", c.Subject.CommonName)
	}
	if v.revoked(c) {
		return fmt.Errorf("certificate %s is revoked", c.SerialNumber.Text(16))
	}
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate key is not ECDSA")
	}
	if !ecdsa.VerifyASN1(pub, payload, sig) {
		return fmt.Errorf("signature does not verify")
	}
	return nil
}

// SealVoterGeneration records, durably, that this node no longer answers
// Prepare or Accept for workload keys under generation gen: the first step of
// a forced reconfiguration (§4.6 "What it does" step 1). Once sealed this
// voter's state for gen can no longer change, which is what lets the other
// survivors import it. Idempotent.
func (c *Client) SealVoterGeneration(ctx context.Context, gen int64, reason string) error {
	return c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		_, err := tx.Exec(ctx, `INSERT OR IGNORE INTO local_voter_seals (generation, reason, sealed_at) VALUES (?, ?, ?)`,
			gen, reason, time.Now().UTC().Format(time.RFC3339Nano))
		return err
	})
}

// VoterGenerationSealed reports whether this node sealed gen by force.
func (c *Client) VoterGenerationSealed(ctx context.Context, gen int64) (bool, error) {
	rows, err := c.Query(ctx, `SELECT 1 AS one FROM local_voter_seals WHERE generation = ?`, gen)
	return len(rows) > 0, err
}

// CertifiedProofStates returns, for every live runtime-action proof carrying a
// claim certificate at a generation up to gen, the value that certificate
// decided, as an accepted voter state — what a forced reconfiguration imports
// alongside the survivors' own state (§4.6 step 3). Certificates are verified
// first: a replicated row can be written by any peer, and an import is a vote.
func CertifiedProofStates(ctx context.Context, c *Client, v *ClaimVerifier, gen int64) ([]ClaimVoterState, error) {
	rows, err := c.Query(ctx, `SELECT id FROM runtime_action_proofs WHERE deleted_at IS NULL AND claim_certificate != ''`)
	if err != nil {
		return nil, err
	}
	var out []ClaimVoterState
	for _, r := range rows {
		pr, ok, err := GetActionProof(ctx, c, r.String("id"))
		if err != nil || !ok {
			continue
		}
		cert, err := CertificateAuthorizesProof(pr.ClaimCertificate, pr.ActionProof)
		if err != nil || cert.ConfigGeneration > gen {
			continue
		}
		cfg, err := GetVoterConfig(ctx, c, cert.ConfigGeneration)
		if err != nil || !cfg.Explicit() {
			continue
		}
		if err := v.Verify(cert, CertExpectation{Key: cert.Key, ValueDigest: cert.ValueDigest, ConfigGeneration: cert.ConfigGeneration,
			Electorate: cfg.Members, Quorum: MajorityOf(len(cfg.Members))}); err != nil {
			continue
		}
		binding := pr.ActionProof
		binding.ClaimCertificate = ""
		binding.LeaseHolder, binding.LeaseExpiresAt, binding.QuorumLive, binding.QuorumNeeded = "", "", 0, 0
		val := ClaimValue{Proof: &binding, SourceHost: cert.SourceHost}
		out = append(out, ClaimVoterState{Key: cert.Key, Promised: cert.Ballot, Accepted: cert.Ballot,
			Value: &val, ValueDigest: cert.ValueDigest, ConfigGeneration: cert.ConfigGeneration})
	}
	return out, nil
}

func (c *Client) noteRefusedForced(gen int64, detail string) {
	c.forcedRefusedMu.Lock()
	defer c.forcedRefusedMu.Unlock()
	if c.forcedRefused == nil {
		c.forcedRefused = map[int64]string{}
	}
	if _, seen := c.forcedRefused[gen]; !seen {
		slog.Error("voter set: refusing a FORCED voter generation over the ordinary one this node adopted",
			"generation", gen, "detail", detail)
	}
	c.forcedRefused[gen] = detail
}

// RefusedForcedVoterConfigs is every forced generation the anti-entropy merge
// refused because this node had already adopted an ordinary row for it, with
// why. In memory: a restart re-learns it on the next merge.
func (c *Client) RefusedForcedVoterConfigs() map[int64]string {
	c.forcedRefusedMu.Lock()
	defer c.forcedRefusedMu.Unlock()
	out := make(map[int64]string, len(c.forcedRefused))
	for g, d := range c.forcedRefused {
		out[g] = d
	}
	return out
}
