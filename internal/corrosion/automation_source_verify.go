package corrosion

import (
	"errors"
	"fmt"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

// VerifyVoterConfigRow is the shared ordinary membership predicate. Source
// preparation supplies its private pure snapshot-backed verifier; normal
// adoption retains its existing verifier and Historical policy.
func VerifyVoterConfigRow(v *ClaimVerifier, prev, row *VoterConfig) error {
	if row == nil {
		return errors.New("missing voter config")
	}
	if err := ValidateVoterChange(prev, row.VoterConfigValue); err != nil {
		return err
	}
	if row.MembersHash != MembersHash(row.Members) {
		return fmt.Errorf("members_hash does not match members_json")
	}
	want, err := ExpectedVoterConfigCertificate(prev, row.VoterConfigValue)
	if err != nil {
		return err
	}
	cert, err := DecodeClaimCertificate(row.Certificate)
	if err != nil {
		return err
	}
	return v.Verify(cert, want)
}

func sourceCertificate(raw string) (ClaimCertificate, error) {
	if len(raw) == 0 || len(raw) > maxSourceCertificateBytes {
		return ClaimCertificate{}, errors.New("over-bound membership certificate")
	}
	if err := preflightProofJSONLimits(raw, false, maxSourceAccepts, MaxAutomationVoters, maxSourceAcceptPEMBytes); err != nil {
		return ClaimCertificate{}, err
	}
	cert, err := DecodeClaimCertificate(raw)
	if err != nil {
		return cert, err
	}
	if len(cert.Accepts) > maxSourceAccepts {
		return cert, errors.New("too many membership accepts")
	}
	for _, a := range cert.Accepts {
		if len(a.CertPEM) > maxSourceAcceptPEMBytes || len(a.Signature) > 256 || len(a.Voter) > 253 || len(a.VoterIncarnation) > 128 || len(a.ValueDigest) > 64 || len(a.Ballot.Coordinator) > 253 {
			return cert, errors.New("over-bound membership accept")
		}
	}
	return cert, nil
}
func sourceLearnMembership(dir string, cert ClaimCertificate) {
	for _, a := range cert.Accepts {
		if leaf, err := parseCertPEM([]byte(a.CertPEM)); err == nil {
			pki.NoteSuccessor(dir, leaf)
		}
	}
}
func verifySourceTransition(view *pki.HostTrust, old, next *VoterConfig) (time.Time, time.Time, error) {
	cert, err := sourceCertificate(next.Certificate)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	v := &ClaimVerifier{sourceTrust: view, pinned: true}
	if err := VerifyVoterConfigRow(v, old, next); err != nil {
		return time.Time{}, time.Time{}, err
	}
	electorate := map[string]string{}
	for _, m := range old.Members {
		electorate[m.Name] = m.Incarnation
	}
	var before, after time.Time
	// Only genuinely counted signatures affect this interval. Invalid extras do
	// not become required signers and a reachable subset never changes quorum.
	for _, a := range cert.Accepts {
		if v.verifyAccept(cert, a, electorate) != nil {
			continue
		}
		leaf, _ := parseCertPEM([]byte(a.CertPEM))
		b, e, err := view.VerifyOrdinaryCertificate(leaf.Raw, false, true)
		if err != nil {
			return before, after, err
		}
		if b.After(before) {
			before = b
		}
		if after.IsZero() || e.Before(after) {
			after = e
		}
	}
	if after.IsZero() {
		return before, after, errors.New("missing counted membership interval")
	}
	return before, after, nil
}
