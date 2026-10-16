package corrosion

import "fmt"

// One bounded retained anchor, its full target value and original electorate.
// These facts detect corruption; they grant no current trust/time authority.
type automationAnchorInput struct {
	Sequence, AnchorSequence int64
	Digest, AnchorDigest     string
	Generation               int64
	MembersHash              string
	Certificate              ClaimCertificate
	Target                   ClaimValue
	TargetDigest             string
	Membership               *VoterConfig
}

func validateAutomationAnchor(in automationAnchorInput) error {
	if in.Sequence <= 0 || in.AnchorSequence < in.Sequence {
		return fmt.Errorf("invalid source anchor sequence")
	}
	if in.Digest != in.AnchorDigest || in.Generation <= 0 || in.MembersHash == "" {
		return fmt.Errorf("source anchor missing or corrupt")
	}
	cert, cfg := in.Certificate, in.Membership
	key, err := AutomationClaimKey(uint64(in.AnchorSequence))
	if err != nil {
		return err
	}
	if cert.Key != key || cert.ConfigGeneration != in.Generation || cert.Ballot.IsZero() || len(cert.Accepts) == 0 {
		return fmt.Errorf("source anchor certificate mismatch")
	}
	if err = validateAutomationValue(key, in.Target); err != nil {
		return err
	}
	actual, err := in.Target.Digest()
	if err != nil || actual != in.TargetDigest || cert.ValueDigest != in.TargetDigest {
		return fmt.Errorf("source anchor target missing")
	}
	if cfg == nil || cfg.Generation != in.Generation {
		return fmt.Errorf("source anchor membership missing")
	}
	if cfg.MembersHash != in.MembersHash || cfg.MembersHash != MembersHash(cfg.Members) || automationElectorateBudget(cfg.Members) != nil {
		return fmt.Errorf("source anchor membership mismatch")
	}
	counted := map[string]bool{}
	incarnations := map[string]bool{}
	for _, a := range cert.Accepts {
		member, ok := cfg.Member(a.Voter)
		if !ok || member.Incarnation != a.VoterIncarnation || counted[a.Voter] || incarnations[a.VoterIncarnation] {
			continue
		}
		if validateRetainedAutomationAccept(a, cert.Key, cert.Ballot, cert.ConfigGeneration, cert.ValueDigest) != nil {
			continue
		}
		counted[a.Voter] = true
		incarnations[a.VoterIncarnation] = true
	}
	if len(counted) < MajorityOf(len(cfg.Members)) {
		return fmt.Errorf("corrupt retained anchor signatures")
	}

	return nil
}
