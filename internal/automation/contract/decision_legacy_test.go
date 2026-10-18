package contract

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math"
	"strings"
)

// Frozen from 641abbe5bdc58f9dbebd1f0701e75cdabd04ce4c. Keep both semantic
// and decoding bodies independent of the production validator and dispatcher.
// legacyEncodeDecision preserves exact recovery bytes. It is distinct from the retry
// identity codec: session, ciphertext and server assignment are all certified.
func legacyEncodeDecision(d Decision) ([]byte, error) {
	if d.Sequence == 0 || d.Sequence > math.MaxInt64 {
		return nil, codedError(CodeValidation)
	}
	if d.Sequence == 1 {
		if d.ParentDigest != "" || d.Command.Kind != "initialize_cluster" || d.Command.ClusterUID != "" {
			return nil, codedError(CodeValidation)
		}
	} else {
		b, e := hex.DecodeString(d.ParentDigest)
		if d.Command.ClusterUID == "" || e != nil || len(b) != 32 || d.ParentDigest != strings.ToLower(d.ParentDigest) || d.Command.Kind == "initialize_cluster" {
			return nil, codedError(CodeValidation)
		}
	}
	c := d.Command
	for _, s := range []string{c.Kind, c.ClusterUID, c.ProjectUID, c.PrincipalID, c.OwnerID, c.ManagementKey, c.RequestID, c.ResourceUID, c.SecretKeyEpoch, c.SessionID} {
		if len(s) > MaxStringBytes {
			return nil, codedError(CodeValidation)
		}
	}
	if len(c.SecretIntentTag) > 256 || len(c.Ciphertext) > MaxDecisionBytes || len(d.Assignment) > 1<<20 {
		return nil, codedError(CodeValidation)
	}
	if _, err := CanonicalCommand(c); err != nil {
		return nil, err
	}
	if _, err := canonicalBody(d.Assignment); err != nil {
		return nil, codedError(CodeValidation)
	}
	b, err := json.Marshal(decisionEnvelope{1, d})
	if err != nil || len(b) > MaxDecisionBytes {
		return nil, codedError(CodeValidation)
	}
	return b, nil
}

// legacyDecodeDecision refuses repairs, duplicates, unknown fields and trailing data.
// Re-encoding equality also prevents alternate representations of accepted bytes.
func legacyDecodeDecision(b []byte) (Decision, error) {
	var e decisionEnvelope
	if len(b) == 0 || len(b) > MaxDecisionBytes {
		return Decision{}, codedError(CodeValidation)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&e) != nil || e.Version != 1 {
		return Decision{}, codedError(CodeValidation)
	}
	canonical, err := legacyEncodeDecision(e.Decision)
	if err != nil || !bytes.Equal(canonical, b) {
		return Decision{}, codedError(CodeValidation)
	}
	return e.Decision, nil
}
