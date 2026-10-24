package contract

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"strings"
)

// MaxDecisionBytes leaves space for the enclosing base64-encoded claim JSON.
// The storage boundary separately bounds the complete encoded claim at 2 MiB.
const MaxDecisionBytes = 1500 << 10
const MaxStringBytes = 4096

type decisionEnvelope struct {
	Version  uint32
	Decision Decision
}

// EncodeDecision preserves exact recovery bytes. It is distinct from the retry
// identity codec: session, ciphertext and server assignment are all certified.
func EncodeDecision(d Decision) ([]byte, error) {
	if err := validateDecision(d); err != nil {
		return nil, err
	}
	b, err := json.Marshal(decisionEnvelope{1, d})
	if err != nil || len(b) > MaxDecisionBytes {
		return nil, codedError(CodeValidation)
	}
	return b, nil
}

func validateDecision(d Decision) error {
	if d.Sequence == 0 || d.Sequence > math.MaxInt64 {
		return codedError(CodeValidation)
	}
	if d.Sequence == 1 {
		if d.ParentDigest != "" || d.Command.Kind != "initialize_cluster" || d.Command.ClusterUID != "" {
			return codedError(CodeValidation)
		}
	} else {
		b, e := hex.DecodeString(d.ParentDigest)
		if d.Command.ClusterUID == "" || e != nil || len(b) != 32 || d.ParentDigest != strings.ToLower(d.ParentDigest) || d.Command.Kind == "initialize_cluster" {
			return codedError(CodeValidation)
		}
	}
	c := d.Command
	for _, s := range []string{c.Kind, c.ClusterUID, c.ProjectUID, c.PrincipalID, c.OwnerID, c.ManagementKey, c.RequestID, c.ResourceUID, c.SecretKeyEpoch, c.SessionID} {
		if len(s) > MaxStringBytes {
			return codedError(CodeValidation)
		}
	}
	if len(c.SecretIntentTag) > 256 || len(c.Ciphertext) > MaxDecisionBytes || len(d.Assignment) > 1<<20 {
		return codedError(CodeValidation)
	}
	if _, err := CanonicalCommand(c); err != nil {
		return err
	}
	if a, ok := canonicalCustodyAssignment(d); ok {
		if !keyTransitionKind(d.Command.Kind) {
			if err := ValidateSupportedCommand(d.Command); err != nil {
				return err
			}
		}
		return validateSupportedAssignment(d, a)
	}
	if _, err := canonicalBody(d.Assignment); err != nil {
		// Preserve the legacy assignment byte domain. The separately allocated
		// key-only outer version must cross the exact supported-kind validator;
		// ordinary command body and envelope versions remain unchanged.
		a, err := DecodeAssignment(d)
		if err != nil || a.Version != CustodyAssignmentVersion || ValidateSupportedDecision(d) != nil {
			return codedError(CodeValidation)
		}
	}
	return nil
}

// DecodeDecision refuses repairs, duplicates, unknown fields and trailing data.
// Re-encoding equality also prevents alternate representations of accepted bytes.
func DecodeDecision(b []byte) (Decision, error) {
	if len(b) == 0 || len(b) > MaxDecisionBytes {
		return Decision{}, codedError(CodeValidation)
	}
	if d, ok := decodeDecisionCiphertext(b); ok {
		return d, nil
	}
	return decodeDecisionJSON(b)
}

func decodeDecisionJSON(b []byte) (Decision, error) {
	var e decisionEnvelope
	if len(b) == 0 || len(b) > MaxDecisionBytes {
		return Decision{}, codedError(CodeValidation)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&e) != nil || e.Version != 1 {
		return Decision{}, codedError(CodeValidation)
	}
	canonical, err := EncodeDecision(e.Decision)
	if err != nil || !bytes.Equal(canonical, b) {
		return Decision{}, codedError(CodeValidation)
	}
	return e.Decision, nil
}

// decodeDecisionCiphertext removes only the large opaque token from a private
// comparison shell. Full shell equality proves its position and every other
// byte; strict base64 proves the removed token's unique canonical encoding.
// Failure publishes nothing: the original decoder owns public errors.
func decodeDecisionCiphertext(b []byte) (Decision, bool) {
	if len(b) == 0 || len(b) > MaxDecisionBytes {
		return Decision{}, false
	}
	const marker = `,"Ciphertext":"`
	i := bytes.Index(b, []byte(marker))
	if i < 0 {
		return Decision{}, false
	}
	start := i + len(marker)
	end := bytes.IndexByte(b[start:], '"')
	if end <= 0 || end%4 != 0 {
		return Decision{}, false
	}
	end += start
	encoded := b[start:end]
	if bytes.IndexByte(encoded, '\r') >= 0 || bytes.IndexByte(encoded, '\n') >= 0 {
		return Decision{}, false
	}
	shell := make([]byte, 0, len(b)-len(encoded)+2)
	shell = append(shell, b[:start-1]...)
	shell = append(shell, "null"...)
	shell = append(shell, b[end+1:]...)
	var e decisionEnvelope
	dec := json.NewDecoder(bytes.NewReader(shell))
	dec.DisallowUnknownFields()
	if dec.Decode(&e) != nil || e.Version != 1 || e.Decision.Command.Ciphertext != nil {
		return Decision{}, false
	}
	canonical, err := json.Marshal(e)
	if err != nil || !bytes.Equal(canonical, shell) {
		return Decision{}, false
	}
	ciphertext := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Strict().Decode(ciphertext, encoded)
	if err != nil || n == 0 {
		return Decision{}, false
	}
	e.Decision.Command.Ciphertext = ciphertext[:n]
	// Validate the restored actual value, never infer semantics from the shell.
	if validateDecision(e.Decision) != nil {
		return Decision{}, false
	}
	return e.Decision, true
}
