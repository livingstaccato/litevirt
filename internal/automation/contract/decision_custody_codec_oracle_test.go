package contract

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"strings"
	"time"
	"unicode/utf8"
)

// Frozen ec9412 codec/dispatcher oracle. Changed functions call only frozen
// counterparts. Types and unchanged canonicalBody/semantic validators are shared;
// their bodies are protected by the finite two-file optimization grant.
// decision.go SHA256 1ce7fb715f71369fc303bd77b312053f8a7a4b40857f4abd688c5e8d08771f3f
// handlers.go SHA256 929b5309c775916ef5abfd37c68b72f2fbcbfefc1c7da444ba4829f8a0c045b1
func ec941EncodeDecision(d Decision) ([]byte, error) {
	if err := ec941ValidateDecision(d); err != nil {
		return nil, err
	}
	b, err := json.Marshal(decisionEnvelope{1, d})
	if err != nil || len(b) > MaxDecisionBytes {
		return nil, codedError(CodeValidation)
	}
	return b, nil
}

func ec941ValidateDecision(d Decision) error {
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
	if _, err := canonicalBody(d.Assignment); err != nil {
		// Preserve the legacy assignment byte domain. The separately allocated
		// key-only outer version must cross the exact supported-kind validator;
		// ordinary command body and envelope versions remain unchanged.
		a, err := ec941DecodeAssignment(d)
		if err != nil || a.Version != CustodyAssignmentVersion || ec941ValidateSupportedDecision(d) != nil {
			return codedError(CodeValidation)
		}
	}
	return nil
}

// ec941DecodeDecision refuses repairs, duplicates, unknown fields and trailing data.
// Re-encoding equality also prevents alternate representations of accepted bytes.
func ec941DecodeDecision(b []byte) (Decision, error) {
	if len(b) == 0 || len(b) > MaxDecisionBytes {
		return Decision{}, codedError(CodeValidation)
	}
	if d, ok := ec941DecodeDecisionCiphertext(b); ok {
		return d, nil
	}
	return ec941DecodeDecisionJSON(b)
}

func ec941DecodeDecisionJSON(b []byte) (Decision, error) {
	var e decisionEnvelope
	if len(b) == 0 || len(b) > MaxDecisionBytes {
		return Decision{}, codedError(CodeValidation)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&e) != nil || e.Version != 1 {
		return Decision{}, codedError(CodeValidation)
	}
	canonical, err := ec941EncodeDecision(e.Decision)
	if err != nil || !bytes.Equal(canonical, b) {
		return Decision{}, codedError(CodeValidation)
	}
	return e.Decision, nil
}

// ec941DecodeDecisionCiphertext removes only the large opaque token from a private
// comparison shell. Full shell equality proves its position and every other
// byte; strict base64 proves the removed token's unique canonical encoding.
// Failure publishes nothing: the original decoder owns public errors.
func ec941DecodeDecisionCiphertext(b []byte) (Decision, bool) {
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
	if ec941ValidateDecision(e.Decision) != nil {
		return Decision{}, false
	}
	return e.Decision, true
}

func ec941DecodeFields(b []byte, out any, fields ...string) error {
	if _, err := canonicalBody(b); err != nil {
		return codedError(CodeValidation)
	}
	return ec941DecodeFieldsObject(b, out, fields...)
}

func ec941DecodeFieldsObject(b []byte, out any, fields ...string) error {
	var keys map[string]json.RawMessage
	if json.Unmarshal(b, &keys) != nil {
		return codedError(CodeValidation)
	}
	allowed := map[string]bool{}
	for _, f := range fields {
		allowed[f] = true
	}
	for k := range keys {
		if !allowed[k] {
			return codedError(CodeValidation)
		}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return codedError(CodeValidation)
	}
	return nil
}

// ec941ValidateSupportedCommand is shared by pre-slot admission and the direct
// acceptor gate. It is structural capability validation, not a second reducer.
func ec941ValidateSupportedCommand(c Command) error {
	if c.Kind == CustodyImportCommand {
		_, err := DecodeCustodyImportBody(c)
		return err
	}
	if c.Kind == IdentityContinuityCommand {
		if _, err := DecodeIdentityContinuityBody(c); err != nil {
			return err
		}
		_, err := CanonicalCommand(c)
		return err
	}
	if executionKind(c.Kind) {
		if _, err := DecodeExecutionBody(c); err != nil {
			return err
		}
		_, err := CanonicalCommand(c)
		return err
	}
	if targetCommand(c.Kind) {
		if _, _, _, _, _, err := targetBody(c); err != nil {
			return err
		}
		_, err := CanonicalCommand(c)
		return err
	}
	if c.Kind == "adopt_resource" || c.Kind == "transfer_owner" {
		if _, err := DecodeOwnershipBody(c); err != nil {
			return err
		}
		_, err := CanonicalCommand(c)
		return err
	}
	if c.Kind == "admit_create" {
		if _, err := DecodeCreateBindingBody(c); err != nil {
			return err
		}
		_, err := CanonicalCommand(c)
		return err
	}
	if c.Kind == "ensure_owner" || c.Kind == "acquire_session" || c.Kind == "handoff_session" {
		if _, err := DecodeOwnerBody(c); err != nil {
			return err
		}
		_, err := CanonicalCommand(c)
		return err
	}
	if c.Kind == "assign_identity" {
		if _, err := DecodeIdentityEnrollment(c); err != nil {
			return err
		}
		_, err := CanonicalCommand(c)
		return err
	}
	if c.Kind != "initialize_cluster" && c.Kind != "read_barrier" {
		return codedError(CodeUnsupported)
	}
	var b controlBody
	if ec941DecodeFields(c.Body, &b, "version") != nil || b.Version != 1 {
		return codedError(CodeValidation)
	}
	if c.ProjectUID != "" || c.OwnerID != "" || c.ManagementKey != "" || c.ResourceUID != "" || c.Session != 0 || c.SessionID != "" || c.Generation != 0 || c.ExpectedRevision != 0 || len(c.Ciphertext) != 0 || len(c.SecretIntentTag) != 0 || c.SecretKeyEpoch != "" || c.RequestID == "" || c.PrincipalID == "" {
		return codedError(CodeValidation)
	}
	_, err := CanonicalCommand(c)
	return err
}
func ec941DecodeAssignmentFields(raw []byte, out any, fields ...string) error {
	if len(raw) > 1<<20 || !utf8.Valid(raw) || !validSurrogates(raw) {
		return codedError(CodeValidation)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, err := jsonValue(dec, 0)
	if err != nil {
		return codedError(CodeValidation)
	}
	if _, err = dec.Token(); err != io.EOF {
		return codedError(CodeValidation)
	}
	object, ok := value.(map[string]any)
	if !ok || object["version"] != json.Number("1") && object["version"] != json.Number("4") {
		return codedError(CodeValidation)
	}
	return ec941DecodeFieldsObject(raw, out, fields...)
}
func ec941DecodeAssignment(d Decision) (Assignment, error) {
	var a Assignment
	fields := []string{"version", "cluster_uid", "operation_id", "recorded_at"}
	if d.Command.Kind == CustodyImportCommand {
		fields = append(fields, "custody_import")
	}
	if d.Command.Kind == "claim_executor" {
		fields = append(fields, "execution")
	}
	if targetCommand(d.Command.Kind) {
		fields = append(fields, "target")
	}
	if keyTransitionKind(d.Command.Kind) {
		fields = append(fields, "key_transition")
	}
	if d.Command.Kind == "adopt_resource" || d.Command.Kind == "transfer_owner" {
		fields = append(fields, "ownership")
	}
	if d.Command.Kind == "admit_create" {
		fields = append(fields, "binding")
	}
	if d.Command.Kind == "acquire_session" || d.Command.Kind == "handoff_session" {
		fields = append(fields, "owner")
	}
	if d.Command.Kind == "assign_identity" {
		fields = append(fields, "identity")
	}
	if d.Command.Kind == IdentityContinuityCommand {
		fields = append(fields, "continuity")
	}
	if err := ec941DecodeAssignmentFields(d.Assignment, &a, fields...); err != nil {
		return a, err
	}
	if d.Command.Kind == IdentityContinuityCommand {
		var raw map[string]json.RawMessage
		if json.Unmarshal(d.Assignment, &raw) != nil || a.Continuity == nil || ec941DecodeFieldsObject(raw["continuity"], a.Continuity, "cluster_uid", "uid", "original_witness", "generation", "parent") != nil || !continuityFields(raw["continuity"], false) || !validContinuity(*a.Continuity) {
			return a, codedError(CodeValidation)
		}
	}
	if a.Version != 1 && (a.Version != CustodyAssignmentVersion || d.Command.Kind != CustodyImportCommand && d.Command.Kind != "activate_key_epoch") || a.ClusterUID == "" || a.OperationID == "" || len(a.ClusterUID) > MaxStringBytes || len(a.OperationID) > MaxStringBytes {
		return a, codedError(CodeValidation)
	}
	if _, err := time.Parse(time.RFC3339Nano, a.RecordedAt); err != nil {
		return a, codedError(CodeValidation)
	}
	return a, nil
}
func ec941ValidateSupportedDecision(d Decision) error {
	if !keyTransitionKind(d.Command.Kind) {
		if err := ec941ValidateSupportedCommand(d.Command); err != nil {
			return err
		}
	}
	a, err := ec941DecodeAssignment(d)
	if err != nil {
		return err
	}
	if d.Command.Kind == CustodyImportCommand {
		return validateCustodyImport(d, a)
	}
	if d.Command.Kind == IdentityContinuityCommand {
		return validateContinuityAssignment(d, a)
	}
	if executionKind(d.Command.Kind) {
		return validateExecutionAssignment(d, a)
	}
	if targetCommand(d.Command.Kind) {
		return validateTargetAssignment(d, a)
	}
	if keyTransitionKind(d.Command.Kind) {
		return validateKeyTransition(d, a)
	}
	if d.Command.Kind == "adopt_resource" || d.Command.Kind == "transfer_owner" {
		return validateOwnershipAssignment(d, a)
	}
	if d.Command.Kind == "admit_create" {
		return validateBindingAssignment(d, a)
	}
	if d.Command.Kind == "ensure_owner" || d.Command.Kind == "acquire_session" || d.Command.Kind == "handoff_session" {
		return validateOwnerAssignment(d, a)
	}
	if d.Command.Kind == "assign_identity" {
		return validateIdentityAssignment(d, a)
	}
	if d.Command.Kind == "read_barrier" && a.ClusterUID != d.Command.ClusterUID {
		return codedError(CodeValidation)
	}
	return nil
}
