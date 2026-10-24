package contract

import (
	"bytes"
	"encoding/json"
	"io"
	"time"
	"unicode/utf8"
)

// Assignment is the complete nonsecret server-assigned schema for the two
// implemented control handlers. New semantic handlers add their own typed
// schema here and extend the one reducer; they never inherit generic success.
type Assignment struct {
	CustodyImport *CustodyImportRecord     `json:"custody_import,omitempty"`
	Continuity    *IdentityContinuity      `json:"continuity,omitempty"`
	Execution     *ExecutionAssignment     `json:"execution,omitempty"`
	KeyTransition *KeyTransitionAssignment `json:"key_transition,omitempty"`
	Ownership     *OwnershipAssignment     `json:"ownership,omitempty"`
	Binding       *BindingAssignment       `json:"binding,omitempty"`
	Version       int                      `json:"version"`
	ClusterUID    string                   `json:"cluster_uid"`
	OperationID   string                   `json:"operation_id"`
	RecordedAt    string                   `json:"recorded_at"`
	Owner         *OwnerAssignment         `json:"owner,omitempty"`
	Identity      *IdentityAssignment      `json:"identity,omitempty"`
	Target        *TargetAssignment        `json:"target,omitempty"`
}
type controlBody struct {
	Version int `json:"version"`
}

func decodeFields(b []byte, out any, fields ...string) error {
	if _, err := canonicalBody(b); err != nil {
		return codedError(CodeValidation)
	}
	return decodeFieldsObject(b, out, fields...)
}

func decodeFieldsObject(b []byte, out any, fields ...string) error {
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

// ValidateSupportedCommand is shared by pre-slot admission and the direct
// acceptor gate. It is structural capability validation, not a second reducer.
func ValidateSupportedCommand(c Command) error {
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
	if decodeFields(c.Body, &b, "version") != nil || b.Version != 1 {
		return codedError(CodeValidation)
	}
	if c.ProjectUID != "" || c.OwnerID != "" || c.ManagementKey != "" || c.ResourceUID != "" || c.Session != 0 || c.SessionID != "" || c.Generation != 0 || c.ExpectedRevision != 0 || len(c.Ciphertext) != 0 || len(c.SecretIntentTag) != 0 || c.SecretKeyEpoch != "" || c.RequestID == "" || c.PrincipalID == "" {
		return codedError(CodeValidation)
	}
	_, err := CanonicalCommand(c)
	return err
}
func decodeAssignmentFields(raw []byte, out any, fields ...string) error {
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
	return decodeFieldsObject(raw, out, fields...)
}

// canonicalCustodyAssignment recognizes only the typed encoding emitted by the
// native key producer. Exact allowed-field re-encoding proves unique syntax:
// duplicates, unknown fields, repaired strings/bytes and other representations
// cannot match. The permitted custody types have fixed, nonrecursive JSON
// shapes below the generic 64-container limit. This is not semantic admission;
// every caller still validates the actual command and assignment together.
// A miss always belongs to the original strict decoder, including valid older
// encodings with whitespace, different field order or escaped strings.
func canonicalCustodyAssignment(d Decision) (Assignment, bool) {
	if d.Command.Kind != CustodyImportCommand && d.Command.Kind != "activate_key_epoch" || len(d.Assignment) == 0 || len(d.Assignment) > 1<<20 {
		return Assignment{}, false
	}
	var decoded Assignment
	if json.Unmarshal(d.Assignment, &decoded) != nil || decoded.Version != CustodyAssignmentVersion {
		return Assignment{}, false
	}
	// Copy only the fields allowed for this command. Marshaling the unrestricted
	// decoded union would incorrectly permit another class's recognized field.
	a := Assignment{Version: decoded.Version, ClusterUID: decoded.ClusterUID, OperationID: decoded.OperationID, RecordedAt: decoded.RecordedAt}
	if d.Command.Kind == CustodyImportCommand {
		a.CustodyImport = decoded.CustodyImport
	} else {
		a.KeyTransition = decoded.KeyTransition
	}
	canonical, err := json.Marshal(a)
	if err != nil || !bytes.Equal(canonical, d.Assignment) || a.ClusterUID == "" || a.OperationID == "" || len(a.ClusterUID) > MaxStringBytes || len(a.OperationID) > MaxStringBytes {
		return Assignment{}, false
	}
	if _, err := time.Parse(time.RFC3339Nano, a.RecordedAt); err != nil {
		return Assignment{}, false
	}
	return a, true
}

func DecodeAssignment(d Decision) (Assignment, error) {
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
	if canonical, ok := canonicalCustodyAssignment(d); ok {
		a = canonical
	} else if err := decodeAssignmentFields(d.Assignment, &a, fields...); err != nil {
		return a, err
	}
	if d.Command.Kind == IdentityContinuityCommand {
		var raw map[string]json.RawMessage
		if json.Unmarshal(d.Assignment, &raw) != nil || a.Continuity == nil || decodeFieldsObject(raw["continuity"], a.Continuity, "cluster_uid", "uid", "original_witness", "generation", "parent") != nil || !continuityFields(raw["continuity"], false) || !validContinuity(*a.Continuity) {
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
func ValidateSupportedDecision(d Decision) error {
	if !keyTransitionKind(d.Command.Kind) {
		if err := ValidateSupportedCommand(d.Command); err != nil {
			return err
		}
	}
	a, err := DecodeAssignment(d)
	if err != nil {
		return err
	}
	return validateSupportedAssignment(d, a)
}

// The assignment is freshly decoded in this invocation, never a cached proof
// attached to the caller's mutable Decision. Keep all semantic checks here.
func validateSupportedAssignment(d Decision, a Assignment) error {
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
