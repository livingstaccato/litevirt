package contract

import (
	"bytes"
	"encoding/json"
	"io"
	"time"
)

// Assignment is the complete nonsecret server-assigned schema for the two
// implemented control handlers. New semantic handlers add their own typed
// schema here and extend the one reducer; they never inherit generic success.
type Assignment struct {
	Version     int    `json:"version"`
	ClusterUID  string `json:"cluster_uid"`
	OperationID string `json:"operation_id"`
	RecordedAt  string `json:"recorded_at"`
}
type controlBody struct {
	Version int `json:"version"`
}

func decodeFields(b []byte, out any, fields ...string) error {
	if _, err := canonicalBody(b); err != nil {
		return codedError(CodeValidation)
	}
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
	if c.Kind != "initialize_cluster" && c.Kind != "read_barrier" {
		return codedError(CodeUnsupported)
	}
	var b controlBody
	if decodeFields(c.Body, &b, "version") != nil || b.Version != 1 {
		return codedError(CodeValidation)
	}
	if c.ProjectUID != "" || c.OwnerID != "" || c.ManagementKey != "" || c.ResourceUID != "" || c.Session != 0 || c.Generation != 0 || c.ExpectedRevision != 0 || len(c.Ciphertext) != 0 || len(c.SecretIntentTag) != 0 || c.SecretKeyEpoch != "" || c.RequestID == "" || c.PrincipalID == "" {
		return codedError(CodeValidation)
	}
	_, err := CanonicalCommand(c)
	return err
}
func DecodeAssignment(d Decision) (Assignment, error) {
	var a Assignment
	if err := decodeFields(d.Assignment, &a, "version", "cluster_uid", "operation_id", "recorded_at"); err != nil {
		return a, err
	}
	if a.Version != 1 || a.ClusterUID == "" || a.OperationID == "" || len(a.ClusterUID) > MaxStringBytes || len(a.OperationID) > MaxStringBytes {
		return a, codedError(CodeValidation)
	}
	if _, err := time.Parse(time.RFC3339Nano, a.RecordedAt); err != nil {
		return a, codedError(CodeValidation)
	}
	return a, nil
}
func ValidateSupportedDecision(d Decision) error {
	if err := ValidateSupportedCommand(d.Command); err != nil {
		return err
	}
	a, err := DecodeAssignment(d)
	if err != nil {
		return err
	}
	if d.Command.Kind == "read_barrier" && a.ClusterUID != d.Command.ClusterUID {
		return codedError(CodeValidation)
	}
	return nil
}
