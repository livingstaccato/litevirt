// Package contract defines the internal durable automation command contract.
// The codec identifies immutable retries; it does not authorize or execute them.
package contract

import "errors"

type Command struct {
	Kind                                         string
	ClusterUID, ProjectUID, PrincipalID, OwnerID string
	ManagementKey, RequestID, ResourceUID        string
	Session, Generation, ExpectedRevision        uint64
	SessionID                                    string `json:"SessionID,omitempty"`
	// Body is a versioned nonsecret JSON object. Reducers define typed fields
	// and defaults; the codec rejects ambiguous JSON and canonicalizes values.
	Body       []byte
	Ciphertext []byte
	// SecretIntentTag and SecretKeyEpoch are PRIVATE equality facts, never
	// public results or diagnostics. SecretKeyEpoch identifies the equality
	// key, not recipient keys. Retry comparison must first rederive the tag
	// using the existing request's equality epoch. Recipient rewrapping changes
	// Ciphertext only and must preserve these equality facts.
	SecretIntentTag []byte
	SecretKeyEpoch  string
}

type Receipt struct {
	// ResourceRevision is the opaque equality token for business resources.
	// Legacy numeric Revision remains zero and retains old control encoding.
	ResourceRevision                          string `json:"ResourceRevision,omitempty"`
	RequestID, OperationID, ResourceUID, Code string
	Sequence, Generation, Revision            uint64
	State                                     string
}

type View struct {
	ResourceRevision                                 string `json:"ResourceRevision,omitempty"`
	ClusterUID, ResourceUID, Name, State, DomainUUID string
	Generation, Revision, AppliedSequence            uint64
	Retired                                          bool
}

type Decision struct {
	Sequence     uint64
	ParentDigest string
	Command      Command
	// Assignment holds reducer-assigned facts, separate from caller retry identity.
	Assignment []byte
}

const (
	CodeValidation          = "validation"
	CodeRevisionConflict    = "revision_conflict"
	CodeOwnershipConflict   = "ownership_conflict"
	CodeIdempotencyConflict = "idempotency_conflict"
	CodeUnavailable         = "unavailable"
	CodeRetired             = "retired"
	CodeUnsupported         = "unsupported"
)

type codedError string

func (e codedError) Error() string { return "automation: " + string(e) }
func (e codedError) Code() string  { return string(e) }

// Code returns a structured error code through wrapping, or "" for nil and
// unexpected errors. An unclassified error must not be interpreted as absence.
func Code(err error) string {
	var coded interface{ Code() string }
	if errors.As(err, &coded) {
		return coded.Code()
	}
	return ""
}
