// Package automation defines the internal automation engine contract.
package automation

import "github.com/litevirt/litevirt/internal/automation/contract"

type Command = contract.Command
type Receipt = contract.Receipt
type View = contract.View
type Decision = contract.Decision

const (
	CodeValidation          = contract.CodeValidation
	CodeRevisionConflict    = contract.CodeRevisionConflict
	CodeOwnershipConflict   = contract.CodeOwnershipConflict
	CodeIdempotencyConflict = contract.CodeIdempotencyConflict
	CodeUnavailable         = contract.CodeUnavailable
	CodeRetired             = contract.CodeRetired
	CodeUnsupported         = contract.CodeUnsupported
)

func Code(err error) string { return contract.Code(err) }
