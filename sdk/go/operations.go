package litevirt

import (
	"context"
	"errors"
	av "github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// WaitOperation observes an existing operation without submitting or canceling
// work. BLOCKED remains nonterminal. A failed terminal operation returns both
// its response and a structural Error. Interrupted waits retain their reference.
// Advice exceeding MaxBackoff defers the wait with ErrWaitBackoffExceeded and a
// WaitError containing cloned operation/retry advice, without overbound sleep.
func (c *Client) WaitOperation(parent context.Context, ref *av.OperationRef) (*av.GetOperationResponse, error) {
	if ref == nil || ref.OperationId == "" {
		return nil, decodeError(status.Error(codes.InvalidArgument, "operation reference required"))
	}
	known := proto.Clone(ref).(*av.OperationRef)
	ctx, done, err := c.begin(parent)
	if err != nil {
		return nil, &WaitError{Operation: known, Cause: err}
	}
	defer done()
	interrupted := func(err error) error { return &WaitError{Operation: proto.Clone(known).(*av.OperationRef), Cause: err} }
	for attempt := 0; ; attempt++ {
		out, err := c.GetOperation(ctx, &av.GetOperationRequest{Lookup: &av.GetOperationRequest_Operation{Operation: known}})
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrClosed) {
				return nil, interrupted(err)
			}
			return nil, err
		}
		op := out.GetOperation()
		if op == nil || op.GetRef().GetOperationId() != known.OperationId {
			return out, status.Error(codes.DataLoss, "operation response identity mismatch")
		}
		known.MinimumSequence = max(known.MinimumSequence, op.GetRef().GetMinimumSequence(), out.GetCursor().GetAppliedSequence())
		switch op.State {
		case av.OperationState_OPERATION_STATE_SUCCEEDED:
			return out, nil
		case av.OperationState_OPERATION_STATE_FAILED:
			detail := op.Error
			if detail == nil {
				detail = &av.ErrorDetail{Code: av.ErrorCode_ERROR_CODE_OPERATION_FAILED, Operation: proto.Clone(known).(*av.OperationRef), Retry: op.Retry}
			}
			return out, &Error{Code: detail.Code, Detail: proto.Clone(detail).(*av.ErrorDetail), Cause: status.Error(codes.FailedPrecondition, "operation failed")}
		case av.OperationState_OPERATION_STATE_ACCEPTED, av.OperationState_OPERATION_STATE_RUNNING, av.OperationState_OPERATION_STATE_BLOCKED:
		default:
			return out, status.Error(codes.DataLoss, "unknown operation state")
		}
		delay := c.backoff(min(attempt, 30))
		if advice := op.GetRetry(); advice.GetRetryAfter() != nil && advice.RetryAfter.IsValid() {
			if advice.RetryAfter.AsDuration() > c.cfg.MaxBackoff {
				return out, &WaitError{Operation: proto.Clone(known).(*av.OperationRef), Retry: proto.Clone(advice).(*av.RetryAdvice), Cause: ErrWaitBackoffExceeded}
			}
			delay = max(delay, advice.RetryAfter.AsDuration())
		}
		if err = sleep(ctx, delay); err != nil {
			return out, interrupted(c.normalize(ctx, err))
		}
	}
}
