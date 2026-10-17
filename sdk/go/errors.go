package litevirt

import (
	"errors"
	"fmt"
	av "github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Error preserves structural application details and the original gRPC status.
// Inspect Code/Detail instead of matching diagnostic strings.
type Error struct {
	Code   av.ErrorCode
	Detail *av.ErrorDetail
	Cause  error
}

func (e *Error) Error() string              { return fmt.Sprintf("litevirt: %s: %v", e.Code, e.Cause) }
func (e *Error) Unwrap() error              { return e.Cause }
func (e *Error) GRPCStatus() *status.Status { return status.Convert(e.Cause) }

// ErrWaitBackoffExceeded means server advice exceeds the configured poll bound.
// Resume the wait later according to the preserved advice and operation reference.
var ErrWaitBackoffExceeded = errors.New("litevirt: advised wait exceeds configured backoff bound")

// WaitError retains a cloned, recoverable operation reference on interruption.
// Retry is present when oversized server advice defers waiting; Cause is then
// ErrWaitBackoffExceeded. Context interruption remains recognizable by errors.Is.
type WaitError struct {
	Retry     *av.RetryAdvice
	Operation *av.OperationRef
	Cause     error
}

func (e *WaitError) Error() string { return fmt.Sprintf("litevirt wait interrupted: %v", e.Cause) }
func (e *WaitError) Unwrap() error { return e.Cause }
func decodeError(err error) error {
	if err == nil {
		return nil
	}
	var typed *Error
	if errors.As(err, &typed) {
		return err
	}
	for _, d := range status.Convert(err).Details() {
		if detail, ok := d.(*av.ErrorDetail); ok {
			return &Error{Code: detail.Code, Detail: proto.Clone(detail).(*av.ErrorDetail), Cause: err}
		}
	}
	code := av.ErrorCode_ERROR_CODE_UNSPECIFIED
	switch status.Code(err) {
	case codes.Unauthenticated:
		code = av.ErrorCode_ERROR_CODE_UNAUTHENTICATED
	case codes.PermissionDenied:
		code = av.ErrorCode_ERROR_CODE_PERMISSION_DENIED
	case codes.Unimplemented:
		code = av.ErrorCode_ERROR_CODE_UNSUPPORTED
	case codes.InvalidArgument:
		code = av.ErrorCode_ERROR_CODE_VALIDATION
	case codes.Unavailable:
		code = av.ErrorCode_ERROR_CODE_AUTHORITY_UNAVAILABLE
	}
	if code != av.ErrorCode_ERROR_CODE_UNSPECIFIED {
		return &Error{Code: code, Cause: err}
	}
	return err
}
func retryAdvice(err error) *av.RetryAdvice {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Detail.GetRetry()
	}
	return nil
}
func retryable(err error) bool {
	advice := retryAdvice(err)
	if advice != nil && advice.Action != av.RetryAction_RETRY_ACTION_UNSPECIFIED {
		return advice.Action == av.RetryAction_RETRY_ACTION_SAME_REQUEST
	}
	return status.Code(err) == codes.Unavailable
}
