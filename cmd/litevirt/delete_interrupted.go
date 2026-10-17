package main

import (
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// interruptedDelete is the error for a delete whose answer the client did
// not get (cancelled, or past its deadline), nil for any other error. The
// host carrying the delete out finishes it once it has started, so the
// outcome is read back with the checks.
func interruptedDelete(what string, err error, checks ...string) error {
	return interruptedOp(what, "delete", err, checks...)
}

// interruptedOp is interruptedDelete for an operation named op (a delete, a
// rebuild, a deploy's re-creates), which its host likewise finishes once it
// has started.
func interruptedOp(what, op string, err error, checks ...string) error {
	switch status.Code(err) {
	case codes.Canceled, codes.DeadlineExceeded:
		return fmt.Errorf("%s: interrupted before the answer arrived (%s); the %s may still complete on its host: check `%s`",
			what, status.Convert(err).Message(), op, strings.Join(checks, "` and `"))
	}
	return nil
}
