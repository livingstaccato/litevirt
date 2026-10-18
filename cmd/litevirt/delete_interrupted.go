package main

import (
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// interruptedDelete is the error for a delete whose answer the client did
// not get (cancelled, or past a deadline: the client's or the server's), nil
// for any other error. The
// host carrying the delete out finishes it once it has started, so the
// outcome is read back with the checks.
func interruptedDelete(what string, err error, checks ...string) error {
	return interruptedOp(what, "delete", err, checks...)
}

// interruptedOp is interruptedDelete for an operation named op (a delete, a
// rebuild, a deploy's re-creates), which its host likewise finishes once it
// has started.
func interruptedOp(what, op string, err error, checks ...string) error {
	var how string
	switch status.Code(err) {
	case codes.Canceled:
		how = "interrupted before the answer arrived"
	case codes.DeadlineExceeded:
		how = "timed out before it finished"
	default:
		return nil
	}
	return fmt.Errorf("%s: %s (%s); the %s may still complete on its host: check `%s`",
		what, how, status.Convert(err).Message(), op, strings.Join(checks, "` and `"))
}

// interruptedReplace is interruptedOp for an operation that re-creates a VM
// (a rebuild, a deploy's re-creates). A VM being re-created is not listed
// until its create finishes, so running the operation again before then
// would create it a second time.
func interruptedReplace(what, op, rerun string, err error) error {
	ierr := interruptedOp(what, op, err, "lv ls")
	if ierr == nil {
		return nil
	}
	return fmt.Errorf("%w. A VM being re-created is not listed until its create finishes: wait until `lv ls` shows it before running `%s` again", ierr, rerun)
}
