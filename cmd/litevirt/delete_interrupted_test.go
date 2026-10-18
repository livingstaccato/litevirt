package main

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A delete the client stopped waiting for may still complete on its host:
// the CLI says so and names the command that shows the outcome, instead of
// a bare "context canceled".
//
// Mutation: drop the DeadlineExceeded case — red.
func TestInterruptedDelete(t *testing.T) {
	for _, c := range []codes.Code{codes.Canceled, codes.DeadlineExceeded} {
		err := interruptedDelete("delete VM web", status.Error(c, "context canceled"), "lv ls")
		if err == nil {
			t.Fatalf("%s: not reported as interrupted", c)
		}
		for _, want := range []string{"delete VM web", "may still complete", "`lv ls`"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: %q lacks %q", c, err, want)
			}
		}
	}
	for _, err := range []error{
		status.Error(codes.Internal, "boom"),
		status.Error(codes.NotFound, "no such VM"),
		errors.New("plain"),
	} {
		if got := interruptedDelete("delete VM web", err, "lv ls"); got != nil {
			t.Errorf("%v reported as interrupted: %v", err, got)
		}
	}
}

// A rebuild or a deploy the client stopped waiting for is said to be the
// operation that may still complete, not a delete.
//
// Mutations: word interruptedOp's message for a delete whatever op is, or
// word a deadline as an interruption — red.
func TestInterruptedOp(t *testing.T) {
	err := interruptedOp("rebuild web", "rebuild", status.Error(codes.Canceled, "context canceled"), "lv ls")
	if err == nil || !strings.Contains(err.Error(), "the rebuild may still complete") || !strings.Contains(err.Error(), "`lv ls`") {
		t.Fatalf("interrupted rebuild: %v", err)
	}
	late := interruptedOp("compose up st", "deploy", status.Error(codes.DeadlineExceeded, "deadline exceeded"), "lv ls")
	if late == nil || strings.Contains(late.Error(), "interrupted") || !strings.Contains(late.Error(), "timed out") ||
		!strings.Contains(late.Error(), "the deploy may still complete") || !strings.Contains(late.Error(), "`lv ls`") {
		t.Errorf("a deadline is worded as an interruption, or names no check: %v", late)
	}
	if got := interruptedOp("rebuild web", "rebuild", status.Error(codes.FailedPrecondition, "no"), "lv ls"); got != nil {
		t.Errorf("a refusal reported as interrupted: %v", got)
	}
}

// An interrupted re-create does not send the operator to run it again while
// its create may still be in flight: the VM is not listed until it finishes.
//
// Mutation: drop the wait note — red.
func TestInterruptedReplace_SaysToWaitForTheVMBeforeARerun(t *testing.T) {
	err := interruptedReplace("compose up st", "deploy", "lv compose up", status.Error(codes.Canceled, "context canceled"))
	if err == nil || !strings.Contains(err.Error(), "the deploy may still complete") ||
		!strings.Contains(err.Error(), "wait until `lv ls` shows it before running `lv compose up` again") {
		t.Fatalf("interrupted compose up: %v", err)
	}
	if got := interruptedReplace("rebuild web", "rebuild", "lv rebuild", status.Error(codes.FailedPrecondition, "no")); got != nil {
		t.Errorf("a refusal reported as interrupted: %v", got)
	}
}
