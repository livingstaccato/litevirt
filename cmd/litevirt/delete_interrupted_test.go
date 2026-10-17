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
