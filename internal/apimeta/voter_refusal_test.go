package apimeta

import (
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// D2 re-review of d7bc5c868, N-4: the voter refusal is recognised by its
// error detail first, and by its wording from a daemon that sends none.
//
// Mutation: ignore the detail — the reworded refusal is not recognised, red.
func TestIsVoterMemberRefusal(t *testing.T) {
	st, err := status.New(codes.FailedPrecondition, "node-9 is a voter (reworded)").
		WithDetails(&errdetails.ErrorInfo{Reason: VoterMemberReason, Domain: ErrorDomain})
	if err != nil {
		t.Fatal(err)
	}
	if !IsVoterMemberRefusal(st.Err()) {
		t.Error("the refusal with the detail is not recognised")
	}
	if !IsVoterMemberRefusal(status.Error(codes.FailedPrecondition, "node-9 is a member of voter generation 3; ...")) {
		t.Error("an older daemon's refusal (wording only) is not recognised")
	}
	if IsVoterMemberRefusal(status.Error(codes.FailedPrecondition, "node-9 is the target of 1 live firmware move(s)")) {
		t.Error("another refusal is read as the voter refusal")
	}
	other, _ := status.New(codes.FailedPrecondition, "x").WithDetails(&errdetails.ErrorInfo{Reason: "OTHER", Domain: ErrorDomain})
	if IsVoterMemberRefusal(other.Err()) {
		t.Error("another reason is read as the voter refusal")
	}
}
