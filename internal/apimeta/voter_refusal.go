package apimeta

import (
	"strings"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrorDomain is the domain of the google.rpc.ErrorInfo details the daemon
// attaches to a refusal a client tells apart by its reason.
const ErrorDomain = "litevirt.io"

// VoterMemberReason is the ErrorInfo reason of RemoveHost's refusal of a
// voter's host.
const VoterMemberReason = "HOST_IS_VOTER"

// VoterMemberRefusal is the part of RemoveHost's refusal of a voter's host
// that names it: "<host> is a member of voter generation <n>; ...". Every
// daemon release words it so, and `lv host rm --dead` reads it to tell that
// refusal (its own voter removal comes first) from every other.
const VoterMemberRefusal = "is a member of voter generation"

// IsVoterMemberRefusal reports whether err is RemoveHost's (or
// PreflightRemoveHost's) refusal of a voter's host.
// It reads the refusal's ErrorInfo first, and its wording from a daemon that
// attaches none.
func IsVoterMemberRefusal(err error) bool {
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.FailedPrecondition {
		return false
	}
	for _, d := range st.Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok && ei.GetDomain() == ErrorDomain {
			return ei.GetReason() == VoterMemberReason
		}
	}
	return strings.Contains(st.Message(), VoterMemberRefusal)
}
