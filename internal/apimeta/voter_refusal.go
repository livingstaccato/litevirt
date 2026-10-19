package apimeta

import (
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// VoterMemberRefusal is the part of RemoveHost's refusal of a voter's host
// that names it: "<host> is a member of voter generation <n>; ...". Every
// daemon release words it so, and `lv host rm --dead` reads it to tell that
// refusal (its own voter removal comes first) from every other.
const VoterMemberRefusal = "is a member of voter generation"

// IsVoterMemberRefusal reports whether err is RemoveHost's (or
// PreflightRemoveHost's) refusal of a voter's host.
func IsVoterMemberRefusal(err error) bool {
	st, ok := status.FromError(err)
	return ok && st.Code() == codes.FailedPrecondition && strings.Contains(st.Message(), VoterMemberRefusal)
}
