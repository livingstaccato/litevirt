package grpcapi

import (
	"errors"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/apimeta"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func absentMarked(err error) bool {
	st, _ := status.FromError(err)
	for _, d := range st.Details() {
		if i, ok := d.(*errdetails.ErrorInfo); ok && i.GetReason() == apimeta.AdmissionAbsentReason {
			return true
		}
	}
	return false
}

// Our review I1: `lv host rm <host> --serial <serial>` revoked a serial no
// row held on one replica's unpulled list. PreflightRemoveHost with an
// expected serial the row of the name does not hold now runs a removal's
// gates (admin, caught up, voter majority, a pull of the hosts table) and
// answers on the pulled table: marked absent only when no live row holds the
// serial, in any spelling.
//
// Mutations: decide before the pull — "a row arrives in the pull" is marked
// absent; compare serials as strings — "another name holds it" (
// held as "00AB01", asked as "0xab01") is marked absent.
func TestPreflightRemoveHost_AnAbsentAdmissionIsDecidedAfterAPull(t *testing.T) {
	ctx := adminCtx()
	t.Run("no row", func(t *testing.T) {
		s := incServer(t, 0)
		p := &fakePuller{}
		s.SetAntiEntropy(p)
		_, err := s.PreflightRemoveHost(ctx, &pb.RemoveHostRequest{Name: "gone", ExpectedCertSerial: "0xAB01"})
		if status.Code(err) != codes.NotFound || !absentMarked(err) || p.pulls != 1 {
			t.Errorf("preflight = %v (pulls %d), want NotFound marked absent after one pull", err, p.pulls)
		}
	})
	t.Run("the name is another admission's", func(t *testing.T) {
		s := incServer(t, 0)
		s.SetAntiEntropy(&fakePuller{})
		_, err := s.PreflightRemoveHost(ctx, &pb.RemoveHostRequest{Name: "peer-host", ExpectedCertSerial: "ab01"})
		if status.Code(err) != codes.FailedPrecondition || !absentMarked(err) {
			t.Errorf("preflight = %v, want FailedPrecondition marked absent", err)
		}
	})
	t.Run("another name holds it", func(t *testing.T) {
		s := incServer(t, 0)
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "host-y", Address: "10.0.0.7", State: "active", CertSerial: "00AB01"}); err != nil {
			t.Fatal(err)
		}
		s.SetAntiEntropy(&fakePuller{})
		_, err := s.PreflightRemoveHost(ctx, &pb.RemoveHostRequest{Name: "gone", ExpectedCertSerial: "0xab01"})
		if err == nil || absentMarked(err) {
			t.Errorf("preflight = %v, want an unmarked refusal", err)
		}
	})
	t.Run("a row arrives in the pull", func(t *testing.T) {
		s := incServer(t, 0)
		s.SetAntiEntropy(&fakePuller{pull: func() {
			_ = corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "late", Address: "10.0.0.8", State: "joining", CertSerial: "ab01"})
		}})
		_, err := s.PreflightRemoveHost(ctx, &pb.RemoveHostRequest{Name: "late", ExpectedCertSerial: "ab01"})
		if absentMarked(err) {
			t.Errorf("preflight = %v: a row the pull brought was taken as absent", err)
		}
	})
	t.Run("a failed pull refuses", func(t *testing.T) {
		s := incServer(t, 0)
		s.SetAntiEntropy(&fakePuller{err: errors.New("no peer answered")})
		_, err := s.PreflightRemoveHost(ctx, &pb.RemoveHostRequest{Name: "gone", ExpectedCertSerial: "ab01"})
		if status.Code(err) != codes.Unavailable || absentMarked(err) {
			t.Errorf("preflight = %v, want Unavailable", err)
		}
	})
	t.Run("not an admin", func(t *testing.T) {
		s := incServer(t, 0)
		s.SetAntiEntropy(&fakePuller{})
		_, err := s.PreflightRemoveHost(viewerCtx(), &pb.RemoveHostRequest{Name: "gone", ExpectedCertSerial: "ab01"})
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("preflight as a viewer = %v, want PermissionDenied", err)
		}
	})
}
