package restapi

import (
	"errors"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

// A create refused because another create of the name is in flight
// (codes.Aborted, "in progress") is a conflict to retry: 409, not the 500 a
// handler's fallback gives an unknown failure (dupcreate re-review m-C).
//
// Mutation: drop Aborted from the conflict case — red.
func TestGRPCHTTPStatus(t *testing.T) {
	for _, tc := range []struct {
		code codes.Code
		want int
	}{
		{codes.Aborted, http.StatusConflict},
		{codes.AlreadyExists, http.StatusConflict},
		{codes.FailedPrecondition, http.StatusConflict},
		{codes.NotFound, http.StatusNotFound},
		{codes.Internal, http.StatusInternalServerError},
	} {
		got, _ := grpcHTTPStatus(http.StatusInternalServerError, grpcstatus.Error(tc.code, "x"))
		if got != tc.want {
			t.Errorf("%v: %d, want %d", tc.code, got, tc.want)
		}
	}
	if got, _ := grpcHTTPStatus(http.StatusInternalServerError, errors.New("plain")); got != http.StatusInternalServerError {
		t.Errorf("a plain error: %d, want the fallback", got)
	}
}
