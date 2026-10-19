package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// voterRefused is the daemon's refusal of a voter's host.
var voterRefused = status.Error(codes.FailedPrecondition,
	"node-9 is a member of voter generation 1; removing the host would not remove its vote")

// preflightSeqClient answers PreflightRemoveHost from answers, one per call
// (the last one repeating), and counts the calls.
type preflightSeqClient struct {
	*hostRemoveTestClient
	answers []error
	n       int
}

func (c *preflightSeqClient) PreflightRemoveHost(_ context.Context, req *pb.RemoveHostRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	c.preflightReq = req
	err := c.answers[min(c.n, len(c.answers)-1)]
	c.n++
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

// A machine that cannot revoke the certificate (no CA key) does not remove
// the vote: `lv host rm --dead` of a voter's host stops before ChangeVoterConfig,
// in a real run and a dry run alike.
//
// Red on e4c38889e: the vote is removed, then the revocation fails.
// Mutation: drop revocationRefusal from deadVoterPreflight — red.
func TestHostRemoveDead_NoCAKeyKeepsTheVote(t *testing.T) {
	pkiDir := rmTestPKI(t)
	if err := os.Remove(filepath.Join(pkiDir, "ca.key")); err != nil {
		t.Fatal(err)
	}
	for _, dry := range []bool{false, true} {
		c := &hostRemoveTestClient{planVoter: true, preflightErr: voterRefused}
		err := HostRemoveDead(context.Background(), c, "node-9", dry)
		if err == nil || !strings.Contains(err.Error(), "no cluster CA private key") {
			t.Errorf("dry=%v: %v, want refused for the missing CA key", dry, err)
		}
		if len(c.calls) != 0 {
			t.Errorf("dry=%v: calls %v, want none (the vote kept)", dry, c.calls)
		}
	}
}

// The check before the vote mints the CRL and throws it away: crl.pem is the
// same bytes afterwards, so a refusal later in the run has revoked nothing.
//
// Mutation: revocationRefusal appends to crl.pem (pki.AppendToCRL) — red.
func TestRevocationRefusal_LeavesTheCRLAsItWas(t *testing.T) {
	pkiDir := rmTestPKI(t)
	if err := revokeHostCert(pkiDir, "node-8", "0badc0de"); err != nil {
		t.Fatal(err)
	}
	crl := filepath.Join(pkiDir, "crl.pem")
	before, err := os.ReadFile(crl)
	if err != nil {
		t.Fatal(err)
	}
	if err := revocationRefusal(pkiDir, "node-9", "a1b2c3"); err != nil {
		t.Fatalf("revocationRefusal: %v", err)
	}
	after, err := os.ReadFile(crl)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("the check before the vote changed crl.pem")
	}
	if serials, _ := pki.LoadCRL(crl); len(serials) != 1 {
		t.Errorf("crl.pem revokes %v, want only the earlier 0badc0de", serials)
	}
	if err := revocationRefusal(pkiDir, "node-9", ""); err == nil {
		t.Error("a host with no recorded serial passed the revocation check")
	}
}

// Once the vote is gone, a removal check refused Unavailable for a moment
// is asked again and the removal finishes; a refusal that lasts says the
// vote was removed and names the command that finishes the removal.
//
// Red on e4c38889e: the first is returned at once, and the second says
// nothing of the vote. Mutations: no retry after the vote — red; the note
// dropped — red.
func TestHostRemoveDead_ARefusalAfterTheVote(t *testing.T) {
	rmTestPKI(t)
	old := removeRetryBackoff
	removeRetryBackoff = []time.Duration{0, 0}
	t.Cleanup(func() { removeRetryBackoff = old })

	flap := &preflightSeqClient{hostRemoveTestClient: &hostRemoveTestClient{planVoter: true},
		answers: []error{voterRefused, status.Error(codes.Unavailable, "no peer completed the pull"), nil}}
	if err := HostRemoveDead(context.Background(), flap, "node-9", false); err != nil {
		t.Fatalf("a check unavailable for a moment after the vote: %v", err)
	}
	if countCalls(flap.calls, "voter-rm") != 1 || countCalls(flap.calls, "remove") != 1 {
		t.Errorf("calls %v, want the vote removed and the host removed", flap.calls)
	}

	lasting := &preflightSeqClient{hostRemoveTestClient: &hostRemoveTestClient{planVoter: true},
		answers: []error{voterRefused, status.Error(codes.FailedPrecondition, "node-9 is active")}}
	err := HostRemoveDead(context.Background(), lasting, "node-9", false)
	if err == nil || !strings.Contains(err.Error(), "node-9 is active") {
		t.Fatalf("a lasting refusal after the vote: %v", err)
	}
	for _, want := range []string{"vote was removed", "lv host rm --dead node-9"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal after the vote does not say %q: %v", want, err)
		}
	}
	if countCalls(lasting.calls, "remove") != 0 || countCalls(lasting.calls, "publish") != 0 {
		t.Errorf("calls %v after a refused check, want nothing revoked or removed", lasting.calls)
	}
}
