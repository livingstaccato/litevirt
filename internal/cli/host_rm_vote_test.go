package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/apimeta"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
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

// funcPreflightClient answers PreflightRemoveHost with answer and records
// every request; serialAfterVote, when set, is node-9's listed serial once
// the vote is removed (a re-admission inside the window).
type funcPreflightClient struct {
	*hostRemoveTestClient
	answer          func(req *pb.RemoveHostRequest) error
	reqs            []*pb.RemoveHostRequest
	serialAfterVote string
}

func (c *funcPreflightClient) PreflightRemoveHost(_ context.Context, req *pb.RemoveHostRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	c.reqs = append(c.reqs, req)
	if err := c.answer(req); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (c *funcPreflightClient) listedSerial() string {
	if c.serialAfterVote != "" && countCalls(c.calls, "voter-rm") > 0 {
		return c.serialAfterVote
	}
	return "a1b2c3"
}

func (c *funcPreflightClient) ListHosts(context.Context, *pb.ListHostsRequest, ...grpc.CallOption) (*pb.ListHostsResponse, error) {
	return &pb.ListHostsResponse{Hosts: []*pb.Host{{Name: "node-9", CertSerial: c.listedSerial()}}}, nil
}

// voterRefusedDetailed is the voter refusal as a daemon that asks it last
// sends it: with its ErrorInfo.
func voterRefusedDetailed(t *testing.T) error {
	t.Helper()
	st, err := status.New(codes.FailedPrecondition, "node-9 is a member of voter generation 1").
		WithDetails(&errdetails.ErrorInfo{Reason: apimeta.VoterMemberReason, Domain: apimeta.ErrorDomain})
	if err != nil {
		t.Fatal(err)
	}
	return st.Err()
}

// stdoutOf runs fn and returns what it printed.
func stdoutOf(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() {
		var b bytes.Buffer
		_, _ = io.Copy(&b, r)
		done <- b.String()
	}()
	fn()
	w.Close()
	os.Stdout = old
	return <-done
}

// hostrmvote review M-1: `--dead --force` is sent on every removal request,
// the check before the vote included, so a refusal --force lifts does not
// stop a voter's removal before its vote. The stand-in refusal is one a
// daemon makes only without Force (feat/ops-d-fwlive's firmware refusal).
//
// Mutation: deadVoterPreflight sends Force false — red.
func TestHostRemoveDeadForce_ForceReachesTheCheckBeforeTheVote(t *testing.T) {
	rmTestPKI(t)
	answer := func(req *pb.RemoveHostRequest) error {
		if !req.GetForce() {
			return status.Error(codes.FailedPrecondition, "node-9 is the target of 1 live firmware move(s) that are not settled")
		}
		return voterRefusedDetailed(t)
	}
	plain := &funcPreflightClient{hostRemoveTestClient: &hostRemoveTestClient{planVoter: true}, answer: answer}
	if err := HostRemoveDeadForce(context.Background(), plain, "node-9", false, false); err == nil || len(plain.calls) != 0 {
		t.Errorf("without --force: %v (calls %v), want refused before the vote", err, plain.calls)
	}
	// After the vote the daemon no longer refuses the voter.
	c := &funcPreflightClient{hostRemoveTestClient: &hostRemoveTestClient{planVoter: true}}
	c.answer = func(req *pb.RemoveHostRequest) error {
		if err := answer(req); countCalls(c.calls, "voter-rm") == 0 || !apimeta.IsVoterMemberRefusal(err) {
			return err
		}
		return nil
	}
	if err := HostRemoveDeadForce(context.Background(), c, "node-9", false, true); err != nil {
		t.Fatalf("--dead --force of a voter: %v", err)
	}
	if countCalls(c.calls, "voter-rm") != 1 || countCalls(c.calls, "remove") != 1 {
		t.Errorf("calls %v, want the vote and the host removed", c.calls)
	}
	for i, r := range c.reqs {
		if !r.GetForce() {
			t.Errorf("preflight %d was sent without Force", i)
		}
	}
	if !c.removeReq.GetForce() {
		t.Error("RemoveHost was sent without Force")
	}
}

// hostrmvote review m-2: the voter dry run says plainly whether the daemon
// asked its other checks before the voter refusal: one that sends the voter
// refusal without its ErrorInfo, or no preflight at all, is older and asked
// none of them.
//
// Mutation: complete always true — the older daemon's run reads "passed", red.
func TestHostRemoveDead_TheDryRunSaysWhenTheDaemonIsOlder(t *testing.T) {
	rmTestPKI(t)
	for _, tc := range []struct {
		name   string
		answer error
		want   string
	}{
		{"this order", voterRefusedDetailed(t), "every check the daemon asks before its voter refusal passed"},
		{"older, wording only", voterRefused, "SKIPPED"},
		{"older, no preflight", status.Error(codes.Unimplemented, "unknown method"), "SKIPPED"},
	} {
		c := &funcPreflightClient{hostRemoveTestClient: &hostRemoveTestClient{planVoter: true},
			answer: func(*pb.RemoveHostRequest) error { return tc.answer }}
		var err error
		out := stdoutOf(t, func() { err = HostRemoveDead(context.Background(), c, "node-9", true) })
		if err != nil || len(c.calls) != 0 {
			t.Errorf("%s: %v (calls %v), want a dry run that changes nothing", tc.name, err, c.calls)
		}
		if !strings.Contains(out, tc.want) {
			t.Errorf("%s: the dry run printed\n%s\nwant %q", tc.name, out, tc.want)
		}
		if tc.want == "SKIPPED" && strings.Contains(out, "passed") {
			t.Errorf("%s: an older daemon's dry run claims the checks passed:\n%s", tc.name, out)
		}
	}
}

// hostrmvote review m-3: the checks after the vote are made against the
// serial the checks before it were, so a re-admission inside the window is
// refused before anything is revoked, not revoked under the old plan.
//
// Mutation: the run after the vote reads the serial afresh — the new
// certificate is revoked and published, red.
func TestHostRemoveDead_TheSerialIsPinnedAcrossTheVote(t *testing.T) {
	pkiDir := rmTestPKI(t)
	c := &funcPreflightClient{hostRemoveTestClient: &hostRemoveTestClient{planVoter: true}, serialAfterVote: "d4e5f6"}
	c.answer = func(req *pb.RemoveHostRequest) error {
		if want := c.listedSerial(); req.GetExpectedCertSerial() != want {
			return status.Errorf(codes.FailedPrecondition, "node-9's row changed since its certificate was revoked (it now names %s, not %s)",
				want, req.GetExpectedCertSerial())
		}
		if countCalls(c.calls, "voter-rm") == 0 {
			return voterRefusedDetailed(t)
		}
		return nil
	}
	err := HostRemoveDead(context.Background(), c, "node-9", false)
	if err == nil || !strings.Contains(err.Error(), "row changed") {
		t.Fatalf("a re-admission between the checks and the revocation: %v, want refused", err)
	}
	if countCalls(c.calls, "publish") != 0 || countCalls(c.calls, "remove") != 0 {
		t.Errorf("calls %v, want nothing revoked or removed", c.calls)
	}
	if serials, _ := pki.LoadCRL(filepath.Join(pkiDir, "crl.pem")); len(serials) != 0 {
		t.Errorf("crl.pem revokes %v, want nothing", serials)
	}
}
