package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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

// serialRemoveClient is hostRemoveTestClient listing hosts of its own (none
// once RemoveHost has run, with gone), and answering PreflightRemoveHost as
// the daemon does: a row of the name decides; no row is the NotFound marked
// as decided after a pull, or, with old, an earlier release's plain one.
type serialRemoveClient struct {
	*hostRemoveTestClient
	hosts     []*pb.Host
	gone, old bool
	preflight []*pb.RemoveHostRequest
}

func (c *serialRemoveClient) listed() []*pb.Host {
	if c.gone && countCalls(c.calls, "remove") > 0 {
		return nil
	}
	return c.hosts
}

func (c *serialRemoveClient) ListHosts(context.Context, *pb.ListHostsRequest, ...grpc.CallOption) (*pb.ListHostsResponse, error) {
	return &pb.ListHostsResponse{Hosts: c.listed()}, nil
}

func (c *serialRemoveClient) PreflightRemoveHost(_ context.Context, req *pb.RemoveHostRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	c.preflight = append(c.preflight, req)
	if c.preflightErr != nil {
		return nil, c.preflightErr
	}
	for _, h := range c.listed() {
		if h.GetName() != req.GetName() {
			continue
		}
		if req.GetExpectedCertSerial() != "" && canonSerial(h.GetCertSerial()) != canonSerial(req.GetExpectedCertSerial()) {
			if c.old {
				return nil, status.Error(codes.FailedPrecondition, "row changed")
			}
			return nil, absentErr(codes.FailedPrecondition)
		}
		for _, v := range c.voters {
			if v == h.GetName() {
				return nil, status.Error(codes.FailedPrecondition, "a voter")
			}
		}
		return &emptypb.Empty{}, nil
	}
	if c.old {
		return nil, status.Errorf(codes.NotFound, "host %q not found", req.GetName())
	}
	return nil, absentErr(codes.NotFound)
}

// absentErr is the daemon's refusal marked as decided after a pull.
func absentErr(code codes.Code) error {
	st, _ := status.New(code, "absent").WithDetails(&errdetails.ErrorInfo{
		Reason: apimeta.AdmissionAbsentReason, Domain: apimeta.AdmissionAbsentDomain})
	return st.Err()
}

func serialInCRL(t *testing.T, pkiDir, serial string) bool {
	t.Helper()
	serials, err := pki.LoadCRL(filepath.Join(pkiDir, "crl.pem"))
	if err != nil {
		return false
	}
	for _, s := range serials {
		if strings.EqualFold(s, serial) {
			return true
		}
	}
	return false
}

// Codex foreign-install N1: `--serial 00a1a1` matched no row (a string
// compare), skipped the ordinary removal and its voter and daemon gates,
// passed the machine probe (another string compare), and the CRL, which
// reads the serial as a number, revoked the live host's a1a1. Every spelling
// of the number is the one serial now: a live row holding it is removed only
// as `lv host rm` removes it, and anything that is not a positive hex number
// is refused before anything is revoked.
//
// Mutation: compare the serial as given (lower-cased) — "00a1a1" and
// "0xa1a1" skip the voter's refusal.
func TestHostRemoveSerial_EverySpellingOfALiveHostsSerialGetsTheOrdinaryGates(t *testing.T) {
	for _, spelling := range []string{"a1a1", "A1A1", "00a1a1", "0xa1a1", "0XA1A1", "  00A1a1 "} {
		t.Run(spelling, func(t *testing.T) {
			for _, voter := range []bool{true, false} {
				pkiDir := rmTestPKI(t)
				c := &serialRemoveClient{hostRemoveTestClient: &hostRemoveTestClient{},
					hosts: []*pb.Host{{Name: "node-9", CertSerial: "a1a1", State: pb.HostState_HOST_ACTIVE, Address: "10.0.0.9"}}}
				if voter {
					c.voters = []string{"node-9"}
				}
				err := HostRemoveAdmission(context.Background(), c, "node-9", spelling, "", false)
				if voter {
					if err == nil || !strings.Contains(err.Error(), "voter") || serialInCRL(t, pkiDir, "a1a1") {
						t.Fatalf("removal of a voter by %q = %v (revoked %v), want the voter refusal and nothing revoked",
							spelling, err, serialInCRL(t, pkiDir, "a1a1"))
					}
					continue
				}
				if err != nil {
					t.Fatalf("removal by %q: %v", spelling, err)
				}
				if countCalls(c.calls, "remove") != 1 || !strings.EqualFold(c.removeReq.GetExpectedCertSerial(), "a1a1") {
					t.Errorf("RemoveHost calls %v, request %v: want the ordinary removal of a1a1", c.calls, c.removeReq)
				}
			}
		})
	}
	for _, bad := range []string{"", "0", "00", "zz", "0x", "a1a1;rm", "-a1"} {
		pkiDir := rmTestPKI(t)
		c := &serialRemoveClient{hostRemoveTestClient: &hostRemoveTestClient{}}
		if err := HostRemoveAdmission(context.Background(), c, "node-9", bad, "10.0.0.9", false); err == nil {
			t.Errorf("--serial %q accepted", bad)
		}
		if len(c.calls) != 0 || len(c.preflight) != 0 {
			t.Errorf("--serial %q reached the cluster: %v", bad, c.calls)
		}
		_ = pkiDir
	}
	c := &serialRemoveClient{hostRemoveTestClient: &hostRemoveTestClient{}}
	if err := HostRemoveAdmission(context.Background(), c, "x;curl|sh", "a1a1", "10.0.0.9", false); err == nil {
		t.Error("a host name that is not one was accepted")
	}
}

// settleMachine is a machine an admission S of node-9 was stranded on (its
// pair and record staged, its install record "installing" and stale), that
// now serves another CA's certificate B; and the operator's pki with S.
type settleMachine struct {
	f      *addFixture
	serial string
	bBytes []byte
}

func newSettleMachine(t *testing.T) *settleMachine {
	t.Helper()
	f := newAddFixture(t)
	serial := strandedAdd(t, f)
	writeMarker(t, f.target, fmt.Sprintf("node-9 %s 1 0123456789ab installing\n", serial))
	installPair(t, f, "", "foreign")
	m := &settleMachine{f: f, serial: serial, bBytes: mustRead(t, filepath.Join(f.targetPKI, "host.crt"))}
	m.dial(t, f.target)
	return m
}

// dial makes r the machine `lv host rm` reaches.
func (m *settleMachine) dial(t *testing.T, r addRemote) {
	t.Helper()
	old := dialAdmissionMachine
	dialAdmissionMachine = func(string) (addRemote, func(), error) { return r, func() {}, nil }
	t.Cleanup(func() { dialAdmissionMachine = old })
}

// settledClean fails unless nothing of S is left on the machine (staged
// files of every kind, records, install record) and B is still installed.
func (m *settleMachine) settledClean(t *testing.T) {
	t.Helper()
	for _, p := range stagedOnTarget(t, m.f.target.Root) {
		if strings.Contains(filepath.Base(p), m.serial) {
			t.Errorf("left on the machine: %s", p)
		}
	}
	if _, err := os.Stat(m.f.target.Path(addInstalledMarker)); !os.IsNotExist(err) {
		t.Errorf("the install record is still there (stat: %v)", err)
	}
	m.untouched(t)
}

func (m *settleMachine) untouched(t *testing.T) {
	t.Helper()
	if !bytes.Equal(mustRead(t, filepath.Join(m.f.targetPKI, "host.crt")), m.bBytes) {
		t.Error("the machine's installed certificate B was replaced")
	}
}

// Our review I1, m3: the no-row revoke decided "no row" from one replica's
// list, trusted an "installing" record as proof the add never finished,
// was not tied to the machine at --address, and checked and revoked without
// the machine locked. It now asks the daemon, through an ordinary removal's
// gates and a pull, that no row holds the serial; refuses a machine that
// serves it, one with no trace of it under the name, and one an add holds;
// and claims the machine, compared with what it checked, before revoking.
//
// Mutations: skip the daemon's confirmation — "an earlier release's daemon"
// revokes; skip the trace — "another name" revokes; accept a served serial —
// "it serves the serial" revokes; claim without comparing — "the machine
// changes while checked" revokes.
func TestHostRemoveSerial_ANoRowRevokeIsConfirmedAndBoundToTheMachine(t *testing.T) {
	type tc struct {
		name    string
		setup   func(t *testing.T, m *settleMachine, c *serialRemoveClient) string // the host name
		wantErr string
	}
	for _, tc := range []tc{
		{"the name is another admission's", func(_ *testing.T, _ *settleMachine, c *serialRemoveClient) string {
			c.hosts = append(c.hosts, &pb.Host{Name: "node-9", CertSerial: "b0b0", State: pb.HostState_HOST_ACTIVE, Address: "10.0.0.9"})
			return "node-9"
		}, ""},
		{"no row", func(*testing.T, *settleMachine, *serialRemoveClient) string { return "node-9" }, ""},
		{"an earlier release's daemon", func(_ *testing.T, _ *settleMachine, c *serialRemoveClient) string {
			c.old = true
			return "node-9"
		}, "earlier release"},
		{"the daemon's gates refuse", func(_ *testing.T, _ *settleMachine, c *serialRemoveClient) string {
			c.preflightErr = status.Error(codes.Unavailable, "could not confirm with a peer")
			return "node-9"
		}, "could not confirm"},
		{"another name", func(*testing.T, *settleMachine, *serialRemoveClient) string { return "node-8" }, "no staged file"},
		{"an add holds the machine", func(t *testing.T, m *settleMachine, _ *serialRemoveClient) string {
			writeMarker(t, m.f.target, fmt.Sprintf("node-9 %s %d ffffffffffff installing\n", m.serial, time.Now().Unix()))
			return "node-9"
		}, "holds the machine"},
		{"the machine changes while checked", func(t *testing.T, m *settleMachine, _ *serialRemoveClient) string {
			beforeSettleClaim = func() { writeMarker(t, m.f.target, "node-x 0abc 1 0123456789ab installed\n") }
			t.Cleanup(func() { beforeSettleClaim = nil })
			return "node-9"
		}, "changed while it was checked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newSettleMachine(t)
			c := &serialRemoveClient{hostRemoveTestClient: &hostRemoveTestClient{}}
			name := tc.setup(t, m, c)
			err := HostRemoveAdmission(context.Background(), c, name, "00"+m.serial, "10.0.0.9", false)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("removal = %v, want a refusal naming %q", err, tc.wantErr)
				}
				if serialInCRL(t, m.f.opPKI, m.serial) || countCalls(c.calls, "publish") != 0 {
					t.Error("refused, but the serial was revoked or a CRL published")
				}
				m.untouched(t)
				return
			}
			if err != nil {
				t.Fatalf("removal: %v", err)
			}
			if !serialInCRL(t, m.f.opPKI, m.serial) || countCalls(c.calls, "publish") != 1 || countCalls(c.calls, "remove") != 0 {
				t.Errorf("revoked %v, calls %v: want the serial revoked and published, and no row removed",
					serialInCRL(t, m.f.opPKI, m.serial), c.calls)
			}
			if len(c.preflight) != 1 || c.preflight[0].GetExpectedCertSerial() != m.serial || c.preflight[0].GetName() != name {
				t.Errorf("preflight %v, want one for %s and serial %s", c.preflight, name, m.serial)
			}
			if serialInCRL(t, m.f.opPKI, "b0b0") {
				t.Error("the other admission's certificate b0b0 was revoked")
			}
			m.settledClean(t)
		})
	}
	// A machine that serves the serial may be a completed add: nothing is
	// revoked, and only the serial's staged files go.
	t.Run("it serves the serial", func(t *testing.T) {
		m := newSettleMachine(t)
		staged, _ := filepath.Glob(filepath.Join(m.f.targetPKI, ".host.*.add-"+m.serial+"-*"))
		for _, p := range staged {
			if strings.HasSuffix(p, ".before") {
				continue
			}
			n := "host.crt"
			if strings.Contains(p, ".host.key.") {
				n = "host.key"
			}
			if err := os.WriteFile(filepath.Join(m.f.targetPKI, n), mustRead(t, p), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		c := &serialRemoveClient{hostRemoveTestClient: &hostRemoveTestClient{}}
		err := HostRemoveAdmission(context.Background(), c, "node-9", "0x"+strings.ToUpper(m.serial), "10.0.0.9", false)
		if err == nil || !strings.Contains(err.Error(), "completed add") {
			t.Fatalf("removal = %v, want the refusal of a possibly completed add", err)
		}
		if serialInCRL(t, m.f.opPKI, m.serial) || countCalls(c.calls, "publish") != 0 {
			t.Error("a served certificate was revoked")
		}
		if left, _ := filepath.Glob(filepath.Join(m.f.targetPKI, ".host.crt.add-"+m.serial+"-*")); len(left) != 0 {
			t.Errorf("its staged files are still there: %v", left)
		}
		if _, err := os.Stat(m.f.target.Path(addInstalledMarker)); err != nil {
			t.Errorf("the install record was removed: %v", err)
		}
	})
}

// failingShell fails the nth shell command of kind, as a connection lost
// mid-cleanup does, and runs every other.
type failingShell struct {
	*LocalAddTarget
	kind string
	nth  int
	seen int
}

func (f *failingShell) Shell(kind, cmd string) ([]byte, error) {
	if kind == f.kind {
		f.seen++
		if f.seen == f.nth {
			return nil, errors.New("connection lost")
		}
	}
	return f.LocalAddTarget.Shell(kind, cmd)
}

// Codex foreign-install I1 residual: a cleanup that failed after the
// revocation was printed and swallowed, and the command reported success
// with manual work left. It fails now, naming the same command, which
// finishes it: once the serial is revoked, a rerun publishes and cleans up
// whether or not a row is left. Both a matching row's removal and the
// no-row settle; a failed publish too.
//
// Mutation: swallow the cleanup failure again — each first run returns nil.
func TestHostRemoveSerial_AFailedCleanupFailsAndTheSameCommandFinishesIt(t *testing.T) {
	again := func(m *settleMachine) string {
		return "lv host rm node-9 --serial " + m.serial + " --address 10.0.0.9"
	}
	t.Run("no row, the cleanup fails", func(t *testing.T) {
		m := newSettleMachine(t)
		m.dial(t, &failingShell{LocalAddTarget: m.f.target, kind: "unstage", nth: 2})
		c := &serialRemoveClient{hostRemoveTestClient: &hostRemoveTestClient{}}
		err := HostRemoveAdmission(context.Background(), c, "node-9", m.serial, "10.0.0.9", false)
		if err == nil || !strings.Contains(err.Error(), again(m)) || !serialInCRL(t, m.f.opPKI, m.serial) {
			t.Fatalf("first run = %v, want the revocation done and the cleanup failure naming %q", err, again(m))
		}
		m.dial(t, m.f.target)
		if err := HostRemoveAdmission(context.Background(), c, "node-9", m.serial, "10.0.0.9", false); err != nil {
			t.Fatalf("the rerun: %v", err)
		}
		m.settledClean(t)
	})
	t.Run("no row, the publish fails", func(t *testing.T) {
		m := newSettleMachine(t)
		c := &serialRemoveClient{hostRemoveTestClient: &hostRemoveTestClient{publishErr: errors.New("unavailable")}}
		err := HostRemoveAdmission(context.Background(), c, "node-9", m.serial, "10.0.0.9", false)
		if err == nil || !strings.Contains(err.Error(), again(m)) {
			t.Fatalf("first run = %v, want the publish failure naming %q", err, again(m))
		}
		c.publishErr = nil
		if err := HostRemoveAdmission(context.Background(), c, "node-9", m.serial, "10.0.0.9", false); err != nil {
			t.Fatalf("the rerun: %v", err)
		}
		if countCalls(c.calls, "publish") != 2 {
			t.Errorf("calls %v, want the rerun to publish", c.calls)
		}
		m.settledClean(t)
	})
	t.Run("the row's removal, the cleanup fails", func(t *testing.T) {
		m := newSettleMachine(t)
		m.dial(t, &failingShell{LocalAddTarget: m.f.target, kind: "unstage", nth: 2})
		c := &serialRemoveClient{hostRemoveTestClient: &hostRemoveTestClient{}, gone: true,
			hosts: []*pb.Host{{Name: "node-9", CertSerial: strings.ToUpper(m.serial), State: pb.HostState_HOST_JOINING, Address: "10.0.0.9"}}}
		err := HostRemoveAdmission(context.Background(), c, "node-9", m.serial, "10.0.0.9", false)
		if err == nil || !strings.Contains(err.Error(), again(m)) || countCalls(c.calls, "remove") != 1 {
			t.Fatalf("first run = %v (calls %v), want the removal done and the cleanup failure naming %q", err, c.calls, again(m))
		}
		m.dial(t, m.f.target)
		if err := HostRemoveAdmission(context.Background(), c, "node-9", m.serial, "10.0.0.9", false); err != nil {
			t.Fatalf("the rerun: %v", err)
		}
		if countCalls(c.calls, "remove") != 1 {
			t.Errorf("calls %v: the rerun removed a row", c.calls)
		}
		m.settledClean(t)
	})
}

// The same for a plain `lv host rm` of a joining host: the failed cleanup is
// reported, with the command that finishes it.
//
// Mutation: print and return nil — the removal reports success.
func TestHostRemove_AJoiningHostsFailedCleanupNamesItsFinish(t *testing.T) {
	rmTestPKI(t)
	old := removeStagedAdmission
	removeStagedAdmission = func(string, string) error { return errors.New("no route to host") }
	t.Cleanup(func() { removeStagedAdmission = old })
	c := &hostRemoveTestClient{hostState: pb.HostState_HOST_JOINING, hostAddr: "10.0.0.9"}
	err := HostRemove(context.Background(), c, "node-9", false)
	if err == nil || !strings.Contains(err.Error(), "lv host rm node-9 --serial a1b2c3 --address 10.0.0.9") {
		t.Fatalf("removal = %v, want the unfinished cleanup naming the command that finishes it", err)
	}
}
