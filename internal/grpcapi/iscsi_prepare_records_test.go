package grpcapi

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/storage"
)

// chapISCSIAdm is an iscsiadm whose node records carry CHAP credentials. A
// record made by a discovery takes iscsid.conf's (conf); a plain sendtargets
// discovery rewrites every record the portal returns from conf, as iscsiadm
// does; a login succeeds only with the credentials the target accepts. No
// secret reaches a command line here: the credentials live in the records.
type chapISCSIAdm struct {
	mu       sync.Mutex
	conf     string            // iscsid.conf's "user:password"
	accept   string            // what every target accepts
	adverts  map[string]string // portal -> the target a discovery returns
	records  map[string]string // "portal target" -> the record's "user:password"
	sessions map[string]bool
	calls    []string
}

func installCHAPISCSIAdm(t *testing.T) *chapISCSIAdm {
	t.Helper()
	f := &chapISCSIAdm{conf: "conf:conf-secret", adverts: map[string]string{}, records: map[string]string{}, sessions: map[string]bool{}}
	t.Cleanup(storage.OverrideISCSICommandForTest(f.run))
	return f
}

func chapPortal(p string) string {
	if !strings.Contains(p, ":") {
		return p + ":3260"
	}
	return p
}

func (f *chapISCSIAdm) run(_ context.Context, _ string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := strings.Join(args, " ")
	f.calls = append(f.calls, a)
	at := func(flag string) string {
		for i := 0; i+1 < len(args); i++ {
			if args[i] == flag {
				return args[i+1]
			}
		}
		return ""
	}
	switch {
	case a == "-m session":
		if len(f.sessions) == 0 {
			return []byte("iscsiadm: No active sessions."), errors.New("exit status 21")
		}
		var b strings.Builder
		for s := range f.sessions {
			p, tg, _ := strings.Cut(s, " ")
			b.WriteString("tcp: [1] " + p + ",1 " + tg + " (non-flash)\n")
		}
		return []byte(b.String()), nil
	case strings.HasPrefix(a, "-m discovery"):
		portal := chapPortal(at("-p"))
		tg, ok := f.adverts[portal]
		if !ok {
			return []byte("iscsiadm: cannot make connection"), errors.New("exit status 4")
		}
		key := portal + " " + tg
		if _, exists := f.records[key]; !exists || !strings.Contains(a, "-o new") {
			f.records[key] = f.conf
		}
		return []byte(portal + ",1 " + tg), nil
	case strings.HasSuffix(a, "--login"):
		key := chapPortal(at("-p")) + " " + at("-T")
		cred, ok := f.records[key]
		if !ok {
			return []byte("iscsiadm: No records found"), errors.New("exit status 21")
		}
		if f.sessions[key] {
			return []byte("iscsiadm: default: 1 session requested, but 1 already present."), errors.New("exit status 15")
		}
		if cred != f.accept {
			return []byte("iscsiadm: initiator reported error (24 - iSCSI login failed due to authorization failure)"),
				errors.New("exit status 24")
		}
		f.sessions[key] = true
		return []byte("Login successful."), nil
	}
	return nil, errors.New("unexpected: " + a)
}

func (f *chapISCSIAdm) record(key string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.records[key]
}

// An operator's per-record CHAP survives an iscsi pool create: the create
// logs in through the record and leaves it as it is.
//
// On main the create's plain discovery rewrote the record from iscsid.conf,
// and its login then failed authorization: the create was refused and the
// record lost its CHAP.
func TestCreateStoragePool_ISCSI_KeepsAnExistingRecordsCHAP(t *testing.T) {
	s := newPoolTestServer(t)
	f := installCHAPISCSIAdm(t)
	f.adverts["10.0.0.5:3260"] = sessTarget
	f.records["10.0.0.5:3260 "+sessTarget] = "op:op-secret"
	f.accept = "op:op-secret"

	if _, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{
		Name: "san", Driver: "iscsi", Source: sessTarget, Options: map[string]string{"portal": "10.0.0.5:3260", "lun": "1"},
	}); err != nil {
		t.Fatalf("CreateStoragePool: %v; calls %v", err, f.calls)
	}
	if got := f.record("10.0.0.5:3260 " + sessTarget); got != "op:op-secret" {
		t.Fatalf("the record's CHAP is %q after the create, want the operator's", got)
	}
}

// A brand-new target still works: the create discovers it (add-only) and
// logs in with iscsid.conf's settings, as on main.
func TestCreateStoragePool_ISCSI_NewTargetIsDiscovered(t *testing.T) {
	s := newPoolTestServer(t)
	f := installCHAPISCSIAdm(t)
	f.adverts["10.0.0.5:3260"] = sessTarget
	f.accept = f.conf

	if _, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{
		Name: "san", Driver: "iscsi", Source: sessTarget, Options: map[string]string{"portal": "10.0.0.5:3260", "lun": "1"},
	}); err != nil {
		t.Fatalf("CreateStoragePool: %v; calls %v", err, f.calls)
	}
	if !f.sessions["10.0.0.5:3260 "+sessTarget] {
		t.Fatalf("no session; calls %v", f.calls)
	}
}

// An operator's per-record CHAP survives a VM disk create on an iscsi pool,
// which runs the same Prepare.
//
// On main the disk create's discovery rewrote the record and its login
// failed: the VM create was refused.
func TestCreateVM_ISCSI_DiskCreateKeepsAnExistingRecordsCHAP(t *testing.T) {
	s := lunTestServer(t)
	f := installCHAPISCSIAdm(t)
	f.adverts["10.0.0.1:3260"] = lunTestTarget
	f.records["10.0.0.1:3260 "+lunTestTarget] = "op:op-secret"
	f.accept = "op:op-secret"

	if _, err := s.CreateVM(adminCtx(), lunVM("a", "lun0")); err != nil {
		t.Fatalf("CreateVM on an iscsi pool: %v; calls %v", err, f.calls)
	}
	if got := f.record("10.0.0.1:3260 " + lunTestTarget); got != "op:op-secret" {
		t.Fatalf("the record's CHAP is %q after the disk create, want the operator's", got)
	}
}
