package grpcapi

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

const sessTarget = "iqn.2003-01.org.example:store"

// sessionISCSIAdm is an iscsiadm with a session table: a login through a
// known node record opens a session, unless loginErr says why it fails.
type sessionISCSIAdm struct {
	mu       sync.Mutex
	sessions map[string]bool // "portal target"
	records  map[string]bool
	loginErr string
	calls    []string
}

func installSessionISCSIAdm(t *testing.T) *sessionISCSIAdm {
	t.Helper()
	f := &sessionISCSIAdm{sessions: map[string]bool{}, records: map[string]bool{}}
	t.Cleanup(storage.OverrideISCSICommandForTest(f.run))
	return f
}

func (f *sessionISCSIAdm) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := strings.Join(args, " ")
	f.calls = append(f.calls, name+" "+a)
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
	case strings.HasSuffix(a, "--login"):
		key := at("-p") + " " + at("-T")
		if f.loginErr != "" {
			return []byte(f.loginErr), errors.New("exit status 24")
		}
		if !f.records[key] {
			return []byte("iscsiadm: No records found"), errors.New("exit status 21")
		}
		f.sessions[key] = true
		return []byte("Login successful."), nil
	case strings.HasPrefix(a, "-m node -o new"):
		f.records[at("-p")+" "+at("-T")] = true
		return []byte("New iSCSI node added"), nil
	case strings.HasPrefix(a, "-m discovery"):
		return []byte("iscsiadm: cannot make connection"), errors.New("exit status 4")
	}
	return nil, errors.New("unexpected: " + a)
}

func (f *sessionISCSIAdm) logins() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.HasSuffix(c, "--login") {
			n++
		}
	}
	return n
}

func (f *sessionISCSIAdm) setLoginErr(s string) {
	f.mu.Lock()
	f.loginErr = s
	f.mu.Unlock()
}

func iscsiPoolRow(t *testing.T, s *Server, name, portal string) {
	t.Helper()
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: name, Driver: "iscsi", Source: sessTarget, State: "active",
		Options: map[string]string{"portal": portal, "lun": "1"},
	}); err != nil {
		t.Fatal(err)
	}
}

func poolState(t *testing.T, s *Server, name string) string {
	t.Helper()
	rec, ok, err := corrosion.GetStoragePool(context.Background(), s.db, s.hostName, name)
	if err != nil || !ok {
		t.Fatalf("pool %s: found=%v err=%v", name, ok, err)
	}
	return rec.State
}

func sessionCondition(t *testing.T, s *Server, pool string) (corrosion.HealthCondition, bool) {
	t.Helper()
	c, ok, err := corrosion.GetHealthCondition(context.Background(), s.db, iscsiPoolEvaluator, condISCSISessionMissing,
		"host", pool+"@"+s.hostName)
	if err != nil {
		t.Fatal(err)
	}
	return c, ok
}

// O-1: after a host reboot the node record is there and the session is not.
// The reconcile logs back in and the pool stays active.
func TestReconcileISCSISessions_LogsBackInAfterAReboot(t *testing.T) {
	s := testServer(t)
	f := installSessionISCSIAdm(t)
	f.records["10.0.0.5:3260 "+sessTarget] = true
	iscsiPoolRow(t, s, "san", "10.0.0.5:3260")

	s.ReconcileISCSISessions(context.Background())

	if !f.sessions["10.0.0.5:3260 "+sessTarget] {
		t.Fatalf("no session after the reconcile; calls %v", f.calls)
	}
	if st := poolState(t, s, "san"); st != "active" {
		t.Fatalf("pool state %q, want active", st)
	}
	if c, ok := sessionCondition(t, s, "san"); ok && c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("condition %+v open with the session up", c)
	}
	s.ReconcileISCSISessions(context.Background())
	if n := f.logins(); n != 1 {
		t.Fatalf("%d logins over two passes, want 1 (the second finds the session)", n)
	}
}

// While the session is missing and the login fails, the pool is not active:
// it is degraded, and a condition names the reason. Once a login succeeds,
// both clear.
func TestReconcileISCSISessions_FailedLoginDegradesThePoolWithTheReason(t *testing.T) {
	s := testServer(t)
	f := installSessionISCSIAdm(t)
	f.records["10.0.0.5:3260 "+sessTarget] = true
	f.setLoginErr("iscsiadm: initiator reported error (24 - iSCSI login failed due to authorization failure)")
	iscsiPoolRow(t, s, "san", "10.0.0.5:3260")
	ctx := context.Background()

	s.ReconcileISCSISessions(ctx)
	if st := poolState(t, s, "san"); st != PoolStateDegraded {
		t.Fatalf("pool state %q with no session, want %q", st, PoolStateDegraded)
	}
	c, ok := sessionCondition(t, s, "san")
	if !ok || c.Lifecycle == corrosion.ConditionResolved || c.Severity != corrosion.SeverityWarning ||
		!strings.Contains(c.Evidence, "authorization failure") || !strings.Contains(c.Evidence, sessTarget) ||
		len(c.Hosts) != 1 || c.Hosts[0] != s.hostName {
		t.Fatalf("condition %+v (found %v), want an open warning with the login's reason", c, ok)
	}
	s.ReconcileISCSISessions(ctx)
	if c, _ := sessionCondition(t, s, "san"); c.Lifecycle != corrosion.ConditionConfirmed {
		t.Fatalf("condition lifecycle %q on the second failing pass, want confirmed", c.Lifecycle)
	}

	f.setLoginErr("")
	s.ReconcileISCSISessions(ctx)
	if st := poolState(t, s, "san"); st != "active" {
		t.Fatalf("pool state %q once logged in, want active", st)
	}
	if c, _ := sessionCondition(t, s, "san"); c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("condition %+v once logged in, want resolved", c)
	}
}

// A pool deleted while (or before) a pass runs is not written back, and its
// condition is resolved.
func TestReconcileISCSISessions_DeletedPoolIsNotResurrected(t *testing.T) {
	s := testServer(t)
	f := installSessionISCSIAdm(t)
	f.setLoginErr("iscsiadm: connection refused")
	iscsiPoolRow(t, s, "san", "10.0.0.5:3260")
	ctx := context.Background()
	s.ReconcileISCSISessions(ctx)
	if _, ok := sessionCondition(t, s, "san"); !ok {
		t.Fatal("no condition for the failing pool")
	}
	s.addStoragePoolRef("san", StoragePoolRef{Driver: "iscsi", Source: sessTarget, Options: map[string]string{"portal": "10.0.0.5:3260"}})
	if err := corrosion.MarkStoragePoolDeleted(ctx, s.db, s.hostName, "san"); err != nil {
		t.Fatal(err)
	}
	s.ReconcileISCSISessions(ctx)
	if _, ok, _ := corrosion.GetStoragePool(ctx, s.db, s.hostName, "san"); ok {
		t.Fatal("the deleted pool's row is live again")
	}
	if c, _ := sessionCondition(t, s, "san"); c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("condition %+v of a deleted pool, want resolved", c)
	}
}

// A pool from the daemon config: its row carries no portal (the daemon
// registers config pools without their driver options), so the portal comes
// from the config definition.
func TestReconcileISCSISessions_ConfigPoolUsesItsConfiguredPortal(t *testing.T) {
	s := testServer(t)
	f := installSessionISCSIAdm(t)
	f.records["10.0.0.7:3260 "+sessTarget] = true
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "cfgsan", Driver: "iscsi", Source: sessTarget, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	s.SetStoragePoolsByName(map[string]StoragePoolRef{
		"cfgsan": {Driver: "iscsi", Source: sessTarget, Options: map[string]string{"portal": "10.0.0.7:3260", "lun": "0"}},
	})
	s.ReconcileISCSISessions(context.Background())
	if !f.sessions["10.0.0.7:3260 "+sessTarget] {
		t.Fatalf("config pool not logged in through its configured portal; calls %v", f.calls)
	}
}

// Other drivers are never touched: no iscsiadm on a host with no iscsi pool.
func TestReconcileISCSISessions_NoISCSIPoolNoCommands(t *testing.T) {
	s := testServer(t)
	f := installSessionISCSIAdm(t)
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "nfs", Driver: "nfs", Source: "10.0.0.1:/x", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	s.ReconcileISCSISessions(context.Background())
	if len(f.calls) != 0 {
		t.Fatalf("iscsiadm run with no iscsi pool: %v", f.calls)
	}
	if st := poolState(t, s, "nfs"); st != "active" {
		t.Fatalf("nfs pool state %q, want untouched", st)
	}
}

// A start of a VM whose iSCSI device is missing logs the session back in
// first; when that fails the start is not refused here (it fails, if at all,
// where it did before).
func TestPrepareHardwareForStart_LogsInAMissingISCSISession(t *testing.T) {
	s, _ := provableCreateServer(t)
	f := installSessionISCSIAdm(t)
	f.records["10.0.0.5:3260 "+sessTarget] = true
	iscsiPoolRow(t, s, "san", "10.0.0.5:3260")
	prevExists, prevWait := iscsiDeviceExists, iscsiDeviceWait
	iscsiDeviceExists, iscsiDeviceWait = func(string) bool { return false }, 0
	t.Cleanup(func() { iscsiDeviceExists, iscsiDeviceWait = prevExists, prevWait })

	path := "/dev/disk/by-path/ip-10.0.0.5:3260-iscsi-" + sessTarget + "-lun-1"
	vm := corrosion.VMRecord{Name: "lunvm", HostName: "test-host", State: "stopped", Spec: `{"name":"lunvm","cpu":1,"memory_mib":256}`}
	if err := corrosion.InsertVM(context.Background(), s.db, vm, nil, []corrosion.DiskRecord{{
		VMName: "lunvm", DiskName: "root", HostName: "test-host", StorageType: "iscsi", StorageVolume: "san", Path: path,
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), &vm); err != nil {
		t.Fatalf("start preflight: %v", err)
	}
	if !f.sessions["10.0.0.5:3260 "+sessTarget] {
		t.Fatalf("start did not log the missing session in; calls %v", f.calls)
	}

	delete(f.sessions, "10.0.0.5:3260 "+sessTarget)
	f.setLoginErr("iscsiadm: connection refused")
	if _, err := s.PrepareHardwareForStart(context.Background(), &vm); err != nil {
		t.Fatalf("start preflight refused on a failed login, which main did not refuse: %v", err)
	}
}

func (f *sessionISCSIAdm) logout(key string) {
	f.mu.Lock()
	delete(f.sessions, key)
	f.mu.Unlock()
}

// I2 (a): a session this daemon has seen up and that then disappears was
// logged out on purpose (SAN maintenance, a LUN re-map): the periodic pass
// does not log it back in, and reports the pool degraded with why.
func TestReconcileISCSISessions_OperatorLogoutMidRunStaysOut(t *testing.T) {
	for name, loggedInByUs := range map[string]bool{"session up at start": false, "session re-logged at start": true} {
		t.Run(name, func(t *testing.T) {
			s := testServer(t)
			f := installSessionISCSIAdm(t)
			key := "10.0.0.5:3260 " + sessTarget
			f.records[key] = true
			if !loggedInByUs {
				f.sessions[key] = true
			}
			iscsiPoolRow(t, s, "san", "10.0.0.5:3260")
			ctx := context.Background()
			s.ReconcileISCSISessions(ctx)
			before := f.logins()

			f.logout(key)
			s.ReconcileISCSISessions(ctx)
			s.ReconcileISCSISessions(ctx)
			if f.logins() != before {
				t.Fatalf("the pass logged a deliberately logged-out session back in; calls %v", f.calls)
			}
			if f.sessions[key] {
				t.Fatal("session back without a start or a restart")
			}
			if st := poolState(t, s, "san"); st != PoolStateDegraded {
				t.Fatalf("pool state %q after a logout, want %q", st, PoolStateDegraded)
			}
			c, ok := sessionCondition(t, s, "san")
			if !ok || c.Lifecycle == corrosion.ConditionResolved || !strings.Contains(c.Evidence, iscsiLoggedOutReason) {
				t.Fatalf("condition %+v (found %v), want an open one with the logout reason", c, ok)
			}
		})
	}
}

// I2 (c): a VM start logs a deliberately logged-out session back in (using the
// LUN is the operator's intent), and the pool is active again on the next pass.
func TestPrepareHardwareForStart_LogsInAfterAnOperatorLogout(t *testing.T) {
	s, _ := provableCreateServer(t)
	f := installSessionISCSIAdm(t)
	key := "10.0.0.5:3260 " + sessTarget
	f.records[key], f.sessions[key] = true, true
	iscsiPoolRow(t, s, "san", "10.0.0.5:3260")
	prevExists, prevWait := iscsiDeviceExists, iscsiDeviceWait
	iscsiDeviceExists, iscsiDeviceWait = func(string) bool { return false }, 0
	t.Cleanup(func() { iscsiDeviceExists, iscsiDeviceWait = prevExists, prevWait })
	ctx := context.Background()
	s.ReconcileISCSISessions(ctx)
	f.logout(key)
	s.ReconcileISCSISessions(ctx)
	if f.sessions[key] {
		t.Fatal("the pass logged the session back in")
	}

	vm := corrosion.VMRecord{Name: "lunvm", HostName: "test-host", State: "stopped", Spec: `{"name":"lunvm","cpu":1,"memory_mib":256}`}
	if err := corrosion.InsertVM(ctx, s.db, vm, nil, []corrosion.DiskRecord{{
		VMName: "lunvm", DiskName: "root", HostName: "test-host", StorageType: "iscsi", StorageVolume: "san",
		Path: "/dev/disk/by-path/ip-10.0.0.5:3260-iscsi-" + sessTarget + "-lun-1",
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareHardwareForStart(ctx, &vm); err != nil {
		t.Fatalf("start preflight: %v", err)
	}
	if !f.sessions[key] {
		t.Fatalf("the start did not log the session back in; calls %v", f.calls)
	}
	s.ReconcileISCSISessions(ctx)
	if st := poolState(t, s, "san"); st != "active" {
		t.Fatalf("pool state %q after the start's login, want active", st)
	}
}

// M-4: a start does not retry a login the session pass saw fail moments ago,
// and does not wait for udev when it made no login.
func TestPrepareHardwareForStart_ISCSIHookIsCheapWhenItCannotHelp(t *testing.T) {
	s, _ := provableCreateServer(t)
	f := installSessionISCSIAdm(t)
	key := "10.0.0.5:3260 " + sessTarget
	f.records[key] = true
	f.setLoginErr("iscsiadm: connection timed out")
	iscsiPoolRow(t, s, "san", "10.0.0.5:3260")
	prevExists, prevWait := iscsiDeviceExists, iscsiDeviceWait
	iscsiDeviceExists, iscsiDeviceWait = func(string) bool { return false }, 3*time.Second
	t.Cleanup(func() { iscsiDeviceExists, iscsiDeviceWait = prevExists, prevWait })
	ctx := context.Background()
	s.ReconcileISCSISessions(ctx) // fails: recorded
	before := f.logins()

	vm := corrosion.VMRecord{Name: "lunvm", HostName: "test-host", State: "stopped", Spec: `{"name":"lunvm","cpu":1,"memory_mib":256}`}
	if err := corrosion.InsertVM(ctx, s.db, vm, nil, []corrosion.DiskRecord{{
		VMName: "lunvm", DiskName: "root", HostName: "test-host", StorageType: "iscsi", StorageVolume: "san",
		Path: "/dev/disk/by-path/ip-10.0.0.5:3260-iscsi-" + sessTarget + "-lun-1",
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareHardwareForStart(ctx, &vm); err != nil {
		t.Fatalf("start preflight: %v", err)
	}
	if f.logins() != before {
		t.Fatalf("the start retried a login that failed moments ago; calls %v", f.calls)
	}
	// Session up but device missing (an unmapped LUN): no login, so no wait.
	f.setLoginErr("")
	f.mu.Lock()
	f.sessions[key] = true
	f.mu.Unlock()
	s.ReconcileISCSISessions(ctx)
	t0 := time.Now()
	if _, err := s.PrepareHardwareForStart(ctx, &vm); err != nil {
		t.Fatalf("start preflight: %v", err)
	}
	if el := time.Since(t0); el > 2*time.Second {
		t.Fatalf("start waited %v for a device although it made no login", el)
	}
}
