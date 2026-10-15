package libvirt

import (
	"errors"
	"strings"
	"testing"

	golibvirt "github.com/digitalocean/go-libvirt"
)

const passworded = `<domain type='kvm'><name>web</name><devices>` +
	`<graphics type='vnc' port='-1' autoport='yes' passwd='Zq3xR8pA'><listen type='address' address='127.0.0.1'/></graphics>` +
	`<graphics type='spice' port='-1' autoport='yes' passwd='SpiceSpiceSpiceSpice1234'/>` +
	`</devices></domain>`

func pwOf(t *testing.T, x, kind string) string {
	t.Helper()
	pw, err := ConsolePasswordFromXML(x, kind)
	if err != nil {
		t.Fatal(err)
	}
	return pw
}

// Before the latch nothing is touched, an operator-set password on an
// imported domain included; keep keeps; and a host without VNC passwords
// (FIPS) drops only the VNC one, in every mode that writes.
//
// Mutation "ConsoleLeave strips" — red. Mutation "noVNC ignored" — red.
func TestApplyConsolePasswords_Modes(t *testing.T) {
	leave, _ := ApplyConsolePasswords(passworded, ConsoleLeave, true)
	if leave != passworded {
		t.Errorf("ConsoleLeave changed the definition:\n%s", leave)
	}
	keep, _ := ApplyConsolePasswords(passworded, ConsoleKeep, false)
	if keep != passworded {
		t.Errorf("ConsoleKeep changed the definition:\n%s", keep)
	}
	for _, mode := range []ConsolePasswordMode{ConsoleKeep, ConsoleFresh} {
		out, err := ApplyConsolePasswords(passworded, mode, true)
		if err != nil {
			t.Fatal(err)
		}
		if pw := pwOf(t, out, "vnc"); pw != "" {
			t.Errorf("mode %d on a host without VNC passwords kept a VNC password", mode)
		}
		if pw := pwOf(t, out, "spice"); pw == "" {
			t.Errorf("mode %d on a host without VNC passwords dropped the SPICE one", mode)
		}
	}
	if got := ConsoleModeFor(PolicyLeave, true); got != ConsoleLeave {
		t.Errorf("PolicyLeave define = %d, want ConsoleLeave", got)
	}
	if got := ConsoleModeFor(PolicySet, false); got != ConsoleKeep {
		t.Errorf("PolicySet redefine-from-self = %d, want ConsoleKeep", got)
	}
	if got := ConsoleModeFor(PolicyStrip, false); got != ConsoleStrip {
		t.Errorf("PolicyStrip redefine-from-self = %d, want ConsoleStrip (the kill switch reaches it)", got)
	}
}

// xmlFlagModel records the flags ConsolePassword dumps with.
type xmlFlagModel struct{ flags []golibvirt.DomainXMLFlags }

func (m *xmlFlagModel) DomainLookupByName(n string) (golibvirt.Domain, error) {
	return golibvirt.Domain{Name: n}, nil
}
func (m *xmlFlagModel) DomainGetXMLDesc(_ golibvirt.Domain, f golibvirt.DomainXMLFlags) (string, error) {
	m.flags = append(m.flags, f)
	if f&golibvirt.DomainXMLSecure == 0 {
		return strings.ReplaceAll(passworded, " passwd='Zq3xR8pA'", ""), nil
	}
	return passworded, nil
}

// ConsolePassword reads the RUNNING guest's password: secure, and not the
// inactive (next-start) definition, which a running redefine changes.
//
// Mutation "add DomainXMLInactive" — red. Mutation "drop DomainXMLSecure" — red.
func TestConsolePassword_ReadsTheLiveSecureDefinition(t *testing.T) {
	m := &xmlFlagModel{}
	pw, err := consolePassword(m, "web", "vnc")
	if err != nil || pw != "Zq3xR8pA" {
		t.Fatalf("consolePassword = %q, %v", pw, err)
	}
	if len(m.flags) != 1 || m.flags[0]&golibvirt.DomainXMLSecure == 0 || m.flags[0]&golibvirt.DomainXMLInactive != 0 {
		t.Fatalf("dumped with flags %v, want DomainXMLSecure and not DomainXMLInactive", m.flags)
	}
}

// startModel is libvirt as a start sees it, with a QEMU that refuses a VNC
// password (a FIPS-mode host).
type startModel struct {
	snapshotAPI
	inactive  string
	refuse    bool
	fail      error // every start fails with this
	failFirst error // the first start fails with this
	starts    int
}

func (m *startModel) DomainLookupByName(n string) (golibvirt.Domain, error) {
	return golibvirt.Domain{Name: n}, nil
}
func (m *startModel) DomainGetXMLDesc(_ golibvirt.Domain, f golibvirt.DomainXMLFlags) (string, error) {
	if f&golibvirt.DomainXMLSecure == 0 {
		return StripConsolePasswords(m.inactive)
	}
	return m.inactive, nil
}
func (m *startModel) DomainDefineXML(x string) (golibvirt.Domain, error) {
	m.inactive = x
	return golibvirt.Domain{Name: "web"}, nil
}
func (m *startModel) DomainCreate(golibvirt.Domain) error {
	m.starts++
	if m.fail != nil {
		return m.fail
	}
	if m.failFirst != nil && m.starts == 1 {
		return m.failFirst
	}
	if pw, _ := ConsolePasswordFromXML(m.inactive, "vnc"); m.refuse && pw != "" {
		return errors.New("internal error: process exited while connecting to monitor: qemu-system-x86_64: -vnc unix:/run/x,password=on: Cipher backend does not support DES algorithm")
	}
	return nil
}

// A start QEMU refuses for its VNC password is retried once without the
// passwords, and the host stops setting VNC passwords: the feature never
// newly fails a start, a failover or a restart.
//
// Mutation "no backstop" — red. Mutation "retry without redefining" — red.
func TestStart_ARefusedConsolePasswordIsRetriedWithout(t *testing.T) {
	m := &startModel{inactive: passworded, refuse: true}
	var reason string
	if err := startWithConsoleBackstop(m, StartGuard{}, "web", PolicySet, func(r string) { reason = r }); err != nil {
		t.Fatalf("start on a host whose QEMU refuses VNC passwords: %v", err)
	}
	if m.starts != 2 {
		t.Errorf("starts = %d, want the refused one and one retry", m.starts)
	}
	if HasConsolePassword(m.inactive) {
		t.Errorf("the definition still carries a console password:\n%s", m.inactive)
	}
	if !strings.Contains(reason, "DES") {
		t.Errorf("the host was not marked, or not with QEMU's reason: %q", reason)
	}
}

// Any other start failure, or a refusal-looking one on a domain with no
// password, stands as it is and changes nothing.
func TestStart_OtherFailuresAreNotRetried(t *testing.T) {
	m := &startModel{inactive: StripMust(passworded), fail: errors.New("qemu-system-x86_64: -vnc unix:/x,password=on: Cipher backend does not support DES algorithm")}
	called := false
	_ = startWithConsoleBackstop(m, StartGuard{}, "web", PolicySet, func(string) { called = true })
	if m.starts != 1 || called {
		t.Errorf("a domain with no password was retried (%d starts) or marked (%v)", m.starts, called)
	}
	if IsConsolePasswordRefusal(errors.New("Cannot access storage file '/x.qcow2'")) {
		t.Error("an unrelated start failure was taken for a console password refusal")
	}
	if IsConsolePasswordRefusal(errors.New("FIPS mode: disk encryption cipher unavailable")) {
		t.Error("a FIPS failure about something else was taken for a console password refusal")
	}
	for _, msg := range []string{
		"internal error: process exited while connecting to monitor: qemu-system-x86_64: VNC password auth disabled due to FIPS mode, consider using the VeNCrypt or SASL authentication methods as an alternative",
		"internal error: qemu unexpectedly closed the monitor: 2026-10-12T10:00:00.000000Z qemu-kvm: -vnc unix:/var/lib/libvirt/qemu/domain-3-web/vnc.sock,password=on: Cipher backend does not support DES algorithm",
	} {
		if !IsConsolePasswordRefusal(errors.New(msg)) {
			t.Errorf("QEMU's refusal %q was not recognised", msg)
		}
	}
}

func StripMust(x string) string {
	out, err := StripConsolePasswords(x)
	if err != nil {
		panic(err)
	}
	return out
}

// A live migration onto a host that cannot do VNC passwords hands it a
// destination definition without the VNC one (SPICE kept), so the guest
// starts there instead of failing.
//
// Mutation "StripVNCPassword ignored by migrationDefinitions" — red.
func TestMigrationDefinitions_StripVNCPassword(t *testing.T) {
	live := func() (string, error) { return passworded, nil }
	dest, persist, err := migrationDefinitions(MigrateParams{StripVNCPassword: true}, live, live)
	if err != nil {
		t.Fatal(err)
	}
	for name, x := range map[string]string{"destination": dest, "persistent": persist} {
		if x == "" {
			t.Fatalf("no %s definition built: libvirt would carry the VNC password over", name)
		}
		if pwOf(t, x, "vnc") != "" || pwOf(t, x, "spice") == "" {
			t.Errorf("%s definition: want no VNC password and the SPICE one kept:\n%s", name, x)
		}
	}
	dest, _, _ = migrationDefinitions(MigrateParams{}, live, live)
	if dest != "" {
		t.Error("a migration with nothing to change built a destination definition")
	}
}

// The snapshot reverts redefine from a dump of the domain itself: they keep
// its console password (secure dumps), and the kill switch reaches them.
//
// Mutation "disk-only revert reads non-secure" / "live revert savedXML
// non-secure" — red. Mutation "reverts bypass the policy" — red.
func TestRevert_ConsolePasswordKeptAndKillSwitchApplies(t *testing.T) {
	for _, live := range []bool{false, true} {
		for _, policy := range []ConsolePolicy{PolicyLeave, PolicySet, PolicyStrip} {
			m := newLibvirt10(t)
			m.consolePasswd = "Zq3xR8pA"
			c := &Client{}
			c.SetConsolePasswordPolicy(func() ConsolePolicy { return policy })
			v := keepConsoleSnapshotAPI{m, c}
			if live {
				save := m.memorySnapshot("m1")
				if err := revertToLiveSnapshot(v, "vm", "m1", save, nil, nil, StartGuard{}, FirmwareMoveGuard{}); err != nil {
					t.Fatal(err)
				}
			} else {
				m.snapshot("s1")
				if err := revertToSnapshot(v, "vm", "s1", nil, StartGuard{}); err != nil {
					t.Fatal(err)
				}
			}
			got := pwOf(t, m.defined, "vnc")
			want := m.consolePasswd
			if policy == PolicyStrip {
				want = ""
			}
			if got != want {
				t.Errorf("live=%v policy=%d: the reverted definition's password is %q, want %q", live, policy, got, want)
			}
		}
	}
}
