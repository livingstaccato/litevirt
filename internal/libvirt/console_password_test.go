package libvirt

import (
	"strings"
	"testing"
)

// consoleDomainXML is a domain as GenerateDomainXML renders one with both
// consoles, plus a libvirt-canonical (single-quoted) graphics element that
// already carries a password, so both quoting styles are covered.
func consoleDomainXML(t *testing.T) string {
	t.Helper()
	x, err := GenerateDomainXML(VMConfig{
		Name: "web", CPU: 1, MemoryMiB: 512, EnableVNC: true, EnableSPICE: true,
		Disks: []DiskConfig{{Name: "root", Path: "/var/lib/litevirt/disks/web/root.qcow2", Bus: "virtio"}},
	})
	if err != nil {
		t.Fatalf("GenerateDomainXML: %v", err)
	}
	return x
}

func TestGenerateDomainXML_RendersNoConsolePassword(t *testing.T) {
	// The password is applied where the domain is DEFINED (Client.DefineDomain),
	// never baked into generated XML: generation runs on paths whose output is
	// logged or compared, and the define is the one place every path passes.
	if x := consoleDomainXML(t); strings.Contains(x, "passwd") {
		t.Fatalf("generated XML carries a passwd attribute:\n%s", x)
	}
}

func TestApplyConsolePasswords_OnSetsAFreshPasswordOnEveryConsole(t *testing.T) {
	x := consoleDomainXML(t)
	out, err := ApplyConsolePasswords(x, true)
	if err != nil {
		t.Fatalf("ApplyConsolePasswords: %v", err)
	}
	vnc, err := ConsolePasswordFromXML(out, "vnc")
	if err != nil {
		t.Fatal(err)
	}
	spice, err := ConsolePasswordFromXML(out, "spice")
	if err != nil {
		t.Fatal(err)
	}
	// VNC authentication keys DES with the first 8 bytes of the password and
	// ignores the rest, so a longer one would only look stronger.
	if len(vnc) != VNCPasswordLen {
		t.Errorf("vnc password %q has length %d, want %d", vnc, len(vnc), VNCPasswordLen)
	}
	if len(spice) != SPICEPasswordLen {
		t.Errorf("spice password has length %d, want %d", len(spice), SPICEPasswordLen)
	}
	if vnc == spice[:VNCPasswordLen] {
		t.Error("the VNC password is a prefix of the SPICE one; they must be independent")
	}

	// A redefine rotates: the same input yields different passwords.
	again, err := ApplyConsolePasswords(out, true)
	if err != nil {
		t.Fatal(err)
	}
	vnc2, _ := ConsolePasswordFromXML(again, "vnc")
	if vnc2 == "" || vnc2 == vnc {
		t.Errorf("a second apply kept the VNC password (%q -> %q); a redefine must rotate it", vnc, vnc2)
	}
	if strings.Count(again, "passwd=") != 2 {
		t.Errorf("want exactly one passwd per console, got:\n%s", again)
	}

	// Nothing outside the graphics start tags changes.
	stripped, err := ApplyConsolePasswords(again, false)
	if err != nil {
		t.Fatal(err)
	}
	if stripped != x {
		t.Errorf("apply then strip is not the identity outside the passwd attribute:\n--- before\n%s\n--- after\n%s", x, stripped)
	}
}

func TestApplyConsolePasswords_OffRemovesAPassword(t *testing.T) {
	x := `<domain type='kvm'><name>web</name><devices>` +
		`<graphics type='vnc' port='5901' autoport='yes' listen='127.0.0.1' passwd='abcdefgh' passwdValidTo='2030-01-01T00:00:00'>` +
		`<listen type='address' address='127.0.0.1'/></graphics>` +
		`<graphics type="spice" autoport="yes" passwd="s3cret"/>` +
		`<graphics type='egl-headless'/>` +
		`</devices></domain>`
	out, err := ApplyConsolePasswords(x, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "passwd=") {
		t.Fatalf("passwd survived the off policy:\n%s", out)
	}
	if !strings.Contains(out, "passwdValidTo='2030-01-01T00:00:00'") {
		t.Errorf("an unrelated attribute that merely starts with passwd was removed:\n%s", out)
	}
	// A graphics type that has no password (egl-headless) is left alone when on.
	on, err := ApplyConsolePasswords(x, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(on, "<graphics type='egl-headless'/>") {
		t.Errorf("a non-console graphics element was rewritten:\n%s", on)
	}
}

func TestApplyConsolePasswords_NoGraphicsIsUnchanged(t *testing.T) {
	x := `<domain type='kvm'><name>headless</name><devices><serial type='pty'/></devices></domain>`
	for _, on := range []bool{true, false} {
		out, err := ApplyConsolePasswords(x, on)
		if err != nil {
			t.Fatal(err)
		}
		if out != x {
			t.Errorf("on=%v changed a domain with no console:\n%s", on, out)
		}
	}
}

func TestConsolePasswordFromXML_NoneIsEmpty(t *testing.T) {
	pw, err := ConsolePasswordFromXML(consoleDomainXML(t), "vnc")
	if err != nil || pw != "" {
		t.Fatalf("ConsolePasswordFromXML on a domain with no password = %q, %v; want \"\", nil", pw, err)
	}
}
