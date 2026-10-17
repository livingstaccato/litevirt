package libvirt

import (
	"os"
	"strings"
	"testing"
)

// litevirtMoveDomain is a litevirt VM's inactive definition as libvirt dumps
// it once the managed stamp and the owner-epoch marker are written: both live
// in <metadata> under litevirt's namespaces, so every litevirt domain carries
// XML namespaces.
func litevirtMoveDomain(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/move_litevirt_domain.xml")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const (
	mvOld = "/var/lib/litevirt/disks/mv1-root.qcow2"
	mvNew = "/srv/pools/fast/mv1-root.qcow2"
	// The two metadata elements exactly as the fixture carries them.
	mvManaged    = `<litevirt-managed:managed xmlns:litevirt-managed="https://litevirt.dev/xmlns/managed/1" incarnation="2026-10-17T18:44:33.798Z"/>`
	mvOwnerEpoch = `<litevirt-owner-epoch:owner-epoch xmlns:litevirt-owner-epoch="https://litevirt.dev/xmlns/owner-epoch/1">4</litevirt-owner-epoch:owner-epoch>`
)

// A move of a litevirt VM's disk repoints that disk and changes no other
// byte: the managed stamp and the owner-epoch marker come through as written.
func TestRewriteDiskSource_LitevirtDomainKeepsMetadata(t *testing.T) {
	in := litevirtMoveDomain(t)
	for _, el := range []string{mvManaged, mvOwnerEpoch} {
		if !strings.Contains(in, el) {
			t.Fatalf("fixture lacks %s", el)
		}
	}
	for name, rewrite := range map[string]func(string, string, string, string) (string, bool, error){
		"RewriteDiskSource":     RewriteDiskSource,
		"RewriteDiskSourceFile": RewriteDiskSourceFile,
	} {
		out, changed, err := rewrite(in, "vda", mvOld, mvNew)
		if err != nil || !changed {
			t.Fatalf("%s: changed=%v err=%v", name, changed, err)
		}
		want := strings.Replace(in, "file='"+mvOld+"'", "file='"+mvNew+"'", 1)
		if out != want {
			t.Fatalf("%s: the rewrite changed more than vda's source:\n%s", name, out)
		}
	}
}

// Matching by source alone (a legacy row with no target dev) works on the
// same domain.
func TestRewriteDiskSource_LitevirtDomainNoTargetDev(t *testing.T) {
	in := litevirtMoveDomain(t)
	out, changed, err := RewriteDiskSource(in, "", mvOld, mvNew)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if want := strings.Replace(in, mvOld, mvNew, 1); out != want {
		t.Fatalf("got\n%s", out)
	}
	// And a retry once cut over is idempotent and returns the input.
	again, changed, err := RewriteDiskSource(out, "vda", mvOld, mvNew)
	if err != nil || changed || again != out {
		t.Fatalf("retry: changed=%v err=%v", changed, err)
	}
}

// A qemu:commandline block, declared on the root, is outside <devices>: it is
// kept byte for byte.
func TestRewriteDiskSource_QemuCommandlineKept(t *testing.T) {
	in := `<domain type="kvm" xmlns:qemu="http://libvirt.org/schemas/domain/qemu/1.0"><name>v</name><devices>` +
		`<disk type="file"><source file="/old/root.qcow2"/><target dev="vda"/></disk>` +
		`</devices><qemu:commandline><qemu:arg value='a&amp;b'/></qemu:commandline></domain>`
	out, changed, err := RewriteDiskSourceFile(in, "vda", "/old/root.qcow2", "/new/a&b.qcow2")
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if want := strings.Replace(in, `"/old/root.qcow2"`, `"/new/a&amp;b.qcow2"`, 1); out != want {
		t.Fatalf("got\n%s\nwant\n%s", out, want)
	}
}

// Namespaces where a disk is matched are refused: a namespaced element under
// <devices>, a namespaced <devices>, or a default namespace on the domain
// would each be read by local name as something it is not.
func TestRewriteDiskSource_RefusesNamespacesAroundDevices(t *testing.T) {
	disk := `<disk><source file="/old/root.qcow2"/><target dev="vda"/></disk>`
	for name, in := range map[string]string{
		"element in devices": `<domain><devices>` + disk + `<x:disk xmlns:x="urn:x"><source file="/old/root.qcow2"/><target dev="vdb"/></x:disk></devices></domain>`,
		"nested in a disk":   `<domain><devices><disk><x:source xmlns:x="urn:x" file="/a"/><source file="/old/root.qcow2"/><target dev="vda"/></disk></devices></domain>`,
		"decl on devices":    `<domain><devices xmlns:x="urn:x">` + disk + `</devices></domain>`,
		"namespaced devices": `<domain xmlns:x="urn:x"><x:devices>` + disk + `</x:devices></domain>`,
		"default namespace":  `<domain xmlns="urn:x"><devices>` + disk + `</devices></domain>`,
		"attr on source":     `<domain xmlns:x="urn:x"><devices><disk><source x:file="/old/root.qcow2" file="/old/root.qcow2"/><target dev="vda"/></disk></devices></domain>`,
	} {
		if _, _, err := RewriteDiskSource(in, "vda", "/old/root.qcow2", "/new/root.qcow2"); err == nil {
			t.Errorf("%s: rewritten, want a refusal", name)
		}
	}
}

// The file attribute is found by parsing the tag's attributes, not by a
// pattern that can match inside another attribute's value.
func TestRewriteDiskSource_FileTextInsideAnotherAttribute(t *testing.T) {
	in := `<domain><devices><disk type="file"><source index="z file='/old/root.qcow2'" file='/old/root.qcow2'/>` +
		`<target dev="vda"/></disk></devices></domain>`
	out, changed, err := RewriteDiskSource(in, "vda", "/old/root.qcow2", "/new/root.qcow2")
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	want := `<domain><devices><disk type="file"><source index="z file='/old/root.qcow2'" file='/new/root.qcow2'/>` +
		`<target dev="vda"/></disk></devices></domain>`
	if out != want {
		t.Fatalf("got\n%s\nwant\n%s", out, want)
	}
}
