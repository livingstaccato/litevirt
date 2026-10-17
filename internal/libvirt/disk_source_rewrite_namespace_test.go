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
	in := `<domain><devices><disk type="file"><source index="z file='/decoy.qcow2'" file='/old/root.qcow2'/>` +
		`<target dev="vda"/></disk></devices></domain>`
	out, changed, err := RewriteDiskSource(in, "vda", "/old/root.qcow2", "/new/root.qcow2")
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	want := `<domain><devices><disk type="file"><source index="z file='/decoy.qcow2'" file='/new/root.qcow2'/>` +
		`<target dev="vda"/></disk></devices></domain>`
	if out != want {
		t.Fatalf("got\n%s\nwant\n%s", out, want)
	}
}

// edgeDomain wraps devices in a litevirt domain's header and metadata.
func edgeDomain(devices string) string {
	return "<domain type='kvm'>\n  <name>mv1</name>\n  <metadata>\n    " + mvManaged + "\n    " + mvOwnerEpoch +
		"\n  </metadata>\n  <devices>\n" + devices + "  </devices>\n</domain>\n"
}

// Each case rewrites vda from its old path to its new one and must return the
// input with only that value changed, byte for byte.
func TestRewriteDiskSource_EdgeCasesByteExact(t *testing.T) {
	const (
		old = "/var/lib/litevirt/disks/mv1-root.qcow2"
		nw  = "/srv/pools/fast/mv1-root.qcow2"
	)
	other := "    <disk type='file' device='disk'>\n      <source file='/var/lib/litevirt/disks/mv1-data.qcow2'/>\n" +
		"      <backingStore type='file'>\n        <format type='qcow2'/>\n        <source file='/var/lib/litevirt/images/base.qcow2'/>\n" +
		"      </backingStore>\n      <target dev='vdb' bus='virtio'/>\n    </disk>\n"
	for _, c := range []struct {
		name, oldPath, newPath, in, want string
	}{{
		name: "backingStore with its own source inside the target disk",
		in: "    <disk type='file' device='disk'>\n      <source file='" + old + "'/>\n      <backingStore type='file'>\n" +
			"        <format type='qcow2'/>\n        <source file='/var/lib/litevirt/images/base.qcow2'/>\n      </backingStore>\n" +
			"      <target dev='vda' bus='virtio'/>\n    </disk>\n",
		want: "    <disk type='file' device='disk'>\n      <source file='" + nw + "'/>\n      <backingStore type='file'>\n" +
			"        <format type='qcow2'/>\n        <source file='/var/lib/litevirt/images/base.qcow2'/>\n      </backingStore>\n" +
			"      <target dev='vda' bus='virtio'/>\n    </disk>\n",
	}, {
		name: "target disk second, after a disk with a backingStore",
		in:   other + "    <disk type='file' device='disk'>\n      <source file='" + old + "'/>\n      <target dev='vda'/>\n    </disk>\n",
		want: other + "    <disk type='file' device='disk'>\n      <source file='" + nw + "'/>\n      <target dev='vda'/>\n    </disk>\n",
	}, {
		name: "non-disk sources between two disks",
		in: other + "    <interface type='network'>\n      <source network='default'/>\n      <model type='virtio'/>\n    </interface>\n" +
			"    <hostdev mode='subsystem' type='pci'>\n      <source>\n        <address domain='0x0000' bus='0x01' slot='0x00' function='0x0'/>\n      </source>\n    </hostdev>\n" +
			"    <disk type='file' device='disk'>\n      <source file='" + old + "'/>\n      <target dev='vda'/>\n    </disk>\n",
		want: other + "    <interface type='network'>\n      <source network='default'/>\n      <model type='virtio'/>\n    </interface>\n" +
			"    <hostdev mode='subsystem' type='pci'>\n      <source>\n        <address domain='0x0000' bus='0x01' slot='0x00' function='0x0'/>\n      </source>\n    </hostdev>\n" +
			"    <disk type='file' device='disk'>\n      <source file='" + nw + "'/>\n      <target dev='vda'/>\n    </disk>\n",
	}, {
		name: "comment and CDATA inside the disk",
		in: "    <disk type='file' device='disk'>\n      <!-- <source file='" + old + "'/> -->\n      <![CDATA[<source file='/decoy.qcow2'/>]]>\n" +
			"      <source file='" + old + "'/>\n      <target dev='vda'/>\n    </disk>\n",
		want: "    <disk type='file' device='disk'>\n      <!-- <source file='" + old + "'/> -->\n      <![CDATA[<source file='/decoy.qcow2'/>]]>\n" +
			"      <source file='" + nw + "'/>\n      <target dev='vda'/>\n    </disk>\n",
	}, {
		name: "newlines and spaces inside the tag",
		in:   "    <disk type='file'>\n      <source\n        file = \"" + old + "\"\n\tindex='1'\n      />\n      <target dev='vda'/>\n    </disk>\n",
		want: "    <disk type='file'>\n      <source\n        file = \"" + nw + "\"\n\tindex='1'\n      />\n      <target dev='vda'/>\n    </disk>\n",
	}, {
		name:    "double-quoted value holding a single quote",
		oldPath: "/var/lib/litevirt/disks/a'b.qcow2",
		in:      "    <disk type='file'>\n      <source file=\"/var/lib/litevirt/disks/a'b.qcow2\"/>\n      <target dev='vda'/>\n    </disk>\n",
		want:    "    <disk type='file'>\n      <source file=\"" + nw + "\"/>\n      <target dev='vda'/>\n    </disk>\n",
	}, {
		name:    "entity-escaped old value",
		oldPath: "/var/lib/litevirt/disks/a&b'c.qcow2",
		in:      "    <disk type='file'>\n      <source file='/var/lib/litevirt/disks/a&amp;b&apos;c.qcow2'/>\n      <target dev='vda'/>\n    </disk>\n",
		want:    "    <disk type='file'>\n      <source file='" + nw + "'/>\n      <target dev='vda'/>\n    </disk>\n",
	}, {
		name: "paired source with children",
		in:   "    <disk type='file'>\n      <source file='" + old + "'>\n        <seclabel model='dac' relabel='no'/>\n      </source>\n      <target dev='vda'/>\n    </disk>\n",
		want: "    <disk type='file'>\n      <source file='" + nw + "'>\n        <seclabel model='dac' relabel='no'/>\n      </source>\n      <target dev='vda'/>\n    </disk>\n",
	}, {
		name:    "new path holding ' \" < & and a double-quoted attribute",
		newPath: `/p/a&b'c"d<e.qcow2`,
		in:      "    <disk type='file'>\n      <source file=\"" + old + "\"/>\n      <target dev='vda'/>\n    </disk>\n",
		want:    "    <disk type='file'>\n      <source file=\"/p/a&amp;b&apos;c&quot;d&lt;e.qcow2\"/>\n      <target dev='vda'/>\n    </disk>\n",
	}, {
		name: "another disk on an overlay of the old path is not a mention",
		in: "    <disk type='file'>\n      <source file='" + old + "'/>\n      <target dev='vda'/>\n    </disk>\n" +
			"    <disk type='file'>\n      <source file='" + old + ".s1'/>\n      <target dev='vdb'/>\n    </disk>\n",
		want: "    <disk type='file'>\n      <source file='" + nw + "'/>\n      <target dev='vda'/>\n    </disk>\n" +
			"    <disk type='file'>\n      <source file='" + old + ".s1'/>\n      <target dev='vdb'/>\n    </disk>\n",
	}, {
		name: "another disk on a longer path ending in the old path is not a mention",
		in: "    <disk type='file'>\n      <source file='" + old + "'/>\n      <target dev='vda'/>\n    </disk>\n" +
			"    <disk type='file'>\n      <source file='/x" + old + "'/>\n      <target dev='vdb'/>\n    </disk>\n",
		want: "    <disk type='file'>\n      <source file='" + nw + "'/>\n      <target dev='vda'/>\n    </disk>\n" +
			"    <disk type='file'>\n      <source file='/x" + old + "'/>\n      <target dev='vdb'/>\n    </disk>\n",
	}} {
		t.Run(c.name, func(t *testing.T) {
			from, to := old, nw
			if c.oldPath != "" {
				from = c.oldPath
			}
			if c.newPath != "" {
				to = c.newPath
			}
			out, changed, err := RewriteDiskSource(edgeDomain(c.in), "vda", from, to)
			if err != nil || !changed {
				t.Fatalf("changed=%v err=%v", changed, err)
			}
			if want := edgeDomain(c.want); out != want {
				t.Fatalf("got\n%s\nwant\n%s", out, want)
			}
			if got := srcOf(t, out, "vda"); got != to {
				t.Fatalf("vda decodes to %q, want %q", got, to)
			}
		})
	}
}

// Refused: a new path libvirt would alter, and an old path the domain still
// names somewhere the rewrite leaves alone.
func TestRewriteDiskSource_RefusesUnsafeRewrites(t *testing.T) {
	const old = "/var/lib/litevirt/disks/mv1-root.qcow2"
	vda := "    <disk type='file'>\n      <source file='" + old + "'/>\n      <target dev='vda'/>\n    </disk>\n"
	for _, c := range []struct {
		name, devices, newPath, extra, wantErr string
	}{
		{name: "tab in the new path", devices: vda, newPath: "/srv/a\tb.qcow2", wantErr: "tab or line break"},
		{name: "newline in the new path", devices: vda, newPath: "/srv/a\nb.qcow2", wantErr: "tab or line break"},
		{name: "carriage return in the new path", devices: vda, newPath: "/srv/a\rb.qcow2", wantErr: "tab or line break"},
		{name: "another disk's backing store", devices: vda +
			"    <disk type='file'>\n      <source file='/d/clone.qcow2'/>\n      <backingStore type='file'>\n        <source file='" + old + "'/>\n      </backingStore>\n      <target dev='vdb'/>\n    </disk>\n",
			wantErr: "<disk/backingStore/source> attribute file"},
		{name: "a qemu:commandline argument", devices: vda,
			extra:   "  <qemu:commandline xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>\n    <qemu:arg value='file=" + old + ",if=none'/>\n  </qemu:commandline>\n",
			wantErr: "/qemu:commandline/qemu:arg> attribute value"},
		{name: "the kernel", devices: vda, extra: "  <os>\n    <kernel>" + old + "</kernel>\n  </os>\n", wantErr: "<domain/os/kernel> text"},
		{name: "a qemu:override argument", devices: vda,
			extra:   "  <qemu:override xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>\n    <qemu:device alias='x'>\n      <qemu:frontend>\n        <qemu:property name='drive' type='string' value='" + old + "'/>\n      </qemu:frontend>\n    </qemu:device>\n  </qemu:override>\n",
			wantErr: "qemu:property> attribute value"},
		{name: "the new path already named by another disk", devices: vda +
			"    <disk type='file'>\n      <source file='/srv/pools/fast/mv1-root.qcow2'/>\n      <target dev='vdb'/>\n    </disk>\n",
			wantErr: "disk vda to \"/srv/pools/fast/mv1-root.qcow2\": the domain already names that path in <devices/disk/source> attribute file"},
	} {
		t.Run(c.name, func(t *testing.T) {
			in := edgeDomain(c.devices)
			in = strings.Replace(in, "</domain>\n", c.extra+"</domain>\n", 1)
			to := "/srv/pools/fast/mv1-root.qcow2"
			if c.newPath != "" {
				to = c.newPath
			}
			_, _, err := RewriteDiskSource(in, "vda", old, to)
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %v, want one naming %q", err, c.wantErr)
			}
			if !strings.Contains(err.Error(), "disk vda") {
				t.Fatalf("err = %v, want one naming disk vda", err)
			}
		})
	}
}

// The old path in free text libvirt opens nothing from (<title>,
// <description>, an element or attribute under <metadata>) does not refuse
// the move, which returns the input with only vda's value changed. The scan
// that decides whether a copy may be removed still finds those mentions.
func TestRewriteDiskSource_FreeTextMentionsAccepted(t *testing.T) {
	const (
		old = "/var/lib/litevirt/disks/mv1-root.qcow2"
		nw  = "/srv/pools/fast/mv1-root.qcow2"
	)
	vda := func(p string) string {
		return "    <disk type='file'>\n      <source file='" + p + "'/>\n      <target dev='vda'/>\n    </disk>\n"
	}
	for _, c := range []struct{ name, find, insert string }{
		{"title", "  <metadata>", "  <title>" + old + "</title>\n"},
		{"description", "  <metadata>", "  <description>disk was " + old + "</description>\n"},
		{"metadata element and attribute", "  </metadata>", "    <x:note xmlns:x='urn:x' path='" + old + "'>" + old + "</x:note>\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			with := func(dom string) string { return strings.Replace(dom, c.find, c.insert+c.find, 1) }
			in, want := with(edgeDomain(vda(old))), with(edgeDomain(vda(nw)))
			if in == edgeDomain(vda(old)) {
				t.Fatal("the mention was not inserted")
			}
			out, changed, err := RewriteDiskSource(in, "vda", old, nw)
			if err != nil || !changed {
				t.Fatalf("changed=%v err=%v", changed, err)
			}
			if out != want {
				t.Fatalf("got\n%s\nwant\n%s", out, want)
			}
			if !DomainXMLNamesPath(out, old) {
				t.Fatal("DomainXMLNamesPath must still find the free-text mention")
			}
		})
	}
}
