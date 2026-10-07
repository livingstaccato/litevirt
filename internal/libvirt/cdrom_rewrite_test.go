package libvirt

import (
	"strings"
	"testing"

	golibvirt "github.com/digitalocean/go-libvirt"
)

const cdromDomain = `<domain type='kvm' xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>
  <name>win</name>
  <devices>
    <disk type='file' device='disk'>
      <source file='/data/a&amp;b/virtio-win.iso'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='/data/a&amp;b/virtio-win.iso' index='2'/>
      <target dev='sda' bus='sata'/>
      <readonly/>
    </disk>
    <disk type="file" device="cdrom">
      <source file="/srv/drivers.iso"></source>
      <target dev="sdb" bus="sata"/>
    </disk>
  </devices>
  <qemu:commandline>
    <qemu:arg value='-set'/>
  </qemu:commandline>
</domain>`

// The installer CD-ROM is pointed at another file: matched decoded, written
// escaped, only CD-ROMs, and every other byte kept — a qemu: namespace too.
//
// Mutation: drop the device='cdrom' condition — the data disk with the same
// source is rewritten too; write the path unescaped — the result does not
// parse.
func TestRewriteCDROMSources(t *testing.T) {
	to := "/data/r&d's/virtio-win-0.1.248.iso"
	out, n, err := RewriteCDROMSources(cdromDomain, map[string]string{"/data/a&b/virtio-win.iso": to})
	if err != nil || n != 1 {
		t.Fatalf("rewrite: n=%d err=%v", n, err)
	}
	if !strings.Contains(out, `<source file='/data/r&amp;d&apos;s/virtio-win-0.1.248.iso' index='2'/>`) {
		t.Fatalf("the CD-ROM source is not the escaped new path:\n%s", out)
	}
	if !strings.Contains(out, `<source file='/data/a&amp;b/virtio-win.iso'/>`) {
		t.Fatalf("a data disk with the same source was rewritten:\n%s", out)
	}
	if !strings.Contains(out, "<qemu:arg value='-set'/>") || !strings.Contains(out, `<source file="/srv/drivers.iso"></source>`) {
		t.Fatalf("other bytes changed:\n%s", out)
	}
	if strings.Count(out, "\n") != strings.Count(cdromDomain, "\n") {
		t.Fatal("the layout changed")
	}
	disks, err := parseDiskSourceInfos(out)
	if err != nil {
		t.Fatalf("the result does not parse: %v", err)
	}
	if disks[1].src[sourceAttrFile] != to {
		t.Fatalf("decoded CD-ROM source = %q, want %q", disks[1].src[sourceAttrFile], to)
	}
	// Double quotes, and nothing to do.
	out, n, err = RewriteCDROMSources(cdromDomain, map[string]string{"/srv/drivers.iso": "/srv/x\"y.iso"})
	if err != nil || n != 1 || !strings.Contains(out, `<source file="/srv/x&quot;y.iso"></source>`) {
		t.Fatalf("double-quoted rewrite: n=%d err=%v\n%s", n, err, out)
	}
	if out, n, err := RewriteCDROMSources(cdromDomain, map[string]string{"/nowhere.iso": "/x.iso"}); err != nil || n != 0 || out != cdromDomain {
		t.Fatalf("no match: n=%d err=%v", n, err)
	}
}

// A migration with CD-ROM sources hands libvirt a destination and a persistent
// definition carrying them; one whose running domain no longer carries the
// CD-ROM is refused rather than migrated onto an unjudged path.
//
// Mutation: drop the destination_xml parameter — red.
func TestMigrationCDROMXML(t *testing.T) {
	remap := map[string]string{"/srv/drivers.iso": "/srv/drivers-here.iso"}
	dest, persist, err := MigrationCDROMXML(cdromDomain, cdromDomain, remap)
	if err != nil || !strings.Contains(dest, "drivers-here.iso") || !strings.Contains(persist, "drivers-here.iso") {
		t.Fatalf("dest/persist: %v", err)
	}
	if _, _, err := MigrationCDROMXML(strings.ReplaceAll(cdromDomain, "/srv/drivers.iso", "/srv/other.iso"), cdromDomain, remap); err == nil {
		t.Fatal("a running domain without the judged CD-ROM was migrated")
	}
	_, params := migrationFlagsAndParams(MigrateParams{Live: true, DestXML: dest, PersistXML: persist})
	if v, n := stringParam(params, golibvirt.MigrateParamDestXML); n != 1 || v != dest {
		t.Errorf("destination_xml (x%d) is not the rewritten definition", n)
	}
	if v, n := stringParam(params, golibvirt.MigrateParamPersistXML); n != 1 || v != persist {
		t.Errorf("persistent_xml (x%d) is not the rewritten definition", n)
	}
	if _, params := migrationFlagsAndParams(MigrateParams{Live: true}); len(params) != 0 {
		t.Errorf("a migration with no CD-ROM sources carries parameters %v", params)
	}
}
