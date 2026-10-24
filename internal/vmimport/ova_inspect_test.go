package vmimport

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
)

type tarMember struct {
	name string
	typ  byte
	body []byte
}

func buildTar(t *testing.T, members ...tarMember) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, m := range members {
		typ := m.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: m.name, Mode: 0o644, Size: int64(len(m.body)), Typeflag: typ}
		if typ == tar.TypeSymlink {
			hdr.Size, hdr.Linkname = 0, "/etc/passwd"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write(m.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// The descriptor of an OVA laid out as the OVF specification has it (the .ovf
// first) is read without reading the disk behind it.
func TestInspectOVA_ReadsOnlyUpToTheDescriptor(t *testing.T) {
	disk := make([]byte, 4<<20)
	ova := buildTar(t,
		tarMember{name: "win2022.ovf", body: []byte(ovfWindowsSCSI)},
		tarMember{name: "disk-0.vmdk", body: disk},
	)
	cr := &countingReader{r: bytes.NewReader(ova)}
	data, err := InspectOVA(cr)
	if err != nil {
		t.Fatalf("InspectOVA: %v", err)
	}
	if string(data) != ovfWindowsSCSI {
		t.Fatalf("descriptor = %d bytes, want the .ovf member's %d", len(data), len(ovfWindowsSCSI))
	}
	if cr.n >= len(disk) {
		t.Fatalf("InspectOVA read %d bytes of a %d-byte archive: it read the disk", cr.n, len(ova))
	}
	fv, err := ParseOVFBytes(data)
	if err != nil {
		t.Fatalf("ParseOVFBytes: %v", err)
	}
	if fv.CPUs != 4 || fv.Firmware != "uefi" || len(fv.NICs) != 1 {
		t.Fatalf("parsed %+v", fv)
	}
}

// A descriptor behind the disk is still found (the disk is skipped, not kept).
func TestInspectOVA_DescriptorAfterTheDisk(t *testing.T) {
	ova := buildTar(t,
		tarMember{name: "disk-0.vmdk", body: make([]byte, 1<<20)},
		tarMember{name: "sub/win2022.OVF", body: []byte(ovfWindowsSCSI)},
	)
	data, err := InspectOVA(bytes.NewReader(ova))
	if err != nil || string(data) != ovfWindowsSCSI {
		t.Fatalf("InspectOVA = %d bytes, %v; want the descriptor", len(data), err)
	}
}

// What UnpackOVA refuses at the head of an archive the preview refuses too.
func TestInspectOVA_RefusesWhatTheImportRefuses(t *testing.T) {
	many := make([]tarMember, 0, maxArchiveMembers+2)
	for i := 0; i <= maxArchiveMembers; i++ {
		many = append(many, tarMember{name: fmt.Sprintf("pad-%d", i)})
	}
	many = append(many, tarMember{name: "a.ovf", body: []byte(ovfWindowsSCSI)})
	for _, tc := range []struct {
		name string
		ova  []tarMember
		want string
	}{
		{"symlink", []tarMember{{name: "evil.vmdk", typ: tar.TypeSymlink}, {name: "a.ovf", body: []byte(ovfWindowsSCSI)}}, "disallowed type"},
		{"member cap", many, "member cap"},
		{"no descriptor", []tarMember{{name: "disk.vmdk", body: []byte("x")}}, "no .ovf descriptor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ova := buildTar(t, tc.ova...)
			if _, err := InspectOVA(bytes.NewReader(ova)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("InspectOVA err = %v, want %q", err, tc.want)
			}
			if _, err := UnpackOVA(bytes.NewReader(ova), t.TempDir(), Budget(1<<30)); err == nil {
				t.Fatalf("UnpackOVA accepted what the preview refuses")
			}
		})
	}
}
