package libvirt

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// FirmwareRuntime is the firmware code a live firmware move depends on: the
// upstream X.Y.Z versions of libvirt, QEMU, swtpm and libtpms, and the OVMF
// content fingerprint. Two hosts move a vTPM / Secure Boot guest live only
// when their runtimes are equal (spec §3.2 item 9). An empty field is never a
// value: every reader returns an error instead.
type FirmwareRuntime struct {
	Libvirt         string
	QEMU            string
	Swtpm           string
	Libtpms         string
	OVMFFingerprint string
}

// xyz is an upstream release, X.Y.Z with no leading zeros.
const xyz = `(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)`

var (
	qemuVersionRe  = regexp.MustCompile(`^QEMU emulator version (` + xyz + `)(?:[ \t(]|$)`)
	swtpmVersionRe = regexp.MustCompile(`^TPM emulator version (` + xyz + `)(?:[ \t,]|$)`)
	libtpmsSoRe    = regexp.MustCompile(`^libtpms\.so\.(` + xyz + `)$`)
)

// ParseQEMUVersion reads the release from the first line of
// `qemu-system-* --version` ("QEMU emulator version 8.2.2 (Debian ...)").
func ParseQEMUVersion(out string) (string, error) {
	m := qemuVersionRe.FindStringSubmatch(firstLine(out))
	if m == nil {
		return "", fmt.Errorf("unrecognised QEMU version output %q", firstLine(out))
	}
	return m[1], nil
}

// ParseSwtpmVersion reads the release from the first line of
// `swtpm --version` ("TPM emulator version 0.7.3, Copyright ...").
func ParseSwtpmVersion(out string) (string, error) {
	m := swtpmVersionRe.FindStringSubmatch(firstLine(out))
	if m == nil {
		return "", fmt.Errorf("unrecognised swtpm version output %q", firstLine(out))
	}
	return m[1], nil
}

// ParseLibtpmsSoname reads the release from the real file name of the
// libtpms library (libtpms.so.0.9.3 → 0.9.3), the name the soname symlink
// resolves to. A bare soname (libtpms.so.0) carries no release and is an
// error: libtpms equality rests on that name (spec K-9).
func ParseLibtpmsSoname(path string) (string, error) {
	m := libtpmsSoRe.FindStringSubmatch(filepath.Base(path))
	if m == nil {
		return "", fmt.Errorf("libtpms file %q does not carry an X.Y.Z release", path)
	}
	return m[1], nil
}

// FormatLibvirtVersion renders libvirt's packed version number
// (major*1000000 + minor*1000 + release) as X.Y.Z.
func FormatLibvirtVersion(v uint64) (string, error) {
	if v == 0 {
		return "", fmt.Errorf("libvirt reported version 0")
	}
	return fmt.Sprintf("%d.%d.%d", v/1000000, v/1000%1000, v%1000), nil
}

// OVMFContentFingerprint is the hex sha256 over dataDir and, for each of the
// four OVMF files in a fixed order, its role and the sha256 of its content
// (spec §3.2 item 9). It is the content counterpart of the layout fingerprint,
// which compares the paths: two hosts with the same paths but a different OVMF
// build differ here, and the same build at other paths does not. A file the
// host does not have (an empty path) counts as absent; a configured file that
// cannot be read is an error.
func OVMFContentFingerprint(fp FirmwarePaths, dataDir string) (string, error) {
	h := sha256.New()
	fmt.Fprintf(h, "dataDir\x00%s\x00", dataDir)
	for _, f := range []struct{ role, path string }{
		{"code", fp.Code}, {"vars", fp.Vars}, {"secboot_code", fp.SecbootCode}, {"ms_vars", fp.MsVars},
	} {
		sum := "-"
		if f.path != "" {
			s, err := sha256File(f.path)
			if err != nil {
				return "", fmt.Errorf("OVMF %s: %w", f.role, err)
			}
			sum = s
		}
		fmt.Fprintf(h, "%s\x00%s\x00", f.role, sum)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// sha256File is the hex sha256 of the file at p (followed through links: the
// OVMF paths are distro symlinks to the real images).
func sha256File(p string) (string, error) {
	fh, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer fh.Close()
	h := sha256.New()
	if _, err := io.Copy(h, fh); err != nil {
		return "", fmt.Errorf("hash %s: %w", p, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// LiveFirmwareFloors are the lowest releases a host may run a live firmware
// move with (spec §3.1, the lab 1 probe's versions). The OVMF fingerprint has
// no floor: it is compared for equality only.
var LiveFirmwareFloors = FirmwareRuntime{Libvirt: "10.0.0", QEMU: "8.2.2", Swtpm: "0.7.3", Libtpms: "0.9.3"}

// FirmwareFloorsMet is nil when every version of rt is at least its floor in
// LiveFirmwareFloors, compared numerically. Otherwise it names the first
// component below its floor, or not X.Y.Z: an unreadable version never meets
// a floor.
func FirmwareFloorsMet(rt FirmwareRuntime) error {
	for _, c := range []struct{ what, have, floor string }{
		{"libvirt", rt.Libvirt, LiveFirmwareFloors.Libvirt},
		{"qemu", rt.QEMU, LiveFirmwareFloors.QEMU},
		{"swtpm", rt.Swtpm, LiveFirmwareFloors.Swtpm},
		{"libtpms", rt.Libtpms, LiveFirmwareFloors.Libtpms},
	} {
		if _, ok := parseXYZ(c.have); !ok {
			return fmt.Errorf("%s %q is not an X.Y.Z release, so it cannot meet the live firmware migration floor %s", c.what, c.have, c.floor)
		}
		if !versionAtLeast(c.have, c.floor) {
			return fmt.Errorf("%s %s is below the live firmware migration floor %s", c.what, c.have, c.floor)
		}
	}
	return nil
}

// versionAtLeast compares two X.Y.Z releases numerically; anything that is not
// X.Y.Z is false.
func versionAtLeast(have, floor string) bool {
	h, ok1 := parseXYZ(have)
	f, ok2 := parseXYZ(floor)
	if !ok1 || !ok2 {
		return false
	}
	for i := range h {
		if h[i] != f[i] {
			return h[i] > f[i]
		}
	}
	return true
}

var xyzRe = regexp.MustCompile(`^(` + xyz + `)$`)

func parseXYZ(v string) ([3]int, bool) {
	var out [3]int
	if !xyzRe.MatchString(v) {
		return out, false
	}
	for i, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
