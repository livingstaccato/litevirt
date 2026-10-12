// Package pitprobe builds the node-side commands of the point-in-time copy
// e2e (tests/e2e/pit_replica_test.go), so each can be tested without a lab.
// Every one of them was wrong once, silently, on a real node (lab 2 run c2).
package pitprobe

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// DirPoolCreateArgs is the lv argv that creates dir pool pool at dir on
// host. A dir pool takes its directory as --target; a --source is refused
// (storage.ValidateSource).
func DirPoolCreateArgs(pool, dir, host string) []string {
	return []string{"pool", "create", pool, "--driver", "dir", "--target", dir, "--host", host}
}

// DumpXMLCmd prints the domain's live XML, which DiskAlias parses. virsh's
// --xpath is not used: libvirt 10 accepts node sets only, refusing
// string(), and prints an attribute node as name="…".
func DumpXMLCmd(vmQuoted string) string { return "virsh dumpxml " + vmQuoted }

// DiskAlias returns the device alias of the disk whose source file is file,
// from a domain's live XML.
func DiskAlias(domXML, file string) (string, error) {
	var d struct {
		Disks []struct {
			Source struct {
				File string `xml:"file,attr"`
			} `xml:"source"`
			Alias struct {
				Name string `xml:"name,attr"`
			} `xml:"alias"`
		} `xml:"devices>disk"`
	}
	if err := xml.Unmarshal([]byte(domXML), &d); err != nil {
		return "", fmt.Errorf("parse domain xml: %w", err)
	}
	for _, disk := range d.Disks {
		if disk.Source.File == file {
			if disk.Alias.Name == "" {
				return "", fmt.Errorf("disk %s has no alias (is the domain running?)", file)
			}
			return disk.Alias.Name, nil
		}
	}
	return "", fmt.Errorf("no disk with source %s", file)
}

// QemuIODevice is what HMP qemu-io -d takes for the virtio-blk disk with
// alias: its qdev path. A disk libvirt attaches with -blockdev has no named
// block backend, so the alias alone is refused ("Device does not have a
// block device backend").
func QemuIODevice(alias string) string {
	return "/machine/peripheral/" + alias + "/virtio-backend"
}

// DomainLogDir is where libvirt keeps the domain logs on a node.
var DomainLogDir = "/var/log/libvirt/qemu"

// HMPQemuIO is the sh command running qemu-io cmd on dev of the domain
// vmQuoted (shell-quoted) and printing its result. The HMP argument is
// double-quoted for the shell, so a shell variable in cmd ($v) expands.
//
// On qemu 8.2 / libvirt 10 the HMP reply to qemu-io is empty (virsh exits 0,
// success or not) and qemu-io's output goes to the domain log. So the command
// prints the HMP reply when there is one, and otherwise only the log bytes
// appended after it was sent (the log's size is taken first).
func HMPQemuIO(vmQuoted, dev, cmd string) string {
	return fmt.Sprintf(`V=%s; L=%s/$V.log; n=$(stat -c %%s "$L" 2>/dev/null || echo 0); `+
		`r=$(virsh qemu-monitor-command "$V" --hmp "qemu-io -d %s \"%s\""); `+
		`if [ -n "$r" ]; then printf '%%s\n' "$r"; else `+
		`for i in 1 2 3 4 5 6 7 8 9 10; do sleep 0.05; o=$(tail -c +$((n+1)) "$L" 2>/dev/null); [ -n "$o" ] && break; done; `+
		`printf '%%s\n' "$o"; fi`,
		vmQuoted, DomainLogDir, dev, cmd)
}

// Wrote reports whether HMPQemuIO's output is a completed write. virsh exits
// 0 whether or not qemu-io wrote, so the output, not the exit status, says
// whether anything was written.
func Wrote(out string) bool { return strings.Contains(out, "wrote ") }

// WriterScript is the writer loop: round v writes the byte v over the slot
// at low, then over the slot at high, and stops (exit 1, printing qemu-io's
// reply) at the first write that does not complete.
func WriterScript(vmQuoted, dev string, rounds int, low, high, slot int64, pause string) string {
	write := func(off int64) string {
		return fmt.Sprintf(`o=$(%s) && case "$o" in *"wrote "*) ;; *) echo "$o"; exit 1;; esac`,
			HMPQemuIO(vmQuoted, dev, fmt.Sprintf("write -P $v %d %d", off, slot)))
	}
	return fmt.Sprintf("for v in $(seq 1 %d); do %s || exit 1; %s || exit 1; sleep %s; done",
		rounds, write(low), write(high), pause)
}

// WindowTokenCmd prints the point-in-time window token on the disk file
// pathQuoted, and nothing else: --absolute-names keeps getfattr's "Removing
// leading '/'" notice out of the output.
func WindowTokenCmd(pathQuoted string) string {
	return "getfattr --absolute-names --only-values -n user.litevirt.pit_window " + pathQuoted
}
