//go:build unix

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Host init makes the data directories the daemon keeps VM disks, images and
// cloud-init seeds in. A NEW one is 0711 — qemu (its own user once libvirt has
// labelled the file) resolves paths through it, nobody else can list it — and
// one that already exists is left as it is (no backfill). The script's own
// line is run, rooted in a temp dir.
//
// Mutation: the plain `mkdir -p` again — the new directories go red.
func TestSetupScript_DiskDirsAreSearchableOnly(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not installed")
	}
	script, err := getSetupScript()
	if err != nil {
		t.Fatal(err)
	}
	var line string
	for _, l := range strings.Split(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "mkdir") && strings.Contains(l, "/var/lib/litevirt/{images,disks,cloudinit}") {
			line = l
		}
	}
	if line == "" {
		t.Fatal("the setup script makes no /var/lib/litevirt/{images,disks,cloudinit}")
	}
	root := t.TempDir()
	run := func() {
		t.Helper()
		cmd := exec.Command("bash", "-c", "umask 022; "+strings.ReplaceAll(line, "/var/lib/litevirt", root+"/var/lib/litevirt"))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", line, err, out)
		}
	}
	run()
	for _, d := range []string{"images", "disks", "cloudinit"} {
		p := filepath.Join(root, "var/lib/litevirt", d)
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o711 {
			t.Errorf("%s: %v %v, want 0711", d, fi.Mode().Perm(), err)
		}
	}
	// A re-init over an existing install changes no mode.
	disks := filepath.Join(root, "var/lib/litevirt", "disks")
	if err := os.Chmod(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	run()
	if fi, _ := os.Stat(disks); fi.Mode().Perm() != 0o755 {
		t.Errorf("a re-init changed an existing disks dir to %04o", fi.Mode().Perm())
	}
}
