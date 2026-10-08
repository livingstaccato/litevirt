package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Container hardening against REAL LXC (node-3/node-4 run LXC 5.0.3).
//
// Every assertion reads the kernel or the filesystem directly — /proc, the
// cgroup tree, the container's config and rootfs — never litevirt's report of
// its own work, so a feature that only wrote a database row cannot pass.
//
// Run on an LXC node with LITEVIRT_E2E=1 and LV_BIN set (tests/e2e/README.md).

// hardenedCT creates and starts a container with extra create flags and
// registers a forced delete for cleanup.
func hardenedCT(t *testing.T, flags ...string) string {
	t.Helper()
	requireLXC(t)
	name := uniqueName("cth")
	cleanup(t, func() { lvErr(t, "ct", "rm", name, "--host", localHost, "--force") })
	args := append([]string{"ct", "create", name, "--host", localHost}, flags...)
	if out, err := lvErr(t, args...); err != nil {
		t.Skipf("cannot create a container on %s (lxc image server reachable?): %v\n%s", localHost, err, out)
	}
	return name
}

func startCT(t *testing.T, name string) {
	t.Helper()
	if out, err := lvErr(t, "ct", "start", name, "--host", localHost); err != nil {
		t.Fatalf("start %s: %v\n%s", name, err, out)
	}
	waitCT(t, name, "running", 90*time.Second)
}

func stopCT(t *testing.T, name string) {
	t.Helper()
	if out, err := lvErr(t, "ct", "stop", name, "--host", localHost); err != nil {
		t.Fatalf("stop %s: %v\n%s", name, err, out)
	}
	waitCT(t, name, "stopped", 90*time.Second)
}

// initPID is the container's init as the host sees it.
func initPID(t *testing.T, name string) int {
	t.Helper()
	out, err := exec.Command("lxc-info", "-n", name, "-p", "-H").Output()
	if err != nil {
		t.Fatalf("lxc-info -p %s: %v", name, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || pid <= 0 {
		t.Fatalf("lxc-info -p %s = %q", name, out)
	}
	return pid
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}

// uidMapOf returns the outside id root (0) maps to, or -1 when the container
// runs in the host's namespace (privileged).
func uidMapOf(t *testing.T, pid int) int64 {
	t.Helper()
	for _, line := range strings.Split(readFile(t, "/proc/"+strconv.Itoa(pid)+"/uid_map"), "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == "0" {
			if f[1] == "0" && f[2] == "4294967295" {
				return -1
			}
			n, _ := strconv.ParseInt(f[1], 10, 64)
			return n
		}
	}
	return -1
}

// Item 4 (proposal 1): a new container is unprivileged in a range of its own;
// root inside is an unprivileged id on the host; the rootfs is owned in the
// range (or mapped by an idmapped mount); lv ct inspect reports it.
func TestContainerHardening_UnprivilegedByDefault(t *testing.T) {
	name := hardenedCT(t)
	startCT(t, name)
	base := uidMapOf(t, initPID(t, name))
	if base < 65536 {
		t.Fatalf("container %s runs with uid map base %d: not unprivileged", name, base)
	}
	if out := lv(t, "ct", "exec", name, "--host", localHost, "--", "id", "-u"); strings.TrimSpace(out) != "0" {
		t.Errorf("id -u inside = %q, want 0", out)
	}
	cfg := readFile(t, filepath.Join(ctDir(name), "config"))
	if !strings.Contains(cfg, "lxc.idmap = u 0 "+strconv.FormatInt(base, 10)+" 65536") {
		t.Errorf("config does not carry the running map:\n%s", cfg)
	}
	if !strings.Contains(cfg, "idmap=container") {
		fi, err := os.Lstat(filepath.Join(ctDir(name), "rootfs", "etc", "passwd"))
		st, ok := fi.Sys().(*syscall.Stat_t)
		if err != nil || !ok || int64(st.Uid) != base {
			t.Errorf("rootfs /etc/passwd stat %+v (%v), want owner %d: the rootfs was not shifted", st, err, base)
		}
	}
	if out := lv(t, "ct", "inspect", name, "--host", localHost); !strings.Contains(out, "Privileged:") || !strings.Contains(out, "no (ids "+strconv.FormatInt(base, 10)) {
		t.Errorf("inspect does not report the range:\n%s", out)
	}
}

// Item 3 (proposal 2): the default confinement is in force in the kernel: an
// AppArmor profile (not unconfined), seccomp filtering, and the dropped
// capabilities absent from the bounding set.
func TestContainerHardening_DefaultConfinement(t *testing.T) {
	name := hardenedCT(t)
	startCT(t, name)
	pid := strconv.Itoa(initPID(t, name))
	if prof := strings.TrimSpace(readFile(t, "/proc/"+pid+"/attr/current")); prof == "unconfined" || prof == "" {
		t.Errorf("container init AppArmor label = %q, want an LXC profile", prof)
	}
	status := readFile(t, "/proc/"+pid+"/status")
	if !strings.Contains(status, "Seccomp:\t2") {
		t.Errorf("container init is not seccomp-filtered:\n%s", status)
	}
	// CAP_SYS_MODULE is bit 16, CAP_SYS_TIME 25, CAP_SYS_RAWIO 17.
	for _, line := range strings.Split(status, "\n") {
		if v, ok := strings.CutPrefix(line, "CapBnd:\t"); ok {
			bnd, _ := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			for _, bit := range []uint{16, 17, 25} {
				if bnd&(1<<bit) != 0 {
					t.Errorf("capability bit %d is in the bounding set %x", bit, bnd)
				}
			}
		}
	}
	cfg := readFile(t, filepath.Join(ctDir(name), "config"))
	if !strings.Contains(cfg, "lxc.apparmor.allow_nesting = 0") {
		t.Errorf("config allows nesting:\n%s", cfg)
	}
}

// The Admin's opt-outs keep today's behaviour, and lv doctor reports them.
func TestContainerHardening_PrivilegedLegacyOptOut(t *testing.T) {
	name := hardenedCT(t, "--privileged", "--confinement", "legacy")
	startCT(t, name)
	if base := uidMapOf(t, initPID(t, name)); base != -1 {
		t.Fatalf("a --privileged container runs mapped at %d", base)
	}
	if out := lv(t, "doctor", "privileged-containers"); !strings.Contains(out, name) {
		t.Errorf("doctor privileged-containers does not list %s:\n%s", name, out)
	}
}

// lv ct convert --unprivileged moves a stopped privileged container over with
// its data, and an existing container's other settings are untouched until
// then.
func TestContainerHardening_ConvertKeepsData(t *testing.T) {
	name := hardenedCT(t, "--privileged", "--confinement", "legacy")
	marker := filepath.Join(ctDir(name), "rootfs", "root", "e2e-convert-marker")
	if err := os.WriteFile(marker, []byte("kept-"+name), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := lvErr(t, "ct", "convert", name, "--host", localHost, "--unprivileged", "--confinement", "default"); err != nil {
		t.Fatalf("convert: %v\n%s", err, out)
	}
	startCT(t, name)
	if base := uidMapOf(t, initPID(t, name)); base < 65536 {
		t.Fatalf("converted container runs with map base %d", base)
	}
	if out := lv(t, "ct", "exec", name, "--host", localHost, "--", "cat", "/root/e2e-convert-marker"); !strings.Contains(out, "kept-"+name) {
		t.Errorf("root-only file unreadable by the converted container's root: %q", out)
	}
	// Converting a running container is refused.
	if _, err := lvErr(t, "ct", "convert", name, "--host", localHost, "--unprivileged"); err == nil {
		t.Error("convert of a running container succeeded")
	}
}

// Item 5: pids.max is in force in the container's cgroup; an existing
// container whose config sets none gets the default at its next start.
func TestContainerHardening_PidsMax(t *testing.T) {
	name := hardenedCT(t)
	cfgPath := filepath.Join(ctDir(name), "config")
	// Model a container from an earlier build: no pids.max in its config.
	cfg := readFile(t, cfgPath)
	var kept []string
	for _, l := range strings.Split(cfg, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "lxc.cgroup2.pids.max") {
			kept = append(kept, l)
		}
	}
	if err := os.WriteFile(cfgPath, []byte(strings.Join(kept, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	startCT(t, name)
	if !strings.Contains(readFile(t, cfgPath), "lxc.cgroup2.pids.max = ") {
		t.Fatal("the start did not give the container the default pids.max")
	}
	cg := readFile(t, "/proc/"+strconv.Itoa(initPID(t, name))+"/cgroup")
	rel := ""
	for _, l := range strings.Split(cg, "\n") {
		if r, ok := strings.CutPrefix(l, "0::"); ok {
			rel = r
		}
	}
	// The init's cgroup may be a leaf below the container's limit; walk up.
	for dir := filepath.Join("/sys/fs/cgroup", rel); dir != "/sys/fs/cgroup"; dir = filepath.Dir(dir) {
		if b, err := os.ReadFile(filepath.Join(dir, "pids.max")); err == nil && strings.TrimSpace(string(b)) != "max" {
			return
		}
	}
	t.Errorf("no finite pids.max above the container's cgroup %s", rel)
}

// Item 1 (proposal 3): a protected host path is refused as a template, for
// the Admin too.
func TestContainerHardening_ProtectedTemplateRefused(t *testing.T) {
	requireLXC(t)
	name := uniqueName("cth")
	cleanup(t, func() { lvErr(t, "ct", "rm", name, "--host", localHost, "--force") })
	out, err := lvErr(t, "ct", "create", name, "--host", localHost, "--template", "/etc")
	if err == nil || !strings.Contains(out, "host secrets") {
		t.Fatalf("create from /etc: err=%v\n%s", err, out)
	}
	if ctExists(name) {
		t.Fatalf("%s exists after a refused create", ctDir(name))
	}
}

// Item 2 (proposal 4) and the lab fixes: the owner record is on disk; a
// snapshot is 0600 with its owner record beside it; deleting the last one
// leaves no directory; a running container is not deleted without --force.
func TestContainerHardening_OwnerSnapshotAndDelete(t *testing.T) {
	name := hardenedCT(t, "--project", "_default")
	var owner struct {
		Project string `json:"project"`
		OwnerID string `json:"owner_id"`
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(ctDir(name), "litevirt-owner"))), &owner); err != nil || owner.OwnerID == "" {
		t.Fatalf("owner record: %+v %v", owner, err)
	}
	lv(t, "ct", "snapshot", "create", name, "s1", "--host", localHost)
	snapDir := filepath.Join("/var/lib/litevirt/ct-snapshots", name)
	for p, want := range map[string]os.FileMode{filepath.Join(snapDir, "s1.tar"): 0o600, filepath.Join(snapDir, "s1.tar.owner"): 0o600, snapDir: 0o700} {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s: %v mode %v, want %o", p, err, fi.Mode().Perm(), want)
		}
	}
	lv(t, "ct", "snapshot", "rm", name, "s1", "--host", localHost)
	if _, err := os.Stat(snapDir); !os.IsNotExist(err) {
		t.Errorf("%s left after the last snapshot was deleted: %v", snapDir, err)
	}
	startCT(t, name)
	if out, err := lvErr(t, "ct", "rm", name, "--host", localHost); err == nil || !strings.Contains(out, "lv ct stop") {
		t.Fatalf("rm of a running container: err=%v\n%s", err, out)
	}
	if !ctExists(name) {
		t.Fatal("the running container was deleted")
	}
	if out, err := lvErr(t, "ct", "rm", name, "--host", localHost, "--force"); err != nil {
		t.Fatalf("rm --force: %v\n%s", err, out)
	}
	if ctExists(name) {
		t.Fatal("rm --force left the container")
	}
}
