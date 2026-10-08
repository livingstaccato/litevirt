package lxc

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// secRunner is a runner whose LXC config files and ownership changes are
// observable without root: the seccomp policy and userns include are temp
// files, and every chown is recorded instead of made.
func secRunner(t *testing.T) (*LxcRunner, *[]chownCall) {
	t.Helper()
	tmp := t.TempDir()
	seccomp := filepath.Join(tmp, "common.seccomp")
	userns := filepath.Join(tmp, "userns.conf")
	for _, f := range []string{seccomp, userns} {
		if err := os.WriteFile(f, []byte("#\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	restore := setLXCConfigPathsForTest(seccomp, userns)
	t.Cleanup(restore)
	// Root's subordinate ranges go to temp files, never /etc.
	oldU, oldG, oldW := subUIDPath, subGIDPath, subIDsWanted
	subUIDPath, subGIDPath = filepath.Join(tmp, "subuid"), filepath.Join(tmp, "subgid")
	subIDsWanted = func() bool { return true }
	subIDsMu.Lock()
	subIDsEnsured = map[int64]bool{}
	subIDsMu.Unlock()
	t.Cleanup(func() { subUIDPath, subGIDPath, subIDsWanted = oldU, oldG, oldW })
	calls := &[]chownCall{}
	restoreChown := setChownForTest(func(p string, uid, gid int) error {
		*calls = append(*calls, chownCall{p, uid, gid})
		return nil
	})
	t.Cleanup(restoreChown)
	return &LxcRunner{Lxcpath: filepath.Join(tmp, "lxc"), IDMappedRootfs: "off"}, calls
}

func readCfg(t *testing.T, r *LxcRunner, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.Lxcpath, name, "config"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mustContain(t *testing.T, cfg string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(cfg, w) {
			t.Errorf("config missing %q\n--- config ---\n%s", w, cfg)
		}
	}
}

func mustNotContain(t *testing.T, cfg string, bad ...string) {
	t.Helper()
	for _, b := range bad {
		if strings.Contains(cfg, b) {
			t.Errorf("config carries %q\n--- config ---\n%s", b, cfg)
		}
	}
}

// The default confinement: LXC's generated AppArmor profile without nesting,
// its common seccomp policy, and the standard capability drop list — written
// explicitly, not left to whatever a template or include supplies.
func TestCreate_DefaultConfinement(t *testing.T) {
	r, _ := secRunner(t)
	tpl := mkRootfs(t, filepath.Join(t.TempDir(), "tpl"))
	if _, err := r.Create(context.Background(), CreateOpts{Name: "c1", Template: tpl, Confinement: ConfinementDefault}); err != nil {
		t.Fatal(err)
	}
	cfg := readCfg(t, r, "c1")
	mustContain(t, cfg,
		"lxc.apparmor.profile = generated\n",
		"lxc.apparmor.allow_nesting = 0\n",
		"lxc.seccomp.profile = "+lxcCommonSeccomp+"\n",
		"lxc.cap.drop = mac_admin mac_override sys_time sys_module sys_rawio\n")
	mustNotContain(t, cfg, "allow_nesting = 1")
	sec, err := r.Security("c1")
	if err != nil || sec.Confinement != ConfinementDefault || sec.IDMap != nil {
		t.Fatalf("Security = %+v, %v", sec, err)
	}
}

// Legacy confinement is today's config, byte for byte the old rendering.
func TestCreate_LegacyConfinementIsToday(t *testing.T) {
	r, _ := secRunner(t)
	tpl := mkRootfs(t, filepath.Join(t.TempDir(), "tpl"))
	if _, err := r.Create(context.Background(), CreateOpts{Name: "c1", Template: tpl}); err != nil {
		t.Fatal(err)
	}
	cfg := readCfg(t, r, "c1")
	mustContain(t, cfg, "lxc.apparmor.profile = generated\n", "lxc.apparmor.allow_nesting = 1\n")
	mustNotContain(t, cfg, "lxc.cap.drop", "lxc.seccomp.profile", "lxc.idmap", "litevirt security")
	sec, _ := r.Security("c1")
	if sec.Confinement != ConfinementLegacy || sec.IDMap != nil {
		t.Fatalf("Security = %+v, want legacy privileged", sec)
	}
}

// An unprivileged container gets its own id range and a rootfs owned within
// it; the template it was copied from is untouched.
func TestCreate_UnprivilegedMapsAndShifts(t *testing.T) {
	r, calls := secRunner(t)
	tpl := mkRootfs(t, filepath.Join(t.TempDir(), "tpl"))
	const base = 1_000_000_000
	if _, err := r.Create(context.Background(), CreateOpts{
		Name: "c1", Template: tpl, Confinement: ConfinementDefault,
		IDMap: &IDMap{Base: base, Size: 65536},
	}); err != nil {
		t.Fatal(err)
	}
	cfg := readCfg(t, r, "c1")
	mustContain(t, cfg,
		"lxc.idmap = u 0 1000000000 65536\n",
		"lxc.idmap = g 0 1000000000 65536\n",
		"lxc.include = "+lxcUsernsConf+"\n")
	// userns.conf resets the drop list, so the include comes first.
	if strings.Index(cfg, "lxc.include = "+lxcUsernsConf) > strings.Index(cfg, "lxc.cap.drop") {
		t.Errorf("userns.conf included after the capability drop list:\n%s", cfg)
	}
	rootfs := filepath.Join(r.Lxcpath, "c1", "rootfs")
	uid, gid := os.Getuid(), os.Getgid()
	var shifted, outside int
	for _, c := range *calls {
		if !strings.HasPrefix(c.path, rootfs) {
			outside++
			continue
		}
		if c.uid != base+uid || c.gid != base+gid {
			t.Errorf("chown %s to %d:%d, want %d:%d", c.path, c.uid, c.gid, base+uid, base+gid)
		}
		shifted++
	}
	if shifted < 4 || outside != 0 {
		t.Fatalf("shifted %d entries in the rootfs, %d outside it: %+v", shifted, outside, *calls)
	}
	sec, _ := r.Security("c1")
	if sec.IDMap == nil || sec.IDMap.Base != base || sec.IDMap.Size != 65536 || sec.IDMappedMount {
		t.Fatalf("Security = %+v", sec)
	}
}

// With an idmapped rootfs mount the files stay as they are and LXC maps them.
func TestCreate_UnprivilegedIDMappedMount(t *testing.T) {
	r, calls := secRunner(t)
	r.IDMappedRootfs = "on"
	tpl := mkRootfs(t, filepath.Join(t.TempDir(), "tpl"))
	if _, err := r.Create(context.Background(), CreateOpts{
		Name: "c1", Template: tpl, Confinement: ConfinementDefault, IDMap: &IDMap{Base: 2_000_000_000, Size: 65536},
	}); err != nil {
		t.Fatal(err)
	}
	mustContain(t, readCfg(t, r, "c1"), "lxc.rootfs.options = idmap=container\n")
	if len(*calls) != 0 {
		t.Fatalf("an idmapped rootfs was chowned: %+v", *calls)
	}
	if sec, _ := r.Security("c1"); !sec.IDMappedMount {
		t.Fatalf("Security = %+v", sec)
	}
}

// The download template's own confinement lines give way to the default ones.
func TestFinalize_DefaultConfinementReplacesTemplateLines(t *testing.T) {
	r, _ := secRunner(t)
	dir := filepath.Join(r.Lxcpath, "dl")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	base := "lxc.include = /usr/share/lxc/config/ubuntu.common.conf\n" +
		"lxc.apparmor.profile = unconfined\nlxc.apparmor.allow_nesting = 1\n" +
		"lxc.seccomp.profile = /tmp/permissive\nlxc.rootfs.path = dir:" + filepath.Join(dir, "rootfs") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.finalizeContainerConfig(CreateOpts{Name: "dl", Confinement: ConfinementDefault}); err != nil {
		t.Fatal(err)
	}
	cfg := readCfg(t, r, "dl")
	mustNotContain(t, cfg, "unconfined", "allow_nesting = 1", "/tmp/permissive")
	mustContain(t, cfg, "lxc.include = /usr/share/lxc/config/ubuntu.common.conf\n", "lxc.apparmor.allow_nesting = 0\n")
}

// pids.max: written at create, and added at the next start to a container
// whose config has none (an existing container gets the default then, and
// only then). One that sets its own keeps it.
func TestPidsMax_CreateAndNextStart(t *testing.T) {
	r, _ := secRunner(t)
	tpl := mkRootfs(t, filepath.Join(t.TempDir(), "tpl"))
	if _, err := r.Create(context.Background(), CreateOpts{Name: "c1", Template: tpl, PidsMax: 2048}); err != nil {
		t.Fatal(err)
	}
	mustContain(t, readCfg(t, r, "c1"), "lxc.cgroup2.pids.max = 2048\n")

	if _, err := r.Create(context.Background(), CreateOpts{Name: "old", Template: tpl}); err != nil {
		t.Fatal(err)
	}
	mustNotContain(t, readCfg(t, r, "old"), "pids.max")
	r.DefaultPidsMax = 4096
	for _, n := range []string{"c1", "old"} {
		if err := r.prepareStart(n); err != nil {
			t.Fatalf("prepareStart %s: %v", n, err)
		}
	}
	mustContain(t, readCfg(t, r, "old"), "lxc.cgroup2.pids.max = 4096\n")
	if cfg := readCfg(t, r, "c1"); strings.Count(cfg, "pids.max") != 1 || !strings.Contains(cfg, "= 2048") {
		t.Errorf("a container's own pids.max was replaced:\n%s", cfg)
	}
	if err := r.prepareStart("old"); err != nil {
		t.Fatal(err)
	}
	if strings.Count(readCfg(t, r, "old"), "pids.max") != 1 {
		t.Error("a second start added the default again")
	}
}

// Root's subordinate ranges cover a new mapping (LXC insists on it when the
// host hands out ranges); an existing covering line is not duplicated.
func TestCreate_UnprivilegedAddsRootSubIDs(t *testing.T) {
	r, _ := secRunner(t)
	r.SubIDSpan = &IDMap{Base: 1_000_000_000, Size: 65536 * 10}
	if err := os.WriteFile(subGIDPath, []byte("root:1000000000:655360\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tpl := mkRootfs(t, filepath.Join(t.TempDir(), "tpl"))
	if _, err := r.Create(context.Background(), CreateOpts{Name: "c1", Template: tpl, IDMap: &IDMap{Base: 1_000_065_536, Size: 65536}}); err != nil {
		t.Fatal(err)
	}
	u, _ := os.ReadFile(subUIDPath)
	g, _ := os.ReadFile(subGIDPath)
	if string(u) != "root:1000000000:655360\n" {
		t.Errorf("subuid = %q", u)
	}
	if string(g) != "root:1000000000:655360\n" {
		t.Errorf("subgid was rewritten or duplicated: %q", g)
	}
}

// A container mapped by an idmapped mount, started on a host that cannot make
// one (it migrated from one that could), is shifted and started instead.
func TestPrepareStart_IDMappedFallsBackToShift(t *testing.T) {
	r, calls := secRunner(t)
	r.IDMappedRootfs = "on"
	tpl := mkRootfs(t, filepath.Join(t.TempDir(), "tpl"))
	if _, err := r.Create(context.Background(), CreateOpts{Name: "c1", Template: tpl, Confinement: ConfinementDefault, IDMap: &IDMap{Base: 1_000_000_000, Size: 65536}}); err != nil {
		t.Fatal(err)
	}
	r2 := &LxcRunner{Lxcpath: r.Lxcpath, IDMappedRootfs: "off"}
	if err := r2.prepareStart("c1"); err != nil {
		t.Fatal(err)
	}
	cfg := readCfg(t, r2, "c1")
	mustNotContain(t, cfg, "idmap=container")
	mustContain(t, cfg, "lxc.idmap = u 0 1000000000 65536\n", "lxc.apparmor.allow_nesting = 0\n")
	if len(*calls) == 0 {
		t.Fatal("the rootfs was not shifted")
	}
}

// A new container gets the configured default at create, without waiting for
// a start.
func TestPidsMax_DefaultAtCreate(t *testing.T) {
	r, _ := secRunner(t)
	r.DefaultPidsMax = 4096
	tpl := mkRootfs(t, filepath.Join(t.TempDir(), "tpl"))
	if _, err := r.Create(context.Background(), CreateOpts{Name: "c1", Template: tpl}); err != nil {
		t.Fatal(err)
	}
	mustContain(t, readCfg(t, r, "c1"), "lxc.cgroup2.pids.max = 4096\n")
}
