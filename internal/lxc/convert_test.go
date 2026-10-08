package lxc

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mkLegacyCT makes a stopped, privileged container the way an earlier build
// did: today's config, files owned by the host's ids.
func mkLegacyCT(t *testing.T, r *LxcRunner, name string) {
	t.Helper()
	tpl := mkRootfs(t, filepath.Join(t.TempDir(), "tpl-"+name))
	if err := os.WriteFile(filepath.Join(tpl, "etc", "passwd"), []byte("root:x:0:0::/root:/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Create(context.Background(), CreateOpts{Name: name, Template: tpl}); err != nil {
		t.Fatal(err)
	}
}

// lv ct convert --unprivileged moves an existing privileged container over:
// its files are shifted into the new range, its config gains the map and the
// default confinement, and its data is all still there.
func TestConvert_PrivilegedToUnprivileged(t *testing.T) {
	r, calls := secRunner(t)
	mkLegacyCT(t, r, "old")
	const base = 1_000_065_536
	if err := r.Convert(context.Background(), "old", ConvertOpts{IDMap: &IDMap{Base: base, Size: 65536}, Confinement: ConfinementDefault}); err != nil {
		t.Fatalf("Convert: %v", err)
	}
	cfg := readCfg(t, r, "old")
	mustContain(t, cfg, "lxc.idmap = u 0 1000065536 65536\n", "lxc.apparmor.allow_nesting = 0\n")
	mustNotContain(t, cfg, "allow_nesting = 1")
	if b, err := os.ReadFile(filepath.Join(r.Lxcpath, "old", "rootfs", "etc", "passwd")); err != nil || !strings.HasPrefix(string(b), "root:x:0:0") {
		t.Fatalf("data after convert: %q %v", b, err)
	}
	if len(*calls) == 0 || (*calls)[0].uid != base+os.Getuid() {
		t.Fatalf("rootfs not shifted into the new range: %+v", *calls)
	}
	if _, err := os.Stat(filepath.Join(r.Lxcpath, "old", convertMarkerFile)); !os.IsNotExist(err) {
		t.Fatalf("the conversion marker was left behind: %v", err)
	}
	sec, _ := r.Security("old")
	if sec.IDMap == nil || sec.IDMap.Base != base || sec.Confinement != ConfinementDefault {
		t.Fatalf("Security = %+v", sec)
	}
}

// Confinement alone can change, both ways, without touching ownership.
func TestConvert_ConfinementOnly(t *testing.T) {
	r, calls := secRunner(t)
	mkLegacyCT(t, r, "c")
	if err := r.Convert(context.Background(), "c", ConvertOpts{Confinement: ConfinementDefault}); err != nil {
		t.Fatal(err)
	}
	mustContain(t, readCfg(t, r, "c"), "lxc.apparmor.allow_nesting = 0\n", "lxc.cap.drop")
	if err := r.Convert(context.Background(), "c", ConvertOpts{Confinement: ConfinementLegacy}); err != nil {
		t.Fatal(err)
	}
	cfg := readCfg(t, r, "c")
	mustContain(t, cfg, "lxc.apparmor.allow_nesting = 1\n")
	mustNotContain(t, cfg, "lxc.cap.drop", "allow_nesting = 0")
	if len(*calls) != 0 {
		t.Fatalf("a confinement change chowned files: %+v", *calls)
	}
}

// A conversion cut short leaves a marker; start refuses the half-converted
// container instead of booting it with half its files in each range, and a
// second convert finishes the job.
func TestConvert_InterruptedIsRefusedAtStartAndResumable(t *testing.T) {
	r, calls := secRunner(t)
	mkLegacyCT(t, r, "c")
	failAfter := 2
	restore := setChownForTest(func(p string, uid, gid int) error {
		if failAfter == 0 {
			return os.ErrPermission
		}
		failAfter--
		*calls = append(*calls, chownCall{p, uid, gid})
		return nil
	})
	err := r.Convert(context.Background(), "c", ConvertOpts{IDMap: &IDMap{Base: 1_000_000_000, Size: 65536}})
	restore()
	if err == nil {
		t.Fatal("convert with a failing chown succeeded")
	}
	if err := r.prepareStart("c"); err == nil || !strings.Contains(err.Error(), "lv ct convert") {
		t.Fatalf("start of a half-converted container: %v", err)
	}
	if err := r.Convert(context.Background(), "c", ConvertOpts{IDMap: &IDMap{Base: 1_000_000_000, Size: 65536}}); err != nil {
		t.Fatalf("resumed convert: %v", err)
	}
	if err := r.prepareStart("c"); err != nil {
		t.Fatalf("start after the resumed convert: %v", err)
	}
}

// Remapping an unprivileged container into another range moves ids from the
// old range to the new one (a clone's fresh range, a collision's fix).
func TestConvert_RemapBetweenRanges(t *testing.T) {
	r, _ := secRunner(t)
	mkLegacyCT(t, r, "c")
	if err := r.Convert(context.Background(), "c", ConvertOpts{IDMap: &IDMap{Base: 1_000_000_000, Size: 65536}}); err != nil {
		t.Fatal(err)
	}
	// Model the first shift having happened on disk.
	from, to := int64(1_000_000_000), int64(1_000_131_072)
	if got := shiftID(int64(from+5), &IDMap{Base: from, Size: 65536}, &IDMap{Base: to, Size: 65536}); got != to+5 {
		t.Fatalf("shiftID = %d", got)
	}
	if got := shiftID(5, nil, &IDMap{Base: to, Size: 65536}); got != to+5 {
		t.Fatalf("shiftID from host = %d", got)
	}
	if got := shiftID(to+5, nil, &IDMap{Base: to, Size: 65536}); got != to+5 {
		t.Fatalf("an id already in the target range moved: %d", got)
	}
	if got := shiftID(70000, nil, &IDMap{Base: to, Size: 65536}); got != -1 {
		t.Fatalf("an id outside the source range was mapped: %d", got)
	}
	if err := r.Convert(context.Background(), "c", ConvertOpts{IDMap: &IDMap{Base: to, Size: 65536}}); err != nil {
		t.Fatal(err)
	}
	if sec, _ := r.Security("c"); sec.IDMap == nil || sec.IDMap.Base != to {
		t.Fatalf("Security = %+v", sec)
	}
}

// File capabilities move with the files: a v2 capability (host root) becomes
// a v3 one rooted at the container's root, a v3 one is re-rooted.
func TestShiftCapability(t *testing.T) {
	v2 := make([]byte, 20)
	binary.LittleEndian.PutUint32(v2, 0x02000000|1)
	v2[4] = 0xff
	out, ok := shiftCapability(v2, nil, &IDMap{Base: 1_000_000_000, Size: 65536})
	if !ok || len(out) != 24 || binary.LittleEndian.Uint32(out)&0xff000000 != 0x03000000 ||
		binary.LittleEndian.Uint32(out[20:]) != 1_000_000_000 || out[4] != 0xff {
		t.Fatalf("v2 → %x ok=%v", out, ok)
	}
	again, ok := shiftCapability(out, &IDMap{Base: 1_000_000_000, Size: 65536}, &IDMap{Base: 1_000_065_536, Size: 65536})
	if !ok || binary.LittleEndian.Uint32(again[20:]) != 1_000_065_536 {
		t.Fatalf("v3 re-root → %x ok=%v", again, ok)
	}
	if _, ok := shiftCapability([]byte{1, 2}, nil, &IDMap{Base: 1, Size: 1}); ok {
		t.Fatal("garbage capability accepted")
	}
}

// POSIX ACL entries naming a user or group move with the files; the owner,
// mask and other entries carry no id.
func TestShiftACL(t *testing.T) {
	acl := []byte{2, 0, 0, 0}
	add := func(tag, perm uint16, id uint32) {
		e := make([]byte, 8)
		binary.LittleEndian.PutUint16(e, tag)
		binary.LittleEndian.PutUint16(e[2:], perm)
		binary.LittleEndian.PutUint32(e[4:], id)
		acl = append(acl, e...)
	}
	add(0x01, 7, 0xffffffff) // USER_OBJ
	add(0x02, 5, 33)         // USER www-data
	add(0x08, 5, 4)          // GROUP adm
	add(0x20, 0, 0xffffffff) // OTHER
	out, ok := shiftACL(acl, nil, &IDMap{Base: 1_000_000_000, Size: 65536})
	if !ok {
		t.Fatal("not shifted")
	}
	id := func(i int) uint32 { return binary.LittleEndian.Uint32(out[4+8*i+4:]) }
	if id(0) != 0xffffffff || id(1) != 1_000_000_033 || id(2) != 1_000_000_004 || id(3) != 0xffffffff {
		t.Fatalf("ACL ids = %d %d %d %d", id(0), id(1), id(2), id(3))
	}
}
