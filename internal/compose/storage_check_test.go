package compose

import "testing"

// A disk's storage: must name a volume the file declares or a storage pool
// that exists. Every one that names neither is reported where it is written,
// with the declared volume or pool it most likely meant.
func TestCheckStorage_UndeclaredNamesAreProblems(t *testing.T) {
	src := `name: s
volumes:
  warm: { driver: nfs, source: "nas:/x" }
vms:
  web:
    image: u
    disks:
      root: { size: 20G, storage: hot }
      data: { size: 20G, storage: wram }
      logs: { size: 1G, storage: nowhere }
      tmp: 5G
      scratch: { size: 1G }
      shared: { size: 1G, storage: warm }
workloads:
  batch:
    image: u
    disks:
      out: { size: 1G, storage: cld }
  ct:
    kind: lxc
    image: alpine
    disks:
      rootfs: { size: 1G, storage: zzz-container-only }
`
	f, err := ParseBytes([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	ps := CheckStorage([]byte(src), f, []string{"hot", "cold"})
	for _, w := range []struct {
		path, msg, hint string
		line, col       int
	}{
		{"vms.web.disks.data.storage", `storage "wram" is neither a volume of this file nor a storage pool`, `did you mean "warm"?`, 9, 35},
		{"vms.web.disks.logs.storage", `storage "nowhere" is neither a volume of this file nor a storage pool`,
			"declare it under volumes:, or create the pool with `lv pool create nowhere`", 10, 34},
		{"workloads.batch.disks.out.storage", `storage "cld" is neither a volume of this file nor a storage pool`, `did you mean "cold"?`, 18, 33},
	} {
		p, ok := findProblem(ps, w.path, w.msg)
		if !ok {
			t.Errorf("no problem %q at %s; got:\n%s", w.msg, w.path, dumpProblems(ps))
			continue
		}
		if p.Hint != w.hint || p.Line != w.line || p.Column != w.col {
			t.Errorf("%s: %d:%d hint %q, want %d:%d hint %q", w.path, p.Line, p.Column, p.Hint, w.line, w.col, w.hint)
		}
	}
	if len(ps) != 3 {
		t.Errorf("want exactly 3 problems (hot is a pool, warm a volume, tmp and scratch use the default, and a container disk does not resolve through volumes or pools); got:\n%s", dumpProblems(ps))
	}
}
