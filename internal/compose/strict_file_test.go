package compose

import "testing"

// Unknown fields are refused across the whole file, not only in healthcheck
// blocks: top level, workloads, networks, disks in full form, depends-on in
// map form — each with the field it most likely meant.
func TestStrict_UnknownFieldsAcrossTheFile(t *testing.T) {
	src := `name: s
vm:
  x: {}
networks:
  lan:
    type: bridge
    subnt: 10.0.0.0/24
vms:
  web:
    image: u
    cpus: 2
    disks:
      root: 20G
      data:
        sise: 10G
    placement:
      anti-afinity: [db]
    depends-on:
      db:
        conditon: vm_started
    network:
      - name: lan
        modl: virtio
  db:
    image: u
workloads:
  c:
    kind: lxc
    image: alpine
    labls: {a: b}
`
	ps := problemsOf(t, src)
	for _, w := range []struct{ path, key, hint string }{
		{"", "vm", `did you mean "vms"?`},
		{"networks.lan", "subnt", `did you mean "subnet"?`},
		{"vms.web", "cpus", `did you mean "cpu"?`},
		{"vms.web.disks.data", "sise", `did you mean "size"?`},
		{"vms.web.placement", "anti-afinity", `did you mean "anti-affinity"?`},
		{"vms.web.depends-on.db", "conditon", `did you mean "condition"?`},
		{"workloads.c", "labls", `did you mean "labels"?`},
		{"vms.web.network[0]", "modl", `did you mean "model"?`},
	} {
		p, ok := findProblem(ps, w.path, `unknown field "`+w.key+`"`)
		if !ok {
			t.Errorf("no unknown-field problem for %q at %q; got:\n%s", w.key, w.path, dumpProblems(ps))
			continue
		}
		if p.Hint != w.hint {
			t.Errorf("%s: hint %q, want %q", w.key, p.Hint, w.hint)
		}
	}
}

// What is legitimate without being a field passes everywhere: x-* extension
// keys (at the top, holding an anchor, and inside blocks), merge keys, and the
// shorthand forms (disk "20G", memory "4G", depends-on as a list).
func TestStrict_LegitimateNonFieldsPass(t *testing.T) {
	src := `name: s
x-base: &base
  image: u
  cpu: 2
  memory: 4G
vms:
  db:
    <<: *base
    x-owner: team-data
    disks:
      root: 20G
  web:
    <<: *base
    depends-on: [db]
    network:
      - name: lan
        x-note: primary
networks:
  lan:
    type: bridge
    interface: br0
`
	if _, err := ParseBytes([]byte(src)); err != nil {
		t.Errorf("legitimate file refused: %v", err)
	}
}

// ParseStored reads a stored stack without validating it: only what is needed
// to read it (decoding, the workloads fold, extends) can fail. A stack the
// current validator refuses — a check added after it was deployed — reads.
func TestParseStored_ReadsWhatTheValidatorRefuses(t *testing.T) {
	src := `volumes:
  shared: { driver: nfs, source: "nas:/export" }
vms:
  base:
    image: u
  db:
    extends: base
    healthcheck: { type: tcp, target: postgres }
    depends-on: [ghost]
  web:
    cpu: 1
  lb:
    image: u
    loadbalancer: { vip: 10.0.0.5/24, ports: [{ listen: 80, target: 80 }] }
`
	if _, err := ParseBytes([]byte(src)); err == nil {
		t.Fatal("the validator accepted the file; the test needs one it refuses")
	}
	f, err := ParseStored([]byte(src))
	if err != nil {
		t.Fatalf("ParseStored refused a stack over validation: %v", err)
	}
	if f.Volumes["shared"].Driver != "nfs" || f.VMs["db"].Image != "u" {
		t.Errorf("ParseStored read volumes=%+v db=%+v, want the nfs volume and db extending base", f.Volumes, f.VMs["db"])
	}
	if !f.VMs["lb"].LoadBalancer.Enabled {
		t.Error("ParseStored did not read a VIP as an enabled load balancer, as ParseBytes does")
	}
	for _, bad := range []string{"vms: [a, b]\n", "vms:\n  a: {extends: nope}\n"} {
		if _, err := ParseStored([]byte(bad)); err == nil {
			t.Errorf("ParseStored read a stack it cannot read:\n%s", bad)
		}
	}
}

// Stored stacks stay readable whatever a later build refuses.
func TestParseStored_AcceptsUnknownFieldsAnywhere(t *testing.T) {
	src := "name: s\nvm: {}\nvms:\n  web:\n    image: u\n    cpus: 2\n"
	if _, err := ParseBytes([]byte(src)); err == nil {
		t.Fatal("ParseBytes accepted unknown fields")
	}
	if _, err := ParseStored([]byte(src)); err != nil {
		t.Errorf("ParseStored refused a stored stack: %v", err)
	}
}
