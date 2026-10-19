package compose

import (
	"testing"
)

// docs/compose.md names `secure-boot` and `tpm` as VM fields (a toggle is a
// restart-class update). The file takes them, and the spec carries them to
// CreateVM and to the update classifier, as `lv run --secure-boot --tpm`
// does.
//
// Mutations: drop either yaml field — "unknown field"; drop either from
// BuildVMSpec — the spec loses it; drop either from the extends merge — the
// child's value is lost.
func TestComposeFirmwareFields_SecureBootAndTPMReachTheSpec(t *testing.T) {
	f, err := ParseBytes([]byte(`name: fw
vms:
  base:
    image: ubuntu
    firmware: uefi
    machine: q35
    secure-boot: true
    tpm: true
    disks: {root: 8G}
  plain:
    image: ubuntu
    disks: {root: 8G}
  child:
    extends: base
  signed:
    extends: plain
    secure-boot: true
    tpm: true
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, name := range []string{"base", "child", "signed"} {
		vm := f.VMs[name]
		spec := mustBuildVMSpec(t, name, name, &vm, f)
		if !spec.SecureBoot || !spec.Tpm {
			t.Errorf("%s: spec secure_boot=%v tpm=%v, want both true", name, spec.SecureBoot, spec.Tpm)
		}
	}
	plain := f.VMs["plain"]
	if spec := mustBuildVMSpec(t, "plain", "plain", &plain, f); spec.SecureBoot || spec.Tpm {
		t.Errorf("plain: spec secure_boot=%v tpm=%v, want both false", spec.SecureBoot, spec.Tpm)
	}
}
