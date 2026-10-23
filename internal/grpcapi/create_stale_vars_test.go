package grpcapi

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// UEFI vars already at the path libvirt gave a new domain are an earlier VM's
// of the name (a migration's source, a delete's): libvirt would give them to
// the new VM's first boot. The create sets them aside before the start, so the
// guest boots from a fresh template, and the old bytes stay.
//
// Mutation: drop the set-aside before StartDomain; the start finds the vars.
func TestCreateVM_SetsAsideAnEarlierVMsUEFIVarsBeforeTheStart(t *testing.T) {
	s, fake := provableCreateServer(t)
	vars := filepath.Join(t.TempDir(), "qemu-nvram", "vm1_VARS.fd")
	if err := os.MkdirAll(filepath.Dir(vars), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vars, []byte("the old VM's vars"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake.FillDefine = func(x string) string {
		return strings.Replace(x, "</os>", "<nvram>"+vars+"</nvram></os>", 1)
	}
	var atStart bool
	fake.FailStartDomain = func(string) error {
		_, err := os.Lstat(vars)
		atStart = err == nil
		return errors.New("stop here")
	}
	if _, err := s.CreateVM(adminCtx(), disklessCreateRequest("vm1")); err == nil {
		t.Fatal("the create succeeded with the start failed")
	}
	if atStart {
		t.Error("the new VM's first boot would have found the earlier VM's vars")
	}
	kept, _ := filepath.Glob(vars + ".superseded-*")
	if len(kept) != 1 {
		t.Fatalf("set-aside copies = %v, want one", kept)
	}
	if b, _ := os.ReadFile(kept[0]); string(b) != "the old VM's vars" {
		t.Errorf("the set-aside copy holds %q", b)
	}
}
