//go:build linux

package firewall

import (
	"fmt"
	"strings"
	"testing"
)

// recSkipper records whether a kernel test skipped or failed.
type recSkipper struct {
	skipped, failed string
}

func (r *recSkipper) Helper()                   {}
func (r *recSkipper) Skipf(f string, a ...any)  { r.skipped = fmt.Sprintf(f, a...) }
func (r *recSkipper) Fatalf(f string, a ...any) { r.failed = fmt.Sprintf(f, a...) }

// A kernel child whose module list names a module that cannot exist skips
// without LITEVIRT_NFT_REQUIRE and fails with it, naming the module.
//
// Mutation: make skipOrRequire always Skipf — the REQUIRE case goes red.
func TestKernelRequire_MissingModuleFailsUnderRequire(t *testing.T) {
	const ghost = "lv_no_such_module"
	t.Setenv(nftRequire, "")
	r := &recSkipper{}
	skipUnlessModules(r, "the ghost rulesets", ghost)
	if r.failed != "" || !strings.Contains(r.skipped, ghost) {
		t.Errorf("switch unset: want a skip naming %s, got skipped=%q failed=%q", ghost, r.skipped, r.failed)
	}
	t.Setenv(nftRequire, "1")
	r = &recSkipper{}
	skipUnlessModules(r, "the ghost rulesets", ghost)
	if r.skipped != "" || !strings.Contains(r.failed, ghost) || !strings.Contains(r.failed, nftRequire) {
		t.Errorf("%s=1: want a failure naming %s, got skipped=%q failed=%q", nftRequire, ghost, r.skipped, r.failed)
	}
	t.Setenv(nftRequire, "1")
	r = &recSkipper{}
	skipOrRequire(r, "nft is not on PATH")
	if r.skipped != "" || !strings.Contains(r.failed, "nft is not on PATH") {
		t.Errorf("%s=1: nft skip not made a failure: skipped=%q failed=%q", nftRequire, r.skipped, r.failed)
	}
}

// With LITEVIRT_NFT_REQUIRE=1 and the opt-in unset, the parent fails instead
// of skipping having run nothing.
//
// Mutation: drop the REQUIRE check in skipUnlessOptedIn — red.
func TestKernelRequire_UnsetOptInFailsUnderRequire(t *testing.T) {
	t.Setenv(nftRequire, "")
	r := &recSkipper{}
	skipUnlessOptedIn(r)
	if r.failed != "" || !strings.Contains(r.skipped, netnsOptIn) {
		t.Errorf("switch unset: want a skip, got skipped=%q failed=%q", r.skipped, r.failed)
	}
	t.Setenv(nftRequire, "1")
	r = &recSkipper{}
	skipUnlessOptedIn(r)
	if r.skipped != "" || !strings.Contains(r.failed, nftRequire+"=1 needs "+netnsOptIn+"=1") {
		t.Errorf("%s=1: want the failure, got skipped=%q failed=%q", nftRequire, r.skipped, r.failed)
	}
}
