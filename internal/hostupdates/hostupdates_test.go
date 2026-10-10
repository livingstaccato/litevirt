package hostupdates

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const aptOut = `Listing...
libssl3/jammy-updates,jammy-security 3.0.2-0ubuntu1.18 amd64 [upgradable from: 3.0.2-0ubuntu1.15]
openssl/jammy-updates,jammy-security 3.0.2-0ubuntu1.18 amd64 [upgradable from: 3.0.2-0ubuntu1.15]
tzdata/jammy-updates,jammy-updates 2024b-0ubuntu0.22.04 all [upgradable from: 2024a-0ubuntu0.22.04]
vim/jammy-updates 2:8.2.3995-1ubuntu2.20 amd64 [upgradable from: 2:8.2.3995-1ubuntu2.1]
`

func TestParseAptUpgradable(t *testing.T) {
	pkgs := ParseAptUpgradable(aptOut)
	if len(pkgs) != 4 {
		t.Fatalf("want 4 packages, got %d: %+v", len(pkgs), pkgs)
	}
	sec := 0
	for _, p := range pkgs {
		if p.Security {
			sec++
		}
	}
	if sec != 2 {
		t.Fatalf("want 2 security packages, got %d: %+v", sec, pkgs)
	}
	if pkgs[0].Name != "libssl3" || pkgs[0].Version != "3.0.2-0ubuntu1.18" {
		t.Fatalf("bad first package: %+v", pkgs[0])
	}
}

func TestParseAptUpgradable_IgnoresNoise(t *testing.T) {
	out := "WARNING: apt does not have a stable CLI interface.\nListing... Done\n\nbash/stable-security 5.2 amd64 [upgradable from: 5.1]\n"
	pkgs := ParseAptUpgradable(out)
	if len(pkgs) != 1 || !pkgs[0].Security || pkgs[0].Name != "bash" {
		t.Fatalf("got %+v", pkgs)
	}
}

func TestParseDnfCheckUpdate(t *testing.T) {
	out := `
kernel.x86_64                 6.1.0-1.el9            baseos
openssl-libs.x86_64           3.0.7-28.el9           baseos
Obsoleting Packages
foo.x86_64                    1.0                    appstream
    old.x86_64                0.9                    @appstream
`
	got := ParseDnfCheckUpdate(out)
	if len(got) != 2 || got[0] != "kernel" || got[1] != "openssl-libs" {
		t.Fatalf("got %v", got)
	}
}

func TestParseDnfSecurity(t *testing.T) {
	out := `
RLSA-2024:1234 Important/Sec. openssl-libs-3.0.7-28.el9.x86_64
RLSA-2024:1235 Moderate/Sec.  kernel-6.1.0-1.el9.x86_64
RLSA-2024:1236 Moderate/Sec.  kernel-core-6.1.0-1.el9.x86_64
`
	got := ParseDnfSecurity(out)
	for _, want := range []string{"openssl-libs", "kernel", "kernel-core"} {
		if !got[want] {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	if len(got) != 3 {
		t.Fatalf("got %v", got)
	}
}

type fakeRun struct {
	calls []string
	out   map[string]string
	err   map[string]error
}

func (f *fakeRun) run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, key)
	if e, ok := f.err[key]; ok {
		return []byte(f.out[key]), e
	}
	return []byte(f.out[key]), nil
}

func TestCheck_AptReadOnlyByDefault(t *testing.T) {
	f := &fakeRun{out: map[string]string{"apt list --upgradable": aptOut}}
	st := Check(context.Background(), Options{Run: f.run, Have: func(b string) bool { return b == "apt" || b == "apt-get" }})
	if st.Manager != "apt" || st.Pending != 4 || st.Security != 2 || st.Err != "" {
		t.Fatalf("bad status %+v", st)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "update") {
			t.Fatalf("index refresh ran without RefreshIndex: %v", f.calls)
		}
	}
}

func TestCheck_AptRefreshOnlyWhenConfigured(t *testing.T) {
	f := &fakeRun{out: map[string]string{"apt list --upgradable": aptOut}}
	st := Check(context.Background(), Options{Run: f.run, RefreshIndex: true, Have: func(b string) bool { return b == "apt" || b == "apt-get" }})
	if st.Err != "" {
		t.Fatal(st.Err)
	}
	if len(f.calls) < 2 || f.calls[0] != "apt-get update -q" {
		t.Fatalf("want refresh first, got %v", f.calls)
	}
}

func TestCheck_RefreshFailureStillReportsCachedIndex(t *testing.T) {
	f := &fakeRun{
		out: map[string]string{"apt list --upgradable": aptOut},
		err: map[string]error{"apt-get update -q": errors.New("exit 100")},
	}
	st := Check(context.Background(), Options{Run: f.run, RefreshIndex: true, Have: func(b string) bool { return b == "apt" || b == "apt-get" }})
	if st.Pending != 4 || !strings.Contains(st.Err, "refresh") {
		t.Fatalf("want cached result plus refresh error, got %+v", st)
	}
}

func TestCheck_DnfExit100MeansUpdates(t *testing.T) {
	f := &fakeRun{
		out: map[string]string{
			"dnf -q --cacheonly check-update":               "kernel.x86_64 6.1 baseos\nopenssl-libs.x86_64 3.0 baseos\n",
			"dnf -q --cacheonly updateinfo list --security": "RLSA-1 Important/Sec. openssl-libs-3.0.7-28.el9.x86_64\n",
		},
		err: map[string]error{"dnf -q --cacheonly check-update": ExitCodeError(100)},
	}
	st := Check(context.Background(), Options{Run: f.run, Have: func(b string) bool { return b == "dnf" }})
	if st.Manager != "dnf" || st.Pending != 2 || st.Security != 1 || st.Err != "" {
		t.Fatalf("bad status %+v", st)
	}
}

func TestCheck_DnfFailureIsAnErrorNotZero(t *testing.T) {
	f := &fakeRun{err: map[string]error{"dnf -q --cacheonly check-update": ExitCodeError(1)}}
	st := Check(context.Background(), Options{Run: f.run, Have: func(b string) bool { return b == "dnf" }})
	if st.Err == "" {
		t.Fatalf("a failed check must not read as zero updates: %+v", st)
	}
}

func TestCheck_NoPackageManager(t *testing.T) {
	st := Check(context.Background(), Options{Run: (&fakeRun{}).run, Have: func(string) bool { return false }})
	if st.Manager != "" || st.Err != "" || st.Supported {
		t.Fatalf("want unsupported with no error, got %+v", st)
	}
}

func TestLabels(t *testing.T) {
	st := Status{Supported: true, Manager: "apt", Pending: 4, Security: 2}
	l := st.Labels()
	if l[LabelPending] != "4" || l[LabelSecurity] != "2" {
		t.Fatalf("got %v", l)
	}
	if l := (Status{Supported: true, Err: "boom"}).Labels(); l[LabelPending] != "unknown" || l[LabelSecurity] != "unknown" {
		t.Fatalf("an errored check must be unknown, got %v", l)
	}
}

func TestFromLabels(t *testing.T) {
	p, s, ok := FromLabels(map[string]string{LabelPending: "4", LabelSecurity: "2"})
	if !ok || p != 4 || s != 2 {
		t.Fatal(p, s, ok)
	}
	if _, _, ok := FromLabels(map[string]string{LabelPending: "unknown", LabelSecurity: "unknown"}); ok {
		t.Fatal("unknown must not parse as a count")
	}
	if _, _, ok := FromLabels(nil); ok {
		t.Fatal("absent must not parse")
	}
}
