package fleet

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// libvirt's migration undefine leaves a plain UEFI VM's vars file
// (<libvirt nvram dir>/<vm>_VARS.fd) on the source: neither
// VIR_MIGRATE_UNDEFINE_SOURCE nor the cold move's keep-state undefine passes
// VIR_DOMAIN_UNDEFINE_NVRAM. A later create of the name there booted from the
// old VM's boot entries. The source removes it once the move committed on the
// target; a failed move keeps it; the target's own file is never touched.
//
// Mutation: drop removeMigratedSourceVars from finishMigrationOnTarget; the
// "committed" case goes red with the source's file left.
func TestFleet_LiveMigrationRemovesThePlainUEFIVarsFromTheSource(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fail    bool
		wantSrc bool
	}{
		{"committed", false, false},
		{"failed", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(t, Options{Nodes: 2, SharedCRDT: true})
			defer c.Stop()
			src, dst := c.Nodes[0], c.Nodes[1]
			for _, n := range c.Nodes {
				setHostCapacity(t, c, n.Name, 64, 65536)
			}
			vars := map[string]string{}
			for _, n := range c.Nodes {
				dir := filepath.Join(c.tmpRoot, n.Name, "libvirt-nvram")
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				n.Server.SetLibvirtNvramDir(dir)
				vars[n.Name] = filepath.Join(dir, "uefi1_VARS.fd")
				if err := os.WriteFile(vars[n.Name], []byte("vars of "+n.Name), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := corrosion.InsertVM(t.Context(), src.DB, corrosion.VMRecord{
				Name: "uefi1", HostName: src.Name, State: "running", Spec: `{"name":"uefi1","cpu":1,"memory_mib":512}`,
				CPUActual: 1, MemActual: 512,
			}, nil, nil); err != nil {
				t.Fatal(err)
			}
			src.Virt.SetState("uefi1", "running")
			if tc.fail {
				src.Virt.FailMigrateToTarget = func(string, string) error { return errors.New("migration failed") }
			} else {
				src.Virt.OnMigrateToTarget = func(name, _ string, _ lv.MigrateParams) error {
					dst.Virt.SetState(name, "running")
					// VIR_MIGRATE_UNDEFINE_SOURCE: the source domain goes,
					// its vars file stays (the fake does not model either).
					src.Virt.VanishDomain(name)
					return nil
				}
			}
			err := migrateAt(t, c, src, "uefi1", dst.Name)
			if tc.fail != (err != nil) {
				t.Fatalf("migrate: err = %v, want failure %v", err, tc.fail)
			}
			if tc.wantSrc {
				if _, err := os.Stat(vars[src.Name]); err != nil {
					t.Fatalf("a failed move removed the source's vars: %v", err)
				}
				return
			}
			eventually(t, 10*time.Second, "the source's vars to go", func() bool {
				_, err := os.Stat(vars[src.Name])
				return errors.Is(err, os.ErrNotExist)
			})
			if got, err := os.ReadFile(vars[dst.Name]); err != nil || string(got) != "vars of "+dst.Name {
				t.Fatalf("the target's own vars were touched: %q, %v", got, err)
			}
		})
	}
}

// The cold move of a stopped plain UEFI VM has no migration stream: its
// libvirt-managed vars ride with the definition, the target writes and hashes
// them, and only then does the source remove its own copy. Without that the
// source's file was the only copy and the VM booted on the target from a fresh
// template. A file of the name already on the target is set aside, not adopted.
//
// Mutations: drop the vars from the request (the bytes never arrive; the source
// keeps its file, the move is refused); drop removeMigratedSourceVars from
// coldMigrateStoppedVM (the source still holds the file).
func TestFleet_ColdMigrationCarriesThePlainUEFIVarsAndRemovesTheSourceCopy(t *testing.T) {
	sc := newColdStoppedScenario(t)
	vars := map[string]string{}
	for _, n := range sc.c.Nodes {
		dir := filepath.Join(sc.c.tmpRoot, n.Name, "libvirt-nvram")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		n.Server.SetLibvirtNvramDir(dir)
		vars[n.Name] = filepath.Join(dir, "os1_VARS.fd")
		if err := os.WriteFile(vars[n.Name], []byte("vars of "+n.Name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := sc.migrateCold(t); err != nil {
		t.Fatalf("migrate --cold: %v", err)
	}
	if got, err := os.ReadFile(vars[sc.dst.Name]); err != nil || string(got) != "vars of "+sc.src.Name {
		t.Fatalf("the target's vars = %q (%v), want the source's bytes", got, err)
	}
	aside, _ := filepath.Glob(vars[sc.dst.Name] + ".superseded-*")
	if len(aside) != 1 {
		t.Fatalf("the target's earlier file: set-aside copies = %v, want one", aside)
	}
	if b, _ := os.ReadFile(aside[0]); string(b) != "vars of "+sc.dst.Name {
		t.Errorf("the set-aside copy holds %q", b)
	}
	if _, err := os.Stat(vars[sc.src.Name]); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the source still holds the moved VM's UEFI vars (stat: %v)", err)
	}
}

// A cold move that fails after the vars reached the target (here, the target's
// define) keeps the source's file and leaves nothing of the attempt on the target.
//
// Mutation: remove the source's file before the handoff; the source's bytes go.
func TestFleet_FailedColdMigrationKeepsThePlainUEFIVarsOnTheSource(t *testing.T) {
	sc := newColdStoppedScenario(t)
	vars := map[string]string{}
	for _, n := range sc.c.Nodes {
		dir := filepath.Join(sc.c.tmpRoot, n.Name, "libvirt-nvram")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		n.Server.SetLibvirtNvramDir(dir)
		vars[n.Name] = filepath.Join(dir, "os1_VARS.fd")
	}
	if err := os.WriteFile(vars[sc.src.Name], []byte("vars of the VM"), 0o600); err != nil {
		t.Fatal(err)
	}
	sc.dst.Virt.FailDefineDomain = func(string) error { return errors.New("define refused") }
	if err := sc.migrateCold(t); err == nil {
		t.Fatal("the migration succeeded; the scenario needs the target's define to fail")
	}
	if got, err := os.ReadFile(vars[sc.src.Name]); err != nil || string(got) != "vars of the VM" {
		t.Errorf("the source's vars after a failed move = %q (%v), want them intact", got, err)
	}
	if _, err := os.Stat(vars[sc.dst.Name]); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the failed attempt left vars on the target (stat: %v)", err)
	}
}
