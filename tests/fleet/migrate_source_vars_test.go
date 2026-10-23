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

// The cold move of a stopped plain UEFI VM keeps the domain's vars through its
// keep-state undefine (KEEP_NVRAM); once the VM is on the target the source's
// file goes, the target's own stays.
//
// Mutation: drop removeMigratedSourceVars from coldMigrateStoppedVM.
func TestFleet_ColdMigrationRemovesThePlainUEFIVarsFromTheSource(t *testing.T) {
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
	if _, err := os.Stat(vars[sc.src.Name]); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the source still holds the moved VM's UEFI vars (stat: %v)", err)
	}
	if got, err := os.ReadFile(vars[sc.dst.Name]); err != nil || string(got) != "vars of "+sc.dst.Name {
		t.Errorf("the target's own vars were touched: %q, %v", got, err)
	}
}
