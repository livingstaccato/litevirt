package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pooltrust"
)

// (re-review rr2 1) A config nfs pool with NO target (mount point <data_dir>/mounts/..)
// is judged "names no host path", not TrustConfig, so nfsPoolConfig's
// config-only branch never runs and the row's forged options are mounted.
func TestRR2Probe_TargetlessConfigNFSPoolForgedOptions(t *testing.T) {
	s := trustServer(t)
	s.PoolTrust().SetConfig(map[string]pooltrust.Binding{"nas": pooltrust.BindingOf("nfs", "srv:/x", "", nil)})
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"nas": {Driver: "nfs", Source: "srv:/x"}})
	row := corrosion.StoragePoolRecord{HostName: s.hostName, Name: "nas", Driver: "nfs", Source: "srv:/x",
		Options: map[string]string{"options": "vers=3,soft,nolock,async"}, State: "active"}
	v := s.poolTrustVerdict(row.Name, StoragePoolRef{Driver: row.Driver, Source: row.Source, Options: row.Options})
	t.Logf("verdict: %+v; mounted with %q", v, s.nfsPoolConfig(row).Options["options"])
	if v.Trusted && s.nfsPoolConfig(row).Options["options"] == "vers=3,soft,nolock,async" {
		t.Errorf("a forged options rewrite of a target-less config nfs pool is trusted and mounted with the row's options")
	}
}

// (re-review rr2 1) A forged target-less nfs row (no config, no ledger) is
// judged like any other nfs row: untrusted, so neither its export nor its
// options are mounted at <data_dir>/mounts/...
//
// Mutation: let an nfs pool with no target need no trust (NeedsTrust on
// write roots only) — red.
func TestRR2Probe_TargetlessForgedNFSRow(t *testing.T) {
	s := trustServer(t)
	row := corrosion.StoragePoolRecord{HostName: s.hostName, Name: "evil", Driver: "nfs", Source: "attacker.example:/x",
		Options: map[string]string{"options": "vers=3,soft,nolock"}, State: "active"}
	t.Logf("trusted=%t mounted with %q", s.poolRowTrusted(row), s.nfsPoolConfig(row).Options["options"])
	if s.poolRowTrusted(row) {
		t.Error("a forged target-less nfs row is trusted")
	}
	if rows, _ := s.ownPools(context.Background()); len(rows) != 0 {
		t.Errorf("ownPools lists a forged target-less nfs row: %+v", rows)
	}
}
