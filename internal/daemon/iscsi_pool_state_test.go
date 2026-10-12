package daemon

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A config iscsi pool's state is its session's: the periodic registration of
// config pools keeps the state the session reconcile recorded (degraded while
// the host has no session), and registers a new one as active.
func TestRegisterStoragePools_KeepsAnISCSIPoolsSessionState(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	pools := []StoragePoolConfig{
		{Name: "san", Driver: "iscsi", Source: "iqn.2003-01.org.example:store", Options: map[string]string{"portal": "10.0.0.5:3260"}},
		{Name: "san2", Driver: "iscsi", Source: "iqn.2003-01.org.example:store2", Options: map[string]string{"portal": "10.0.0.5:3260"}},
	}
	if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{
		HostName: "host-a", Name: "san", Driver: "iscsi", Source: pools[0].Source, State: "degraded",
	}); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{db: db, cfg: &Config{HostName: "host-a", DataDir: t.TempDir(), StoragePools: pools}}
	d.registerStoragePools(ctx)
	for name, want := range map[string]string{"san": "degraded", "san2": "active"} {
		rec, ok, err := corrosion.GetStoragePool(ctx, db, "host-a", name)
		if err != nil || !ok || rec.State != want {
			t.Fatalf("pool %s: %+v found=%v err=%v; want state %q", name, rec, ok, err, want)
		}
	}
}
