package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/storage"
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

// The daemon's session loop makes its first pass at once, not a ticker later:
// after a reboot the session is back as soon as the daemon is up.
func TestRunISCSISessionReconcile_FirstPassAtOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{
		HostName: "host-a", Name: "san", Driver: "iscsi", Source: "iqn.2003-01.org.example:store", State: "active",
		Options: map[string]string{"portal": "10.0.0.5:3260"},
	}); err != nil {
		t.Fatal(err)
	}
	logins := make(chan struct{}, 4)
	t.Cleanup(storage.OverrideISCSICommandForTest(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if strings.Join(args, " ") == "-m session" {
			return []byte("iscsiadm: No active sessions."), errors.New("exit status 21")
		}
		if strings.HasSuffix(strings.Join(args, " "), "--login") {
			logins <- struct{}{}
		}
		return nil, nil
	}))
	dir := t.TempDir()
	d := &Daemon{db: db, cfg: &Config{HostName: "host-a", DataDir: dir}, svc: grpcapi.NewServer("host-a", dir, dir, db, nil, nil)}
	go d.runISCSISessionReconcile(ctx)
	select {
	case <-logins:
	case <-time.After(5 * time.Second):
		t.Fatal("no login within 5s of the loop's start")
	}
}
