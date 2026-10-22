package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func addPeer(t *testing.T, s *Server, name, version string, schema int) {
	t.Helper()
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{
		Name: name, Address: "10.0.0." + name[len(name)-1:], State: "active",
		Version: version, SchemaVersion: schema,
	}); err != nil {
		t.Fatal(err)
	}
	// InsertHost leaves schema_version at its default; a running peer reports it.
	if err := s.db.Execute(context.Background(), `UPDATE hosts SET schema_version = ? WHERE name = ?`, schema, name); err != nil {
		t.Fatal(err)
	}
}

// A peer on a pre-release (v1.10.0-rc1) is never followed automatically, but the
// operator must be told why a node that is behind does nothing: one INFO line per
// distinct skipped version, and a line in the upgrade status.
func TestSelfUpgrade_PrereleasePeerSkipSaysWhy(t *testing.T) {
	s := upgradeStatusServer(t)
	s.version = "v1.9.0"
	addPeer(t, s, "peer1", "v1.10.0-rc1", corrosion.CurrentSchemaVersion+1)
	logs := captureSlog(t)

	for i := 0; i < 2; i++ {
		if _, _, _, ok := s.selfUpgradeTarget(context.Background()); ok {
			t.Fatal("a pre-release peer must never be a self-upgrade target")
		}
	}
	out := logs.String()
	if n := strings.Count(out, "pre-release"); n == 0 {
		t.Fatalf("no log line says the pre-release was skipped:\n%s", out)
	}
	for _, want := range []string{"peer1", "v1.10.0-rc1", "lv host upgrade"} {
		if !strings.Contains(out, want) {
			t.Errorf("log line lacks %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "not following it"); n != 1 {
		t.Errorf("logged %d times over two intervals, want exactly once:\n%s", n, out)
	}

	// A different skipped version is a new fact and is logged again.
	addPeer(t, s, "peer2", "v1.10.0-rc2", corrosion.CurrentSchemaVersion+1)
	s.selfUpgradeTarget(context.Background())
	if n := strings.Count(logs.String(), "not following it"); n != 2 {
		t.Errorf("a second distinct version should log once more, got %d lines total", n)
	}
}

// A peer that is not ahead (same release core as ours, a dev build) is not news.
func TestSelfUpgrade_PrereleaseNotAheadIsQuiet(t *testing.T) {
	s := upgradeStatusServer(t)
	s.version = "v1.9.0"
	addPeer(t, s, "peer1", "v1.9.0-3-gabc1234", corrosion.CurrentSchemaVersion)
	logs := captureSlog(t)
	s.selfUpgradeTarget(context.Background())
	if strings.Contains(logs.String(), "pre-release") {
		t.Errorf("a dev build of our own release core is not a skipped upgrade:\n%s", logs.String())
	}
}

// The same fact is shown by `lv cluster upgrade-status` (GetUpgradeStatus).
func TestSelfUpgrade_PrereleaseSkipShownInUpgradeStatus(t *testing.T) {
	s := upgradeStatusServer(t)
	s.version = "v1.9.0"
	addPeer(t, s, "peer1", "v1.10.0-rc1", corrosion.CurrentSchemaVersion+1)
	s.selfUpgradeTarget(context.Background())
	st, err := s.GetUpgradeStatus(viewerCtx(), &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if got := st.GetSelfUpgradeSkipped(); len(got) != 1 || !strings.Contains(got[0], "v1.10.0-rc1") {
		t.Errorf("upgrade status does not show the skipped pre-release: %v", got)
	}
}
