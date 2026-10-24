package hostboot

import (
	"os"
	"path/filepath"
	"testing"
)

func readOr(t *testing.T, p string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// Undo reverts a decision's own changes and nothing else.
func TestBootFilesUndo(t *testing.T) {
	t.Run("a decision from nothing", func(t *testing.T) {
		dir := t.TempDir()
		b := SnapshotBootFiles(dir)
		_ = os.WriteFile(AwaitingPath(dir), []byte("x"), 0o600)
		_ = os.WriteFile(filepath.Join(dir, UncleanHistoryName), []byte("y\n"), 0o600)
		if err := b.Undo(); err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{AwaitingPath(dir), filepath.Join(dir, UncleanHistoryName), MarkerPath(dir)} {
			if _, ok := readOr(t, p); ok {
				t.Errorf("%s left", filepath.Base(p))
			}
		}
	})
	t.Run("files an earlier boot left", func(t *testing.T) {
		dir := t.TempDir()
		hist := filepath.Join(dir, UncleanHistoryName)
		_ = os.WriteFile(MarkerPath(dir), []byte("m"), 0o600)
		_ = os.WriteFile(AwaitingPath(dir), []byte("a"), 0o600)
		_ = os.WriteFile(hist, []byte("h1\n"), 0o600)
		b := SnapshotBootFiles(dir)
		_ = os.Remove(MarkerPath(dir))                    // consumed
		_ = os.WriteFile(hist, []byte("h1\nh2\n"), 0o600) // added to
		if err := b.Undo(); err != nil {
			t.Fatal(err)
		}
		for p, want := range map[string]string{MarkerPath(dir): "m", AwaitingPath(dir): "a", hist: "h1\n"} {
			if got, ok := readOr(t, p); !ok || got != want {
				t.Errorf("%s = %q %v, want %q", filepath.Base(p), got, ok, want)
			}
		}
	})
	t.Run("a note a serving daemon removed meanwhile is not put back", func(t *testing.T) {
		dir := t.TempDir()
		_ = os.WriteFile(AwaitingPath(dir), []byte("a"), 0o600)
		b := SnapshotBootFiles(dir)
		Served(dir)
		if err := b.Undo(); err != nil {
			t.Fatal(err)
		}
		if _, ok := readOr(t, AwaitingPath(dir)); ok {
			t.Error("the awaiting note was put back after the daemon served")
		}
	})
}
