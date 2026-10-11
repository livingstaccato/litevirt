package storage

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCephClientKey_ReadsTheClientsSection(t *testing.T) {
	_, keyring, key := labCephFiles(t)
	got, err := CephClientKey(keyring, "litevirt")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("key = %q, want %q", got, key)
	}
	if _, err := CephClientKey(keyring, "admin"); !errors.Is(err, ErrNoCephKey) {
		t.Fatalf("another client's key: got %v, want ErrNoCephKey", err)
	}
}

// A keyring section for one client is never read as another's, even when the
// other's is the only section with a key.
func TestCephClientKey_SectionsAreNotMixed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k")
	body := "[client.admin]\n\tkey = QUJDREVGR0g=\n[client.litevirt]\n\tcaps osd = \"profile rbd\"\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CephClientKey(p, "litevirt"); !errors.Is(err, ErrNoCephKey) {
		t.Fatalf("got %v, want ErrNoCephKey", err)
	}
}

// An undecodable key is reported without the key text.
func TestCephClientKey_BadKeyIsNotEchoed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k")
	if err := os.WriteFile(p, []byte("[client.x]\nkey = SECRET!!notbase64\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := CephClientKey(p, "x")
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("got %v", err)
	}
}

func TestParseMonHost(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"[v2:10.0.0.1:3300/0,v1:10.0.0.1:6789/0]", []string{"10.0.0.1:6789"}},
		{"[v2:10.0.0.1:3300/0,v1:10.0.0.1:6789/0] [v2:10.0.0.2:3300/0,v1:10.0.0.2:6789/0],[v2:10.0.0.3:3300/0]",
			[]string{"10.0.0.1:6789", "10.0.0.2:6789", "10.0.0.3:3300"}},
		{"10.0.0.1, 10.0.0.2:6789;mon-c", []string{"10.0.0.1", "10.0.0.2:6789", "mon-c"}},
		{"[::1]:6789", []string{"[::1]:6789"}},
		{"", nil},
	} {
		if got := ParseMonHost(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ParseMonHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCephMonHosts_SpacedKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ceph.conf")
	if err := os.WriteFile(p, []byte("[global]\n  mon host = 10.0.0.5,10.0.0.6\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := CephMonHosts(p)
	if err != nil || !reflect.DeepEqual(got, []string{"10.0.0.5", "10.0.0.6"}) {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestCephAuthOf(t *testing.T) {
	dir := t.TempDir()
	prev := cephConfDir
	cephConfDir = dir
	t.Cleanup(func() { cephConfDir = prev })

	if _, ok := CephAuthOf(map[string]string{}); ok {
		t.Error("no id and no keyring must name no identity (qemu's defaults, as before)")
	}
	if _, ok := CephAuthOf(map[string]string{"id": "litevirt"}); ok {
		t.Error("an id with no keyring anywhere must name no identity")
	}
	// The rbd CLI finds client.<id>'s key at ceph's default path; so does the domain.
	def := filepath.Join(dir, "ceph.client.litevirt.keyring")
	if err := os.WriteFile(def, []byte("[client.litevirt]\nkey = QUJD\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if a, ok := CephAuthOf(map[string]string{"id": "litevirt"}); !ok || a.Keyring != def || a.ID != "litevirt" {
		t.Errorf("default keyring: %+v %v", a, ok)
	}
	if a, ok := CephAuthOf(map[string]string{"keyring": "/x//k"}); !ok || a.ID != "admin" || a.Keyring != "/x/k" {
		t.Errorf("keyring only: %+v %v", a, ok)
	}
}
