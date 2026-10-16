package network

import (
	"errors"
	"reflect"
	"testing"

	"github.com/litevirt/litevirt/internal/network/fdbfake"
)

func TestFDBWith_PreservesLocalGuardAndCommandSemantics(t *testing.T) {
	k := fdbfake.New()
	mac := "52:54:00:78:00:01"
	if err := AddFDBEntryWith(5178, mac, "192.0.2.1", k.Exec, []string{"192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	if got := k.Dsts("vxlan5178", mac); len(got) != 0 {
		t.Fatalf("installed a local destination: %v", got)
	}
	for i := 0; i < 2; i++ {
		if err := AddFDBEntryWith(5178, mac, "192.0.2.2", k.Exec, []string{"192.0.2.1"}); err != nil {
			t.Fatal(err)
		}
	}
	if got := k.Dsts("vxlan5178", mac); !reflect.DeepEqual(got, []string{"192.0.2.2"}) {
		t.Fatalf("idempotent remote add: %v", got)
	}
	if err := DeleteFDBEntryWith(5178, mac, "192.0.2.2", k.Exec); err != nil {
		t.Fatal(err)
	}
	if got := k.Dsts("vxlan5178", mac); len(got) != 0 {
		t.Fatalf("delete left %v", got)
	}
	want := errors.New("injected executor error")
	fail := func(string, ...string) ([]byte, error) { return nil, want }
	if err := AddFDBEntryWith(5178, mac, "192.0.2.2", fail, nil); !errors.Is(err, want) {
		t.Fatalf("add hid failure: %v", err)
	}
	if err := DeleteFDBEntryWith(5178, mac, "192.0.2.2", fail); !errors.Is(err, want) {
		t.Fatalf("delete hid failure: %v", err)
	}
}

func TestSendGARPWith_ExplicitExecutor(t *testing.T) {
	var calls [][]string
	want := errors.New("injected executor error")
	exec := func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return []byte("refused"), want
	}
	if err := SendGARPWith("", "192.0.2.2", exec); err != nil {
		t.Fatal(err)
	}
	if err := SendGARPWith("br-test", "", exec); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 0 {
		t.Fatalf("empty GARP made calls: %v", calls)
	}
	if err := SendGARPWith("br-test", "192.0.2.2", exec); !errors.Is(err, want) {
		t.Fatalf("GARP hid executor failure: %v", err)
	}
	if !reflect.DeepEqual(calls, [][]string{{"arping", "-A", "-c", "3", "-I", "br-test", "192.0.2.2"}}) {
		t.Fatalf("GARP command changed: %v", calls)
	}
}
