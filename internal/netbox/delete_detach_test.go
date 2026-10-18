package netbox

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// NetBox deletes the addresses assigned to an interface WITH the interface: the
// vminterface's ip_addresses relation is a generic relation, and Django cascades
// it. So a delete of an interface, or of the VM above it, has to detach those
// addresses first or every one of them is destroyed — litevirt's leased objects
// and an operator's own address alike.

// detachRecorder answers the address list with a fixed page and records every
// request that follows, in order.
type detachRecorder struct {
	mu   sync.Mutex
	page string
	log  []string
	// failPatch, when set, makes the PATCH of this address id a 500.
	failPatch string
}

func (d *detachRecorder) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		entry := r.Method + " " + r.URL.Path
		if r.Method == http.MethodGet {
			entry += "?" + r.URL.RawQuery
		}
		if r.Method == http.MethodPatch {
			b, _ := io.ReadAll(r.Body)
			var body map[string]any
			if err := json.Unmarshal(b, &body); err != nil {
				t.Errorf("PATCH %s: bad body %q", r.URL.Path, b)
			}
			if v, ok := body["assigned_object_type"]; !ok || v != nil {
				t.Errorf("PATCH %s must null assigned_object_type, got %q", r.URL.Path, b)
			}
			if v, ok := body["assigned_object_id"]; !ok || v != nil {
				t.Errorf("PATCH %s must null assigned_object_id, got %q", r.URL.Path, b)
			}
		}
		d.log = append(d.log, entry)
		failing := d.failPatch != "" && r.Method == http.MethodPatch &&
			strings.HasSuffix(r.URL.Path, "/"+d.failPatch+"/")
		d.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case failing:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"detail":"boom"}`))
		case r.Method == http.MethodGet && r.URL.Path == ipAddressesPath:
			_, _ = w.Write([]byte(d.page))
		case r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"id":40}`))
		case r.Method == http.MethodPatch:
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}
}

func (d *detachRecorder) requests() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.log...)
}

func TestDeleteInterfaceDetachesItsAddressesFirst(t *testing.T) {
	// 900 is on interface 61 — an operator's address, no identity — and must be
	// detached. 901 is on interface 62, and 902 is on a DCIM interface that
	// happens to share the id 61: neither is this interface's, and both are
	// what a server that IGNORED the filter would hand back. Clearing them would
	// detach somebody else's address, so they are re-checked here and skipped.
	d := &detachRecorder{page: `{"results":[
		{"id":900,"address":"10.0.0.9/24","assigned_object_type":"virtualization.vminterface","assigned_object_id":61,"custom_fields":{}},
		{"id":901,"address":"10.0.0.10/24","assigned_object_type":"virtualization.vminterface","assigned_object_id":62,"custom_fields":{}},
		{"id":902,"address":"10.0.0.11/24","assigned_object_type":"dcim.interface","assigned_object_id":61,"custom_fields":{}}
	],"next":null}`}
	c := testClient(t, d.handler(t))
	if err := c.DeleteInterface(context.Background(), 61); err != nil {
		t.Fatal(err)
	}
	got := d.requests()
	if len(got) != 3 {
		t.Fatalf("requests = %q, want list, one detach, delete", got)
	}
	if !strings.HasPrefix(got[0], "GET "+ipAddressesPath+"?") ||
		!strings.Contains(got[0], "assigned_object_type=virtualization.vminterface") ||
		!strings.Contains(got[0], "assigned_object_id=61") {
		t.Errorf("first request = %q, want the address list scoped to interface 61", got[0])
	}
	if got[1] != "PATCH "+ipAddressesPath+"900/" {
		t.Errorf("second request = %q, want the detach of address 900", got[1])
	}
	if got[2] != "DELETE "+vmInterfacesPath+"61/" {
		t.Errorf("last request = %q, want the interface delete AFTER the detach", got[2])
	}
}

func TestDeleteInterfaceRefusesWhenADetachFails(t *testing.T) {
	// The delete would destroy the address the failed detach left attached.
	d := &detachRecorder{failPatch: "900", page: `{"results":[
		{"id":900,"address":"10.0.0.9/24","assigned_object_type":"virtualization.vminterface","assigned_object_id":61,"custom_fields":{}}
	],"next":null}`}
	c := testClient(t, d.handler(t))
	if err := c.DeleteInterface(context.Background(), 61); err == nil {
		t.Fatal("DeleteInterface succeeded although the detach of address 900 failed")
	}
	for _, r := range d.requests() {
		if strings.HasPrefix(r, "DELETE") {
			t.Fatalf("interface deleted after a failed detach: %q", d.requests())
		}
	}
}

func TestDeleteVMDetachesItsInterfacesAddressesFirst(t *testing.T) {
	// 910 sits on an interface of VM 40 and must be detached; 911 sits on an
	// interface of VM 41, which only a server ignoring the filter would return.
	d := &detachRecorder{page: `{"results":[
		{"id":910,"address":"10.0.0.20/24","assigned_object_type":"virtualization.vminterface","assigned_object_id":70,"assigned_object":{"id":70,"virtual_machine":{"id":40}},"custom_fields":{}},
		{"id":911,"address":"10.0.0.21/24","assigned_object_type":"virtualization.vminterface","assigned_object_id":71,"assigned_object":{"id":71,"virtual_machine":{"id":41}},"custom_fields":{}}
	],"next":null}`}
	c := testClient(t, d.handler(t))
	if err := c.DeleteVM(context.Background(), 40); err != nil {
		t.Fatal(err)
	}
	got := d.requests()
	var patches []string
	for _, r := range got {
		if strings.HasPrefix(r, "PATCH") {
			patches = append(patches, r)
		}
	}
	if len(patches) != 1 || patches[0] != "PATCH "+ipAddressesPath+"910/" {
		t.Errorf("detaches = %q, want exactly address 910", patches)
	}
	if last := got[len(got)-1]; last != "DELETE "+vmsPath+"40/" {
		t.Errorf("last request = %q, want the VM delete AFTER the detach", last)
	}
	var listed bool
	for _, r := range got {
		if strings.HasPrefix(r, "GET "+ipAddressesPath+"?") && strings.Contains(r, "virtual_machine_id=40") {
			listed = true
		}
	}
	if !listed {
		t.Errorf("requests = %q, want an address list scoped to virtual_machine_id=40", got)
	}
}
