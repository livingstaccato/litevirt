package netbox

import (
	"context"
	"encoding/json"
	"errors"
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
//
// And NetBox refuses to detach an address that is its VM's primary_ip4 or
// primary_ip6 (IPAddress.clean(): "Cannot reassign IP address while it is
// designated as the primary IP for the parent object"), so the primary that
// names one has to be cleared first.

// detachRecorder answers the address list with a fixed page, each object GET
// from gets, and records every request in order.
type detachRecorder struct {
	mu   sync.Mutex
	page string
	gets map[string]string // path -> body for object GETs
	log  []string
	// vmPatches is every PATCH body sent to a virtual machine.
	vmPatches []map[string]any
	// failPatch, when set, makes the PATCH of this address id fail with
	// failStatus (500 when unset).
	failPatch  string
	failStatus int
}

func (d *detachRecorder) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		entry := r.Method + " " + r.URL.Path
		if r.Method == http.MethodGet && r.URL.Path == ipAddressesPath {
			entry += "?" + r.URL.RawQuery
		}
		if r.Method == http.MethodPatch {
			b, _ := io.ReadAll(r.Body)
			var body map[string]any
			if err := json.Unmarshal(b, &body); err != nil {
				t.Errorf("PATCH %s: bad body %q", r.URL.Path, b)
			}
			if strings.HasPrefix(r.URL.Path, vmsPath) {
				d.vmPatches = append(d.vmPatches, body)
			} else {
				if v, ok := body["assigned_object_type"]; !ok || v != nil {
					t.Errorf("PATCH %s must null assigned_object_type, got %q", r.URL.Path, b)
				}
				if v, ok := body["assigned_object_id"]; !ok || v != nil {
					t.Errorf("PATCH %s must null assigned_object_id, got %q", r.URL.Path, b)
				}
			}
		}
		d.log = append(d.log, entry)
		failing := d.failPatch != "" && r.Method == http.MethodPatch &&
			strings.HasSuffix(r.URL.Path, ipAddressesPath+d.failPatch+"/")
		status := d.failStatus
		body, known := d.gets[r.URL.Path]
		d.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case failing:
			if status == 0 {
				status = http.StatusInternalServerError
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"detail":"refused"}`))
		case r.Method == http.MethodGet && r.URL.Path == ipAddressesPath:
			_, _ = w.Write([]byte(d.page))
		case r.Method == http.MethodGet && known:
			_, _ = w.Write([]byte(body))
		case r.Method == http.MethodGet:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"detail":"Not found."}`))
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

// indexOf is the position of the first request with this prefix, or -1.
func indexOf(reqs []string, prefix string) int {
	for i, r := range reqs {
		if strings.HasPrefix(r, prefix) {
			return i
		}
	}
	return -1
}

func patchesOf(reqs []string, prefix string) []string {
	var out []string
	for _, r := range reqs {
		if strings.HasPrefix(r, "PATCH "+prefix) {
			out = append(out, r)
		}
	}
	return out
}

// ifaceOn61 is interface 61 of VM 40.
var ifaceOn61 = map[string]string{
	vmInterfacesPath + "61/": `{"id":61,"name":"eth0","virtual_machine":{"id":40}}`,
	vmsPath + "40/":          `{"id":40,"name":"vm-1","primary_ip4":null,"primary_ip6":null}`,
}

func TestDeleteInterfaceDetachesItsAddressesFirst(t *testing.T) {
	// 900 is on interface 61 — an operator's address, no identity — and must be
	// detached. 901 is on interface 62, and 902 is on a DCIM interface that
	// happens to share the id 61: neither is this interface's, and both are
	// what a server that IGNORED the filter would hand back. Clearing them would
	// detach somebody else's address, so they are re-checked here and skipped.
	d := &detachRecorder{gets: ifaceOn61, page: `{"results":[
		{"id":900,"address":"10.0.0.9/24","assigned_object_type":"virtualization.vminterface","assigned_object_id":61,"custom_fields":{}},
		{"id":901,"address":"10.0.0.10/24","assigned_object_type":"virtualization.vminterface","assigned_object_id":62,"custom_fields":{}},
		{"id":902,"address":"10.0.0.11/24","assigned_object_type":"dcim.interface","assigned_object_id":61,"custom_fields":{}}
	],"next":null}`}
	c := testClient(t, d.handler(t))
	if err := c.DeleteInterface(context.Background(), 61); err != nil {
		t.Fatal(err)
	}
	got := d.requests()
	if !strings.HasPrefix(got[0], "GET "+ipAddressesPath+"?") ||
		!strings.Contains(got[0], "assigned_object_type=virtualization.vminterface") ||
		!strings.Contains(got[0], "assigned_object_id=61") {
		t.Errorf("first request = %q, want the address list scoped to interface 61", got[0])
	}
	if p := patchesOf(got, ipAddressesPath); len(p) != 1 || p[0] != "PATCH "+ipAddressesPath+"900/" {
		t.Errorf("detaches = %q, want exactly address 900", p)
	}
	if last := got[len(got)-1]; last != "DELETE "+vmInterfacesPath+"61/" {
		t.Errorf("last request = %q, want the interface delete AFTER the detach", last)
	}
}

func TestDeleteInterfaceClearsAPrimaryItIsAboutToDetach(t *testing.T) {
	// 900 is VM 40's primary_ip4. NetBox refuses to detach it while it is, so
	// the primary goes first — and only that field: primary_ip6 names an
	// address on another interface, which stays.
	gets := map[string]string{
		vmInterfacesPath + "61/": `{"id":61,"name":"eth0","virtual_machine":{"id":40}}`,
		vmsPath + "40/":          `{"id":40,"name":"vm-1","primary_ip4":{"id":900},"primary_ip6":{"id":950}}`,
	}
	d := &detachRecorder{gets: gets, page: `{"results":[
		{"id":900,"address":"10.0.0.9/24","assigned_object_type":"virtualization.vminterface","assigned_object_id":61,"custom_fields":{}}
	],"next":null}`}
	c := testClient(t, d.handler(t))
	if err := c.DeleteInterface(context.Background(), 61); err != nil {
		t.Fatal(err)
	}
	got := d.requests()
	vmPatch, ipPatch := indexOf(got, "PATCH "+vmsPath+"40/"), indexOf(got, "PATCH "+ipAddressesPath+"900/")
	if vmPatch < 0 || ipPatch < 0 || vmPatch > ipPatch {
		t.Fatalf("requests = %q, want VM 40's primary cleared BEFORE address 900 is detached", got)
	}
	if len(d.vmPatches) != 1 {
		t.Fatalf("VM patches = %v, want one", d.vmPatches)
	}
	p := d.vmPatches[0]
	if v, ok := p["primary_ip4"]; !ok || v != nil {
		t.Errorf("VM patch %v must null primary_ip4", p)
	}
	if _, ok := p["primary_ip6"]; ok {
		t.Errorf("VM patch %v touched primary_ip6, which names an address this delete keeps", p)
	}
}

func TestDeleteInterfaceRefusesWhenADetachFails(t *testing.T) {
	// The delete would destroy the address the failed detach left attached.
	d := &detachRecorder{gets: ifaceOn61, failPatch: "900", page: `{"results":[
		{"id":900,"address":"10.0.0.9/24","assigned_object_type":"virtualization.vminterface","assigned_object_id":61,"custom_fields":{}}
	],"next":null}`}
	c := testClient(t, d.handler(t))
	err := c.DeleteInterface(context.Background(), 61)
	if err == nil {
		t.Fatal("DeleteInterface succeeded although the detach of address 900 failed")
	}
	if indexOf(d.requests(), "DELETE") >= 0 {
		t.Fatalf("interface deleted after a failed detach: %q", d.requests())
	}
}

func TestDeleteInterfaceSkipsAnAddressGoneBeforeItsDetach(t *testing.T) {
	// The address was deleted between the list and its PATCH. That is not the
	// interface being gone: the delete goes on, and no 404 escapes to read as
	// "already absent".
	d := &detachRecorder{gets: ifaceOn61, failPatch: "900", failStatus: http.StatusNotFound,
		page: `{"results":[
		{"id":900,"address":"10.0.0.9/24","assigned_object_type":"virtualization.vminterface","assigned_object_id":61,"custom_fields":{}}
	],"next":null}`}
	c := testClient(t, d.handler(t))
	if err := c.DeleteInterface(context.Background(), 61); err != nil {
		t.Fatalf("a vanished address failed the delete: %v", err)
	}
	if last := d.requests()[len(d.requests())-1]; last != "DELETE "+vmInterfacesPath+"61/" {
		t.Fatalf("last request = %q, want the interface delete", last)
	}
}

func TestDeleteInterfaceFailureIsNotReadAsAbsence(t *testing.T) {
	// A failure on the way to the DELETE is never a 404 to the caller: only the
	// DELETE (or the interface itself being gone) proves absence.
	gets := map[string]string{vmInterfacesPath + "61/": `{"id":61,"name":"eth0","virtual_machine":{"id":40}}`}
	d := &detachRecorder{gets: gets, page: `{"results":[
		{"id":900,"address":"10.0.0.9/24","assigned_object_type":"virtualization.vminterface","assigned_object_id":61,"custom_fields":{}}
	],"next":null}`}
	c := testClient(t, d.handler(t))
	err := c.DeleteInterface(context.Background(), 61)
	if err == nil {
		t.Fatal("DeleteInterface succeeded although its VM could not be read")
	}
	var ae *APIError
	if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
		t.Fatalf("the VM read's 404 escaped as %v; the caller would retire a live interface's mapping", err)
	}
}

func TestDeleteVMClearsItsPrimariesBeforeDetaching(t *testing.T) {
	gets := map[string]string{
		vmsPath + "40/": `{"id":40,"name":"vm-1","primary_ip4":{"id":910},"primary_ip6":null}`,
	}
	d := &detachRecorder{gets: gets, page: `{"results":[
		{"id":910,"address":"10.0.0.20/24","assigned_object_type":"virtualization.vminterface","assigned_object_id":70,"assigned_object":{"id":70,"virtual_machine":{"id":40}},"custom_fields":{}}
	],"next":null}`}
	c := testClient(t, d.handler(t))
	if err := c.DeleteVM(context.Background(), 40); err != nil {
		t.Fatal(err)
	}
	got := d.requests()
	vmPatch, ipPatch := indexOf(got, "PATCH "+vmsPath+"40/"), indexOf(got, "PATCH "+ipAddressesPath+"910/")
	if vmPatch < 0 || ipPatch < 0 || vmPatch > ipPatch {
		t.Fatalf("requests = %q, want the VM's primaries cleared BEFORE its address is detached", got)
	}
	if v, ok := d.vmPatches[0]["primary_ip4"]; !ok || v != nil {
		t.Errorf("VM patch %v must null primary_ip4", d.vmPatches[0])
	}
}

func TestDeleteVMDetachesItsInterfacesAddressesFirst(t *testing.T) {
	// 910 sits on an interface of VM 40 and must be detached; 911 sits on an
	// interface of VM 41, which only a server ignoring the filter would return.
	gets := map[string]string{vmsPath + "40/": `{"id":40,"name":"vm-1"}`}
	d := &detachRecorder{gets: gets, page: `{"results":[
		{"id":910,"address":"10.0.0.20/24","assigned_object_type":"virtualization.vminterface","assigned_object_id":70,"assigned_object":{"id":70,"virtual_machine":{"id":40}},"custom_fields":{}},
		{"id":911,"address":"10.0.0.21/24","assigned_object_type":"virtualization.vminterface","assigned_object_id":71,"assigned_object":{"id":71,"virtual_machine":{"id":41}},"custom_fields":{}}
	],"next":null}`}
	c := testClient(t, d.handler(t))
	if err := c.DeleteVM(context.Background(), 40); err != nil {
		t.Fatal(err)
	}
	got := d.requests()
	if p := patchesOf(got, ipAddressesPath); len(p) != 1 || p[0] != "PATCH "+ipAddressesPath+"910/" {
		t.Errorf("detaches = %q, want exactly address 910", p)
	}
	if last := got[len(got)-1]; last != "DELETE "+vmsPath+"40/" {
		t.Errorf("last request = %q, want the VM delete AFTER the detach", last)
	}
	if i := indexOf(got, "GET "+ipAddressesPath+"?"); i < 0 || !strings.Contains(got[i], "virtual_machine_id=40") {
		t.Errorf("requests = %q, want an address list scoped to virtual_machine_id=40", got)
	}
}

func TestDeleteVMRefusesAnAddressWhoseVMItCannotRead(t *testing.T) {
	// An interface address with no nested VM cannot be re-checked. Skipping it
	// would leave it to the cascade — the destruction this exists to prevent —
	// so the delete is refused instead.
	gets := map[string]string{vmsPath + "40/": `{"id":40,"name":"vm-1"}`}
	d := &detachRecorder{gets: gets, page: `{"results":[
		{"id":910,"address":"10.0.0.20/24","assigned_object_type":"virtualization.vminterface","assigned_object_id":70,"assigned_object":{"id":70},"custom_fields":{}}
	],"next":null}`}
	c := testClient(t, d.handler(t))
	if err := c.DeleteVM(context.Background(), 40); err == nil {
		t.Fatal("DeleteVM went ahead with an address whose VM it could not read")
	}
	if indexOf(d.requests(), "DELETE") >= 0 {
		t.Fatalf("VM deleted with an unverifiable address on it: %q", d.requests())
	}
}

func TestDeleteInterfaceRefusesAnAddressItMayViewButNotChange(t *testing.T) {
	// NetBox scopes a PATCH to the objects the token may CHANGE and a GET to
	// those it may VIEW, so a token that sees an operator's address but may
	// not change it gets a 404 on the detach. That is not the address being
	// gone: it is still attached, and the interface DELETE would cascade it
	// away. Only a GET that also 404s proves it gone.
	gets := map[string]string{
		vmInterfacesPath + "61/": `{"id":61,"name":"eth0","virtual_machine":{"id":40}}`,
		vmsPath + "40/":          `{"id":40,"name":"vm-1"}`,
		ipAddressesPath + "900/": `{"id":900,"address":"10.0.0.9/24","assigned_object_type":"virtualization.vminterface","assigned_object_id":61,"custom_fields":{}}`,
	}
	d := &detachRecorder{gets: gets, failPatch: "900", failStatus: http.StatusNotFound,
		page: `{"results":[
		{"id":900,"address":"10.0.0.9/24","assigned_object_type":"virtualization.vminterface","assigned_object_id":61,"custom_fields":{}}
	],"next":null}`}
	c := testClient(t, d.handler(t))
	err := c.DeleteInterface(context.Background(), 61)
	if err == nil {
		t.Fatal("DeleteInterface went ahead although address 900 is still attached")
	}
	var ae *APIError
	if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
		t.Fatalf("the refusal escaped as a 404 (%v); the caller would read the interface as gone", err)
	}
	if indexOf(d.requests(), "DELETE") >= 0 {
		t.Fatalf("interface deleted with an address still attached: %q", d.requests())
	}
}
