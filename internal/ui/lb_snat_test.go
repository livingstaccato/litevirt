package ui

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func lbCreateForm(extra url.Values) url.Values {
	f := url.Values{
		"name": {"web-lb"}, "vip": {"10.0.100.50/24"}, "algorithm": {"roundrobin"},
		"listen": {"80"}, "target": {"8080"}, "protocol": {"tcp"},
	}
	for k, v := range extra {
		f[k] = v
	}
	return f
}

// The create form's SNAT checkbox is off unless ticked, and what it says is
// what the create RPC is asked for.
func TestCreateLB_SNATCheckbox(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra url.Values
		want  bool
	}{
		{"unticked", nil, false},
		{"ticked", url.Values{"snat": {"true"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := newDefaultMock()
			s := newTestUIServer(t, mock)
			w := serveRequest(s, formPost(t, "/ui/lb", lbCreateForm(tc.extra)))
			assertStatus(t, w, http.StatusOK)
			if mock.createLBReq == nil {
				t.Fatal("CreateLoadBalancer not called")
			}
			if got := mock.createLBReq.GetSnat(); got != tc.want {
				t.Errorf("create snat = %v, want %v", got, tc.want)
			}
		})
	}
}

// The create form offers the checkbox, unchecked.
func TestLBCreateModal_HasSNATCheckbox(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	r, err := http.NewRequest("GET", "/ui/lb/create-modal", nil)
	if err != nil {
		t.Fatal(err)
	}
	w := serveRequest(s, withAuth(r))
	assertStatus(t, w, http.StatusOK)
	body := w.Body.String()
	if !strings.Contains(body, `name="snat"`) || !strings.Contains(body, "SNAT (outbound NAT via the VIP)") {
		t.Errorf("create modal has no SNAT checkbox:\n%s", body)
	}
	i := strings.Index(body, `name="snat"`)
	if i < 0 {
		return
	}
	tag := body[strings.LastIndex(body[:i], "<") : i+strings.Index(body[i:], ">")]
	if strings.Contains(tag, "checked") {
		t.Errorf("SNAT checkbox is checked by default: %s", tag)
	}
}

// A create the server refuses because the cluster is mid-upgrade says so in the
// UI's terms, not the CLI's --snat.
func TestCreateLB_PreLatchRefusalSpeaksUI(t *testing.T) {
	mock := newDefaultMock()
	mock.createLBErr = status.Errorf(codes.FailedPrecondition,
		"load balancer %q: %v. Create it with --snat, or without it once failover_scope_v1 shows as latched in `lv cluster upgrade-status`",
		"web-lb", corrosion.ErrLBSNATGateClosed)
	s := newTestUIServer(t, mock)
	w := serveRequest(s, formPost(t, "/ui/lb", lbCreateForm(nil)))
	assertStatus(t, w, http.StatusBadRequest)
	trig := w.Header().Get("HX-Trigger")
	if !strings.Contains(trig, "SNAT") || !strings.Contains(trig, "upgrading") {
		t.Errorf("toast = %q, want SNAT and upgrading advice", trig)
	}
	if strings.Contains(trig, "--snat") || strings.Contains(trig, "lv cluster") {
		t.Errorf("toast = %q speaks CLI", trig)
	}
}

// Another refusal is shown as the server worded it.
func TestCreateLB_OtherRefusalUnchanged(t *testing.T) {
	mock := newDefaultMock()
	mock.createLBErr = status.Error(codes.FailedPrecondition, "VIP is held elsewhere")
	s := newTestUIServer(t, mock)
	w := serveRequest(s, formPost(t, "/ui/lb", lbCreateForm(nil)))
	assertStatus(t, w, http.StatusBadRequest)
	assertToast(t, w, "VIP is held elsewhere")
}

// The LB list and detail show SNAT as on, off, or unknown (never off for an
// LB whose setting the daemon could not read).
func TestLBPages_SNATOnOffUnknown(t *testing.T) {
	mock := newDefaultMock()
	mock.listLBsResp = &pb.ListLBResponse{Lbs: []*pb.LoadBalancer{
		{Name: "plain", State: "active", Snat: proto.Bool(false)},
		{Name: "unread", State: "active"},
	}}
	s := newTestUIServer(t, mock)
	r, _ := http.NewRequest("GET", "/lb", nil)
	w := serveRequest(s, withAuth(r))
	assertStatus(t, w, http.StatusOK)
	body := w.Body.String()
	if !strings.Contains(body, "<th>SNAT</th>") {
		t.Fatalf("no SNAT column:\n%s", body)
	}
	row := func(name string) string {
		i := strings.Index(body, `/lb/`+name+`"`)
		if i < 0 {
			t.Fatalf("no row for %s", name)
		}
		j := strings.Index(body[i:], "</tr>")
		return body[i : i+j]
	}
	if r := row("plain"); !strings.Contains(r, "<td>off</td>") {
		t.Errorf("plain row has no SNAT off: %s", r)
	}
	if r := row("unread"); !strings.Contains(r, "<td>unknown</td>") || strings.Contains(r, "<td>off</td>") {
		t.Errorf("unread row is not SNAT unknown: %s", r)
	}
}
