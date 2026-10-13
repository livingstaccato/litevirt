// Fleet scenario: who a console session is logged as (lab-1 F2 on
// fix/spice-listen-address).
//
// A console a user opens through another host reaches the VM's host as a
// relayed call from the entry daemon, authenticated by its host certificate.
// The VM's host must not log that as the user "admin" (the peer identity the
// call carries), and the entry host — the only one that knows the user —
// must log the session itself.
package fleet

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// sessionLines returns the captured log lines carrying msg.
func sessionLines(logs *lockedBuffer, msg string) []string {
	var out []string
	for _, l := range strings.Split(logs.String(), "\n") {
		if strings.Contains(l, `msg="`+msg) {
			out = append(out, l)
		}
	}
	return out
}

// checkSessionAttribution: the entry host logged start and end for user,
// naming the owner; the owner's lines name the relaying peer, never a user.
func checkSessionAttribution(t *testing.T, logs *lockedBuffer, kind, user string, relay, owner *Node) {
	t.Helper()
	for _, phase := range []string{"started", "ended"} {
		msg := kind + " proxy session " + phase
		var entry, relayed bool
		eventually(t, 5*time.Second, "the "+phase+" lines for "+kind, func() bool {
			entry, relayed = false, false
			for _, l := range sessionLines(logs, msg) {
				if strings.Contains(l, " user="+user) && strings.Contains(l, " owner="+owner.Name) {
					entry = true
				}
				if strings.Contains(l, " via_peer="+relay.Name) {
					relayed = true
				}
			}
			return entry && relayed
		})
		for _, l := range sessionLines(logs, msg) {
			if strings.Contains(l, " user=admin") {
				t.Errorf("%s: a session %s logged as user=admin (the relaying peer's identity):\n%s", kind, phase, l)
			}
			if strings.Contains(l, " via_peer=") && strings.Contains(l, " user=") {
				t.Errorf("%s: the owner's line names a user it only has the peer's word for:\n%s", kind, l)
			}
		}
		if !entry {
			t.Errorf("%s: no %q line on the entry host for user=%s owner=%s:\n%s", kind, msg, user, owner.Name, logs.String())
		}
		if !relayed {
			t.Errorf("%s: no %q line on the owner naming via_peer=%s", kind, msg, relay.Name)
		}
	}
}

// TestFleet_ConsoleSession_LoggedAsTheUserOnTheEntryHost: bob opens a SPICE
// channel and a VNC console entering on relay, for VMs on owner.
//
// Mutation "entry host logs nothing on a forward" — red.
// Mutation "owner logs user=callerUsername for a relayed call" — red.
func TestFleet_ConsoleSession_LoggedAsTheUserOnTheEntryHost(t *testing.T) {
	c := consoleCluster(t)
	relay, owner := c.Nodes[0], c.Nodes[1]
	createConsoleVM(t, c, relay, "desk", owner.Name, true)
	sl := startSpiceListener(t)
	owner.Virt.SetSpicePort("desk", sl.port())
	relay.Virt.SetSpicePort("desk", 1)
	vl := startVNCListener(t, consolePassword(t, owner, "desk", "vnc"))
	owner.Virt.SetVNCPort("desk", vl.port())

	ctx := context.Background()
	admin := c.SelfClient(relay)
	if _, err := admin.CreateUser(ctx, &pb.CreateUserRequest{Username: "bob", Password: "bobs-password-0123456789", Role: "operator"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	login, err := admin.Login(ctx, &pb.LoginRequest{Username: "bob", Password: "bobs-password-0123456789"})
	if err != nil {
		t.Fatalf("bob's login on %s: %v", relay.Name, err)
	}
	bob := c.bearerClient(relay, login.Token)
	logs := captureLogs(t)

	// SPICE: one channel, opened and closed.
	sctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	st, err := bob.ProxySpice(metadata.NewOutgoingContext(sctx, metadata.Pairs("x-vm-name", "desk")))
	if err != nil {
		t.Fatalf("ProxySpice as bob: %v", err)
	}
	greet := make([]byte, len(spiceGreeting))
	if _, err := io.ReadFull(&spiceStreamReader{st: st}, greet); err != nil {
		t.Fatalf("bob's SPICE channel: %v", err)
	}
	_ = st.CloseSend()
	cancel()
	checkSessionAttribution(t, logs, "SPICE", "bob", relay, owner)

	// VNC: the same shape.
	if _, init, err := viewVNCVia(t, bob, "desk"); err != nil || len(init) == 0 {
		t.Fatalf("bob's VNC console through %s: init %q, %v", relay.Name, init, err)
	}
	checkSessionAttribution(t, logs, "VNC", "bob", relay, owner)
}
