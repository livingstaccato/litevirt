package rfb

import (
	"errors"
	"io"
	"net"
	"testing"
)

// AuthenticateVNC refuses a listener that offers only None: it must prove a
// password is enforced, not merely that the listener lets us in. One that
// offers VNC authentication goes on to it (and here fails for want of a
// challenge, which is not ErrNoVNCAuth).
//
// Mutation "requireVNC ignored" — red.
func TestAuthenticateVNC_RefusesAListenerOfferingNone(t *testing.T) {
	for _, offered := range [][]byte{{1, 1}, {2, 1, 2}} {
		proxy, qemu := net.Pipe()
		go func(types []byte) {
			defer qemu.Close()
			_, _ = qemu.Write([]byte("RFB 003.008\n"))
			ver := make([]byte, 12)
			_, _ = io.ReadFull(qemu, ver)
			_, _ = qemu.Write(types)
			pick := make([]byte, 1)
			_, _ = io.ReadFull(qemu, pick)
		}(offered)
		err := AuthenticateVNC(proxy, "x")
		if offered[0] == 1 && !errors.Is(err, ErrNoVNCAuth) {
			t.Errorf("offered None only: err = %v, want ErrNoVNCAuth", err)
		}
		if offered[0] == 2 && errors.Is(err, ErrNoVNCAuth) {
			t.Errorf("offered VNC authentication too, but got ErrNoVNCAuth")
		}
		proxy.Close()
	}
}
