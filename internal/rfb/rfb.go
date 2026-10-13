// Package rfb terminates the security handshake of the RFB (VNC) protocol,
// RFC 6143 §7.1–7.2, for the daemon's console proxy.
//
// A VM's VNC listener requires a password (docs/ui.md "Console passwords").
// The daemon on the VM's host is the only party that knows it: it
// authenticates to the listener with Authenticate, then presents the viewer
// with a handshake offering only security type None (ServeNoAuth), and from
// there relays bytes unchanged. Everything after the security handshake —
// ClientInit, ServerInit and the protocol proper — is identical in RFB 3.3,
// 3.7 and 3.8, so the two sides need not have agreed on the same minor
// version.
//
// So the viewer (noVNC in the web UI, behind any number of daemons that only
// relay) never sees the password, and a peer on an older build relaying the
// stream needs no change.
package rfb

import (
	"crypto/des"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"strconv"
	"strings"
)

const (
	secInvalid = 0
	secNone    = 1
	secVNCAuth = 2
)

// secTypeNames names the security types a listener offered, for an error.
func secTypeNames(types []byte) string {
	names := map[byte]string{secNone: "None", secVNCAuth: "VNC authentication", 16: "Tight", 18: "TLS", 19: "VeNCrypt", 20: "SASL"}
	out := make([]string, 0, len(types))
	for _, t := range types {
		if n, ok := names[t]; ok {
			out = append(out, fmt.Sprintf("%s (%d)", n, t))
		} else {
			out = append(out, strconv.Itoa(int(t)))
		}
	}
	return strings.Join(out, ", ")
}

// ErrAuthFailed is the listener refusing the password.
var ErrAuthFailed = errors.New("VNC authentication failed")

// maxReason caps a failure reason the listener sends, so a confused or
// hostile peer cannot make us allocate without bound.
const maxReason = 4096

// parseVersion returns the minor version of an RFB ProtocolVersion message
// ("RFB 003.008\n"), mapped as RFC 6143 §7.1.1 says a server must: anything
// at or above 8 is 3.8, 7 is 3.7, anything else is 3.3.
func parseVersion(b []byte) (int, error) {
	if len(b) != 12 || string(b[:4]) != "RFB " || b[7] != '.' || b[11] != '\n' {
		return 0, fmt.Errorf("not an RFB protocol version: %q", b)
	}
	major, err1 := strconv.Atoi(string(b[4:7]))
	minor, err2 := strconv.Atoi(string(b[8:11]))
	if err1 != nil || err2 != nil || major != 3 {
		return 0, fmt.Errorf("unsupported RFB protocol version: %q", b)
	}
	switch {
	case minor >= 8:
		return 8, nil
	case minor == 7:
		return 7, nil
	default:
		return 3, nil
	}
}

func versionMessage(minor int) []byte {
	return []byte(fmt.Sprintf("RFB 003.%03d\n", minor))
}

func readU32(r io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

func writeU32(w io.Writer, v uint32) error {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	_, err := w.Write(b[:])
	return err
}

// readReason reads a length-prefixed failure reason.
func readReason(r io.Reader) string {
	n, err := readU32(r)
	if err != nil || n > maxReason {
		return ""
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return ""
	}
	return string(b)
}

// AuthResponse is the VNC authentication response to challenge: the
// challenge DES-encrypted, as two ECB blocks, under a key made of the
// password's first eight bytes (zero-padded), each with its bits reversed.
// The eight-byte key is the protocol's: a longer password adds nothing.
func AuthResponse(challenge [16]byte, password string) ([16]byte, error) {
	var key [8]byte
	copy(key[:], password)
	for i := range key {
		key[i] = bits.Reverse8(key[i])
	}
	c, err := des.NewCipher(key[:])
	if err != nil {
		return [16]byte{}, err
	}
	var out [16]byte
	c.Encrypt(out[:8], challenge[:8])
	c.Encrypt(out[8:], challenge[8:])
	return out, nil
}

// Authenticate performs the client half of the RFB handshake against a VNC
// listener, up to and including the security result, answering a VNC
// authentication challenge with password. On success the listener expects
// ClientInit next. A listener offering None is accepted as it is.
func Authenticate(rw io.ReadWriter, password string) error {
	return authenticate(rw, password, false)
}

// ErrNoVNCAuth is a listener that does not offer VNC authentication.
var ErrNoVNCAuth = errors.New("the listener does not offer VNC authentication")

// AuthenticateVNC is Authenticate that accepts only VNC authentication: a
// listener offering None (no password asked for) fails with ErrNoVNCAuth. It
// is what proves a password is ENFORCED, not merely accepted.
func AuthenticateVNC(rw io.ReadWriter, password string) error {
	return authenticate(rw, password, true)
}

func authenticate(rw io.ReadWriter, password string, requireVNC bool) error {
	ver := make([]byte, 12)
	if _, err := io.ReadFull(rw, ver); err != nil {
		return fmt.Errorf("read the listener's protocol version: %w", err)
	}
	minor, err := parseVersion(ver)
	if err != nil {
		return err
	}
	if _, err := rw.Write(versionMessage(minor)); err != nil {
		return fmt.Errorf("send protocol version: %w", err)
	}

	var sec byte
	if minor == 3 {
		t, err := readU32(rw)
		if err != nil {
			return fmt.Errorf("read security type: %w", err)
		}
		if t == secInvalid {
			return fmt.Errorf("the listener refused the connection: %s", readReason(rw))
		}
		if t > 255 {
			return fmt.Errorf("unsupported security type %d", t)
		}
		sec = byte(t)
	} else {
		n := make([]byte, 1)
		if _, err := io.ReadFull(rw, n); err != nil {
			return fmt.Errorf("read security types: %w", err)
		}
		if n[0] == 0 {
			return fmt.Errorf("the listener refused the connection: %s", readReason(rw))
		}
		types := make([]byte, n[0])
		if _, err := io.ReadFull(rw, types); err != nil {
			return fmt.Errorf("read security types: %w", err)
		}
		for _, t := range types {
			if t == secVNCAuth {
				sec = secVNCAuth
				break
			}
			if t == secNone {
				sec = secNone
			}
		}
		if sec == 0 {
			return fmt.Errorf("the listener offers no security type the console proxy supports (offered %s); "+
				"a VNC console with TLS or SASL (vnc_tls / vnc_sasl in qemu.conf) is not supported", secTypeNames(types))
		}
		if requireVNC && sec != secVNCAuth {
			return fmt.Errorf("%w (offered %s)", ErrNoVNCAuth, secTypeNames(types))
		}
		if _, err := rw.Write([]byte{sec}); err != nil {
			return fmt.Errorf("send security type: %w", err)
		}
	}
	if requireVNC && sec != secVNCAuth {
		return fmt.Errorf("%w (offered %s)", ErrNoVNCAuth, secTypeNames([]byte{sec}))
	}

	switch sec {
	case secNone:
		// RFC 6143: in 3.8 a SecurityResult follows even None; in 3.3 and
		// 3.7 nothing does.
		if minor < 8 {
			return nil
		}
	case secVNCAuth:
		var challenge [16]byte
		if _, err := io.ReadFull(rw, challenge[:]); err != nil {
			return fmt.Errorf("read VNC authentication challenge: %w", err)
		}
		resp, err := AuthResponse(challenge, password)
		if err != nil {
			return err
		}
		if _, err := rw.Write(resp[:]); err != nil {
			return fmt.Errorf("send VNC authentication response: %w", err)
		}
	default:
		return fmt.Errorf("unsupported security type %d", sec)
	}

	res, err := readU32(rw)
	if err != nil {
		return fmt.Errorf("read security result: %w", err)
	}
	if res != 0 {
		if minor >= 8 {
			if r := readReason(rw); r != "" {
				return fmt.Errorf("%w: %s", ErrAuthFailed, r)
			}
		}
		return ErrAuthFailed
	}
	return nil
}

// ServeNoAuth performs the server half of the RFB handshake toward a viewer,
// offering security type None only. backend, when not nil, runs after the
// viewer has chosen and before it is told the result: the caller
// authenticates to the listener there, so a viewer that never gets this far
// holds no authenticated listener connection, and a listener that refuses
// reaches a 3.8 viewer as a failed security result (3.3: a refused
// connection). backend's error is returned as it is. After ServeNoAuth
// returns nil the viewer sends ClientInit, which belongs to that listener.
func ServeNoAuth(rw io.ReadWriter, backend func() error) error {
	if _, err := rw.Write(versionMessage(8)); err != nil {
		return fmt.Errorf("send protocol version: %w", err)
	}
	ver := make([]byte, 12)
	if _, err := io.ReadFull(rw, ver); err != nil {
		return fmt.Errorf("read the viewer's protocol version: %w", err)
	}
	minor, err := parseVersion(ver)
	if err != nil {
		return err
	}
	runBackend := func() error {
		if backend == nil {
			return nil
		}
		return backend()
	}
	const refused = "the console could not be opened"
	if minor == 3 {
		if err := runBackend(); err != nil {
			_ = writeU32(rw, secInvalid)
			_ = writeU32(rw, uint32(len(refused)))
			_, _ = rw.Write([]byte(refused))
			return err
		}
		return writeU32(rw, secNone)
	}
	if _, err := rw.Write([]byte{1, secNone}); err != nil {
		return fmt.Errorf("send security types: %w", err)
	}
	pick := make([]byte, 1)
	if _, err := io.ReadFull(rw, pick); err != nil {
		return fmt.Errorf("read the viewer's security type: %w", err)
	}
	if pick[0] != secNone {
		if minor >= 8 {
			reason := "only security type None is offered"
			_ = writeU32(rw, 1)
			_ = writeU32(rw, uint32(len(reason)))
			_, _ = rw.Write([]byte(reason))
		}
		return fmt.Errorf("the viewer chose security type %d, which was not offered", pick[0])
	}
	if err := runBackend(); err != nil {
		if minor >= 8 {
			_ = writeU32(rw, 1)
			_ = writeU32(rw, uint32(len(refused)))
			_, _ = rw.Write([]byte(refused))
		}
		return err
	}
	if minor >= 8 {
		return writeU32(rw, 0)
	}
	return nil
}
