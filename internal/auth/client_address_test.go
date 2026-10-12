package auth

import (
	"net/http/httptest"
	"testing"
)

// TestClientAddress_TrustedProxies (re-review N1): a forwarding header is
// believed only from a configured trusted proxy, and then only up to the
// right-most hop no trusted proxy vouches for.
func TestClientAddress_TrustedProxies(t *testing.T) {
	trusted, err := ParseTrustedProxies([]string{"127.0.0.1", "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, peer, xff string
		trusted         bool
		want            string
	}{
		{"no trusted proxies: the peer, header ignored", "127.0.0.1:5000", "198.51.100.7", false, "127.0.0.1"},
		{"untrusted peer: header ignored", "203.0.113.9:5000", "198.51.100.7", true, "203.0.113.9"},
		{"trusted peer: the forwarded client", "127.0.0.1:5000", "198.51.100.7", true, "198.51.100.7"},
		{"a spoofed left-most hop is not believed", "127.0.0.1:5000", "6.6.6.6, 198.51.100.7", true, "198.51.100.7"},
		{"a chain of trusted proxies is skipped", "127.0.0.1:5000", "198.51.100.7, 10.1.2.3", true, "198.51.100.7"},
		{"a non-address hop falls back to its proxy", "127.0.0.1:5000", "10.9.9.9, garbage", true, "127.0.0.1"},
		{"trusted peer, no header: the peer", "127.0.0.1:5000", "", true, "127.0.0.1"},
		{"an IPv4-mapped hop is its IPv4 form", "127.0.0.1:5000", "::ffff:198.51.100.7", true, "198.51.100.7"},
		{"a hop with a port is its address", "127.0.0.1:5000", "198.51.100.7:51234", true, "198.51.100.7"},
		{"an IPv6 hop with a port", "127.0.0.1:5000", "[2001:db8::7]:443", true, "2001:db8::7"},
		{"a non-address hop falls back to the trusted hop that recorded it", "127.0.0.1:5000", "unknown, 10.9.9.9", true, "10.9.9.9"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.peer
		if tc.xff != "" {
			r.Header.Set("X-Forwarded-For", tc.xff)
		}
		tp := trusted
		if !tc.trusted {
			tp = nil
		}
		if got := ClientAddress(r, tp); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	if _, err := ParseTrustedProxies([]string{"not-a-cidr"}); err == nil {
		t.Error("a bad trusted_proxies entry parsed")
	}
}

// TestClientAddress_SeveralHeaderLines (re-review 2, M4): X-Forwarded-For on
// several lines is one list in order (RFC 9110 §5.3); the right-most line is
// the nearest proxy's.
func TestClientAddress_SeveralHeaderLines(t *testing.T) {
	trusted, _ := ParseTrustedProxies([]string{"127.0.0.1", "10.0.0.0/8"})
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Add("X-Forwarded-For", "6.6.6.6")
	r.Header.Add("X-Forwarded-For", "198.51.100.7, 10.1.2.3")
	if got := ClientAddress(r, trusted); got != "198.51.100.7" {
		t.Fatalf("%q, want the right-most untrusted hop across both lines", got)
	}
	r.Header.Del("X-Forwarded-For")
	r.Header.Add("X-Forwarded-For", "6.6.6.6, 198.51.100.7")
	r.Header.Add("X-Forwarded-For", "10.1.2.3")
	if got := ClientAddress(r, trusted); got != "198.51.100.7" {
		t.Fatalf("%q, want 198.51.100.7 (only the first line read?)", got)
	}
}
