package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// (re-review rr2 5) Characters, lengths and forms the interactive refusal
// takes: every one is refused interactively and nothing is sent, but a
// visible homoglyph, which is plain text (accepted: it cannot disguise a
// dangerous directory, only make a harmless one look like another).
//
// Mutations: accept any graphic character (drop the Zs/Mn/Me/ignorable/
// filler rule) — red; drop the length cap — red; drop the clean-form check
// — red; drop the spacing rule — red.
func TestRR2Probe_N1Bypasses(t *testing.T) {
	long := "/srv/vmpool/" + strings.Repeat("x/", 400) + strings.Repeat("../", 402) + "var/lib/polkit-1/localauthority/50-local.d"
	cases := []struct {
		label  string
		source string
		target string
	}{
		{"RLO U+202E (Cf)", "", "/srv/da‮ta"},
		{"ZWSP U+200B (Cf)", "", "/srv/vm​pool"},
		{"ZWJ U+200D (Cf)", "", "/srv/vm‍pool"},
		{"BOM U+FEFF (Cf)", "", "/srv/vm" + string(rune(0xFEFF)) + "pool"},
		{"tag U+E0041 (Cf)", "", "/srv/vm\U000E0041pool"},
		{"NEL U+0085 (Cc)", "", "/srv/vm\u0085pool"},
		{"LINE SEP U+2028 (Zl)", "", "/srv/vm pool"},
		{"PARA SEP U+2029 (Zp)", "", "/srv/vm pool"},
		{"variation selector U+FE0F (Mn)", "", "/srv/vm️pool"},
		{"combining grapheme joiner U+034F (Mn)", "", "/srv/vm͏pool"},
		{"Hangul filler U+3164 (Lo)", "", "/srv/vmㅤpool"},
		{"braille blank U+2800 (So)", "", "/srv/vm⠀pool"},
		{"NBSP U+00A0 (Zs)", "", "/srv/vm pool"},
		{"combining stack x500 U+0336 (Mn)", "", "/srv/vmpool" + strings.Repeat("̶", 500)},
		{"Cyrillic homoglyph a U+0430", "", "/srv/vmpoоl"},
		{"Hebrew RTL run (Lo, implicit bidi)", "", "/srv/אב/../../var/lib/polkit-1/x"},
		{"non-clean long traversal", "", long},
		{"source padded with spaces + fake target line", strings.Repeat(" ", 300) + "  target:        /srv/vmpool", "/var/lib/polkit-1/localauthority/50-local.d"},
	}
	for _, c := range cases {
		h := &trustHost{row: &pb.StoragePool{Name: "data", Host: "h1", Driver: "dir", Source: c.source, Target: c.target}}
		var out bytes.Buffer
		err := runPoolTrust(context.Background(), h, "data", "h1", poolTrustExpect{}, true, strings.NewReader("y\n"), &out)
		refused := err != nil && strings.Contains(err.Error(), "--expect-")
		shown := out.String()
		if len(shown) > 160 {
			shown = shown[:160] + "..."
		}
		t.Logf("%-45s refused=%-5t sent=%d len(out)=%d out=%q", c.label, refused, len(h.confirmed), out.Len(), shown)
		wantRefused := !strings.Contains(c.label, "homoglyph")
		if refused != wantRefused || (wantRefused && len(h.confirmed) != 0) {
			t.Errorf("%s: refused=%t sent=%d, want refused=%t", c.label, refused, len(h.confirmed), wantRefused)
		}
		if out.Len() > 6*trustFieldMax+512 {
			t.Errorf("%s: the preview printed %d bytes: a field is not cut", c.label, out.Len())
		}
	}
}
