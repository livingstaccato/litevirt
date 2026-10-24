package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// (re-review rr3 6) More bypass candidates, and legitimate paths the
// plain-rune and spacing rules refuse. Every candidate but the visible glyphs
// (U+FFFC, a fullwidth solidus, a clean Hebrew path) is refused
// interactively, and the refusal points at --expect-*; every one, refused or
// not, confirms with the exact --expect-target.
//
// Mutations: drop the --expect-* pointer from the refusal — red; accept a
// legitimate path's exact --expect-target only after cleaning it on one side
// — red.
func TestRR3Probe_N1MoreCasesAndLegitPaths(t *testing.T) {
	cases := []struct{ label, target string }{
		// bypass candidates
		{"ideographic space U+3000 (Zs)", "/srv/vm　pool"},
		{"soft hyphen U+00AD (Cf)", "/srv/vm­pool"},
		{"LRI U+2066 (Cf)", "/srv/vm⁦pool"},
		{"tag space U+E0020 (Cf)", "/srv/vm\U000E0020pool"},
		{"musical end-phrase U+1D17A (Cf)", "/srv/vm\U0001D17Apool"},
		{"Khmer inherent vowel U+17B4 (Mn)", "/srv/vm឴pool"},
		{"private use U+E000 (Co)", "/srv/vmpool"},
		{"unassigned U+0378 (Cn)", "/srv/vm͸pool"},
		{"object replacement U+FFFC (So)", "/srv/vm￼pool"},
		{"fullwidth solidus U+FF0F", "/srv/vmpool／..／etc"},
		{"Hebrew clean path (implicit bidi)", "/srv/אב/1/2/ג"},
		{"Arabic letter mark U+061C (Cf)", "/srv/vm؜pool"},
		{"Hangul choseong filler U+115F", "/srv/vmᅟpool"},
		{"Mongolian FVS U+180B (Mn)", "/srv/vm᠋pool"},
		{"tab", "/srv/vm\tpool"},
		{"dot-dot only", "/srv/vmpool/.."},
		{"trailing slash", "/srv/vmpool/"},
		{"double slash", "/srv//vmpool"},
		// legitimate names
		{"LEGIT plain", "/srv/vmpool"},
		{"LEGIT single inner space", "/srv/My VMs"},
		{"LEGIT double inner space", "/srv/My  VMs"},
		{"LEGIT trailing space", "/srv/vms "},
		{"LEGIT leading-space component", "/srv/ vms"},
		{"LEGIT CJK", "/srv/東京"},
		{"LEGIT NFC accent", "/srv/café"},
		{"LEGIT NFD accent (Mn U+0301)", "/srv/café"},
		{"LEGIT Devanagari (virama Mn)", "/srv/हिन्दी"},
		{"LEGIT Thai (Mn vowel)", "/srv/ที่"},
		{"LEGIT Japanese ideographic space", "/srv/データ　プール"},
		{"LEGIT emoji with VS16", "/srv/❤️"},
	}
	for _, c := range cases {
		h := &trustHost{row: &pb.StoragePool{Name: "data", Host: "h1", Driver: "dir", Target: c.target}}
		var out bytes.Buffer
		err := runPoolTrust(context.Background(), h, "data", "h1", poolTrustExpect{}, true, strings.NewReader("y\n"), &out)
		refused := err != nil && strings.Contains(err.Error(), "--expect-")
		why := ""
		if err != nil {
			why = err.Error()
			if i := strings.Index(why, ", so what"); i > 0 {
				why = why[:i]
			}
		}
		h2 := &trustHost{row: &pb.StoragePool{Name: "data", Host: "h1", Driver: "dir", Target: c.target}}
		eerr := runPoolTrust(context.Background(), h2, "data", "h1", poolTrustExpect{driver: "dir", target: c.target}, false, nil, &bytes.Buffer{})
		t.Logf("%-40s interactive_refused=%-5t sent=%d expect_ok=%-5t why=%q", c.label, refused, len(h.confirmed), eerr == nil, why)
		if eerr != nil {
			t.Errorf("%s: --expect-target with the exact value failed: %v", c.label, eerr)
		}
		visible := strings.Contains(c.label, "U+FFFC") || strings.Contains(c.label, "fullwidth") || strings.Contains(c.label, "Hebrew") ||
			c.label == "LEGIT plain" || c.label == "LEGIT single inner space" || c.label == "LEGIT leading-space component" ||
			c.label == "LEGIT CJK" || c.label == "LEGIT NFC accent"
		if refused == visible {
			t.Errorf("%s: interactively refused=%t, want %t", c.label, refused, !visible)
		}
		if refused && !strings.Contains(err.Error(), "--expect-target") {
			t.Errorf("%s: the refusal does not point at --expect-target: %v", c.label, err)
		}
	}
}
