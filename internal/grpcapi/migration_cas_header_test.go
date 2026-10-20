package grpcapi

import (
	"strings"
	"testing"
)

func fpN(c byte) string { return strings.Repeat(string(c), 64) }

// The CA list header is written by a peer. The reader keeps only SHA-256 hex
// fingerprints, so nothing else reaches the refusal error or the event.
func TestReadMigrationCAList_KeepsOnlyFingerprints(t *testing.T) {
	good1, good2 := fpN('a'), fpN('b')
	got := readMigrationCAList([]string{good1 + ",evil\x1b[31m text," + strings.Repeat("g", 64) + "," + strings.ToUpper(good2) + "," + good2 + "," + good1[:63]}, nil)
	if len(got) != 2 || got[0] != good1 || got[1] != good2 {
		t.Fatalf("got %q, want only the two well-formed fingerprints", got)
	}
	if got := readMigrationCAList([]string{"junk,more junk"}, nil); len(got) != 1 || got[0] != migrationCAsUnreadable {
		t.Fatalf("a header with no fingerprint must read as unreadable, got %q", got)
	}
	if got := readMigrationCAList(nil, nil); got != nil {
		t.Fatalf("no header must read as none, got %q", got)
	}
	msg := migrationCAsShown("a", fpN('a'), []string{fpN('a')}, "b", fpN('b'), []string{migrationCAsUnreadable})
	if !strings.Contains(msg, "could not be read") || strings.Contains(msg, "does not list") || strings.Contains(msg, "(unreadable)") {
		t.Fatalf("unreadable list shown as %q", msg)
	}
}

func TestReadMigrationCAList_CapsTheCount(t *testing.T) {
	var fps []string
	for i := 0; i < 40; i++ {
		fps = append(fps, strings.Repeat(string("0123456789abcdef"[i%16]), 64))
	}
	got := readMigrationCAList([]string{strings.Join(fps, ",")}, nil)
	if len(got) != maxMigrationCAsShown+1 {
		t.Fatalf("got %d elements, want %d fingerprints and a marker", len(got), maxMigrationCAsShown)
	}
	if want := "+24 more (list incomplete)"; got[len(got)-1] != want {
		t.Fatalf("marker = %q, want %q", got[len(got)-1], want)
	}
}

func TestReadMigrationCAList_MarksASenderTruncation(t *testing.T) {
	got := readMigrationCAList([]string{fpN('a')}, []string{"3"})
	if len(got) != 2 || got[1] != "+3 more (list incomplete)" {
		t.Fatalf("got %q", got)
	}
	// A garbage count adds nothing and does not fail.
	if got := readMigrationCAList([]string{fpN('a')}, []string{"-5x"}); len(got) != 1 {
		t.Fatalf("got %q", got)
	}
}

// A fingerprint is never cut in half: only whole ones that fit go out, and the
// count of those left out goes beside them.
func TestPackMigrationCAList_NeverCutsAFingerprint(t *testing.T) {
	var fps []string
	for i := 0; i < 10; i++ {
		fps = append(fps, strings.Repeat(string("0123456789"[i]), 64))
	}
	packed, dropped := packMigrationCAList(fps)
	if len(packed) > 512 {
		t.Fatalf("packed %d bytes, over the 512 budget", len(packed))
	}
	parts := strings.Split(packed, ",")
	for _, p := range parts {
		if !isSHA256Hex(p) {
			t.Fatalf("element %q is not a whole fingerprint", p)
		}
	}
	if len(parts) != 7 || dropped != 3 {
		t.Fatalf("kept %d dropped %d, want 7 and 3", len(parts), dropped)
	}
	if p, d := packMigrationCAList(fps[:3]); d != 0 || p != strings.Join(fps[:3], ",") {
		t.Fatalf("a list that fits must go whole, got %d dropped", d)
	}
	// Round trip: the reader shows the list as incomplete.
	got := readMigrationCAList([]string{packed}, []string{"3"})
	if len(got) != 8 || got[7] != "+3 more (list incomplete)" {
		t.Fatalf("round trip: %q", got)
	}
}

// The unusable-credentials reason is peer-supplied too: bounded and printable.
func TestReadMigrationTLSUnusable_IsSanitised(t *testing.T) {
	got := sanitizeMigrationTLSUnusable("bad\x1b[31m\nca" + strings.Repeat("x", 2000))
	if len(got) > 512 || strings.ContainsAny(got, "\x1b\n") {
		t.Fatalf("not sanitised: %d bytes %q", len(got), got[:20])
	}
}

// The single-digest header is peer-supplied too. Anything but a fingerprint
// reads as absent, so it can reach no message and agreement treats it as an
// older peer's silence (compares nothing).
func TestReadMigrationCA_ABadValueReadsAsAbsent(t *testing.T) {
	good := fpN('c')
	if got := readMigrationCA([]string{good}); got != good {
		t.Fatalf("got %q", got)
	}
	for _, bad := range []string{"digest-of-one", "evil\x1b[31m", strings.Repeat("c", 63), strings.Repeat("C", 64), ""} {
		if got := readMigrationCA([]string{bad}); got != "" {
			t.Fatalf("%q read as %q, want absent", bad, got)
		}
	}
	if readMigrationCA(nil) != "" {
		t.Fatal("no header must read as absent")
	}
	if !migrationCAsAgree(fpN('a'), readMigrationCA([]string{"junk"})) {
		t.Fatal("a bad value must compare nothing, as an absent header does")
	}
}
