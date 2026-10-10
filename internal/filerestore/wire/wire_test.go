package wire

import (
	"bufio"
	"errors"
	"strings"
	"testing"
)

func TestEscape(t *testing.T) {
	for in, want := range map[string]string{
		"hosts":                "hosts",
		"résumé.txt":           "résumé.txt",
		"evil\x1b]0;pwn\x07":   `evil\x1b]0;pwn\x07`,
		"two\nlines":           `two\x0alines`,
		"c1\u009bcsi":          `c1\u009bcsi`,
		"invoice\u202egnp.exe": `invoice\u202egnp.exe`,
		"zw\u200bsp":           `zw\u200bsp`,
		"bad\xffbyte":          `bad\xffbyte`,
		"literal � stays":      "literal � stays",
	} {
		if got := Escape(in); got != want {
			t.Errorf("Escape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReadLineBounded(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 100)+"\n"), 16)
	if _, err := ReadLine(r, 50); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("a 100-byte line under a 50-byte bound: %v", err)
	}
	r = bufio.NewReaderSize(strings.NewReader("short\n"), 16)
	if l, err := ReadLine(r, 50); err != nil || string(l) != "short\n" {
		t.Fatalf("%q %v", l, err)
	}
}

func TestRecordRoundTrip(t *testing.T) {
	var b strings.Builder
	if err := WriteRecord(&b, Record{Name: "vda1/x", Type: TypeFile, Size: 3}); err != nil {
		t.Fatal(err)
	}
	if err := WriteRecord(&b, Record{Name: strings.Repeat("y", MaxRecordLine)}); !errors.Is(err, ErrRecordTooLong) {
		t.Fatalf("an oversized record: %v", err)
	}
	r, err := ReadRecord(bufio.NewReader(strings.NewReader(b.String())))
	if err != nil || r.Name != "vda1/x" || r.Size != 3 {
		t.Fatalf("%+v %v", r, err)
	}
}
