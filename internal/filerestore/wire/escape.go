package wire

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Escape makes a string from a restore VM safe to print: C0 and C1 control
// characters, DEL, and the Unicode bidi and invisible formatting controls
// that can reorder or hide text (U+061C, U+200B–U+200F, U+202A–U+202E,
// U+2060–U+2069, U+FEFF) are written as \x.. / \u.... Invalid UTF-8 bytes
// are written as \x... A string with none of them is returned unchanged.
//
// Names, symlink targets, agent errors and console output all pass through
// it before they reach an operator's terminal.
func Escape(s string) string {
	clean := true
	for i, r := range s {
		if r == utf8.RuneError && !strings.HasPrefix(s[i:], "�") || unsafeRune(r) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n <= 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r < 0x80 && unsafeRune(r):
			fmt.Fprintf(&b, `\x%02x`, r)
		case unsafeRune(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	return b.String()
}

func unsafeRune(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x061c, r >= 0x200b && r <= 0x200f, r >= 0x202a && r <= 0x202e,
		r >= 0x2060 && r <= 0x2069, r == 0xfeff:
		return true
	}
	return false
}

// EscapeBounded is Escape of at most max bytes of s.
func EscapeBounded(s string, max int) string {
	if len(s) > max {
		s = s[:max]
	}
	return Escape(s)
}
