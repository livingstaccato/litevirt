// Package latchparse reads `lv cluster upgrade-status` for the e2e tests.
package latchparse

import "strings"

// TokenLatched reports whether token has a row in the TOKEN table of an
// `lv cluster upgrade-status` output: the table lists only tokens latched on
// the host asked. The release-features table below it has a row for every
// declared feature whether or not the token has latched, and its first column
// is also a token, so matching a token name anywhere in the output (or any
// row of any table) is wrong: only the rows between the TOKEN header and the
// next blank line count.
func TokenLatched(out, token string) bool {
	inTokens := false
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
			inTokens = false
		case f[0] == "TOKEN":
			inTokens = true
		case inTokens && f[0] == token:
			return true
		}
	}
	return false
}
