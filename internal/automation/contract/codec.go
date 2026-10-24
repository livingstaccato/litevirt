package contract

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// CanonicalCommand returns PRIVATE, version-domain-separated identity bytes.
// Callers may hash them internally but must not publish them: they contain the
// keyed secret equality tag. Session authorization and ciphertext/recipient
// rotation are deliberately excluded. Strings and byte payloads are not trimmed,
// Unicode-normalized, or newline-normalized. Empty Body is distinct from an object.
//
// Body v1 accepts at most 1 MiB and 64 nested containers. Numbers are exact
// decimals (no float rounding), with input and normalized exponents in [-1e9, 1e9], encoded as
// compact coefficient/exponent pairs without expanding powers of ten. Unknown
// command kinds fail closed; per-kind fields/defaults belong to typed reducers.
func CanonicalCommand(c Command) ([]byte, error) {
	switch c.Kind {
	case IdentityContinuityCommand, LegacyRebuildCommand, OrdinaryCreateCommand, "initialize_cluster", "assign_identity", "ensure_owner", "acquire_session",
		"handoff_session", "adopt_resource", "transfer_owner", "admit_create",
		"admit_update", "admit_delete", "claim_executor", "record_progress",
		"complete_operation", "retire_artifact", "rewrap_payload", "activate_key_epoch", CustodyImportCommand, "read_barrier":
	default:
		return nil, codedError(CodeUnsupported)
	}
	for _, s := range []string{c.ClusterUID, c.ProjectUID, c.PrincipalID, c.OwnerID,
		c.ManagementKey, c.RequestID, c.ResourceUID, c.SecretKeyEpoch, c.SessionID} {
		if !utf8.ValidString(s) {
			return nil, codedError(CodeValidation)
		}
	}
	if c.RequestID == "" || (len(c.SecretIntentTag) == 0) != (c.SecretKeyEpoch == "") {
		return nil, codedError(CodeValidation)
	}
	body, err := canonicalBody(c.Body)
	if err != nil {
		return nil, codedError(CodeValidation)
	}
	if len(c.SecretIntentTag) == 0 {
		c.SecretIntentTag = nil
	}
	// A fixed struct provides unambiguous framing and deterministic field order.
	identity := struct {
		Kind                                         string
		ClusterUID, ProjectUID, PrincipalID, OwnerID string
		ManagementKey, RequestID, ResourceUID        string
		Generation, ExpectedRevision                 uint64
		Body                                         json.RawMessage
		SecretIntentTag                              []byte
		SecretKeyEpoch                               string
	}{c.Kind, c.ClusterUID, c.ProjectUID, c.PrincipalID, c.OwnerID,
		c.ManagementKey, c.RequestID, c.ResourceUID, c.Generation, c.ExpectedRevision,
		body, c.SecretIntentTag, c.SecretKeyEpoch}
	encoded, err := json.Marshal(identity)
	if err != nil {
		return nil, codedError(CodeValidation)
	}
	return append([]byte("litevirt/automation/command/v1\x00"), encoded...), nil
}

func canonicalBody(body []byte) ([]byte, error) {
	if len(body) == 0 {
		return nil, nil
	}
	if len(body) > 1<<20 || !utf8.Valid(body) || !validSurrogates(body) {
		return nil, codedError(CodeValidation)
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	v, err := jsonValue(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, codedError(CodeValidation)
	}
	object, ok := v.(map[string]any)
	if !ok || object["version"] != json.Number("1") {
		return nil, codedError(CodeValidation)
	}
	return json.Marshal(object)
}

func jsonValue(d *json.Decoder, depth int) (any, error) {
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch t := t.(type) {
	case json.Delim:
		if depth >= 64 {
			return nil, codedError(CodeValidation)
		}
		switch t {
		case '{':
			m := map[string]any{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return nil, err
				}
				key, ok := k.(string)
				if !ok {
					return nil, codedError(CodeValidation)
				}
				if _, duplicate := m[key]; duplicate {
					return nil, codedError(CodeValidation)
				}
				v, err := jsonValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				m[key] = v
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, codedError(CodeValidation)
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				v, err := jsonValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, codedError(CodeValidation)
			}
			return a, nil
		}
		return nil, codedError(CodeValidation)
	case json.Number:
		return canonicalNumber(string(t))
	default:
		return t, nil
	}
}

func canonicalNumber(s string) (json.Number, error) {
	negative := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var exponent int64
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		var err error
		exponent, err = strconv.ParseInt(s[i+1:], 10, 64)
		if err != nil || exponent < -1e9 || exponent > 1e9 {
			return "", codedError(CodeValidation)
		}
		s = s[:i]
	}
	if i := strings.IndexByte(s, '.'); i >= 0 {
		exponent -= int64(len(s) - i - 1)
		s = s[:i] + s[i+1:]
	}
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0", nil
	}
	trimmed := strings.TrimRight(s, "0")
	exponent += int64(len(s) - len(trimmed))
	if exponent < -1e9 || exponent > 1e9 {
		return "", codedError(CodeValidation)
	}
	s = trimmed
	if negative {
		s = "-" + s
	}
	if exponent != 0 {
		s += "e" + strconv.FormatInt(exponent, 10)
	}
	return json.Number(s), nil
}

// encoding/json replaces malformed UTF-16 escapes; reject them before decoding
// so two distinct invalid payloads cannot collapse to the replacement character.
func validSurrogates(b []byte) bool {
	inString := false
	for i := 0; i < len(b); i++ {
		if b[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || b[i] != '\\' {
			continue
		}
		i++
		if i >= len(b) {
			return false
		}
		if b[i] != 'u' {
			continue
		}
		if i+4 >= len(b) {
			return false
		}
		n, err := strconv.ParseUint(string(b[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n < 0xd800 || n > 0xdbff {
			continue
		}
		if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
			return false
		}
		low, err := strconv.ParseUint(string(b[i+3:i+7]), 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}
