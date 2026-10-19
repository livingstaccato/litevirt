package cli

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// These are independent wire oracles, not output from the codec under test.
// Their arbitrary payload is framing evidence only, not an enrollment grant.
var nativeRequestGoldens = []struct {
	name, phase, frameHex string
	payload               []byte
}{
	{"destination", "destination", "4c564e454e5130310000001730150201010c0b64657374696e6174696f6e040300ff41", []byte{0, 255, 'A'}},
	{"apply", "apply", "4c564e454e51303100000011300f0201010c056170706c79040300ff41", []byte{0, 255, 'A'}},
	{"status", "status", "4c564e454e5130310000001230100201010c06737461747573040300ff41", []byte{0, 255, 'A'}},
	{"empty_apply", "apply", "4c564e454e5130310000000e300c0201010c056170706c790400", nil},
}

func TestNativeEnrollmentRequestReadGolden(t *testing.T) {
	// Catches wrong magic/version/UTF8 phase layout and interpreting opaque data.
	for _, tc := range nativeRequestGoldens {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := readNativeEnrollmentRequest(bytes.NewReader(nativeRequestHex(t, tc.frameHex)), tc.phase)
			if err != nil {
				t.Fatalf("valid independent frame refused: %v", err)
			}
			if !bytes.Equal(payload, tc.payload) {
				t.Fatal("decoded payload differs from independent wire oracle")
			}
		})
	}
}

func TestNativeEnrollmentRequestWriteGolden(t *testing.T) {
	// Catches PrintableString substitution, little-endian length, or a JSON body.
	for _, tc := range nativeRequestGoldens {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := writeNativeEnrollmentRequest(&out, tc.phase, tc.payload); err != nil {
				t.Fatalf("encode valid opaque payload: %v", err)
			}
			if !bytes.Equal(out.Bytes(), nativeRequestHex(t, tc.frameHex)) {
				t.Fatal("encoded bytes differ from independent exact frame oracle")
			}
		})
	}
}

// Each prefix is hand-counted DER including the outer and OCTET length fields.
// In particular the limits count the BODY, not payload alone or header+body.
var nativeRequestBoundaries = []struct {
	phase, name, prefixHex    string
	bodyLength, payloadLength int
	allowed                   bool
}{
	{"destination", "max_minus_one", "30823ffb0201010c0b64657374696e6174696f6e04823fe7", 16383, 16359, true},
	{"destination", "max", "30823ffc0201010c0b64657374696e6174696f6e04823fe8", 16384, 16360, true},
	{"destination", "max_plus_one", "30823ffd0201010c0b64657374696e6174696f6e04823fe9", 16385, 16361, false},
	{"status", "max_minus_one", "30823ffb0201010c0673746174757304823fec", 16383, 16364, true},
	{"status", "max", "30823ffc0201010c0673746174757304823fed", 16384, 16365, true},
	{"status", "max_plus_one", "30823ffd0201010c0673746174757304823fee", 16385, 16366, false},
	{"apply", "max_minus_one", "3083bffffa0201010c056170706c790483bfffeb", 12582911, 12582891, true},
	{"apply", "max", "3083bffffb0201010c056170706c790483bfffec", 12582912, 12582892, true},
	{"apply", "max_plus_one", "3083bffffc0201010c056170706c790483bfffed", 12582913, 12582893, false},
}

func TestNativeEnrollmentRequestReadBodyBounds(t *testing.T) {
	// Catches off-by-one bounds and incorrectly counting DER/header overhead.
	for _, tc := range nativeRequestBoundaries {
		t.Run(tc.phase+"/"+tc.name, func(t *testing.T) {
			payload := bytes.Repeat([]byte{0xa5}, tc.payloadLength)
			body := append(nativeRequestHex(t, tc.prefixHex), payload...)
			if len(body) != tc.bodyLength {
				t.Fatal("independent boundary fixture has wrong body length")
			}
			frame := nativeRequestTestFrame(body)
			if len(frame) != 12+tc.bodyLength {
				t.Fatal("independent frame-header count is wrong")
			}
			if !tc.allowed {
				r := &nativeRequestHeaderOnlyReader{t: t, header: frame[:12]}
				got, err := readNativeEnrollmentRequest(r, tc.phase)
				nativeRequestRequireRefusal(t, got, err)
				if r.offset != 12 {
					t.Fatalf("overbound declaration must be read from the 12-byte header: got %d bytes", r.offset)
				}
				return
			}
			r := &nativeRequestBudgetReader{t: t, source: bytes.NewReader(frame), headerAndBody: len(frame)}
			got, err := readNativeEnrollmentRequest(r, tc.phase)
			if err != nil {
				t.Fatalf("allowed body refused (header is additional): %v", err)
			}
			if !bytes.Equal(got, payload) || r.consumed != len(frame) || r.probes != 1 {
				t.Fatal("allowed boundary lost payload, exact frame, or one-byte EOF probe")
			}
			withTrailing := &nativeRequestBudgetReader{t: t, source: bytes.NewReader(append(frame, 0x7f)), headerAndBody: len(frame)}
			got, err = readNativeEnrollmentRequest(withTrailing, tc.phase)
			nativeRequestRequireRefusal(t, got, err)
			if withTrailing.probes != 1 || withTrailing.consumed != len(frame)+1 {
				t.Fatal("boundary trailing byte must be rejected with just one extra byte")
			}
		})
	}
}

func TestNativeEnrollmentRequestWriteBodyBounds(t *testing.T) {
	// Catches accepting a full-size payload whose DER wrapping exceeds the cap.
	for _, tc := range nativeRequestBoundaries {
		t.Run(tc.phase+"/"+tc.name, func(t *testing.T) {
			payload := bytes.Repeat([]byte{0xa5}, tc.payloadLength)
			var out bytes.Buffer
			err := writeNativeEnrollmentRequest(&out, tc.phase, payload)
			if !tc.allowed {
				if err == nil || out.Len() != 0 {
					t.Fatal("overbound DER must refuse before emitting any frame bytes")
				}
				return
			}
			if err != nil {
				t.Fatalf("allowed body encode refused: %v", err)
			}
			want := nativeRequestTestFrame(append(nativeRequestHex(t, tc.prefixHex), payload...))
			if !bytes.Equal(out.Bytes(), want) {
				t.Fatal("boundary encoding differs from hand-counted DER oracle")
			}
		})
	}
}

func TestNativeEnrollmentRequestSelector(t *testing.T) {
	// Catches accepting arbitrary/case-folded selectors or reading before admission.
	for _, tc := range []struct{ name, selector string }{
		{"empty", ""}, {"uppercase", "Apply"}, {"trailing_space", "apply "},
		{"unknown", "unknown"}, {"nul", "status\x00"},
	} {
		t.Run("invalid_"+tc.name, func(t *testing.T) {
			r := &nativeRequestNoRead{t: t}
			got, err := readNativeEnrollmentRequest(r, tc.selector)
			nativeRequestRequireRefusal(t, got, err)
			var out bytes.Buffer
			if err := writeNativeEnrollmentRequest(&out, tc.selector, []byte{1}); err == nil || out.Len() != 0 {
				t.Fatal("invalid selector must refuse before writing")
			}
		})
	}
	for _, pair := range []struct{ encoded, expected string }{
		{"destination", "apply"}, {"destination", "status"},
		{"apply", "destination"}, {"apply", "status"},
		{"status", "destination"}, {"status", "apply"},
	} {
		t.Run("mismatch_"+pair.encoded+"_as_"+pair.expected, func(t *testing.T) {
			for _, golden := range nativeRequestGoldens[:3] {
				if golden.phase == pair.encoded {
					got, err := readNativeEnrollmentRequest(bytes.NewReader(nativeRequestHex(t, golden.frameHex)), pair.expected)
					nativeRequestRequireRefusal(t, got, err)
				}
			}
		})
	}
}

func TestNativeEnrollmentRequestDeclaredLengthPreflight(t *testing.T) {
	// Catches using apply's limit on a tighter expected destination/status path,
	// or allocating/reading a declared uint32 length before bounding it.
	for _, tc := range []struct {
		name, phase string
		length      uint32
	}{
		{"destination_apply_sized", "destination", 12582912},
		{"status_apply_sized", "status", 12582912},
		{"destination_uint32_max", "destination", 0xffffffff},
		{"status_uint32_max", "status", 0xffffffff},
		{"apply_uint32_max", "apply", 0xffffffff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := []byte("LVNENQ01\x00\x00\x00\x00")
			binary.BigEndian.PutUint32(header[8:], tc.length)
			r := &nativeRequestHeaderOnlyReader{t: t, header: header}
			got, err := readNativeEnrollmentRequest(r, tc.phase)
			nativeRequestRequireRefusal(t, got, err)
			if r.offset != 12 {
				t.Fatalf("declaration preflight did not consume exactly the header: %d", r.offset)
			}
		})
	}
}

func TestNativeEnrollmentRequestRejectFrame(t *testing.T) {
	// Catches marker scanning, missing EOF, ignored length bytes and partial input.
	golden := nativeRequestHex(t, nativeRequestGoldens[1].frameHex)
	cases := []struct {
		name  string
		frame []byte
	}{
		{"empty", nil},
		{"wrong_magic", append([]byte("LVNENR01"), golden[8:]...)},
		{"log_prefix", append([]byte("helper ready\n"), golden...)},
		{"trailing_byte", append(append([]byte(nil), golden...), 0)},
		{"second_frame", append(append([]byte(nil), golden...), golden...)},
		{"zero_body", []byte("LVNENQ01\x00\x00\x00\x00")},
		{"little_endian_length", append([]byte("LVNENQ01\x11\x00\x00\x00"), golden[12:]...)},
		{"declared_short_body", append([]byte("LVNENQ01\x00\x00\x00\x10"), golden[12:]...)},
		{"declared_long_body", append([]byte("LVNENQ01\x00\x00\x00\x12"), golden[12:]...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readNativeEnrollmentRequest(bytes.NewReader(tc.frame), "apply")
			nativeRequestRequireRefusal(t, got, err)
		})
	}
	// Every truncation offset includes magic, uint32 header and actual DER body.
	for offset := 1; offset < len(golden); offset++ {
		t.Run(fmt.Sprintf("truncated_%02d", offset), func(t *testing.T) {
			got, err := readNativeEnrollmentRequest(bytes.NewReader(golden[:offset]), "apply")
			nativeRequestRequireRefusal(t, got, err)
		})
	}
}

func TestNativeEnrollmentRequestRejectDER(t *testing.T) {
	// Catches permissive BER/ASN.1 decoding without exact tags and reencoding.
	for _, tc := range []struct{ name, bodyHex string }{
		{"set_instead_of_sequence", "310f0201010c056170706c79040300ff41"},
		{"indefinite_sequence", "30800201010c056170706c79040300ff410000"},
		{"nonminimal_sequence_length", "30810f0201010c056170706c79040300ff41"},
		{"leading_zero_sequence_length", "3082000f0201010c056170706c79040300ff41"},
		{"nonminimal_integer", "3010020200010c056170706c79040300ff41"},
		{"version_zero", "300f0201000c056170706c79040300ff41"},
		{"version_two", "300f0201020c056170706c79040300ff41"},
		{"negative_version", "300f0201ff0c056170706c79040300ff41"},
		{"wrong_version_tag", "300f0401010c056170706c79040300ff41"},
		{"printable_phase", "300f02010113056170706c79040300ff41"},
		{"ia5_phase", "300f02010116056170706c79040300ff41"},
		{"octet_phase", "300f02010104056170706c79040300ff41"},
		{"constructed_utf8_phase", "300f0201012c056170706c79040300ff41"},
		{"invalid_utf8_phase", "300f0201010c056170706cff040300ff41"},
		{"uppercase_phase", "300f0201010c054170706c79040300ff41"},
		{"unknown_phase", "300f0201010c056f74686572040300ff41"},
		{"wrong_payload_tag", "300f0201010c056170706c790c0300ff41"},
		{"constructed_payload", "300f0201010c056170706c79240300ff41"},
		{"missing_payload", "300a0201010c056170706c79"},
		{"extra_field", "30110201010c056170706c79040300ff410500"},
		{"reordered_fields", "300f0c056170706c79020101040300ff41"},
		{"trailing_body_byte", "300f0201010c056170706c79040300ff4100"},
		{"nonminimal_phase_length", "30100201010c81056170706c79040300ff41"},
		{"nonminimal_payload_length", "30100201010c056170706c7904810300ff41"},
		{"truncated_sequence", "300f0201010c056170706c79040300ff"},
		{"overflow_sequence_length", "3084ffffffff0201010c056170706c79040300ff41"},
		{"empty_integer", "300e02000c056170706c79040300ff41"},
		{"empty_sequence", "3000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readNativeEnrollmentRequest(bytes.NewReader(nativeRequestTestFrame(nativeRequestHex(t, tc.bodyHex))), "apply")
			nativeRequestRequireRefusal(t, got, err)
		})
	}
}

func TestNativeEnrollmentRequestReadIO(t *testing.T) {
	// Catches assuming a single Read fills a frame or ignoring real read errors.
	golden := nativeRequestHex(t, nativeRequestGoldens[1].frameHex)
	for _, chunk := range []int{1, 2, 7} {
		t.Run(fmt.Sprintf("short_reads_%d", chunk), func(t *testing.T) {
			r := &nativeRequestChunkReader{source: bytes.NewReader(golden), chunk: chunk}
			got, err := readNativeEnrollmentRequest(r, "apply")
			if err != nil || !bytes.Equal(got, []byte{0, 255, 'A'}) {
				t.Fatalf("valid fragmented input refused or changed: %v", err)
			}
		})
	}
	t.Run("data_with_eof", func(t *testing.T) {
		r := &nativeRequestTerminalReader{data: append([]byte(nil), golden...), terminal: io.EOF}
		got, err := readNativeEnrollmentRequest(r, "apply")
		if err != nil || !bytes.Equal(got, []byte{0, 255, 'A'}) {
			t.Fatalf("final data returned with EOF must be processed: %v", err)
		}
	})
	for _, tc := range []struct {
		name   string
		offset int
	}{
		{"header_error", 5}, {"body_error", 16}, {"eof_probe_error", len(golden)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			failure := errors.New("native request test read failure")
			r := &nativeRequestTerminalReader{data: append([]byte(nil), golden[:tc.offset]...), terminal: failure}
			got, err := readNativeEnrollmentRequest(r, "apply")
			nativeRequestRequireRefusal(t, got, err)
			if !errors.Is(err, failure) {
				t.Fatal("real reader failure was discarded or replaced")
			}
		})
	}
}

func TestNativeEnrollmentRequestWriteIO(t *testing.T) {
	// Catches treating a nil-error short write as success or retrying after error.
	golden := nativeRequestHex(t, nativeRequestGoldens[1].frameHex)
	for _, tc := range []struct {
		name      string
		limit     int
		withError bool
	}{
		{"short_header", 5, false}, {"zero_write", 0, false},
		{"short_body", 15, false}, {"header_error", 5, true}, {"body_error", 15, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			failure := error(nil)
			if tc.withError {
				failure = errors.New("native request test write failure")
			}
			w := &nativeRequestFailWriter{remaining: tc.limit, failure: failure}
			err := writeNativeEnrollmentRequest(w, "apply", []byte{0, 255, 'A'})
			want := failure
			if want == nil {
				want = io.ErrShortWrite
			}
			if !errors.Is(err, want) {
				t.Fatalf("write must preserve failure or report short write: %v", err)
			}
			if !bytes.Equal(w.out.Bytes(), golden[:tc.limit]) || w.afterFailure != 0 {
				t.Fatal("partial output is not the frame prefix, or writer was retried after failure")
			}
		})
	}
}

func TestNativeEnrollmentRequestErrorsDoNotExposeInput(t *testing.T) {
	// Catches diagnostics that quote private payloads, selectors, or input frames.
	secret := "PRIVATE_NATIVE_PAYLOAD_DO_NOT_LOG"
	for _, mode := range []string{"read_payload", "read_selector", "write_selector"} {
		t.Run(mode, func(t *testing.T) {
			var err error
			switch mode {
			case "read_payload":
				// Deliberately wrong version, independently encoded short lengths.
				body := append([]byte{0x30, byte(12 + len(secret)), 2, 1, 2, 12, 5, 'a', 'p', 'p', 'l', 'y', 4, byte(len(secret))}, []byte(secret)...)
				_, err = readNativeEnrollmentRequest(bytes.NewReader(nativeRequestTestFrame(body)), "apply")
			case "read_selector":
				_, err = readNativeEnrollmentRequest(&nativeRequestNoRead{t: t}, secret)
			case "write_selector":
				var out bytes.Buffer
				err = writeNativeEnrollmentRequest(&out, secret, []byte(secret))
				if out.Len() != 0 {
					t.Fatal("invalid private selector produced output")
				}
			}
			if err == nil || strings.Contains(err.Error(), secret) {
				t.Fatal("invalid request must fail without quoting private input")
			}
		})
	}
}

func nativeRequestHex(t *testing.T, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("invalid literal hex fixture: %v", err)
	}
	return b
}

// Only test fixture framing; DER bytes never come from the new encoder.
func nativeRequestTestFrame(body []byte) []byte {
	frame := make([]byte, 12, 12+len(body))
	copy(frame, "LVNENQ01")
	binary.BigEndian.PutUint32(frame[8:], uint32(len(body)))
	return append(frame, body...)
}

func nativeRequestRequireRefusal(t *testing.T, payload []byte, err error) {
	t.Helper()
	if err == nil || len(payload) != 0 {
		t.Fatal("invalid request returned success or partial payload")
	}
}

type nativeRequestNoRead struct{ t *testing.T }

func (r *nativeRequestNoRead) Read([]byte) (int, error) {
	r.t.Fatal("invalid selector touched input")
	return 0, io.EOF
}

type nativeRequestHeaderOnlyReader struct {
	t      *testing.T
	header []byte
	offset int
}

func (r *nativeRequestHeaderOnlyReader) Read(p []byte) (int, error) {
	remaining := len(r.header) - r.offset
	if remaining == 0 || len(p) > remaining {
		r.t.Fatal("overbound request accessed body or requested bytes beyond header")
	}
	n := copy(p, r.header[r.offset:])
	r.offset += n
	return n, nil
}

type nativeRequestBudgetReader struct {
	t                               *testing.T
	source                          *bytes.Reader
	headerAndBody, consumed, probes int
}

func (r *nativeRequestBudgetReader) Read(p []byte) (int, error) {
	remaining := r.headerAndBody - r.consumed
	if remaining > 0 {
		if len(p) > remaining {
			r.t.Fatal("request read buffer exceeds remaining frame")
		}
	} else {
		r.probes++
		if r.probes != 1 || len(p) != 1 {
			r.t.Fatal("EOF check must request exactly one byte once")
		}
	}
	n, err := r.source.Read(p)
	r.consumed += n
	return n, err
}

type nativeRequestChunkReader struct {
	source *bytes.Reader
	chunk  int
}

func (r *nativeRequestChunkReader) Read(p []byte) (int, error) {
	if len(p) > r.chunk {
		p = p[:r.chunk]
	}
	return r.source.Read(p)
}

// Return final bytes and an error together, as the io.Reader contract permits.
type nativeRequestTerminalReader struct {
	data     []byte
	terminal error
}

func (r *nativeRequestTerminalReader) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, r.terminal
	}
	return n, nil
}

type nativeRequestFailWriter struct {
	out          bytes.Buffer
	remaining    int
	failure      error
	failed       bool
	afterFailure int
}

func (w *nativeRequestFailWriter) Write(p []byte) (int, error) {
	if w.failed {
		w.afterFailure++
		return 0, errors.New("write retried after terminal failure")
	}
	if len(p) <= w.remaining {
		w.remaining -= len(p)
		return w.out.Write(p)
	}
	n, _ := w.out.Write(p[:w.remaining])
	w.remaining = 0
	w.failed = true
	return n, w.failure
}
