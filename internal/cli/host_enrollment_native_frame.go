package cli

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"io"
)

type nativeEnrollmentRequestDER struct {
	Version int
	Phase   string `asn1:"utf8"`
	Payload []byte
}

// readNativeEnrollmentRequest decodes only the outer framing. Its returned
// payload remains opaque and establishes no enrollment identity or permission.
// Cancellation and absolute deadlines belong to the caller's transport.
func readNativeEnrollmentRequest(r io.Reader, expectedPhase string) ([]byte, error) {
	limit, err := nativeEnrollmentRequestBodyLimit(expectedPhase)
	if err != nil {
		return nil, err
	}
	var header [12]byte
	if err := readNativeEnrollmentRequestBytes(r, header[:]); err != nil {
		return nil, err
	}
	if string(header[:8]) != "LVNENQ01" {
		return nil, errors.New("invalid native enrollment request magic")
	}
	length := binary.BigEndian.Uint32(header[8:])
	// The expected selector's complete DER-body limit is checked before either
	// allocation or body access; the frame header is additional to this limit.
	if length > uint32(limit) {
		return nil, errors.New("native enrollment request body exceeds bound")
	}
	body := make([]byte, int(length))
	if err := readNativeEnrollmentRequestBytes(r, body); err != nil {
		return nil, err
	}
	var request nativeEnrollmentRequestDER
	rest, err := asn1.Unmarshal(body, &request)
	if err != nil || len(rest) != 0 || request.Version != 1 || request.Phase != expectedPhase {
		return nil, errors.New("invalid native enrollment request DER")
	}
	canonical, err := asn1.Marshal(request)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, errors.New("noncanonical native enrollment request DER")
	}
	// A single-byte probe rejects suffixes and second frames without consuming
	// unbounded output. A zero-byte read without EOF cannot establish success.
	var probe [1]byte
	n, err := r.Read(probe[:])
	if err != nil && err != io.EOF {
		return nil, err
	}
	if n != 0 {
		return nil, errors.New("trailing native enrollment request input")
	}
	if err != io.EOF {
		return nil, io.ErrNoProgress
	}
	return request.Payload, nil
}

func writeNativeEnrollmentRequest(w io.Writer, phase string, payload []byte) error {
	limit, err := nativeEnrollmentRequestBodyLimit(phase)
	if err != nil {
		return err
	}
	if len(payload) > limit {
		return errors.New("native enrollment request body exceeds bound")
	}
	// INTEGER1 occupies three bytes; these exact phase names have a one-byte
	// UTF8 length. Include both OCTET and SEQUENCE tag/length overhead before
	// marshaling or emitting any bytes. Payload length alone is not the bound.
	contentLength := 3 + 2 + len(phase) + 1 + nativeEnrollmentDERLengthSize(len(payload)) + len(payload)
	bodyLength := 1 + nativeEnrollmentDERLengthSize(contentLength) + contentLength
	if bodyLength > limit {
		return errors.New("native enrollment request body exceeds bound")
	}
	body, err := asn1.Marshal(nativeEnrollmentRequestDER{Version: 1, Phase: phase, Payload: payload})
	if err != nil || len(body) != bodyLength {
		return errors.New("cannot encode native enrollment request DER")
	}
	var header [12]byte
	copy(header[:8], "LVNENQ01")
	binary.BigEndian.PutUint32(header[8:], uint32(len(body)))
	if err := writeNativeEnrollmentRequestBytes(w, header[:]); err != nil {
		return err
	}
	return writeNativeEnrollmentRequestBytes(w, body)
}

func nativeEnrollmentRequestBodyLimit(phase string) (int, error) {
	switch phase {
	case "destination", "status":
		return 16 << 10, nil
	case "apply":
		return 12 << 20, nil
	default:
		return 0, errors.New("invalid native enrollment request phase")
	}
}

func nativeEnrollmentDERLengthSize(length int) int {
	if length < 128 {
		return 1
	}
	size := 1
	for length > 0 {
		size++
		length >>= 8
	}
	return size
}

func readNativeEnrollmentRequestBytes(r io.Reader, remaining []byte) error {
	for len(remaining) > 0 {
		n, err := r.Read(remaining)
		if n < 0 || n > len(remaining) {
			return errors.New("invalid native enrollment request read count")
		}
		remaining = remaining[n:]
		if err != nil {
			if err == io.EOF {
				if len(remaining) == 0 {
					return nil
				}
				return io.ErrUnexpectedEOF
			}
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func writeNativeEnrollmentRequestBytes(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}
