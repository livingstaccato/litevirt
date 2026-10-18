package corrosion

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"
)

const retainedReceiptDomain = "litevirt/automation-completed-import/v1"
const maxRetainedReceiptBytes = 64 << 10

// retainedImportReceipt is the consumed immutable finalizer receipt format.
// Decoding a receipt does not establish adoption or confer current authority.
type retainedImportReceipt struct {
	Version              int
	Purpose              string
	Host                 string
	Incarnation          string
	Generation           int64
	ConfigDigest         string
	MembersDigest        string
	Attempt              string
	BindingDigest        string
	AggregateDigest      string
	HeaderDigest         string
	LocalInventoryDigest string
	EvidenceGraphRoot    string
	EvidenceObjects      int64
	EvidenceBytes        int64
	BaselineDigest       string
	ClaimsDigest         string
}

func decodeRetainedReceipt(raw []byte) (retainedImportReceipt, error) {
	var v retainedImportReceipt
	if err := retainedCanonical(raw, maxRetainedReceiptBytes, &v); err != nil {
		return v, err
	}
	if v.Version != 1 || v.Purpose != "automation-completed-import" ||
		!retainedField(v.Host, 253) || !retainedField(v.Incarnation, 128) ||
		v.Generation <= 0 || v.EvidenceObjects <= 0 || v.EvidenceBytes < 0 {
		return v, errors.New("invalid retained receipt metadata")
	}
	for _, d := range []string{v.ConfigDigest, v.MembersDigest, v.Attempt, v.BindingDigest,
		v.AggregateDigest, v.HeaderDigest, v.LocalInventoryDigest, v.EvidenceGraphRoot,
		v.BaselineDigest, v.ClaimsDigest} {
		if !receiverDigest(d) {
			return v, errors.New("invalid retained receipt digest")
		}
	}
	return v, nil
}

func retainedNamespace(delivery string, ordinal int64) (string, error) {
	if !receiverDigest(delivery) || ordinal < 0 {
		return "", errors.New("invalid retained storage address")
	}
	return "retained-v1:" + delivery + ":" + strconv.FormatInt(ordinal, 10), nil
}

// Canonical re-encoding also rejects duplicate/unknown keys, alternate number
// syntax, omitted fields and nested permissive JSON decoders. Bound before decode.
func retainedCanonical(raw []byte, bound int, value any) error {
	if len(raw) == 0 || len(raw) > bound || !utf8.Valid(raw) {
		return errors.New("retained metadata exceeds bound or is not UTF-8")
	}
	if err := json.Unmarshal(raw, value); err != nil {
		return err
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		return errors.New("retained metadata is not canonical")
	}
	return nil
}

func retainedField(v string, bound int) bool {
	return len(v) > 0 && len(v) <= bound && utf8.ValidString(v) && !strings.ContainsRune(v, 0)
}
