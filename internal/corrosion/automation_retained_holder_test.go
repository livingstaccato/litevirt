package corrosion

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// Adversarial signing input only: no completed import or donor producer is
// fabricated. Tests below exercise syntax/current authority, never completion.
func retainedAdversarialHolder(t *testing.T, a *AutomationReceiverAttempt) retainedHolderBody {
	t.Helper()
	d := strings.Repeat("a", 64)
	admission, _ := json.Marshal(a.facts.Target)
	fp := sha256.Sum256(a.pair.Certificate[0])
	return retainedHolderBody{1, "automation-retained-holder", a.request.Target, a.facts.Incarnation,
		a.facts.Next.Generation, sourceConfigDigest(a.facts.Next), a.facts.Next.MembersHash,
		sourceDigest([]byte("litevirt/retained-admission/v1"), admission), hex.EncodeToString(fp[:]),
		d, d, d, 7, 2048, a.request.Sources[0].Name, a.request.Sources[0].Incarnation, strings.Repeat("a", 32), d,
		ClaimKey{TargetKind: ClaimKindAutomation, TargetName: "cluster", OwnerEpoch: 1},
		testBallot(1, a.request.Target), d, d, a.request.Target, a.facts.Incarnation, a.id,
		a.request.Job, a.request.Revision, sourceConfigDigest(a.facts.Next), a.facts.Next.MembersHash}
}

func retainedSignAdversarial(t *testing.T, pair *tls.Certificate, body retainedHolderBody, domain string) []byte {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := hex.DecodeString(sourceDigest([]byte(domain), b))
	sig, err := ecdsa.SignASN1(rand.Reader, pair.PrivateKey.(*ecdsa.PrivateKey), h)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(retainedSignedHolder{b, sig, pair.Certificate})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRetainedHolderFreshSignatureCodec(t *testing.T) {
	_, r, q, _, _ := receiverFixture(t)
	a, err := r.Begin(context.Background(), q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := retainedAdversarialHolder(t, a)
	raw := retainedSignAdversarial(t, a.pair, body, retainedHolderDomain)
	h, err := decodeRetainedHolder(raw)
	if err != nil {
		t.Fatalf("canonical signed input refused before bundle verification: %v", err)
	}
	if h.id != sourceDigest([]byte("litevirt/retained-delivery/v1"), raw) {
		t.Fatal("delivery lost exact signed bytes")
	}
	for _, domain := range []string{"", sourceManifestDomain, "litevirt/automation-retained-holder/v2"} {
		if _, err := decodeRetainedHolder(retainedSignAdversarial(t, a.pair, body, domain)); err == nil {
			t.Fatal("wrong signature domain accepted")
		}
	}
	for name, mutate := range map[string]func(*retainedHolderBody){
		"version":          func(v *retainedHolderBody) { v.Version++ },
		"purpose":          func(v *retainedHolderBody) { v.Purpose = "automation-membership-source" },
		"candidate-key":    func(v *retainedHolderBody) { v.Key.TargetKind = "unknown" },
		"candidate-ballot": func(v *retainedHolderBody) { v.Accepted = Ballot{} },
		"receipt":          func(v *retainedHolderBody) { v.ReceiptDigest = "bad" },
		"original-root":    func(v *retainedHolderBody) { v.OriginalRoot = "bad" },
		"cut-wrong-kind":   func(v *retainedHolderBody) { v.OriginalCut = strings.Repeat("a", 64) },
		"cut-uppercase":    func(v *retainedHolderBody) { v.OriginalCut = strings.Repeat("A", 32) },
		"candidate-value":  func(v *retainedHolderBody) { v.ValueDigest = "" },
		"acceptance":       func(v *retainedHolderBody) { v.AcceptanceDigest = "bad" },
		"directory-count":  func(v *retainedHolderBody) { v.DirectoryObjects = 0 },
		"directory-bytes":  func(v *retainedHolderBody) { v.DirectoryBytes = -1 },
		"receiver-bound":   func(v *retainedHolderBody) { v.Receiver = strings.Repeat("x", 254) },
		"signer":           func(v *retainedHolderBody) { v.Signer = strings.Repeat("b", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			v := body
			mutate(&v)
			if _, err := decodeRetainedHolder(retainedSignAdversarial(t, a.pair, v, retainedHolderDomain)); err == nil {
				t.Fatal("malformed signed holder accepted")
			}
		})
	}
}

func TestRetainedHolderCurrentSuccessorBinding(t *testing.T) {
	_, r, q, _, _ := receiverFixture(t)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := retainedAdversarialHolder(t, a)
	active := receiverActive(t, r.client)
	check := func(body retainedHolderBody) error {
		h, err := decodeRetainedHolder(retainedSignAdversarial(t, a.pair, body, retainedHolderDomain))
		if err != nil {
			return err
		}
		if err = r.lock(ctx); err != nil {
			return err
		}
		defer r.mu.Unlock()
		auth, err := r.authorizeRetainedHolder(ctx, a, h)
		auth.discard()
		return err
	}
	if err := check(body); err != nil {
		t.Fatalf("current successor authentication gate refused: %v", err)
	}
	// The new target is not in the old roster. The ordinary gate must stay closed.
	if auth, err := r.authorizeSource(ctx, a, body.Donor); err == nil {
		auth.discard()
		t.Fatal("retained successor leaked into ordinary old source roster")
	}
	for name, mutate := range map[string]func(*retainedHolderBody){
		"receiver":             func(v *retainedHolderBody) { v.Receiver = "other" },
		"receiver-incarnation": func(v *retainedHolderBody) { v.ReceiverIncarnation = "other" },
		"attempt":              func(v *retainedHolderBody) { v.Attempt = strings.Repeat("c", 64) },
		"job":                  func(v *retainedHolderBody) { v.Job = "other" },
		"revision":             func(v *retainedHolderBody) { v.Revision++ },
		"receiver-config":      func(v *retainedHolderBody) { v.ReceiverConfigDigest = strings.Repeat("c", 64) },
		"receiver-members":     func(v *retainedHolderBody) { v.ReceiverMembersDigest = strings.Repeat("c", 64) },
		"donor-config":         func(v *retainedHolderBody) { v.ConfigDigest = strings.Repeat("c", 64) },
		"donor-members":        func(v *retainedHolderBody) { v.MembersDigest = strings.Repeat("c", 64) },
		"donor-generation":     func(v *retainedHolderBody) { v.Generation++ },
		"donor-incarnation":    func(v *retainedHolderBody) { v.DonorIncarnation = "other" },
		"donor-admission":      func(v *retainedHolderBody) { v.AdmissionDigest = strings.Repeat("c", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			v := body
			mutate(&v)
			if err := check(v); err == nil {
				t.Fatal("fresh signed delivery splice passed current holder gate")
			}
			if receiverActive(t, r.client) != active {
				t.Fatal("holder refusal mutated ACTIVE state")
			}
		})
	}
	if receiverActive(t, r.client) != active {
		t.Fatal("holder authentication mutated ACTIVE state")
	}
}
