package automation

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"

	"filippo.io/age"
)

func secretBindingFixture() SecretBinding {
	return SecretBinding{ClusterUID: "cluster", ProjectUID: "project", ResourceUID: "resource", OperationID: "operation", PayloadID: "payload", AdmittedGeneration: 7}
}
func secretIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal("identity generation failed")
	}
	return key
}
func encryptRawBootstrap(t *testing.T, plaintext []byte, recipient *age.X25519Recipient) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := age.Encrypt(&out, recipient)
	if err != nil {
		t.Fatal("fixture encrypt failed")
	}
	if _, err = w.Write(plaintext); err != nil {
		t.Fatal("fixture write failed")
	}
	if w.Close() != nil {
		t.Fatal("fixture close failed")
	}
	return out.Bytes()
}
func requireNoBootstrap(t *testing.T, files EffectiveBootstrap, err error) {
	t.Helper()
	if err == nil || files.UserData != nil || files.Metadata != nil || files.NetworkConfig != nil || files.VendorData != nil {
		t.Fatal("invalid payload returned data or success")
	}
	if err.Error() != "invalid bootstrap secret" {
		t.Fatal("error is not fixed and redacted")
	}
}

func TestAutomationSecretExactFilesAndIndependentRecipients(t *testing.T) {
	a, b, c := secretIdentity(t), secretIdentity(t), secretIdentity(t)
	binding := secretBindingFixture()
	for _, files := range []EffectiveBootstrap{
		{}, {UserData: []byte{}, Metadata: []byte{}, NetworkConfig: []byte{}},
		{UserData: []byte("USER-MARKER\x00\xff\r\n"), Metadata: []byte("META-MARKER\r\n"), NetworkConfig: []byte("NETWORK-MARKER\x00\xfe")},
		{UserData: []byte{}, Metadata: []byte("m"), NetworkConfig: nil},
	} {
		cipher, err := EncryptBootstrap(binding, files, []*age.X25519Recipient{a.Recipient(), b.Recipient()})
		if err != nil {
			t.Fatal("valid files were not encrypted")
		}
		for _, id := range []*age.X25519Identity{a, b} {
			got, err := DecryptBootstrap(binding, cipher, []*age.X25519Identity{id})
			if err != nil || !reflect.DeepEqual(got, files) {
				t.Fatal("recipient did not recover exact files and presence")
			}
		}
		// Only B's private identity is supplied; entry A and its key are not needed.
		got, err := DecryptBootstrap(binding, cipher, []*age.X25519Identity{c, b})
		if err != nil || !reflect.DeepEqual(got, files) {
			t.Fatal("surviving recipient could not recover")
		}
		got, err = DecryptBootstrap(binding, cipher, []*age.X25519Identity{c})
		requireNoBootstrap(t, got, err)
	}
}

func TestAutomationSecretBindingAndOriginPreservedOnRewrap(t *testing.T) {
	a, b := secretIdentity(t), secretIdentity(t)
	binding := secretBindingFixture()
	files := EffectiveBootstrap{UserData: []byte("user"), Metadata: []byte("meta"), NetworkConfig: []byte{}}
	cipher, err := EncryptBootstrap(binding, files, []*age.X25519Recipient{a.Recipient()})
	if err != nil {
		t.Fatal("encryption failed")
	}
	mutations := []func(*SecretBinding){
		func(x *SecretBinding) { x.ClusterUID = "X" + x.ClusterUID[1:] }, func(x *SecretBinding) { x.ProjectUID = "X" + x.ProjectUID[1:] }, func(x *SecretBinding) { x.ResourceUID = "X" + x.ResourceUID[1:] },
		func(x *SecretBinding) { x.OperationID = "X" + x.OperationID[1:] }, func(x *SecretBinding) { x.PayloadID = "X" + x.PayloadID[1:] }, func(x *SecretBinding) { x.AdmittedGeneration++ },
	}
	names := []string{"cluster", "project", "resource", "operation", "payload", "origin-generation"}
	for i, mutate := range mutations {
		t.Run(names[i], func(t *testing.T) {
			wrong := binding
			mutate(&wrong)
			got, err := DecryptBootstrap(wrong, cipher, []*age.X25519Identity{a})
			requireNoBootstrap(t, got, err)
		})
	}
	recovered, err := DecryptBootstrap(binding, cipher, []*age.X25519Identity{a})
	if err != nil {
		t.Fatal("original binding failed")
	}
	replacement, err := EncryptBootstrap(binding, recovered, []*age.X25519Recipient{b.Recipient()})
	if err != nil || bytes.Equal(cipher, replacement) {
		t.Fatal("fresh wrapping failed")
	}
	got, err := DecryptBootstrap(binding, replacement, []*age.X25519Identity{b})
	if err != nil || !reflect.DeepEqual(got, files) {
		t.Fatal("rewrap lost original files or admission binding")
	}
	got, err = DecryptBootstrap(binding, replacement, []*age.X25519Identity{a})
	requireNoBootstrap(t, got, err)
}

func TestAutomationSecretAuthenticatedEOF(t *testing.T) {
	id := secretIdentity(t)
	binding := secretBindingFixture()
	files := EffectiveBootstrap{UserData: bytes.Repeat([]byte("PRIVATE-FINAL-MARKER"), 10000), Metadata: []byte("m")}
	cipher, err := EncryptBootstrap(binding, files, []*age.X25519Recipient{id.Recipient()})
	if err != nil {
		t.Fatal("encryption failed")
	}
	for _, cut := range []int{0, 1, len(cipher) / 2, len(cipher) - 17, len(cipher) - 1} {
		got, err := DecryptBootstrap(binding, cipher[:cut], []*age.X25519Identity{id})
		requireNoBootstrap(t, got, err)
	}
	corrupt := bytes.Clone(cipher)
	corrupt[len(corrupt)-1] ^= 1
	got, err := DecryptBootstrap(binding, corrupt, []*age.X25519Identity{id})
	requireNoBootstrap(t, got, err)
	got, err = DecryptBootstrap(binding, append(bytes.Clone(cipher), 0), []*age.X25519Identity{id})
	requireNoBootstrap(t, got, err)
}

func TestAutomationSecretCodecStrictFramingAndBounds(t *testing.T) {
	binding := secretBindingFixture()
	files := EffectiveBootstrap{UserData: []byte{}, Metadata: []byte("m"), NetworkConfig: []byte{0, 255}}
	encoded, err := encodeBootstrap(binding, files)
	if err != nil {
		t.Fatal("valid frame rejected")
	}
	got, err := decodeBootstrap(binding, encoded)
	if err != nil || !reflect.DeepEqual(got, files) {
		t.Fatal("frame lost bytes or presence")
	}
	// An independent reader pins version, field order, lengths and absence tags.
	want := new(bytes.Buffer)
	want.WriteString("litevirt/automation/effective-bootstrap\x00")
	binary.Write(want, binary.BigEndian, uint32(2))
	for _, s := range []string{binding.ClusterUID, binding.ProjectUID, binding.ResourceUID, binding.OperationID, binding.PayloadID} {
		binary.Write(want, binary.BigEndian, uint32(len(s)))
		want.WriteString(s)
	}
	binary.Write(want, binary.BigEndian, binding.AdmittedGeneration)
	for _, b := range [][]byte{files.UserData, files.Metadata, files.NetworkConfig} {
		want.WriteByte(1)
		binary.Write(want, binary.BigEndian, uint32(len(b)))
		want.Write(b)
	}
	want.Write([]byte{0, 0, 0, 0, 0}) // v2 absent vendor-data
	if !bytes.Equal(encoded, want.Bytes()) {
		t.Fatal("versioned frame changed")
	}
	for i := 0; i < len(encoded); i++ {
		got, err := decodeBootstrap(binding, encoded[:i])
		requireNoBootstrap(t, got, err)
	}
	for _, malformed := range [][]byte{append(bytes.Clone(encoded), 0), bytes.Repeat([]byte{1}, bootstrapPlaintextMaxBytes+1)} {
		got, err := decodeBootstrap(binding, malformed)
		requireNoBootstrap(t, got, err)
	}
	badVersion := bytes.Clone(encoded)
	badVersion[len("litevirt/automation/effective-bootstrap\x00")+3] = 3
	got, err = decodeBootstrap(binding, badVersion)
	requireNoBootstrap(t, got, err)
	offset := len(encoded) - 5 - 5 - 2 - 5 - 1 - 5 // first file presence, known fixture lengths
	badPresence := bytes.Clone(encoded)
	badPresence[offset] = 2
	got, err = decodeBootstrap(binding, badPresence)
	requireNoBootstrap(t, got, err)
	badLength := bytes.Clone(encoded)
	binary.BigEndian.PutUint32(badLength[offset+1:], 0xffffffff)
	got, err = decodeBootstrap(binding, badLength)
	requireNoBootstrap(t, got, err)
	// No absent field may smuggle bytes behind a zero presence marker.
	badAbsent := bytes.Clone(encoded)
	badAbsent[len(encoded)-12] = 0
	got, err = decodeBootstrap(binding, badAbsent)
	requireNoBootstrap(t, got, err)
	huge := EffectiveBootstrap{UserData: make([]byte, bootstrapPlaintextMaxBytes)}
	if b, err := encodeBootstrap(binding, huge); err == nil || b != nil {
		t.Fatal("oversized frame accepted")
	}
	// Verify aggregate boundary, including framing overhead, not per-field limits.
	empty, err := encodeBootstrap(binding, EffectiveBootstrap{UserData: []byte{}})
	if err != nil {
		t.Fatal("empty frame failed")
	}
	exact := EffectiveBootstrap{UserData: make([]byte, bootstrapPlaintextMaxBytes-len(empty))}
	exactBytes, err := encodeBootstrap(binding, exact)
	if err != nil || len(exactBytes) != bootstrapPlaintextMaxBytes {
		t.Fatal("exact internal frame bound failed")
	}
	exact.UserData = append(exact.UserData, 0)
	if b, err := encodeBootstrap(binding, exact); err == nil || b != nil {
		t.Fatal("one-over frame bound accepted")
	}
	owned, err := decodeBootstrap(binding, encoded)
	if err != nil {
		t.Fatal("owned decode failed")
	}
	owned.Metadata[0] ^= 1
	again, err := decodeBootstrap(binding, encoded)
	if err != nil || !reflect.DeepEqual(again, files) {
		t.Fatal("decoded buffers alias input")
	}
	encoded[len(encoded)-6] ^= 1
	if !bytes.Equal(owned.NetworkConfig, files.NetworkConfig) {
		t.Fatal("input mutation changed decoded files")
	}

}

func TestAutomationSecretRefusesInvalidInputsWithoutMarkers(t *testing.T) {
	id := secretIdentity(t)
	binding := secretBindingFixture()
	files := EffectiveBootstrap{UserData: []byte("SECRET-MARKER")}
	invalidBindings := []SecretBinding{{}, binding, binding, binding, binding, binding, binding, binding}
	invalidBindings[1].ClusterUID = ""
	invalidBindings[2].ProjectUID = ""
	invalidBindings[3].ResourceUID = ""
	invalidBindings[4].OperationID = ""
	invalidBindings[5].PayloadID = ""
	invalidBindings[6].AdmittedGeneration = 0
	invalidBindings[7].PayloadID = strings.Repeat("MARKER", 1000)
	for _, invalid := range invalidBindings {
		b, err := EncryptBootstrap(invalid, files, []*age.X25519Recipient{id.Recipient()})
		if err == nil || b != nil || err.Error() != "invalid bootstrap secret" {
			t.Fatal("invalid binding was not safely rejected")
		}
	}
	for _, recipients := range [][]*age.X25519Recipient{nil, {nil}, {id.Recipient(), id.Recipient()}, make([]*age.X25519Recipient, bootstrapRecipientsMax+1), {new(age.X25519Recipient)}} {
		b, err := EncryptBootstrap(binding, files, recipients)
		if err == nil || b != nil || err.Error() != "invalid bootstrap secret" {
			t.Fatal("invalid recipients were not safely rejected")
		}
	}
	for _, identities := range [][]*age.X25519Identity{nil, {nil}, {new(age.X25519Identity)}} {
		got, err := DecryptBootstrap(binding, []byte("MALFORMED-CIPHERTEXT-MARKER"), identities)
		requireNoBootstrap(t, got, err)
	}
	got, err := DecryptBootstrap(binding, make([]byte, bootstrapCiphertextMaxBytes+1), []*age.X25519Identity{id})
	requireNoBootstrap(t, got, err)
	// Authenticated but oversized or invalid application data still yields no files.
	for _, raw := range [][]byte{[]byte("PRIVATE-BAD-FRAME-MARKER"), make([]byte, bootstrapPlaintextMaxBytes+1)} {
		cipher := encryptRawBootstrap(t, raw, id.Recipient())
		got, err := DecryptBootstrap(binding, cipher, []*age.X25519Identity{id})
		requireNoBootstrap(t, got, err)
	}
}

// The first authenticated chunk contains an entire valid application frame.
// Only consuming the subsequent chunk to authenticated EOF can reject this
// truncated/corrupted stream; parsing the available prefix is insufficient.
func TestAutomationSecretNoPlaintextFromAuthenticatedPrefix(t *testing.T) {
	id := secretIdentity(t)
	binding := secretBindingFixture()
	overhead, err := encodeBootstrap(binding, EffectiveBootstrap{UserData: []byte{}})
	if err != nil {
		t.Fatal("frame setup failed")
	}
	frame, err := encodeBootstrap(binding, EffectiveBootstrap{UserData: make([]byte, (64<<10)-len(overhead))})
	if err != nil || len(frame) != (64<<10) {
		t.Fatal("chunk-aligned frame setup failed")
	}
	cipher := encryptRawBootstrap(t, append(bytes.Clone(frame), 1), id.Recipient())
	for _, cut := range []int{len(cipher) - 1, len(cipher) - 17} {
		got, err := DecryptBootstrap(binding, cipher[:cut], []*age.X25519Identity{id})
		requireNoBootstrap(t, got, err)
	}
	cipher[len(cipher)-1] ^= 1
	got, err := DecryptBootstrap(binding, cipher, []*age.X25519Identity{id})
	requireNoBootstrap(t, got, err)
}

func TestAutomationSecretValidatesEntireIdentityList(t *testing.T) {
	a, b := secretIdentity(t), secretIdentity(t)
	copyA, err := age.ParseX25519Identity(a.String())
	if err != nil {
		t.Fatal("independent identity parse failed")
	}
	binding := secretBindingFixture()
	files := EffectiveBootstrap{UserData: []byte("IDENTITY-LIST-PRIVATE-MARKER"), Metadata: []byte{}, NetworkConfig: nil}
	ciphertext, err := EncryptBootstrap(binding, files, []*age.X25519Recipient{a.Recipient()})
	if err != nil {
		t.Fatal("identity-list fixture encryption failed")
	}
	invalid := map[string][]*age.X25519Identity{
		"repeated-pointer":          {a, a},
		"independently-parsed-copy": {a, copyA},
		"zero-first":                {new(age.X25519Identity), a},
		"zero-last":                 {a, new(age.X25519Identity)},
		"nil-first":                 {nil, a},
		"nil-last":                  {a, nil},
	}
	for name, identities := range invalid {
		t.Run(name, func(t *testing.T) {
			got, err := DecryptBootstrap(binding, ciphertext, identities)
			requireNoBootstrap(t, got, err)
		})
	}
	valid := map[string][]*age.X25519Identity{
		"original":       {a},
		"parsed":         {copyA},
		"matching-first": {a, b},
		"matching-last":  {b, a},
	}
	for name, identities := range valid {
		t.Run(name, func(t *testing.T) {
			got, err := DecryptBootstrap(binding, ciphertext, identities)
			if err != nil || !reflect.DeepEqual(got, files) {
				t.Fatal("valid distinct identities did not recover exact files")
			}
		})
	}
}
