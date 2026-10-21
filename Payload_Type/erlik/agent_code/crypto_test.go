package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

const testUUID = "11111111-2222-3333-4444-555555555555"

var testPSK = bytes.Repeat([]byte{0x42}, 32)

func TestSealOpenNone(t *testing.T) {
	msg := []byte(`{"action":"checkin"}`)
	raw, err := sealRaw(testUUID, msg, "none", nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != testUUID+string(msg) {
		t.Fatalf("raw layout wrong: %q", raw)
	}
	env, err := sealEnvelope(testUUID, msg, "none", nil)
	if err != nil {
		t.Fatal(err)
	}
	if env != base64.StdEncoding.EncodeToString(raw) {
		t.Fatal("envelope is not base64(raw)")
	}
	uuid, out, err := openRaw(raw, "none", nil)
	if err != nil || uuid != testUUID || string(out) != string(msg) {
		t.Fatalf("openRaw = %q %q %v", uuid, out, err)
	}
	uuid, out, err = openEnvelope(env, "none", nil)
	if err != nil || uuid != testUUID || string(out) != string(msg) {
		t.Fatalf("openEnvelope = %q %q %v", uuid, out, err)
	}
}

func TestSealOpenAESRoundtrip(t *testing.T) {
	msg := []byte(`{"action":"get_tasking","tasking_size":-1}`)
	raw, err := sealRaw(testUUID, msg, "aes256_hmac", testPSK)
	if err != nil {
		t.Fatal(err)
	}
	if uuid, out, err := openRaw(raw, "aes256_hmac", testPSK); err != nil || uuid != testUUID || !bytes.Equal(out, msg) {
		t.Fatalf("raw roundtrip = %q %q %v", uuid, out, err)
	}
	env, err := sealEnvelope(testUUID, msg, "aes256_hmac", testPSK)
	if err != nil {
		t.Fatal(err)
	}
	if uuid, out, err := openEnvelope(env, "aes256_hmac", testPSK); err != nil || uuid != testUUID || !bytes.Equal(out, msg) {
		t.Fatalf("envelope roundtrip = %q %q %v", uuid, out, err)
	}
}

// TestSealAESLayout pins the sealed wire layout with straight-line stdlib
// calls, independent of openRaw: UUID prefix, block alignment, HMAC over
// IV||ciphertext, CBC decrypt plus PKCS7 unpad.
func TestSealAESLayout(t *testing.T) {
	msg := []byte(`{"action":"checkin"}`)
	raw, err := sealRaw(testUUID, msg, "aes256_hmac", testPSK)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw), testUUID) {
		t.Fatalf("missing uuid prefix: %q", raw[:36])
	}
	blob := raw[36:]
	if len(blob) < 16+32+16 || (len(blob)-16-32)%aes.BlockSize != 0 {
		t.Fatalf("bad length %d", len(blob))
	}
	iv, ct, tag := blob[:16], blob[16:len(blob)-32], blob[len(blob)-32:]
	mac := hmac.New(sha256.New, testPSK)
	mac.Write(iv)
	mac.Write(ct)
	if !hmac.Equal(mac.Sum(nil), tag) {
		t.Fatal("HMAC mismatch")
	}
	block, err := aes.NewCipher(testPSK)
	if err != nil {
		t.Fatal(err)
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	n := int(pt[len(pt)-1])
	if n == 0 || n > aes.BlockSize {
		t.Fatalf("bad padding %d", n)
	}
	if !bytes.Equal(pt[:len(pt)-n], msg) {
		t.Fatalf("decrypt mismatch: %q", pt[:len(pt)-n])
	}
}

func TestEnvelopeRejects(t *testing.T) {
	if _, _, err := openRaw([]byte("short"), "none", nil); err == nil {
		t.Fatal("short raw accepted")
	}
	if _, _, err := openEnvelope("!!!", "none", nil); err == nil {
		t.Fatal("bad base64 accepted")
	}
	if _, err := sealRaw(testUUID, []byte("{}"), "rot13", nil); err == nil {
		t.Fatal("bad mode sealed")
	}
	if _, _, err := openRaw(bytes.Repeat([]byte{0}, 40), "rot13", nil); err == nil {
		t.Fatal("bad mode opened")
	}
	if _, err := sealRaw(testUUID, []byte("{}"), "aes256_hmac", []byte("short")); err == nil {
		t.Fatal("short key sealed")
	}
	raw, err := sealRaw(testUUID, []byte("{}"), "aes256_hmac", testPSK)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xff
	if _, _, err := openRaw(raw, "aes256_hmac", testPSK); err == nil {
		t.Fatal("tampered tag accepted")
	}
}
