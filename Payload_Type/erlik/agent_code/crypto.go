package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

// Mythic agent envelope, both directions:
//
//	none:       base64(UUID + JSON)
//	aes256_hmac: base64(UUID + IV(16) + AES256-CBC-PKCS7(JSON) + HMAC-SHA256(key, IV||ct))
//
// ponytail: duplicated in Mythic harness tests and the payload container
// because the agent must build dependency-free; the algorithm is small and
// both copies are pinned by the same golden vectors.
//
// Raw variants carry the same bytes without base64 for transports (dns)
// that frame raw envelopes.
func sealRaw(uuid string, payload []byte, cryptoMode string, psk []byte) ([]byte, error) {
	switch cryptoMode {
	case "none":
		out := make([]byte, 0, len(uuid)+len(payload))
		out = append(out, uuid...)
		out = append(out, payload...)
		return out, nil
	case "aes256_hmac":
		if len(psk) != 32 {
			return nil, fmt.Errorf("aes256_hmac needs 32-byte key, got %d", len(psk))
		}
		iv := make([]byte, 16)
		if _, err := rand.Read(iv); err != nil {
			return nil, err
		}
		block, err := aes.NewCipher(psk)
		if err != nil {
			return nil, err
		}
		padded := pkcs7Pad(payload, aes.BlockSize)
		ct := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
		mac := hmac.New(sha256.New, psk)
		mac.Write(iv)
		mac.Write(ct)
		out := make([]byte, 0, len(uuid)+len(iv)+len(ct)+sha256.Size)
		out = append(out, uuid...)
		out = append(out, iv...)
		out = append(out, ct...)
		out = append(out, mac.Sum(nil)...)
		return out, nil
	}
	return nil, fmt.Errorf("unknown crypto mode %q", cryptoMode)
}

func sealEnvelope(uuid string, payload []byte, cryptoMode string, psk []byte) (string, error) {
	raw, err := sealRaw(uuid, payload, cryptoMode, psk)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func openRaw(raw []byte, cryptoMode string, psk []byte) (string, []byte, error) {
	if len(raw) < 36 {
		return "", nil, fmt.Errorf("envelope too short: %d bytes", len(raw))
	}
	uuid := string(raw[:36])
	blob := raw[36:]
	switch cryptoMode {
	case "none":
		return uuid, blob, nil
	case "aes256_hmac":
		if len(psk) != 32 {
			return "", nil, fmt.Errorf("aes256_hmac needs 32-byte key, got %d", len(psk))
		}
		if len(blob) < 16+32+16 { // iv + hmac + one block
			return "", nil, fmt.Errorf("encrypted blob too short: %d bytes", len(blob))
		}
		iv := blob[:16]
		ct := blob[16 : len(blob)-32]
		want := blob[len(blob)-32:]
		mac := hmac.New(sha256.New, psk)
		mac.Write(iv)
		mac.Write(ct)
		if subtle.ConstantTimeCompare(mac.Sum(nil), want) != 1 {
			return "", nil, fmt.Errorf("HMAC mismatch")
		}
		block, err := aes.NewCipher(psk)
		if err != nil {
			return "", nil, err
		}
		if len(ct)%aes.BlockSize != 0 {
			return "", nil, fmt.Errorf("ciphertext not a whole number of blocks")
		}
		pt := make([]byte, len(ct))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
		out, err := pkcs7Unpad(pt)
		if err != nil {
			return "", nil, err
		}
		return uuid, out, nil
	default:
		return "", nil, fmt.Errorf("unknown crypto mode %q", cryptoMode)
	}
}

func openEnvelope(msg string, cryptoMode string, psk []byte) (string, []byte, error) {
	raw, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		return "", nil, err
	}
	return openRaw(raw, cryptoMode, psk)
}

func pkcs7Pad(b []byte, blocksize int) []byte {
	n := blocksize - (len(b) % blocksize)
	return append(b, bytes.Repeat([]byte{byte(n)}, n)...)
}

func pkcs7Unpad(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("empty plaintext")
	}
	n := int(b[len(b)-1])
	if n == 0 || n > aes.BlockSize || n > len(b) {
		return nil, fmt.Errorf("bad padding")
	}
	for _, v := range b[len(b)-n:] {
		if int(v) != n {
			return nil, fmt.Errorf("bad padding")
		}
	}
	return b[:len(b)-n], nil
}
