package cryptor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rc4"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	crand "math/rand"
	"os"

	"github.com/ulikunitz/xz"
	"golang.org/x/crypto/chacha20poly1305"
)

const capletters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const hexchar = "abcdef1234567890"

var (
	ErrInvalidBlockSize = errors.New("[-] Invalid Blocksize")

	ErrInvalidPKCS7Data = errors.New("[-] Invalid PKCS7 Data (Empty or Not Padded)")

	ErrInvalidPKCS7Padding = errors.New("[-] Invalid Padding on Input")
)

// EncryptShellcode reads inputFile and encrypts it under mode.
// Modes: AES-GCM, CHACHA20 (AEAD, recommended), AES (CBC, legacy),
// RC4 and ELZMA (deprecated, kept for loader compatibility).
// Unknown modes return an error instead of empty output.
func EncryptShellcode(inputFile string, encryptionmode string) (string, string, string, error) {
	src, err := os.ReadFile(inputFile)
	if err != nil {
		return "", "", "", fmt.Errorf("reading shellcode file %s: %w", inputFile, err)
	}
	if len(src) == 0 {
		return "", "", "", fmt.Errorf("shellcode file %s is empty: provide raw 64-bit shellcode", inputFile)
	}
	switch encryptionmode {
	case "ELZMA":
		fmt.Println("[*] Encrypting Shellcode Using ELZMA Encryption")
	case "RC4":
		fmt.Println("[*] Encrypting Shellcode Using RC4 Encryption")
	case "CHACHA20":
		fmt.Println("[*] Encrypting Shellcode Using ChaCha20-Poly1305 Encryption")
	case "AES-GCM":
		fmt.Println("[*] Encrypting Shellcode Using AES-256-GCM Encryption")
	}
	return EncryptBytes(src, encryptionmode)
}

// EncryptBytes encrypts in-memory src under mode. Same wire formats as
// EncryptShellcode; generated-from-zero payloads use this instead of a file.
func EncryptBytes(src []byte, encryptionmode string) (string, string, string, error) {
	if len(src) == 0 {
		return "", "", "", fmt.Errorf("cannot encrypt empty input")
	}
	hexenc := func(b []byte) string { return fmt.Sprintf("%x", b) }
	switch encryptionmode {
	case "AES":
		key, err := generateRandomBytes(32)
		if err != nil {
			return "", "", "", err
		}
		iv, err := generateRandomBytes(16)
		if err != nil {
			return "", "", "", err
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return "", "", "", err
		}
		paddedInput, err := Pkcs7Pad(src, aes.BlockSize)
		if err != nil {
			return "", "", "", err
		}
		cipherText := make([]byte, len(paddedInput))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(cipherText, paddedInput)
		return hexenc(cipherText), hexenc(key), hexenc(iv), nil
	case "ELZMA":
		var buf bytes.Buffer
		w, err := xz.NewWriter(&buf)
		if err != nil {
			return "", "", "", err
		}
		if _, err := w.Write(src); err != nil {
			return "", "", "", err
		}
		if err := w.Close(); err != nil {
			return "", "", "", err
		}
		return hexenc(buf.Bytes()), "", "", nil
	case "RC4":
		key, err := generateRandomBytes(32)
		if err != nil {
			return "", "", "", err
		}
		block, err := rc4.NewCipher(key)
		if err != nil {
			return "", "", "", err
		}
		ciphertext := make([]byte, len(src))
		block.XORKeyStream(ciphertext, src)
		return hexenc(ciphertext), hexenc(key), "", nil
	case "CHACHA20", "AES-GCM":
		key, err := generateRandomBytes(32)
		if err != nil {
			return "", "", "", err
		}
		var aead cipher.AEAD
		if encryptionmode == "CHACHA20" {
			aead, err = chacha20poly1305.NewX(key)
		} else {
			var block cipher.Block
			block, err = aes.NewCipher(key)
			if err == nil {
				aead, err = cipher.NewGCM(block)
			}
		}
		if err != nil {
			return "", "", "", err
		}
		nonce := make([]byte, aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return "", "", "", err
		}
		return hexenc(aead.Seal(nil, nonce, src, nil)), hexenc(key), hexenc(nonce), nil
	}
	return "", "", "", fmt.Errorf("unknown encryption mode %q", encryptionmode)
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func Pkcs7Pad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb, nil
}

func RandomBuffer(size int) []byte {
	buffer := make([]byte, size)
	_, err := rand.Read(buffer)
	if err != nil {
		log.Fatal(err)
	}
	return buffer
}

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[crand.Intn(len(letters))]

	}
	return string(b)
}

func Mangle(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = hexchar[crand.Intn(len(hexchar))]

	}
	return string(b)
}

func VarNumberLength(min, max int) string {
	var r string
	num := crand.Intn(max-min) + min
	n := num
	r = RandStringBytes(n)
	return r
}

func printHexOutput(input ...[]byte) {
	for _, i := range input {
		fmt.Println(hex.EncodeToString(i))
	}
}

func GenerateNumer(min, max int) int {
	num := crand.Intn(max-min) + min
	n := num
	return n

}

func CapLetter() string {
	n := 1
	b := make([]byte, n)
	for i := range b {
		b[i] = capletters[crand.Intn(len(capletters))]

	}
	return string(b)
}
