package obfuscator

import (
	"fmt"
	mrand "math/rand"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ponytail: Go's syscall.LazyProc needs a name string at runtime, so full
// PEB-hash resolution would need an unsafe PEB walker; XOR-encoded names
// decoded at runtime hide them from static scans instead. Upgrade path:
// PEB-walk resolver returning proc addresses by djb2 hash.
var (
	winProcRe    = regexp.MustCompile(`((?:NewLazyDLL|NewProc)\()"([A-Za-z][A-Za-z0-9_.]*)"\)`)
	winSSNRe     = regexp.MustCompile(`(ResolveSSN\(.*),\s*"([A-Za-z][A-Za-z0-9_]*)"\)`)
	winRegPathRe = regexp.MustCompile(`"(SOFTWARE|SYSTEM|HARDWARE)(\\\\(?:[^"\\]|\\.)*)"`)
	winRegValRe  = regexp.MustCompile(`((?:GetStringsValue|GetStringValue|GetIntegerValue|GetBinaryValue)\()"([A-Za-z][A-Za-z0-9_]*)"\)`)
)

// ObfuscateWinAPI rewrites plaintext DLL/proc names in generated Go source
// to runtime-decoded XOR blobs, e.g. NewProc("CreateProcessW") becomes
// NewProc(xYk([]byte{0x..})). Semantics-preserving.
func ObfuscateWinAPI(dir string) {
	for _, f := range collectGoFiles(dir) {
		ObfuscateWinAPIFile(f)
	}
}

func ObfuscateWinAPIFile(path string) {
	src, err := os.ReadFile(path)
	if err != nil {
		return
	}
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	helper := randomFuncName(rng)
	mult := byte(2*rng.Intn(128) + 1)
	add := byte(rng.Intn(256))
	encode := func(name string) string {
		parts := make([]string, len(name))
		for i := 0; i < len(name); i++ {
			parts[i] = fmt.Sprintf("0x%02x", name[i]^(byte(i)*mult+add))
		}
		return fmt.Sprintf("%s([]byte{%s})", helper, strings.Join(parts, ","))
	}
	content := string(src)
	content = winProcRe.ReplaceAllStringFunc(content, func(m string) string {
		parts := winProcRe.FindStringSubmatch(m)
		return parts[1] + encode(parts[2]) + ")"
	})
	content = winSSNRe.ReplaceAllStringFunc(content, func(m string) string {
		parts := winSSNRe.FindStringSubmatch(m)
		return parts[1] + ", " + encode(parts[2]) + ")"
	})
	content = winRegPathRe.ReplaceAllStringFunc(content, func(m string) string {
		val, err := strconv.Unquote(m)
		if err != nil {
			return m
		}
		return encode(val)
	})
	content = winRegValRe.ReplaceAllStringFunc(content, func(m string) string {
		parts := winRegValRe.FindStringSubmatch(m)
		return parts[1] + encode(parts[2]) + ")"
	})
	if content == string(src) {
		return
	}
	content += fmt.Sprintf("\nfunc %s(b []byte) string {\n\tfor i := range b { b[i] ^= (byte(i)*0x%02x+0x%02x) }\n\treturn string(b)\n}\n", helper, mult, add)
	os.WriteFile(path, []byte(content), 0666)
}
