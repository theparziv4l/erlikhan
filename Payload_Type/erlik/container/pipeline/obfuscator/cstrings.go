package obfuscator

import (
	mrand "math/rand"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ObfuscateCStringLiterals encrypts C string literals in place with per-string
// keys, rotating among XOR, add/sub, bit-rotate, and index-XOR schemes.
// Each literal becomes a dec_<rand>() call backed by an encrypted byte array
// emitted after the last #include. Array initializers (char x[] = "...") are
// skipped: a call expression is not a valid array initializer in C.
func ObfuscateCStringLiterals(path string) {
	src, err := os.ReadFile(path)
	if err != nil {
		return
	}
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	lines := strings.Split(string(src), "\n")
	litRe := regexp.MustCompile(`"((?:[^"\\\n]|\\.){3,256})"`)
	arrInitRe := regexp.MustCompile(`\[\s*\]\s*=`)

	var decryptors []string
	changed := false
	inAsm := false
	inDefine := false
	depth := 0
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(line, "__asm__") {
			inAsm = true
		}
		atFileScope := depth == 0
		switch {
		case strings.HasPrefix(trimmed, "#"):
			inDefine = strings.HasSuffix(trimmed, "\\")
		case inDefine:
			inDefine = strings.HasSuffix(trimmed, "\\")
		case !inAsm:
			depth += braceDeltaC(line)
		}
		if inAsm {
			if strings.Contains(line, ");") {
				inAsm = false
			}
			continue
		}
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "/*") {
			continue
		}
		// Attribute arguments (e.g. section(".CRT$XLB")) must stay
		// literals: a decryptor call is not valid there.
		if strings.Contains(line, "__attribute__") {
			continue
		}
		if arrInitRe.MatchString(line) {
			continue
		}
		// File-scope single-line initializers must stay constant
		// expressions; a call is not valid there. Multi-line
		// file-scope string initializers are out of scope (none in
		// native templates; zig fails loud if one appears).
		if atFileScope && strings.Contains(line, "=") && strings.Contains(line, `"`) {
			continue
		}
		lines[i] = litRe.ReplaceAllStringFunc(line, func(match string) string {
			inner := match[1 : len(match)-1]
			raw, err := parseCStringInner(inner)
			if err != nil || len(raw) == 0 || len(raw) > 256 {
				return match
			}
			name := randomFuncName(rng)
			switch rng.Intn(4) {
			case 0:
				key := byte(rng.Intn(255) + 1)
				enc := make([]byte, len(raw))
				for j := range raw {
					enc[j] = raw[j] ^ key
				}
				decryptors = append(decryptors, cDecryptor(name, enc, key))
			case 1:
				key := byte(rng.Intn(255) + 1)
				enc := make([]byte, len(raw))
				for j := range raw {
					enc[j] = raw[j] + key
				}
				decryptors = append(decryptors, cAddSubDecryptor(name, enc, key))
			case 2:
				shift := byte(1 + rng.Intn(6))
				enc := make([]byte, len(raw))
				for j := range raw {
					enc[j] = (raw[j] << shift) | (raw[j] >> (8 - shift))
				}
				decryptors = append(decryptors, cRotDecryptor(name, enc, shift))
			case 3:
				key := byte(rng.Intn(255) + 1)
				enc := make([]byte, len(raw))
				for j := range raw {
					enc[j] = raw[j] ^ key ^ byte(j)
				}
				decryptors = append(decryptors, cIndexXORDecryptor(name, enc, key))
			}
			changed = true
			return name + "()"
		})
	}
	if !changed {
		return
	}
	content := strings.Join(lines, "\n")
	block := strings.Join(decryptors, "\n")
	content = insertAfterIncludes(content, "\n"+block+"\n")
	os.WriteFile(path, []byte(content), 0666)
}

var (
	cStrStripRe = regexp.MustCompile(`"([^"\\\n]|\\.)*"`)
	cChrStripRe = regexp.MustCompile(`'([^'\\\n]|\\.)*'`)
)

// braceDeltaC counts { minus } outside line comments and literals.
func braceDeltaC(line string) int {
	if i := strings.Index(line, "//"); i >= 0 {
		line = line[:i]
	}
	line = cStrStripRe.ReplaceAllString(line, "")
	line = cChrStripRe.ReplaceAllString(line, "")
	delta := 0
	for _, c := range line {
		switch c {
		case '{':
			delta++
		case '}':
			delta--
		}
	}
	return delta
}

// parseCStringInner decodes the inside of a C string literal (no quotes).
// strconv.Unquote handles standard escapes; octal/hex escapes included.
func parseCStringInner(inner string) ([]byte, error) {
	s, err := strconv.Unquote(`"` + inner + `"`)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

func cDecryptor(name string, enc []byte, key byte) string {
	parts := make([]string, len(enc))
	for i, b := range enc {
		parts[i] = "0x" + strings.ToUpper(strconv.FormatUint(uint64(b), 16))
		if len(parts[i]) == 3 {
			parts[i] = "0x0" + parts[i][2:]
		}
	}
	return "static unsigned char cenc_" + name + "[] = {" + strings.Join(parts, ",") + "};\n" +
		"static char cdec_" + name + "[" + strconv.Itoa(len(enc)+1) + "];\n" +
		"static const char *" + name + "(void) {\n" +
		"\tunsigned int cbi;\n" +
		"\tfor (cbi = 0; cbi < " + strconv.Itoa(len(enc)) + "; cbi++) cdec_" + name + "[cbi] = (char)(cenc_" + name + "[cbi] ^ 0x" + strings.ToUpper(strconv.FormatUint(uint64(key), 16)) + ");\n" +
		"\tcdec_" + name + "[" + strconv.Itoa(len(enc)) + "] = 0;\n" +
		"\treturn cdec_" + name + ";\n" +
		"}"
}

func cHex(b byte) string {
	s := "0x" + strings.ToUpper(strconv.FormatUint(uint64(b), 16))
	if len(s) == 3 {
		s = "0x0" + s[2:]
	}
	return s
}

func cEncDecl(name string, enc []byte) string {
	parts := make([]string, len(enc))
	for i, b := range enc {
		parts[i] = cHex(b)
	}
	return "static unsigned char cenc_" + name + "[] = {" + strings.Join(parts, ",") + "};\n" +
		"static char cdec_" + name + "[" + strconv.Itoa(len(enc)+1) + "];\n"
}

func cAddSubDecryptor(name string, enc []byte, key byte) string {
	return cEncDecl(name, enc) +
		"static const char *" + name + "(void) {\n" +
		"\tunsigned int cbi;\n" +
		"\tfor (cbi = 0; cbi < " + strconv.Itoa(len(enc)) + "; cbi++) cdec_" + name + "[cbi] = (char)(cenc_" + name + "[cbi] - " + cHex(key) + ");\n" +
		"\tcdec_" + name + "[" + strconv.Itoa(len(enc)) + "] = 0;\n" +
		"\treturn cdec_" + name + ";\n" +
		"}"
}

func cRotDecryptor(name string, enc []byte, shift byte) string {
	return cEncDecl(name, enc) +
		"static const char *" + name + "(void) {\n" +
		"\tunsigned int cbi;\n" +
		"\tfor (cbi = 0; cbi < " + strconv.Itoa(len(enc)) + "; cbi++) cdec_" + name + "[cbi] = (char)((cenc_" + name + "[cbi] >> " + strconv.Itoa(int(shift)) + ") | ((cenc_" + name + "[cbi] << " + strconv.Itoa(int(8-shift)) + ") & 0xFF));\n" +
		"\tcdec_" + name + "[" + strconv.Itoa(len(enc)) + "] = 0;\n" +
		"\treturn cdec_" + name + ";\n" +
		"}"
}

func cIndexXORDecryptor(name string, enc []byte, key byte) string {
	return cEncDecl(name, enc) +
		"static const char *" + name + "(void) {\n" +
		"\tunsigned int cbi;\n" +
		"\tfor (cbi = 0; cbi < " + strconv.Itoa(len(enc)) + "; cbi++) cdec_" + name + "[cbi] = (char)(cenc_" + name + "[cbi] ^ " + cHex(key) + " ^ (cbi & 0xFF));\n" +
		"\tcdec_" + name + "[" + strconv.Itoa(len(enc)) + "] = 0;\n" +
		"\treturn cdec_" + name + ";\n" +
		"}"
}

func insertAfterIncludes(content, block string) string {
	lines := strings.Split(content, "\n")
	last := -1
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "#include") {
			last = i
		}
	}
	if last < 0 {
		return block + "\n" + content
	}
	lines = append(lines[:last+1], append([]string{block}, lines[last+1:]...)...)
	return strings.Join(lines, "\n")
}
