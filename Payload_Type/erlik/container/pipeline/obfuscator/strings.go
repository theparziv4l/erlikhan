package obfuscator

import (
	"crypto/rand"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	mrand "math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

func ObfuscateStrings(filepath string) {
	src, err := os.ReadFile(filepath)
	if err != nil {
		return
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath, src, parser.ParseComments)
	if err != nil {
		return
	}

	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))

	importPositions := make(map[token.Pos]bool)
	for _, imp := range f.Imports {
		importPositions[imp.Path.Pos()] = true
	}

	// String consts cannot become call expressions; mirror mba.go.
	var constDecls [][2]token.Pos
	for _, decl := range f.Decls {
		if gd, ok := decl.(*ast.GenDecl); ok && gd.Tok == token.CONST {
			constDecls = append(constDecls, [2]token.Pos{gd.Pos(), gd.End()})
		}
	}

	type replacement struct {
		offset   int
		length   int
		funcName string
	}
	var replacements []replacement
	var decryptFuncs []string

	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}

		if importPositions[lit.Pos()] {
			return true
		}

		// Raw literals are struct tags or templates; calls are not
		// valid in tag position.
		if strings.HasPrefix(lit.Value, "`") {
			return true
		}

		for _, r := range constDecls {
			if lit.Pos() >= r[0] && lit.Pos() <= r[1] {
				return true
			}
		}

		val, err := strconv.Unquote(lit.Value)
		if err != nil || len(val) == 0 || len(val) > 512 {
			return true
		}

		if len(val) < 3 {
			return true
		}

		funcName := randomFuncName(rng)
		pattern := rng.Intn(4)

		var decryptFunc string
		switch pattern {
		case 0:
			decryptFunc = generateXORDecrypt(funcName, val, rng)
		case 1:
			decryptFunc = generateAddSubDecrypt(funcName, val, rng)
		case 2:
			decryptFunc = generateBitRotateDecrypt(funcName, val, rng)
		case 3:
			decryptFunc = generateIndexXORDecrypt(funcName, val, rng)
		}

		decryptFuncs = append(decryptFuncs, decryptFunc)

		offset := fset.Position(lit.Pos()).Offset
		replacements = append(replacements, replacement{
			offset:   offset,
			length:   len(lit.Value),
			funcName: funcName,
		})

		return true
	})

	if len(replacements) == 0 {
		return
	}

	sort.Slice(replacements, func(i, j int) bool {
		return replacements[i].offset > replacements[j].offset
	})

	content := string(src)
	for _, r := range replacements {
		before := content[:r.offset]
		after := content[r.offset+r.length:]
		content = before + r.funcName + "()" + after
	}

	funcBlock := "\n" + strings.Join(decryptFuncs, "\n")
	content = content + funcBlock

	os.WriteFile(filepath, []byte(content), 0666)
}

var reservedNames = map[string]bool{
	"break": true, "case": true, "chan": true, "const": true,
	"continue": true, "default": true, "defer": true, "else": true,
	"fallthrough": true, "for": true, "func": true, "go": true,
	"goto": true, "if": true, "import": true, "interface": true,
	"map": true, "package": true, "range": true, "return": true,
	"select": true, "struct": true, "switch": true, "type": true,
	"var": true, "string": true, "byte": true,
}

func randomFuncName(rng *mrand.Rand) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	const allChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for {
		length := 8 + rng.Intn(12)
		b := make([]byte, length)
		b[0] = letters[rng.Intn(len(letters))]
		for i := 1; i < length; i++ {
			b[i] = allChars[rng.Intn(len(allChars))]
		}
		if name := string(b); !reservedNames[name] {
			return name
		}
	}
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func byteSliceLiteral(data []byte) string {
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("0x%02x", b)
	}
	return "[]byte{" + strings.Join(parts, ",") + "}"
}

func generateXORDecrypt(funcName string, plaintext string, rng *mrand.Rand) string {
	data := []byte(plaintext)
	key := randomBytes(len(data))
	encrypted := make([]byte, len(data))
	for i := range data {
		encrypted[i] = data[i] ^ key[i]
	}

	iterVar := randomVarName(rng)
	keyVar := randomVarName(rng)
	encVar := randomVarName(rng)

	return fmt.Sprintf(`func %s() string {
	%s := %s
	%s := %s
	for %s := range %s { %s[%s] ^= %s[%s] }
	return string(%s)
}`, funcName, keyVar, byteSliceLiteral(key), encVar, byteSliceLiteral(encrypted),
		iterVar, encVar, encVar, iterVar, keyVar, iterVar, encVar)
}

func generateAddSubDecrypt(funcName string, plaintext string, rng *mrand.Rand) string {
	data := []byte(plaintext)
	key := randomBytes(len(data))
	encrypted := make([]byte, len(data))
	for i := range data {
		encrypted[i] = data[i] + key[i]
	}

	iterVar := randomVarName(rng)
	keyVar := randomVarName(rng)
	encVar := randomVarName(rng)

	return fmt.Sprintf(`func %s() string {
	%s := %s
	%s := %s
	for %s := range %s { %s[%s] -= %s[%s] }
	return string(%s)
}`, funcName, keyVar, byteSliceLiteral(key), encVar, byteSliceLiteral(encrypted),
		iterVar, encVar, encVar, iterVar, keyVar, iterVar, encVar)
}

func generateBitRotateDecrypt(funcName string, plaintext string, rng *mrand.Rand) string {
	data := []byte(plaintext)
	shift := byte(1 + rng.Intn(6))
	encrypted := make([]byte, len(data))
	for i := range data {
		encrypted[i] = (data[i] << shift) | (data[i] >> (8 - shift))
	}

	iterVar := randomVarName(rng)
	encVar := randomVarName(rng)

	return fmt.Sprintf(`func %s() string {
	%s := %s
	for %s := range %s { %s[%s] = (%s[%s] >> %d) | (%s[%s] << %d) }
	return string(%s)
}`, funcName, encVar, byteSliceLiteral(encrypted),
		iterVar, encVar, encVar, iterVar, encVar, iterVar, shift, encVar, iterVar, 8-shift, encVar)
}

func generateIndexXORDecrypt(funcName string, plaintext string, rng *mrand.Rand) string {
	data := []byte(plaintext)
	key := byte(rng.Intn(255) + 1)
	encrypted := make([]byte, len(data))
	for i := range data {
		encrypted[i] = data[i] ^ key ^ byte(i)
	}

	iterVar := randomVarName(rng)
	encVar := randomVarName(rng)

	return fmt.Sprintf(`func %s() string {
	%s := %s
	for %s := range %s { %s[%s] ^= 0x%02x ^ byte(%s) }
	return string(%s)
}`, funcName, encVar, byteSliceLiteral(encrypted),
		iterVar, encVar, encVar, iterVar, key, iterVar, encVar)
}

func randomVarName(rng *mrand.Rand) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	for {
		length := 3 + rng.Intn(6)
		b := make([]byte, length)
		for i := range b {
			b[i] = letters[rng.Intn(len(letters))]
		}
		if name := string(b); !reservedNames[name] {
			return name
		}
	}
}
