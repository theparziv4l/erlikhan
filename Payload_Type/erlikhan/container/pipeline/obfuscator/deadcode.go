package obfuscator

import (
	"fmt"
	mrand "math/rand"
	"os"
	"strings"
	"time"
)

var junkFuncTemplates = []string{
	`func %s(%s []byte) []byte {
	%s := make([]byte, len(%s))
	for %s := range %s { %s[%s] = %s[%s] ^ byte(%s + %d) }
	return %s
}`,
	`func %s(%s string) int {
	%s := 0
	for _, %s := range %s { %s += int(%s) * %d }
	return %s %% %d
}`,
	`func %s(%s int) int {
	if %s <= 1 { return %s }
	%s, %s := 0, 1
	for %s := 2; %s <= %s; %s++ { %s, %s = %s, %s + %s }
	return %s
}`,
	`func %s(%s []byte) [32]byte {
	var %s [32]byte
	for %s := range %s {
		%s[%s %% 32] ^= %s[%s]
		%s[(%s+1) %% 32] = %s[%s %% 32] + byte(%s)
	}
	return %s
}`,
	`func %s(%s, %s int) int {
	%s := %s
	for %s > 0 { %s, %s = %s, %s %% %s }
	return %s
}`,
	`func %s(%s []byte, %s int) []byte {
	%s := len(%s)
	%s := make([]byte, %s)
	for %s := range %s { %s[%s] = %s[(%s + %s) %% %s] }
	return %s
}`,
}

// ponytail: junk funcs are never called, so the Go linker removes
// them; this pass only slows builds and litters source-level review.
// Upgrade path: wire calls into opaque dead branches so the code
// survives into the binary.
func InjectDeadCode(filepath string) {
	src, err := os.ReadFile(filepath)
	if err != nil {
		return
	}

	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	content := string(src)

	numFuncs := 3 + rng.Intn(6)
	var junkCode strings.Builder

	for i := 0; i < numFuncs; i++ {
		junkCode.WriteString("\n")
		junkCode.WriteString(generateJunkFunction(rng, i))
		junkCode.WriteString("\n")
	}

	content = content + junkCode.String()

	os.WriteFile(filepath, []byte(content), 0666)
}

func generateJunkFunction(rng *mrand.Rand, idx int) string {
	templateIdx := rng.Intn(len(junkFuncTemplates))
	funcName := randomFuncName(rng)

	switch templateIdx {
	case 0:
		p1 := randomVarName(rng)
		p2 := randomVarName(rng)
		it := randomVarName(rng)
		c := rng.Intn(200) + 1
		return fmt.Sprintf(junkFuncTemplates[0],
			funcName, p1, p2, p1, it, p1, p2, it, p1, it, it, c, p2)

	case 1:
		p1 := randomVarName(rng)
		acc := randomVarName(rng)
		ch := randomVarName(rng)
		m1 := rng.Intn(100) + 7
		m2 := rng.Intn(1000) + 100
		return fmt.Sprintf(junkFuncTemplates[1],
			funcName, p1, acc, ch, p1, acc, ch, m1, acc, m2)

	case 2:
		p1 := randomVarName(rng)
		a := randomVarName(rng)
		b := randomVarName(rng)
		it := randomVarName(rng)
		return fmt.Sprintf(junkFuncTemplates[2],
			funcName, p1, p1, p1, a, b, it, it, p1, it, a, b, b, a, b, b)

	case 3:
		p1 := randomVarName(rng)
		h := randomVarName(rng)
		it := randomVarName(rng)
		return fmt.Sprintf(junkFuncTemplates[3],
			funcName, p1, h, it, p1,
			h, it, p1, it,
			h, it, h, it, it, h)

	case 4:
		p1 := randomVarName(rng)
		p2 := randomVarName(rng)
		t := randomVarName(rng)
		return fmt.Sprintf(junkFuncTemplates[4],
			funcName, p1, p2, t, p1, p2, p1, p2, p2, p1, p2, t)

	case 5:
		p1 := randomVarName(rng)
		p2 := randomVarName(rng)
		ln := randomVarName(rng)
		res := randomVarName(rng)
		it := randomVarName(rng)
		return fmt.Sprintf(junkFuncTemplates[5],
			funcName, p1, p2, ln, p1, res, ln, it, p1, res, it, p1, it, p2, ln, res)
	}

	return ""
}
