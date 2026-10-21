package obfuscator

import (
	"fmt"
	mrand "math/rand"
	"os"
	"regexp"
	"time"
)

const numOpaquePatterns = 5

func InsertOpaquePredicates(filepath string) {
	src, err := os.ReadFile(filepath)
	if err != nil {
		return
	}

	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	content := string(src)

	funcPattern := regexp.MustCompile(`(?m)^func\s+\w+\s*\([^)]*\)[^{]*\{`)
	matches := funcPattern.FindAllStringIndex(content, -1)

	if len(matches) == 0 {
		return
	}

	insertions := make([]struct {
		pos  int
		code string
	}, 0)

	for _, match := range matches {
		bracePos := match[1]
		numPredicates := 1 + rng.Intn(3)

		for p := 0; p < numPredicates; p++ {
			code := generateOpaquePredicate(rng)
			insertions = append(insertions, struct {
				pos  int
				code string
			}{bracePos, code})
		}
	}

	// Insert from end to start to preserve positions
	for i := len(insertions) - 1; i >= 0; i-- {
		ins := insertions[i]
		content = content[:ins.pos] + "\n" + ins.code + "\n" + content[ins.pos:]
	}

	os.WriteFile(filepath, []byte(content), 0666)
}

func generateOpaquePredicate(rng *mrand.Rand) string {
	templateIdx := rng.Intn(numOpaquePatterns)

	junkBody := generateJunkBody(rng)

	switch templateIdx {
	case 0:
		// (x*x + x) % 2 == 0 -- always true
		v := randomVarName(rng)
		seed := rng.Intn(1000) + 2
		initCode := fmt.Sprintf("\t%s := %d", v, seed)
		cond := fmt.Sprintf("(%s*%s+%s)%%2 == 0", v, v, v)
		return fmt.Sprintf("%s\n\tif %s {\n\t_ = %s\n\t} else {\n%s\n\t}", initCode, cond, v, junkBody)

	case 1:
		// x*x >= 0 -- always true for integers
		v := randomVarName(rng)
		seed := rng.Intn(500) + 1
		initCode := fmt.Sprintf("\t%s := %d", v, seed)
		cond := fmt.Sprintf("(%s*%s) >= 0", v, v)
		return fmt.Sprintf("%s\n\tif %s {\n\t_ = %s\n\t} else {\n%s\n\t}", initCode, cond, v, junkBody)

	case 2:
		// (x | 1) > 0 -- always true for positive x
		v := randomVarName(rng)
		seed := rng.Intn(1000) + 1
		initCode := fmt.Sprintf("\t%s := %d", v, seed)
		cond := fmt.Sprintf("(%s|1) > 0", v)
		return fmt.Sprintf("%s\n\tif %s {\n\t_ = %s\n\t} else {\n%s\n\t}", initCode, cond, v, junkBody)

	case 3:
		// (a + b) == (a ^ b) + 2*(a & b) -- always true (mathematical identity)
		v1 := randomVarName(rng)
		v2 := randomVarName(rng)
		s1 := rng.Intn(200) + 1
		s2 := rng.Intn(200) + 1
		initCode := fmt.Sprintf("\t%s := %d\n\t%s := %d", v1, s1, v2, s2)
		cond := fmt.Sprintf("(%s + %s) == (%s ^ %s) + 2*(%s & %s)", v1, v2, v1, v2, v1, v2)
		return fmt.Sprintf("%s\n\tif %s {\n\t_ = %s + %s\n\t} else {\n%s\n\t}", initCode, cond, v1, v2, junkBody)

	case 4:
		// (x >> 1) + (x >> 1) <= x -- always true for non-negative x
		v := randomVarName(rng)
		seed := rng.Intn(1000) + 2
		initCode := fmt.Sprintf("\t%s := %d", v, seed)
		cond := fmt.Sprintf("((%s >> 1) + (%s >> 1)) <= %s", v, v, v)
		return fmt.Sprintf("%s\n\tif %s {\n\t_ = %s\n\t} else {\n%s\n\t}", initCode, cond, v, junkBody)
	}

	return ""
}

func generateJunkBody(rng *mrand.Rand) string {
	bodies := []string{
		"\t\t_ = make([]byte, %d)\n\t\t_ = %d * %d",
		"\t\tvar %s [%d]byte\n\t\t_ = %s",
		"\t\t%s := %d\n\t\t_ = %s + %d",
	}

	switch rng.Intn(len(bodies)) {
	case 0:
		return fmt.Sprintf(bodies[0], rng.Intn(100)+1, rng.Intn(1000)+1, rng.Intn(1000)+1)
	case 1:
		v := randomVarName(rng)
		return fmt.Sprintf(bodies[1], v, rng.Intn(64)+1, v)
	case 2:
		v := randomVarName(rng)
		return fmt.Sprintf(bodies[2], v, rng.Intn(5000)+1, v, rng.Intn(5000)+1)
	}
	return "\t\t_ = 0"
}
