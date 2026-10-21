package obfuscator

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	mrand "math/rand"
	"os"
	"sort"
	"strconv"
	"time"
)

func ObfuscateMBA(filepath string) {
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

	type replacement struct {
		offset int
		length int
		expr   string
	}
	var replacements []replacement

	constPositions := make(map[token.Pos]token.Pos)
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		if gd.Tok == token.CONST || gd.Tok == token.IMPORT {
			constPositions[gd.Pos()] = gd.End()
		}
	}

	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.INT {
			return true
		}

		for start, end := range constPositions {
			if lit.Pos() >= start && lit.Pos() <= end {
				return true
			}
		}

		val, err := strconv.ParseInt(lit.Value, 0, 64)
		if err != nil {
			return true
		}

		if val <= 1 || val > 0xFFFFFFFF {
			return true
		}

		expr := generateMBAExpression(val, rng)
		offset := fset.Position(lit.Pos()).Offset
		replacements = append(replacements, replacement{
			offset: offset,
			length: len(lit.Value),
			expr:   "(" + expr + ")",
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
		content = before + r.expr + after
	}

	os.WriteFile(filepath, []byte(content), 0666)
}

// All MBA expressions use only untyped constant arithmetic to preserve
// compatibility with any numeric type context (uintptr, time.Duration, etc.)
func generateMBAExpression(val int64, rng *mrand.Rand) string {
	pattern := rng.Intn(5)

	switch pattern {
	case 0:
		// (val ^ mask) ^ mask == val
		mask := int64(rng.Intn(0xFFFF) + 1)
		xored := val ^ mask
		return fmt.Sprintf("%d ^ %d", xored, mask)

	case 1:
		// (val + r) - r == val
		r := int64(rng.Intn(10000) + 100)
		return fmt.Sprintf("%d - %d", val+r, r)

	case 2:
		// (a & b) + (a | b) == a + b == val
		a := int64(rng.Intn(int(val)) + 1)
		b := val - a
		return fmt.Sprintf("(%d & %d) + (%d | %d)", a, b, a, b)

	case 3:
		// (val - r2 + r1) + r2 - r1 == val
		r1 := int64(rng.Intn(5000) + 50)
		r2 := int64(rng.Intn(5000) + 50)
		return fmt.Sprintf("%d + %d - %d", val-r2+r1, r2, r1)

	case 4:
		// ((val ^ a ^ b) ^ (a ^ b)) == val
		a := int64(rng.Intn(0xFFFF) + 1)
		b := int64(rng.Intn(0xFFFF) + 1)
		inner := val ^ a ^ b
		ab := a ^ b
		return fmt.Sprintf("%d ^ %d", inner, ab)
	}

	return fmt.Sprintf("%d", val)
}
