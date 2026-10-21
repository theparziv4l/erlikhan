package obfuscator

import (
	"fmt"
	mrand "math/rand"
	"os"
	"regexp"
	"strings"
	"time"
)

func FlattenControlFlow(filepath string) {
	src, err := os.ReadFile(filepath)
	if err != nil {
		return
	}

	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	content := string(src)

	// Match function bodies - find functions with substantial bodies
	funcPattern := regexp.MustCompile(`(?ms)^(func\s+\w+\s*\([^)]*\)[^{]*)\{(.*?)\n\}`)
	matches := funcPattern.FindAllStringSubmatchIndex(content, -1)

	if len(matches) == 0 {
		return
	}

	// Process from end to preserve indices
	for i := len(matches) - 1; i >= 0; i-- {
		match := matches[i]
		sig := content[match[2]:match[3]]
		body := content[match[4]:match[5]]

		// Skip tiny functions, exported functions starting with uppercase that might be entry points,
		// and functions with complex control flow already (if/for/switch/select)
		lines := splitStatements(body)
		if len(lines) < 4 {
			continue
		}

		// Skip if body contains return with value, defer, go, select, or channel ops
		if containsComplexFlow(body) {
			continue
		}

		// Skip bodies with multi-line statements; flattening splits
		// by line and would corrupt them.
		if hasUnbalancedLine(lines) {
			continue
		}

		flattened := flattenBody(lines, rng)
		newFunc := sig + " {\n" + flattened + "\n}"
		content = content[:match[0]] + newFunc + content[match[1]:]
	}

	os.WriteFile(filepath, []byte(content), 0666)
}

func splitStatements(body string) []string {
	lines := strings.Split(strings.TrimSpace(body), "\n")
	var statements []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && trimmed != "{" && trimmed != "}" {
			statements = append(statements, line)
		}
	}
	return statements
}

func containsComplexFlow(body string) bool {
	keywords := []string{"return ", "defer ", "go ", "select ", "<-", "for ", "switch ", "if ", "range "}
	for _, kw := range keywords {
		if strings.Contains(body, kw) {
			return true
		}
	}
	return false
}

// hasUnbalancedLine reports lines with unbalanced delimiters after
// stripping double-quoted runs. Errors conservative: strings the
// stripper misses only cause skips, never corruption.
func hasUnbalancedLine(lines []string) bool {
	for _, ln := range lines {
		s := ln
		for {
			i := strings.IndexByte(s, '"')
			if i < 0 {
				break
			}
			j := i + 1
			for j < len(s) {
				if s[j] == '\\' {
					j += 2
					continue
				}
				if s[j] == '"' {
					break
				}
				j++
			}
			s = s[:i] + s[min(j+1, len(s)):]
		}
		var paren, bracket, brace int
		for _, r := range s {
			switch r {
			case '(':
				paren++
			case ')':
				paren--
			case '[':
				bracket++
			case ']':
				bracket--
			case '{':
				brace++
			case '}':
				brace--
			}
		}
		if paren != 0 || bracket != 0 || brace != 0 {
			return true
		}
	}
	return false
}

func flattenBody(statements []string, rng *mrand.Rand) string {
	n := len(statements)
	stateVar := randomVarName(rng)
	loopVar := randomVarName(rng)

	// Generate randomized state IDs (non-sequential to confuse analysis)
	stateIDs := make([]int, n+1)
	used := make(map[int]bool)
	for i := range stateIDs {
		for {
			id := rng.Intn(n*10+50) + 1
			if !used[id] {
				used[id] = true
				stateIDs[i] = id
				break
			}
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\t%s := %d\n", stateVar, stateIDs[0]))
	sb.WriteString(fmt.Sprintf("\t%s := true\n", loopVar))
	sb.WriteString(fmt.Sprintf("\tfor %s {\n", loopVar))
	sb.WriteString(fmt.Sprintf("\t\tswitch %s {\n", stateVar))

	for i, stmt := range statements {
		sb.WriteString(fmt.Sprintf("\t\tcase %d:\n", stateIDs[i]))
		sb.WriteString(fmt.Sprintf("\t\t\t%s\n", strings.TrimSpace(stmt)))
		sb.WriteString(fmt.Sprintf("\t\t\t%s = %d\n", stateVar, stateIDs[i+1]))
	}

	// Terminal state
	sb.WriteString(fmt.Sprintf("\t\tcase %d:\n", stateIDs[n]))
	sb.WriteString(fmt.Sprintf("\t\t\t%s = false\n", loopVar))

	// Add 2-4 junk cases that are never reached
	numJunk := 2 + rng.Intn(3)
	for j := 0; j < numJunk; j++ {
		var junkID int
		for {
			junkID = rng.Intn(n*10+100) + n*10 + 51
			if !used[junkID] {
				used[junkID] = true
				break
			}
		}
		junkVar := randomVarName(rng)
		sb.WriteString(fmt.Sprintf("\t\tcase %d:\n", junkID))
		sb.WriteString(fmt.Sprintf("\t\t\t%s := %d\n", junkVar, rng.Intn(9999)+1))
		sb.WriteString(fmt.Sprintf("\t\t\t_ = %s\n", junkVar))
		sb.WriteString(fmt.Sprintf("\t\t\t%s = %d\n", stateVar, stateIDs[n]))
	}

	sb.WriteString("\t\t}\n")
	sb.WriteString("\t}")

	return sb.String()
}
