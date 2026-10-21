package obfuscator

import (
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"strings"
	"time"
)

var GarbleProfile string

func generateGarbleDirective(profile string) string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	switch profile {
	case "fixed":
		return "//garble:controlflow flatten_passes=2 junk_jumps=4 block_splits=2"
	case "aggressive":
		fp := r.Intn(4) + 3
		jj := r.Intn(7) + 6
		bs := r.Intn(4) + 3
		return fmt.Sprintf("//garble:controlflow flatten_passes=%d junk_jumps=%d block_splits=%d", fp, jj, bs)
	default:
		fp := r.Intn(4) + 1
		jj := r.Intn(7) + 2
		bs := r.Intn(4) + 1
		return fmt.Sprintf("//garble:controlflow flatten_passes=%d junk_jumps=%d block_splits=%d", fp, jj, bs)
	}
}

func InjectGarbleDirectives(filepath string) {
	src, err := os.ReadFile(filepath)
	if err != nil {
		return
	}

	content := string(src)

	if strings.Contains(content, "//garble:controlflow") {
		return
	}

	funcPattern := regexp.MustCompile(`(?m)^func (\w+)\(`)
	content = funcPattern.ReplaceAllStringFunc(content, func(match string) string {
		sub := funcPattern.FindStringSubmatch(match)
		if len(sub) > 1 && (sub[1] == "init" || sub[1] == "main") {
			return match
		}
		return generateGarbleDirective(GarbleProfile) + "\n" + match
	})

	os.WriteFile(filepath, []byte(content), 0666)
}
