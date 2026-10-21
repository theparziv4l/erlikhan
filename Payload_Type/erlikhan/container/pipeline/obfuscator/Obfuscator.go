package obfuscator

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type ObfuOptions struct {
	Strings     bool
	DeadCode    bool
	Opaque      bool
	MBA         bool
	ControlFlow bool
	Garble      bool
}

func (o ObfuOptions) AnyEnabled() bool {
	return o.Strings || o.DeadCode || o.Opaque || o.MBA || o.ControlFlow || o.Garble
}

func ObfuscateSource(dir string, opts ObfuOptions) {
	if !opts.AnyEnabled() {
		return
	}

	goFiles := collectGoFiles(dir)
	if len(goFiles) == 0 {
		return
	}

	if opts.Strings {
		fmt.Println("[*] Applying XOR string encryption obfuscation...")
		for _, f := range goFiles {
			ObfuscateStrings(f)
		}
	}

	if opts.DeadCode {
		fmt.Println("[*] Injecting dead code and junk functions...")
		for _, f := range goFiles {
			InjectDeadCode(f)
		}
	}

	if opts.Opaque {
		fmt.Println("[*] Inserting opaque predicates...")
		for _, f := range goFiles {
			InsertOpaquePredicates(f)
		}
	}

	if opts.MBA {
		fmt.Println("[*] Applying MBA numeric obfuscation...")
		for _, f := range goFiles {
			ObfuscateMBA(f)
		}
	}

	if opts.ControlFlow {
		fmt.Println("[*] Applying control flow flattening...")
		for _, f := range goFiles {
			FlattenControlFlow(f)
		}
	}

	if opts.Garble {
		fmt.Println("[*] Injecting garble controlflow directives...")
		for _, f := range goFiles {
			InjectGarbleDirectives(f)
		}
	}
}

func collectGoFiles(dir string) []string {
	var files []string
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(path, ".go") {
			files = append(files, path)
		}
		return nil
	})
	return files
}
