package palace

import (
	"archive/zip"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// PICOBlob is the tag-dispatch header wrapping PICO code:
// [total_size u32][num_exports u32][tag,offset u32 pairs...][code].
// Offsets are relative to the code start.

// BuildPICOStub returns the no-op PICO for Go runtimes: two exported
// tags (setup_hooks=0, setup_memory=1) pointing at RET stubs.
func BuildPICOStub() []byte {
	code := []byte{0xC3, 0xC3} // RET, RET
	blob := make([]byte, 0, 8+16+len(code))
	u32 := func(v uint32) {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], v)
		blob = append(blob, b[:]...)
	}
	u32(uint32(8 + 16 + len(code)))
	u32(2)
	u32(0)
	u32(0) // setup_hooks -> code[0]
	u32(1)
	u32(1) // setup_memory -> code[1]
	blob = append(blob, code...)
	return blob
}

// XORBytes XORs data with a cycling key.
func XORBytes(data, key []byte) []byte {
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

// PrependLen builds a RESOURCE struct: {uint32 len; bytes...}.
func PrependLen(data []byte) []byte {
	out := make([]byte, 4+len(data))
	binary.LittleEndian.PutUint32(out[:4], uint32(len(data)))
	copy(out[4:], data)
	return out
}

type stagedObj struct {
	raw []byte
	src string
}

// Evaluator runs a Crystal Kit spec file top to bottom.
type Evaluator struct {
	linker  *Linker
	vars    map[string][]byte
	stack   [][]byte
	named   map[string][]byte
	order   []string
	exports map[string]int
	nextTag int
	objDir  string
	staged  *stagedObj
	// picoStub decides what `run` pushes when the sub-spec file is
	// absent: the RET stub blob, or empty when PICO is disabled.
	picoStub bool
	done     bool
}

// NewEvaluator creates an evaluator resolving load/run paths against
// objDir, with shellcode preloaded as $DLL.
func NewEvaluator(objDir string, shellcode []byte, picoStub bool) *Evaluator {
	return &Evaluator{
		linker:   NewLinker(),
		vars:     map[string][]byte{"$DLL": append([]byte(nil), shellcode...)},
		named:    map[string][]byte{},
		exports:  map[string]int{},
		objDir:   objDir,
		picoStub: picoStub,
	}
}

// NamedSections returns linked sections in link order.
func (e *Evaluator) NamedSections() (map[string][]byte, []string) {
	return e.named, e.order
}

// Assembly flushes staged objects and assembles the final blob.
func (e *Evaluator) Assembly() ([]byte, error) {
	if err := e.flush(); err != nil {
		return nil, err
	}
	return e.linker.Assemble(e.named, e.order)
}

func (e *Evaluator) flush() error {
	if e.staged == nil {
		return nil
	}
	s := e.staged
	e.staged = nil
	if err := e.linker.MergeObject(s.raw, false); err != nil {
		return fmt.Errorf("load %s: %w", s.src, err)
	}
	return nil
}

func (e *Evaluator) resolve(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(e.objDir, path)
}

// splitArgs tokenizes a directive line, honoring double quotes.
func splitArgs(line string) ([]string, error) {
	var args []string
	var cur strings.Builder
	inQ := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			inQ = !inQ
		case c == ' ' || c == '\t':
			if inQ {
				cur.WriteByte(c)
			} else if cur.Len() > 0 {
				args = append(args, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if inQ {
		return nil, fmt.Errorf("unterminated quote")
	}
	if cur.Len() > 0 {
		args = append(args, cur.String())
	}
	return args, nil
}

// Eval runs spec text.
func (e *Evaluator) Eval(text string) error {
	seenArch := false
	for ln, raw := range strings.Split(text, "\n") {
		lineNo := ln + 1
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !seenArch {
			if trimmed != "x64:" {
				return fmt.Errorf("spec line %d: want x64: header, got %q", lineNo, trimmed)
			}
			seenArch = true
			continue
		}
		if e.done {
			return fmt.Errorf("spec line %d: directive after export", lineNo)
		}
		args, err := splitArgs(trimmed)
		if err != nil {
			return fmt.Errorf("spec line %d: %w", lineNo, err)
		}
		if err := e.directive(args); err != nil {
			return fmt.Errorf("spec line %d (%s): %w", lineNo, args[0], err)
		}
	}
	return nil
}

// EvalFile runs a spec file from disk.
func (e *Evaluator) EvalFile(path string) error {
	raw, err := os.ReadFile(e.resolve(path))
	if err != nil {
		return err
	}
	return e.Eval(string(raw))
}

func needArgs(args []string, n int) error {
	if len(args) != n+1 {
		return fmt.Errorf("want %d args, got %d", n, len(args)-1)
	}
	return nil
}

func (e *Evaluator) directive(args []string) error {
	if e.done {
		return fmt.Errorf("directive after export")
	}
	switch args[0] {
	case "load":
		if err := needArgs(args, 1); err != nil {
			return err
		}
		if err := e.flush(); err != nil {
			return err
		}
		raw, err := os.ReadFile(e.resolve(args[1]))
		if err != nil {
			return err
		}
		e.staged = &stagedObj{raw: raw, src: args[1]}
		return nil
	case "make":
		// Modifier line for the preceding load: make pic
		// +gofirst +optimize (or make object +disco).
		if e.staged == nil {
			return fmt.Errorf("make without a preceding load")
		}
		goFirst := false
		for _, tok := range args[1:] {
			switch tok {
			case "pic", "object", "+optimize", "+disco":
			case "+gofirst":
				goFirst = true
			default:
				return fmt.Errorf("unknown modifier %q", tok)
			}
		}
		s := e.staged
		e.staged = nil
		if err := e.linker.MergeObject(s.raw, goFirst); err != nil {
			return fmt.Errorf("load %s: %w", s.src, err)
		}
		return nil
	case "merge":
		// Bare merge (modifier after load) or merge "file.o".
		if len(args) == 1 {
			if e.staged == nil {
				return fmt.Errorf("bare merge without a preceding load")
			}
			return e.flush()
		}
		if err := needArgs(args, 1); err != nil {
			return err
		}
		if err := e.flush(); err != nil {
			return err
		}
		raw, err := os.ReadFile(e.resolve(args[1]))
		if err != nil {
			return err
		}
		return e.linker.MergeObject(raw, false)
	case "mergelib":
		if err := needArgs(args, 1); err != nil {
			return err
		}
		if err := e.flush(); err != nil {
			return err
		}
		return e.mergeLib(args[1])
	case "dfr", "attach", "addhook":
		// No-ops: ROR13 resolution and direct _Func calls live in
		// the C code, and Sliver/Go builds carry no hooks.
		if err := needArgs(args, 2); err != nil {
			return err
		}
		return nil
	case "generate":
		if err := needArgs(args, 2); err != nil {
			return err
		}
		if !strings.HasPrefix(args[1], "$") {
			return fmt.Errorf("variable %q must start with $", args[1])
		}
		n, err := strconv.Atoi(args[2])
		if err != nil || n <= 0 || n > 1<<20 {
			return fmt.Errorf("bad length %q", args[2])
		}
		buf := make([]byte, n)
		if _, err := rand.Read(buf); err != nil {
			return err
		}
		e.vars[args[1]] = buf
		return nil
	case "push":
		if err := needArgs(args, 1); err != nil {
			return err
		}
		var b []byte
		if strings.HasPrefix(args[1], "$") {
			v, ok := e.vars[args[1]]
			if !ok {
				return fmt.Errorf("unknown variable %s", args[1])
			}
			b = v
		} else {
			v, ok := e.named[args[1]]
			if !ok {
				return fmt.Errorf("unknown section %q", args[1])
			}
			b = v
		}
		e.stack = append(e.stack, append([]byte(nil), b...))
		return nil
	case "xor":
		if err := needArgs(args, 1); err != nil {
			return err
		}
		if len(e.stack) == 0 {
			return fmt.Errorf("xor with an empty stack")
		}
		key, ok := e.vars[args[1]]
		if !ok || len(key) == 0 {
			return fmt.Errorf("unknown or empty key %s", args[1])
		}
		top := e.stack[len(e.stack)-1]
		e.stack[len(e.stack)-1] = XORBytes(top, key)
		return nil
	case "preplen":
		if len(args) != 1 {
			return fmt.Errorf("preplen takes no args")
		}
		if len(e.stack) == 0 {
			return fmt.Errorf("preplen with an empty stack")
		}
		top := e.stack[len(e.stack)-1]
		e.stack[len(e.stack)-1] = PrependLen(top)
		return nil
	case "link":
		if err := needArgs(args, 1); err != nil {
			return err
		}
		if len(e.stack) == 0 {
			return fmt.Errorf("link with an empty stack")
		}
		top := e.stack[len(e.stack)-1]
		e.stack = e.stack[:len(e.stack)-1]
		if _, seen := e.named[args[1]]; !seen {
			e.order = append(e.order, args[1])
		}
		e.named[args[1]] = top
		return nil
	case "run":
		if err := needArgs(args, 1); err != nil {
			return err
		}
		blob, err := e.runSub(args[1])
		if err != nil {
			return err
		}
		e.stack = append(e.stack, blob)
		return nil
	case "exportfunc":
		if err := needArgs(args, 2); err != nil {
			return err
		}
		if _, dup := e.exports[args[1]]; dup {
			return fmt.Errorf("duplicate export %q", args[1])
		}
		e.exports[args[1]] = e.nextTag
		e.nextTag++
		return nil
	case "export":
		if len(args) != 1 {
			return fmt.Errorf("export takes no args")
		}
		if err := e.flush(); err != nil {
			return err
		}
		e.done = true
		return nil
	default:
		return fmt.Errorf("unknown directive %q", args[0])
	}
}

func (e *Evaluator) mergeLib(path string) error {
	zr, err := zip.OpenReader(e.resolve(path))
	if err != nil {
		return err
	}
	defer zr.Close()
	var names []string
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		if strings.HasSuffix(strings.ToLower(f.Name), ".o") {
			names = append(names, f.Name)
			files[f.Name] = f
		}
	}
	sort.Strings(names) // deterministic link order
	for _, n := range names {
		rc, err := files[n].Open()
		if err != nil {
			return err
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return err
		}
		if err := e.linker.MergeObject(data, false); err != nil {
			return fmt.Errorf("mergelib %s: %w", n, err)
		}
	}
	return nil
}

// runSub evaluates a PICO sub-spec and returns its blob. A missing
// sub-spec falls back to the stub (or empty when PICO is off).
func (e *Evaluator) runSub(path string) ([]byte, error) {
	raw, err := os.ReadFile(e.resolve(path))
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		if e.picoStub {
			return BuildPICOStub(), nil
		}
		return []byte{}, nil
	}
	child := &Evaluator{
		linker:   NewLinker(),
		vars:     map[string][]byte{},
		named:    map[string][]byte{},
		exports:  map[string]int{},
		objDir:   e.objDir,
		picoStub: e.picoStub,
	}
	for k, v := range e.vars {
		child.vars[k] = v
	}
	if err := child.Eval(string(raw)); err != nil {
		return nil, fmt.Errorf("sub-spec %s: %w", path, err)
	}
	if err := child.flush(); err != nil {
		return nil, err
	}
	return child.picoBlob()
}

// picoBlob assembles the child link as a PICO blob with the export
// tag table.
func (e *Evaluator) picoBlob() ([]byte, error) {
	code, err := e.linker.AssembleCode()
	if err != nil {
		return nil, err
	}
	type pair struct {
		tag int
		off int
	}
	var pairs []pair
	for name, tag := range e.exports {
		off, ok := e.linker.SymbolOffset(name)
		if !ok {
			return nil, fmt.Errorf("export %q not found in PICO objects", name)
		}
		pairs = append(pairs, pair{tag, off})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].tag < pairs[j].tag })
	total := 8 + 8*len(pairs) + len(code)
	blob := make([]byte, 0, total)
	put := func(v uint32) {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], v)
		blob = append(blob, b[:]...)
	}
	put(uint32(total))
	put(uint32(len(pairs)))
	for _, p := range pairs {
		put(uint32(p.tag))
		put(uint32(p.off))
	}
	blob = append(blob, code...)
	return blob, nil
}
