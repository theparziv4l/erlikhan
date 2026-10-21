package agentfunctions

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func registeredCommands(t *testing.T) []agentstructs.Command {
	t.Helper()
	cmds := agentstructs.AllPayloadData.Get("erlikhan").GetCommands()
	if len(cmds) == 0 {
		t.Fatal("no commands registered for erlikhan")
	}
	return cmds
}

func findCommand(t *testing.T, cmds []agentstructs.Command, name string) agentstructs.Command {
	t.Helper()
	for _, c := range cmds {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("command %q not registered (have %v)", name, AllCommandNames())
	return agentstructs.Command{}
}

// TestExitCommandRecognized guards the callbacks-table "Exit Callback" action:
// Mythic resolves it through supported_ui_features == "callback_table:exit".
func TestExitCommandRecognized(t *testing.T) {
	exit := findCommand(t, registeredCommands(t), "exit")
	for _, f := range exit.SupportedUIFeatures {
		if f == "callback_table:exit" {
			return
		}
	}
	t.Fatalf("exit lacks callback_table:exit UI feature (have %v)", exit.SupportedUIFeatures)
}

func TestCoreCommandsAreBuiltin(t *testing.T) {
	cmds := registeredCommands(t)
	for _, name := range []string{"shell", "powershell", "sleep", "exit"} {
		if c := findCommand(t, cmds, name); !c.CommandAttributes.CommandIsBuiltin {
			t.Errorf("core command %q must be builtin", name)
		}
	}
}

func TestOptionalCommandsAreSelectable(t *testing.T) {
	cmds := registeredCommands(t)
	for _, tc := range []struct {
		name       string
		uiFeatures []string
	}{
		{"ls", []string{"file_browser:list"}},
		{"download", []string{"file_browser:download"}},
		{"upload", []string{"file_browser:upload"}},
		{"rm", []string{"file_browser:remove"}},
		{"mkdir", nil},
		{"ps", []string{"process_browser:list"}},
		{"kill", []string{"kill", "process_browser:kill"}},
		{"execute_assembly", nil},
		{"execute_coff", nil},
		{"whoami", nil},
		{"env", nil},
		{"pwd", nil},
		{"cd", nil},
		{"cp", nil},
		{"mv", nil},
		{"ipconfig", nil},
		{"uptime", nil},
		{"load", nil},
		{"unload", nil},
	} {
		c := findCommand(t, cmds, tc.name)
		if c.CommandAttributes.CommandIsBuiltin {
			t.Errorf("%s must not be builtin (operators should be able to remove it)", tc.name)
		}
		if !c.CommandAttributes.CommandIsSuggested {
			t.Errorf("%s should be suggested (pre-selected) for new payloads", tc.name)
		}
		for _, want := range tc.uiFeatures {
			found := false
			for _, f := range c.SupportedUIFeatures {
				if f == want {
					found = true
				}
			}
			if !found {
				t.Errorf("%s lacks UI feature %q (have %v)", tc.name, want, c.SupportedUIFeatures)
			}
		}
	}
}

func TestLoadTarget(t *testing.T) {
	args := &agentstructs.PTTaskMessageArgsData{}
	args.AddArg(agentstructs.CommandParameter{Name: "arguments",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING, DefaultValue: "ls"})
	name, err := loadTarget(&agentstructs.PTTaskMessageAllData{
		Task: agentstructs.PTTaskMessageTaskData{ID: 1}, Args: *args,
	})
	if err != nil || name != "ls" {
		t.Fatalf("target: %q %v", name, err)
	}
	args = &agentstructs.PTTaskMessageArgsData{}
	args.AddArg(agentstructs.CommandParameter{Name: "arguments",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING, DefaultValue: "nope"})
	if _, err := loadTarget(&agentstructs.PTTaskMessageAllData{Args: *args}); err == nil {
		t.Fatal("unknown command should fail")
	}
	if _, err := loadTarget(&agentstructs.PTTaskMessageAllData{}); err == nil {
		t.Fatal("missing arg should fail")
	}
}

func TestUnloadProtection(t *testing.T) {
	for _, p := range []string{"exit", "load", "unload"} {
		if !isProtected(p) {
			t.Errorf("%s should be protected", p)
		}
	}
	for _, ok := range []string{"shell", "ls", "ps"} {
		if isProtected(ok) {
			t.Errorf("%s should not be protected", ok)
		}
	}
	if !knownCommand("sleep") || knownCommand("nope") {
		t.Fatal("knownCommand wrong")
	}
}

func TestKillParse(t *testing.T) {
	args := &agentstructs.PTTaskMessageArgsData{}
	if err := killLine(args, "1234"); err != nil {
		t.Fatal(err)
	}
	if got := stringArg(t, args, "arguments"); got != "1234" {
		t.Fatalf("pid = %q", got)
	}
	for _, bad := range []string{"", "abc", "0", "-4", "12x"} {
		if err := killLine(&agentstructs.PTTaskMessageArgsData{}, bad); err == nil {
			t.Fatalf("input %q should fail", bad)
		}
	}
	args = &agentstructs.PTTaskMessageArgsData{}
	err := killDict(args, map[string]any{"host": "H", "process_id": float64(5678), "architecture": "x64"})
	if err != nil {
		t.Fatal(err)
	}
	if got := stringArg(t, args, "arguments"); got != "5678" {
		t.Fatalf("pid = %q", got)
	}
	args = &agentstructs.PTTaskMessageArgsData{}
	if err := killDict(args, map[string]any{"host": "H", "process_id": "4321"}); err != nil {
		t.Fatal(err)
	}
	if got := stringArg(t, args, "arguments"); got != "4321" {
		t.Fatalf("pid = %q", got)
	}
	if err := killDict(&agentstructs.PTTaskMessageArgsData{}, map[string]any{}); err == nil {
		t.Fatal("missing pid should fail")
	}
}

func TestPayloadSupportsDynamicLoading(t *testing.T) {
	if !payloadDefinition.SupportsDynamicLoading {
		t.Fatal("payload must set SupportsDynamicLoading so operators can add/remove commands")
	}
}

func TestRegisteredMatchesSpecs(t *testing.T) {
	cmds := registeredCommands(t)
	if len(cmds) != len(commandSpecs) {
		t.Fatalf("registered %d commands, specs list %d", len(cmds), len(commandSpecs))
	}
	seen := map[string]bool{}
	for _, c := range cmds {
		seen[c.Name] = true
	}
	for _, name := range AllCommandNames() {
		if !seen[name] {
			t.Errorf("spec command %q not registered", name)
		}
	}
}

func TestResolveCommandList(t *testing.T) {
	all := AllCommandNames()
	final, added, err := resolveCommandList(nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(final, ",") != strings.Join(all, ",") {
		t.Fatalf("empty input should default to all commands, got %v", final)
	}
	if len(added) != 0 {
		t.Fatalf("default selection should not report added commands, got %v", added)
	}

	final, added, err = resolveCommandList([]string{"ls"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"shell", "powershell", "sleep", "exit", "ls"} {
		found := false
		for _, got := range final {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("resolved list %v missing %q", final, want)
		}
	}
	if len(added) != 4 {
		t.Errorf("expected 4 auto-added core commands, got %v", added)
	}

	dupes := append([]string{"ls"}, all...)
	final, added, err = resolveCommandList(dupes)
	if err != nil {
		t.Fatal(err)
	}
	if len(final) != len(all) {
		t.Errorf("duplicates should collapse, got %v", final)
	}
	if len(added) != 0 {
		t.Errorf("complete selection should add nothing, got %v", added)
	}

	if _, _, err = resolveCommandList([]string{"shell", "rm-rf"}); err == nil ||
		!strings.Contains(err.Error(), "rm-rf") {
		t.Fatalf("unknown command should fail naming it, got %v", err)
	}
}

// TestCommandLayersAgree keeps the three command implementations in sync:
// the container specs, the Go agent dispatch table and the C agent
// dispatch table. Add a command to all three or this fails naming the gap.
func TestCommandLayersAgree(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(thisFile)
	goSrc, err := os.ReadFile(filepath.Join(root, "..", "..", "agent_code", "tasks.go"))
	if err != nil {
		t.Fatal(err)
	}
	cSrc, err := os.ReadFile(filepath.Join(root, "..", "..", "agent_code_c", "tasks.c"))
	if err != nil {
		t.Fatal(err)
	}
	want := AllCommandNames()
	for _, tc := range []struct {
		layer string
		src   string
		block string
		end   string
		re    *regexp.Regexp
	}{
		{"go", string(goSrc), "commandTable = []commandEntry{", "\n}",
			regexp.MustCompile(`\{\s*name:\s*"([a-z0-9_]+)"`)},
		{"c", string(cSrc), "task_table[] = {", "};",
			regexp.MustCompile(`\{\s*"([a-z0-9_]+)"\s*,`)},
	} {
		got := extractTableNames(t, tc.layer, tc.src, tc.block, tc.end, tc.re)
		if strings.Join(got, ",") != strings.Join(sortedCopy(want), ",") {
			t.Errorf("%s layer commands %v disagree with container %v", tc.layer, got, want)
		}
	}
}

func extractTableNames(t *testing.T, layer, src, block, endMark string, re *regexp.Regexp) []string {
	t.Helper()
	start := strings.Index(src, block)
	if start < 0 {
		t.Fatalf("%s dispatch table %q not found", layer, block)
	}
	rest := src[start:]
	end := strings.Index(rest, endMark)
	if end < 0 {
		t.Fatalf("%s dispatch table unterminated", layer)
	}
	var names []string
	for _, m := range re.FindAllStringSubmatch(rest[:end], -1) {
		names = append(names, m[1])
	}
	if len(names) == 0 {
		t.Fatalf("%s dispatch table holds no commands", layer)
	}
	return sortedCopy(names)
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func stringArg(t *testing.T, args *agentstructs.PTTaskMessageArgsData, name string) string {
	t.Helper()
	v, err := args.GetStringArg(name)
	if err != nil {
		t.Fatalf("arg %q: %v", name, err)
	}
	return v
}

func TestFbPathDict(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input map[string]any
		want  string
	}{
		{"full path wins", map[string]any{"path": "C:\\a", "full_path": "C:\\a\\b", "file": "c"}, "C:\\a\\b"},
		{"path fallback", map[string]any{"path": "C:\\a"}, "C:\\a"},
		{"file fallback", map[string]any{"file": "c", "host": "H"}, "c"},
		{"plain arguments", map[string]any{"arguments": "C:\\x"}, "C:\\x"},
		{"plain path", map[string]any{"path": "C:\\x"}, "C:\\x"},
		{"empty", map[string]any{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := &agentstructs.PTTaskMessageArgsData{}
			if err := fbPathDict(args, tc.input); err != nil {
				t.Fatal(err)
			}
			if got := stringArg(t, args, "arguments"); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestUploadDict(t *testing.T) {
	args := &agentstructs.PTTaskMessageArgsData{}
	err := uploadDict(args, map[string]any{"file": "uuid-1", "remote_path": "C:\\x\\a.bin"})
	if err != nil {
		t.Fatal(err)
	}
	if got := stringArg(t, args, "remote_path"); got != "C:\\x\\a.bin" {
		t.Fatalf("remote_path = %q", got)
	}
	fileID, err := args.GetFileArg("file")
	if err != nil || fileID != "uuid-1" {
		t.Fatalf("file = %q, err %v", fileID, err)
	}
	// Browser context supplies the remote path.
	args = &agentstructs.PTTaskMessageArgsData{}
	if err := uploadDict(args, map[string]any{"file": "uuid-2", "full_path": "C:\\drop"}); err != nil {
		t.Fatal(err)
	}
	if got := stringArg(t, args, "remote_path"); got != "C:\\drop" {
		t.Fatalf("remote_path = %q", got)
	}
	// No file chosen.
	if err := uploadDict(&agentstructs.PTTaskMessageArgsData{}, map[string]any{"remote_path": "x"}); err == nil {
		t.Fatal("missing file should fail")
	}
}

func TestUploadLine(t *testing.T) {
	args := &agentstructs.PTTaskMessageArgsData{}
	err := uploadLine(args, `{"remote_path": "C:\\x", "file": "uuid-3"}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := stringArg(t, args, "remote_path"); got != "C:\\x" {
		t.Fatalf("remote_path = %q", got)
	}
	if _, err := args.GetFileArg("file"); err != nil {
		t.Fatalf("file: %v", err)
	}
	for _, bad := range []string{"", "C:\\x", `{"remote_path": "C:\\x"}`, "{nope"} {
		if err := uploadLine(&agentstructs.PTTaskMessageArgsData{}, bad); err == nil {
			t.Fatalf("input %q should fail", bad)
		}
	}
}

func TestExecAsmDict(t *testing.T) {
	args := &agentstructs.PTTaskMessageArgsData{}
	if err := execAsmDict(args, map[string]any{"assembly_file": "uuid-1", "assembly_arguments": "a b"}); err != nil {
		t.Fatal(err)
	}
	if got := stringArg(t, args, "assembly_arguments"); got != "a b" {
		t.Fatalf("assembly_arguments = %q", got)
	}
	fileID, err := args.GetFileArg("assembly_file")
	if err != nil || fileID != "uuid-1" {
		t.Fatalf("assembly_file = %q, err %v", fileID, err)
	}
	if err := execAsmDict(&agentstructs.PTTaskMessageArgsData{}, map[string]any{}); err == nil {
		t.Fatal("missing file should fail")
	}
}

func TestExecAsmLine(t *testing.T) {
	args := &agentstructs.PTTaskMessageArgsData{}
	if err := execAsmLine(args, `{"assembly_file": "uuid-2", "assembly_arguments": "--x"}`); err != nil {
		t.Fatal(err)
	}
	if got := stringArg(t, args, "assembly_arguments"); got != "--x" {
		t.Fatalf("assembly_arguments = %q", got)
	}
	for _, bad := range []string{"", "uuid-2", `{"assembly_arguments": "x"}`, "{nope"} {
		if err := execAsmLine(&agentstructs.PTTaskMessageArgsData{}, bad); err == nil {
			t.Fatalf("input %q should fail", bad)
		}
	}
}

func TestExecAsmTask(t *testing.T) {
	args := &agentstructs.PTTaskMessageArgsData{}
	args.AddArg(agentstructs.CommandParameter{Name: "assembly_file",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_FILE, DefaultValue: "uuid-3"})
	args.AddArg(agentstructs.CommandParameter{Name: "assembly_arguments",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING, DefaultValue: "a"})
	resp := execAsmTask(&agentstructs.PTTaskMessageAllData{
		Task: agentstructs.PTTaskMessageTaskData{ID: 11}, Args: *args,
	})
	if !resp.Success || resp.TaskID != 11 {
		t.Fatalf("execute_assembly task: %+v", resp)
	}
	if resp.DisplayParams == nil || *resp.DisplayParams != "-Assembly uuid-3 -Arguments a" {
		t.Fatalf("display params: %+v", resp.DisplayParams)
	}
	resp = execAsmTask(&agentstructs.PTTaskMessageAllData{
		Task: agentstructs.PTTaskMessageTaskData{ID: 12},
	})
	if resp.Success {
		t.Fatal("missing args should fail")
	}
}

func TestCanonicalCoffType(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"s", "s"}, {"int16", "s"}, {"short", "s"}, {"-s", "s"},
		{"i", "i"}, {"int32", "i"}, {"int", "i"}, {"integer", "i"}, {"-i", "i"},
		{"z", "z"}, {"string", "z"}, {"-z", "z"},
		{"Z", "Z"}, {"-Z", "Z"}, {"wchar", "Z"}, {"wstring", "Z"}, {"WCHAR", "Z"},
		{"b", "b"}, {"base64", "b"}, {"file", "b"}, {"-b", "b"},
	} {
		got, ok := canonicalCoffType(tc.in)
		if !ok || got != tc.want {
			t.Errorf("type %q -> %q, want %q", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"", "x", "bool", "float"} {
		if _, ok := canonicalCoffType(bad); ok {
			t.Errorf("type %q should fail", bad)
		}
	}
}

func TestNormalizeCoffArgs(t *testing.T) {
	// Forge-shaped input: short codes, JSON numbers (float64).
	got, err := normalizeCoffArgs([]any{
		[]any{"i", float64(42)},
		[]any{"Z", "hi"},
		[]any{"b", "aGk="},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []coffArg{{"i", "42"}, {"Z", "hi"}, {"b", "aGk="}}
	if len(got) != len(want) {
		t.Fatalf("args = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("args = %+v, want %+v", got, want)
		}
	}
	// Long modal spellings normalize to short codes.
	got, err = normalizeCoffArgs([]any{[]any{"string", "x"}, []any{"int16", "7"}})
	if err != nil || len(got) != 2 || got[0].typ != "z" || got[1].typ != "s" {
		t.Fatalf("long forms: %+v %v", got, err)
	}
	// Nil and empty mean no arguments.
	if got, err := normalizeCoffArgs(nil); err != nil || got != nil {
		t.Fatalf("nil: %+v %v", got, err)
	}
	if got, err := normalizeCoffArgs([]any{}); err != nil || len(got) != 0 {
		t.Fatalf("empty: %+v %v", got, err)
	}
	for _, bad := range []any{
		"nope",
		[]any{[]any{"z"}},
		[]any{[]any{"z", "a", "b"}},
		[]any{[]any{"wobble", "a"}},
		[]any{[]any{42, "a"}},
		[]any{[]any{"i", 1.5}},
		[]any{[]any{"i", true}},
	} {
		if _, err := normalizeCoffArgs(bad); err == nil {
			t.Fatalf("input %+v should fail", bad)
		}
	}
}

func TestPackCoffArgs(t *testing.T) {
	// Apollo-identical golden vectors: u32LE total, raw LE ints,
	// LE-length-prefixed NUL-terminated strings, hexlified.
	for _, tc := range []struct {
		name string
		args []coffArg
		want string
	}{
		{"empty", nil, "00000000"},
		{"int and string", []coffArg{{"i", "42"}, {"z", "hi"}},
			"0b0000002a00000003000000686900"},
		{"short", []coffArg{{"s", "-1"}}, "02000000ffff"},
		{"wchar", []coffArg{{"Z", "A"}}, "080000000400000041000000"},
		{"base64", []coffArg{{"b", "aGk="}}, "06000000020000006869"},
	} {
		got, err := packCoffArgs(tc.args)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
	for _, bad := range [][]coffArg{
		{{"s", "99999"}},
		{{"s", "x"}},
		{{"i", "99999999999"}},
		{{"i", "x"}},
		{{"b", "!!!"}},
	} {
		if _, err := packCoffArgs(bad); err == nil {
			t.Fatalf("args %+v should fail", bad)
		}
	}
}

func TestCoffTimeout(t *testing.T) {
	if coffTimeout(nil) != 30 || coffTimeout(float64(45)) != 45 {
		t.Fatal("defaults")
	}
	if coffTimeout("60") != 60 || coffTimeout(7) != 7 || coffTimeout(int64(8)) != 8 {
		t.Fatal("shapes")
	}
	if coffTimeout(0) != 1 || coffTimeout(-5) != 1 || coffTimeout(999999) != 86400 {
		t.Fatal("clamp")
	}
	if coffTimeout("bogus") != 30 || coffTimeout(true) != 30 {
		t.Fatal("fallback")
	}
}

func TestCoffDict(t *testing.T) {
	args := &agentstructs.PTTaskMessageArgsData{}
	err := coffDict(args, map[string]any{
		"bof_file": "uuid-1", "function_name": "run", "timeout": float64(10),
		"coff_arguments": []any{[]any{"string", "hi"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := stringArg(t, args, "function_name"); got != "run" {
		t.Fatalf("function_name = %q", got)
	}
	if n, err := args.GetNumberArg("timeout"); err != nil || n != 10 {
		t.Fatalf("timeout = %v, err %v", n, err)
	}
	typed, err := args.GetTypedArrayArg("coff_arguments")
	if err != nil || len(typed) != 1 || typed[0][0] != "z" || typed[0][1] != "hi" {
		t.Fatalf("typed args = %+v, err %v", typed, err)
	}
	// Defaults: entrypoint go, timeout 30, no args.
	args = &agentstructs.PTTaskMessageArgsData{}
	if err := coffDict(args, map[string]any{"bof_file": "uuid-2"}); err != nil {
		t.Fatal(err)
	}
	if got := stringArg(t, args, "function_name"); got != "go" {
		t.Fatalf("default function = %q", got)
	}
	if err := coffDict(&agentstructs.PTTaskMessageArgsData{}, map[string]any{}); err == nil {
		t.Fatal("missing file should fail")
	}
	if err := coffDict(&agentstructs.PTTaskMessageArgsData{},
		map[string]any{"bof_file": "uuid-2", "coff_arguments": "nope"}); err == nil {
		t.Fatal("bad args should fail")
	}
}

func TestCoffLine(t *testing.T) {
	args := &agentstructs.PTTaskMessageArgsData{}
	err := coffLine(args, `{"bof_file": "uuid-3", "function_name": "go", "timeout": 5, "coff_arguments": [["i", 42]]}`)
	if err != nil {
		t.Fatal(err)
	}
	typed, err := args.GetTypedArrayArg("coff_arguments")
	if err != nil || len(typed) != 1 || typed[0][0] != "i" || typed[0][1] != "42" {
		t.Fatalf("typed args = %+v, err %v", typed, err)
	}
	for _, bad := range []string{"", "uuid-3", `{"function_name": "go"}`, "{nope"} {
		if err := coffLine(&agentstructs.PTTaskMessageArgsData{}, bad); err == nil {
			t.Fatalf("input %q should fail", bad)
		}
	}
}

// TestCoffTaskForgeShape is the Forge-compat contract: short type codes
// with JSON numbers, as Forge's forge_bof_* aliases forward them, must
// pack to the Apollo-identical hex buffer.
func TestCoffTaskForgeShape(t *testing.T) {
	args := &agentstructs.PTTaskMessageArgsData{}
	args.AddArg(agentstructs.CommandParameter{Name: "bof_file",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_FILE, DefaultValue: "uuid-4"})
	args.AddArg(agentstructs.CommandParameter{Name: "function_name",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING, DefaultValue: "go"})
	args.AddArg(agentstructs.CommandParameter{Name: "coff_arguments",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_TYPED_ARRAY,
		DefaultValue:  []any{[]any{"i", float64(42)}, []any{"z", "hi"}}})
	// Pass Args by struct copy like the framework does, then re-read
	// through the same task handle: AddArg appends are only visible on
	// the struct that create_tasking mutated.
	td := &agentstructs.PTTaskMessageAllData{
		Task: agentstructs.PTTaskMessageTaskData{ID: 13}, Args: *args,
	}
	resp := coffTask(td)
	if !resp.Success || resp.TaskID != 13 {
		t.Fatalf("coff task: %+v", resp)
	}
	if got := stringArg(t, &td.Args, "coff_arguments"); got != "0b0000002a00000003000000686900" {
		t.Fatalf("packed args = %q", got)
	}
	if n, err := td.Args.GetNumberArg("timeout"); err != nil || n != 30 {
		t.Fatalf("default timeout = %v, err %v", n, err)
	}
	if resp.DisplayParams == nil || *resp.DisplayParams != "-Coff uuid-4 -Function go -Timeout 30" {
		t.Fatalf("display params: %+v", resp.DisplayParams)
	}
	resp = coffTask(&agentstructs.PTTaskMessageAllData{
		Task: agentstructs.PTTaskMessageTaskData{ID: 14},
	})
	if resp.Success {
		t.Fatal("missing args should fail")
	}
}

func TestTwinPathLine(t *testing.T) {
	for _, cmd := range []string{"cp", "mv"} {
		parse := twinPathLine(cmd)
		args := &agentstructs.PTTaskMessageArgsData{}
		if err := parse(args, `C:\a C:\b`); err != nil {
			t.Fatal(err)
		}
		if got := stringArg(t, args, "source"); got != `C:\a` {
			t.Fatalf("source = %q", got)
		}
		if got := stringArg(t, args, "destination"); got != `C:\b` {
			t.Fatalf("destination = %q", got)
		}
		args = &agentstructs.PTTaskMessageArgsData{}
		if err := parse(args, `{"source": "a", "destination": "b"}`); err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"", "only", "a b c", `{"source": "a"}`} {
			if err := parse(&agentstructs.PTTaskMessageArgsData{}, bad); err == nil {
				t.Fatalf("%s input %q should fail", cmd, bad)
			}
		}
	}
}

func TestTwinPathDictAndTask(t *testing.T) {
	args := &agentstructs.PTTaskMessageArgsData{}
	if err := twinPathDict(args, map[string]any{"source": "a", "destination": "b"}); err != nil {
		t.Fatal(err)
	}
	resp := twinPathTask(&agentstructs.PTTaskMessageAllData{
		Task: agentstructs.PTTaskMessageTaskData{ID: 15}, Args: *args,
	})
	if !resp.Success || resp.DisplayParams == nil || *resp.DisplayParams != "a -> b" {
		t.Fatalf("twin task: %+v", resp)
	}
	if err := twinPathDict(&agentstructs.PTTaskMessageArgsData{}, map[string]any{"source": "a"}); err == nil {
		t.Fatal("missing destination should fail")
	}
	resp = twinPathTask(&agentstructs.PTTaskMessageAllData{
		Task: agentstructs.PTTaskMessageTaskData{ID: 16},
	})
	if resp.Success {
		t.Fatal("missing args should fail")
	}
}

func TestUploadTask(t *testing.T) {
	args := &agentstructs.PTTaskMessageArgsData{}
	args.AddArg(agentstructs.CommandParameter{Name: "remote_path",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING, DefaultValue: "C:\\x"})
	args.AddArg(agentstructs.CommandParameter{Name: "file",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_FILE, DefaultValue: "uuid-4"})
	resp := uploadTask(&agentstructs.PTTaskMessageAllData{
		Task: agentstructs.PTTaskMessageTaskData{ID: 7}, Args: *args,
	})
	if !resp.Success || resp.TaskID != 7 {
		t.Fatalf("upload task: %+v", resp)
	}
	if resp.DisplayParams == nil || *resp.DisplayParams != "C:\\x" {
		t.Fatalf("display params: %+v", resp.DisplayParams)
	}
	resp = uploadTask(&agentstructs.PTTaskMessageAllData{
		Task: agentstructs.PTTaskMessageTaskData{ID: 8},
	})
	if resp.Success {
		t.Fatal("missing args should fail")
	}
}
