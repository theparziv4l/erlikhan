package agentfunctions

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
	"github.com/mitchellh/mapstructure"
)

// stringDict decodes UI modal input {"arguments": "..."} into task args.
func stringDict(args *agentstructs.PTTaskMessageArgsData, input map[string]any) error {
	var decoded struct {
		Arguments string `mapstructure:"arguments"`
	}
	if err := mapstructure.Decode(input, &decoded); err != nil {
		logging.LogError(err, "Failed to decode arguments")
		return err
	}
	args.AddArg(agentstructs.CommandParameter{
		Name:          "arguments",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
		DefaultValue:  decoded.Arguments,
	})
	return nil
}

func stringLine(args *agentstructs.PTTaskMessageArgsData, input string) error {
	args.AddArg(agentstructs.CommandParameter{
		Name:          "arguments",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
		DefaultValue:  input,
	})
	return nil
}

// passthroughTask forwards args to the agent untouched; the agent parses
// the parameters string itself.
func passthroughTask(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
	response := agentstructs.PTTaskCreateTaskingMessageResponse{Success: true, TaskID: taskData.Task.ID}
	if params, err := taskData.Args.GetStringArg("arguments"); err != nil {
		logging.LogError(err, "Failed to get arguments")
		response.Error, response.Success = err.Error(), false
	} else {
		response.DisplayParams = &params
	}
	return response
}

func noArgsTask(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
	return agentstructs.PTTaskCreateTaskingMessageResponse{Success: true, TaskID: taskData.Task.ID}
}

func noArgsParse(args *agentstructs.PTTaskMessageArgsData, input string) error { return nil }

func noArgsParseDict(args *agentstructs.PTTaskMessageArgsData, input map[string]any) error {
	return nil
}

// fbPathDict resolves file-browser tasking (path/full_path/file keys) or a
// plain {"arguments"|"path": ...} modal into the single path argument the
// agent reads. Single-host agent: the browser "host" key is ignored.
func fbPathDict(args *agentstructs.PTTaskMessageArgsData, input map[string]any) error {
	var fb agentstructs.FileBrowserTask
	if err := mapstructure.Decode(input, &fb); err != nil {
		logging.LogError(err, "Failed to decode file browser data")
		return err
	}
	path := firstNonEmpty(fb.FullPath, fb.Path, fb.Filename)
	if path == "" {
		var plain struct {
			Arguments string `mapstructure:"arguments"`
			Path      string `mapstructure:"path"`
		}
		if err := mapstructure.Decode(input, &plain); err != nil {
			logging.LogError(err, "Failed to decode arguments")
			return err
		}
		path = firstNonEmpty(plain.Arguments, plain.Path)
	}
	args.AddArg(agentstructs.CommandParameter{
		Name:          "arguments",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
		DefaultValue:  path,
	})
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// killLine validates a CLI pid argument.
func killLine(args *agentstructs.PTTaskMessageArgsData, input string) error {
	pid, err := parsePID(strings.TrimSpace(input))
	if err != nil {
		return err
	}
	args.AddArg(agentstructs.CommandParameter{
		Name:          "arguments",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
		DefaultValue:  strconv.Itoa(pid),
	})
	return nil
}

// killDict reads the process-browser tasking {host, process_id,
// architecture}; only the pid matters to this single-host agent.
func killDict(args *agentstructs.PTTaskMessageArgsData, input map[string]any) error {
	var decoded struct {
		ProcessID any `mapstructure:"process_id"`
	}
	if err := mapstructure.Decode(input, &decoded); err != nil {
		logging.LogError(err, "Failed to decode kill arguments")
		return err
	}
	pid, err := parsePID(fmt.Sprint(decoded.ProcessID))
	if err != nil {
		return err
	}
	args.AddArg(agentstructs.CommandParameter{
		Name:          "arguments",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
		DefaultValue:  strconv.Itoa(pid),
	})
	return nil
}

func parsePID(s string) (int, error) {
	pid, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("usage: kill <pid>")
	}
	return pid, nil
}

// knownCommand reports whether name is a registered command.
func knownCommand(name string) bool {
	for _, s := range commandSpecs {
		if s.name == name {
			return true
		}
	}
	return false
}

// protectedCommands cannot be unloaded at runtime: without them a
// callback could neither exit nor load anything back.
var protectedCommands = []string{"exit", "load", "unload"}

func isProtected(name string) bool {
	for _, p := range protectedCommands {
		if p == name {
			return true
		}
	}
	return false
}

// loadTarget validates the load/unload argument.
func loadTarget(taskData *agentstructs.PTTaskMessageAllData) (string, error) {
	name, err := taskData.Args.GetStringArg("arguments")
	if err != nil {
		return "", err
	}
	name = strings.TrimSpace(name)
	if !knownCommand(name) {
		return "", fmt.Errorf("unknown command %q", name)
	}
	return name, nil
}

// loadTask marks a command loaded on the callback; the agent flips its
// own runtime allowlist when the task runs. All handlers stay compiled
// in, so any known command can be loaded back.
func loadTask(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
	response := agentstructs.PTTaskCreateTaskingMessageResponse{Success: true, TaskID: taskData.Task.ID}
	name, err := loadTarget(taskData)
	if err != nil {
		response.Error, response.Success = err.Error(), false
		return response
	}
	resp, err := mythicrpc.SendMythicRPCCallbackAddCommand(mythicrpc.MythicRPCCallbackAddCommandMessage{
		TaskID: taskData.Task.ID, Commands: []string{name},
	})
	if err != nil {
		logging.LogError(err, "Failed to add command to callback")
		response.Error, response.Success = err.Error(), false
		return response
	}
	if resp == nil || !resp.Success {
		msg := "unknown error"
		if resp != nil {
			msg = resp.Error
		}
		response.Error, response.Success = msg, false
		return response
	}
	response.DisplayParams = &name
	return response
}

func unloadTask(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
	response := agentstructs.PTTaskCreateTaskingMessageResponse{Success: true, TaskID: taskData.Task.ID}
	name, err := loadTarget(taskData)
	if err != nil {
		response.Error, response.Success = err.Error(), false
		return response
	}
	if isProtected(name) {
		response.Error, response.Success = fmt.Sprintf("cannot unload %s", name), false
		return response
	}
	resp, err := mythicrpc.SendMythicRPCCallbackRemoveCommand(mythicrpc.MythicRPCCallbackRemoveCommandMessage{
		TaskID: taskData.Task.ID, Commands: []string{name},
	})
	if err != nil {
		logging.LogError(err, "Failed to remove command from callback")
		response.Error, response.Success = err.Error(), false
		return response
	}
	if resp == nil || !resp.Success {
		msg := "unknown error"
		if resp != nil {
			msg = resp.Error
		}
		response.Error, response.Success = msg, false
		return response
	}
	response.DisplayParams = &name
	return response
}

// uploadDict handles the task-modal form: {"file": <uuid>, "remote_path":
// ...}, falling back to file-browser context keys for the remote path.
func uploadDict(args *agentstructs.PTTaskMessageArgsData, input map[string]any) error {
	var up struct {
		File       string `mapstructure:"file"`
		RemotePath string `mapstructure:"remote_path"`
	}
	if err := mapstructure.Decode(input, &up); err != nil {
		logging.LogError(err, "Failed to decode upload arguments")
		return err
	}
	if up.File == "" {
		return fmt.Errorf("upload requires choosing a file")
	}
	if up.RemotePath == "" {
		var fb agentstructs.FileBrowserTask
		if err := mapstructure.Decode(input, &fb); err != nil {
			logging.LogError(err, "Failed to decode file browser data")
			return err
		}
		up.RemotePath = firstNonEmpty(fb.FullPath, fb.Path, fb.Filename)
	}
	args.AddArg(agentstructs.CommandParameter{
		Name:          "remote_path",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
		DefaultValue:  up.RemotePath,
	})
	args.AddArg(agentstructs.CommandParameter{
		Name:          "file",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_FILE,
		DefaultValue:  up.File,
	})
	return nil
}

// uploadLine handles CLI tasking, which must reference an already-uploaded
// Mythic file: {"remote_path": "...", "file": "<uuid>"}.
func uploadLine(args *agentstructs.PTTaskMessageArgsData, input string) error {
	trimmed := strings.TrimSpace(input)
	usage := fmt.Errorf(`upload needs a file: use the task modal or pass {"remote_path": "...", "file": "<mythic-file-uuid>"}`)
	if !strings.HasPrefix(trimmed, "{") {
		return usage
	}
	var up struct {
		File       string `json:"file"`
		RemotePath string `json:"remote_path"`
	}
	if err := json.Unmarshal([]byte(trimmed), &up); err != nil {
		return usage
	}
	if up.File == "" {
		return usage
	}
	args.AddArg(agentstructs.CommandParameter{
		Name:          "remote_path",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
		DefaultValue:  up.RemotePath,
	})
	args.AddArg(agentstructs.CommandParameter{
		Name:          "file",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_FILE,
		DefaultValue:  up.File,
	})
	return nil
}

// uploadTask validates the file reference and shows the remote path. No
// RPC: the agent pulls chunks itself with the file UUID in its task args.
func uploadTask(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
	response := agentstructs.PTTaskCreateTaskingMessageResponse{Success: true, TaskID: taskData.Task.ID}
	remote, err := taskData.Args.GetStringArg("remote_path")
	if err != nil {
		logging.LogError(err, "Failed to get remote_path")
		response.Error, response.Success = err.Error(), false
		return response
	}
	if _, err := taskData.Args.GetFileArg("file"); err != nil {
		if _, err2 := taskData.Args.GetStringArg("file"); err2 != nil {
			logging.LogError(err, "Failed to get file")
			response.Error, response.Success = err.Error(), false
			return response
		}
	}
	response.DisplayParams = &remote
	return response
}

// execAsmDict handles the task-modal form: {"assembly_file": <uuid>,
// "assembly_arguments": "..."}. The agent pulls the file itself and
// hosts the CLR in-process, so no RPC is needed at tasking time.
func execAsmDict(args *agentstructs.PTTaskMessageArgsData, input map[string]any) error {
	var asm struct {
		File string `mapstructure:"assembly_file"`
		Args string `mapstructure:"assembly_arguments"`
	}
	if err := mapstructure.Decode(input, &asm); err != nil {
		logging.LogError(err, "Failed to decode execute_assembly arguments")
		return err
	}
	if asm.File == "" {
		return fmt.Errorf("execute_assembly requires choosing an assembly file")
	}
	args.AddArg(agentstructs.CommandParameter{
		Name:          "assembly_file",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_FILE,
		DefaultValue:  asm.File,
	})
	args.AddArg(agentstructs.CommandParameter{
		Name:          "assembly_arguments",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
		DefaultValue:  asm.Args,
	})
	return nil
}

// execAsmLine handles CLI tasking, which must reference an already-uploaded
// Mythic file: {"assembly_file": "<uuid>", "assembly_arguments": "..."}.
func execAsmLine(args *agentstructs.PTTaskMessageArgsData, input string) error {
	trimmed := strings.TrimSpace(input)
	usage := fmt.Errorf(`execute_assembly needs an assembly: use the task modal or pass {"assembly_file": "<mythic-file-uuid>", "assembly_arguments": "..."}`)
	if !strings.HasPrefix(trimmed, "{") {
		return usage
	}
	var asm struct {
		File string `json:"assembly_file"`
		Args string `json:"assembly_arguments"`
	}
	if err := json.Unmarshal([]byte(trimmed), &asm); err != nil {
		return usage
	}
	if asm.File == "" {
		return usage
	}
	args.AddArg(agentstructs.CommandParameter{
		Name:          "assembly_file",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_FILE,
		DefaultValue:  asm.File,
	})
	args.AddArg(agentstructs.CommandParameter{
		Name:          "assembly_arguments",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
		DefaultValue:  asm.Args,
	})
	return nil
}

// fileOrStringArg reads a file reference whether Mythic typed it as File
// (modal, Forge reprocess) or String.
func fileOrStringArg(taskData *agentstructs.PTTaskMessageAllData, name string) (string, error) {
	if id, err := taskData.Args.GetFileArg(name); err == nil && id != "" {
		return id, nil
	}
	return taskData.Args.GetStringArg(name)
}

// execAsmTask validates the assembly reference and shows the argument
// string. Forge's forge_net_* aliases land here via reprocessing with the
// same two parameters.
func execAsmTask(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
	response := agentstructs.PTTaskCreateTaskingMessageResponse{Success: true, TaskID: taskData.Task.ID}
	file, err := fileOrStringArg(taskData, "assembly_file")
	if err != nil || file == "" {
		msg := "execute_assembly requires an assembly file"
		if err != nil {
			logging.LogError(err, "Failed to get assembly_file")
		}
		response.Error, response.Success = msg, false
		return response
	}
	display, _ := taskData.Args.GetStringArg("assembly_arguments")
	taskData.Args.AddArg(agentstructs.CommandParameter{
		Name:          "assembly_arguments",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
		DefaultValue:  display,
	})
	summary := fmt.Sprintf("-Assembly %s -Arguments %s", file, display)
	response.DisplayParams = &summary
	return response
}

// coffArg is one normalized BOF argument: canonical short type plus the raw
// value string. Short codes match what Forge forwards (b/i/s/z/Z); long
// forms come from our own modal choices and CLI JSON.
type coffArg struct {
	typ string
	val string
}

// canonicalCoffType maps every accepted type spelling to its short code.
// Case matters: "Z" is wchar while "z" is string.
func canonicalCoffType(t string) (string, bool) {
	t = strings.TrimSpace(t)
	if t == "Z" || t == "-Z" {
		return "Z", true
	}
	switch strings.ToLower(t) {
	case "s", "int16", "short", "-s":
		return "s", true
	case "i", "int32", "int", "integer", "-i":
		return "i", true
	case "z", "string", "-z":
		return "z", true
	case "wchar", "wstring":
		return "Z", true
	case "b", "base64", "file", "-b":
		return "b", true
	}
	return "", false
}

func coffValString(v any) (string, error) {
	switch n := v.(type) {
	case string:
		return n, nil
	case float64:
		if n != float64(int64(n)) {
			return "", fmt.Errorf("must be an integer, got %v", v)
		}
		return strconv.FormatInt(int64(n), 10), nil
	case int:
		return strconv.Itoa(n), nil
	case int64:
		return strconv.FormatInt(n, 10), nil
	case json.Number:
		return n.String(), nil
	}
	return "", fmt.Errorf("must be a string or number, got %T", v)
}

// normalizeCoffArgs accepts a typed array in any of the shapes that reach
// create_tasking: Forge's [][]any with short codes and JSON numbers, our
// modal's pairs with long choice names, or CLI JSON. Nil means no args.
func normalizeCoffArgs(val any) ([]coffArg, error) {
	if val == nil {
		return nil, nil
	}
	var pairs []any
	switch v := val.(type) {
	case []any:
		pairs = v
	case []coffArg:
		return v, nil
	default:
		return nil, fmt.Errorf("coff_arguments must be an array of [type, value] pairs")
	}
	out := make([]coffArg, 0, len(pairs))
	for i, p := range pairs {
		entry, ok := p.([]any)
		if !ok || len(entry) != 2 {
			return nil, fmt.Errorf("coff_arguments[%d] must be a [type, value] pair", i)
		}
		typeName, ok := entry[0].(string)
		if !ok {
			return nil, fmt.Errorf("coff_arguments[%d] type must be a string", i)
		}
		short, ok := canonicalCoffType(typeName)
		if !ok {
			return nil, fmt.Errorf("coff_arguments[%d] has unknown type %q (want int16/int32/string/wchar/base64)", i, typeName)
		}
		str, err := coffValString(entry[1])
		if err != nil {
			return nil, fmt.Errorf("coff_arguments[%d]: %w", i, err)
		}
		out = append(out, coffArg{typ: short, val: str})
	}
	return out, nil
}

// packCoffArgs serializes BOF arguments exactly like Apollo's execute_coff:
// a u32LE total length, raw LE int16/int32 values, and LE-length-prefixed
// blobs for strings (NUL-terminated), wchars (UTF-16LE NUL-terminated)
// and base64 payloads; the whole buffer is hex-encoded for the agent.
// Same packing as Apollo means Armory BOFs behave identically here.
func packCoffArgs(args []coffArg) (string, error) {
	body := []byte{}
	putU32 := func(n uint32) {
		body = append(body, byte(n), byte(n>>8), byte(n>>16), byte(n>>24))
	}
	for i, a := range args {
		switch a.typ {
		case "s":
			n, err := strconv.Atoi(a.val)
			if err != nil || n < -32768 || n > 32767 {
				return "", fmt.Errorf("coff_arguments[%d] bad int16 %q", i, a.val)
			}
			body = append(body, byte(n), byte(n>>8))
		case "i":
			n, err := strconv.ParseInt(a.val, 10, 32)
			if err != nil {
				return "", fmt.Errorf("coff_arguments[%d] bad int32 %q", i, a.val)
			}
			u := uint32(n)
			body = append(body, byte(u), byte(u>>8), byte(u>>16), byte(u>>24))
		case "z":
			raw := append([]byte(a.val), 0)
			putU32(uint32(len(raw)))
			body = append(body, raw...)
		case "Z":
			var raw []byte
			for _, r := range a.val {
				raw = append(raw, byte(r), byte(r>>8))
			}
			raw = append(raw, 0, 0)
			putU32(uint32(len(raw)))
			body = append(body, raw...)
		case "b":
			raw, err := base64.StdEncoding.DecodeString(a.val)
			if err != nil {
				return "", fmt.Errorf("coff_arguments[%d] bad base64: %w", i, err)
			}
			putU32(uint32(len(raw)))
			body = append(body, raw...)
		}
	}
	packed := make([]byte, 0, 4+len(body))
	total := uint32(len(body))
	packed = append(packed, byte(total), byte(total>>8), byte(total>>16), byte(total>>24))
	packed = append(packed, body...)
	return hex.EncodeToString(packed), nil
}

// coffTimeout reads the BOF thread timeout in seconds, defaulting to 30 and
// clamping to a sane range. Accepts JSON numbers, ints and strings.
func coffTimeout(val any) int {
	const def, min, max = 30, 1, 86400
	n := def
	switch v := val.(type) {
	case nil:
	case float64:
		n = int(v)
	case int:
		n = v
	case int64:
		n = int(v)
	case string:
		if parsed, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			n = parsed
		} else {
			return def
		}
	case json.Number:
		if parsed, err := strconv.Atoi(v.String()); err == nil {
			n = parsed
		} else {
			return def
		}
	default:
		return def
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

// coffFileAndMeta extracts the .o reference, entrypoint and timeout from a
// decoded CLI/modal form, shared by coffLine and coffDict.
func coffFileAndMeta(file, fn string, timeout any) (string, string, int, error) {
	if file == "" {
		return "", "", 0, fmt.Errorf("execute_coff requires choosing a BOF (.o) file")
	}
	if fn == "" {
		fn = "go"
	}
	return file, fn, coffTimeout(timeout), nil
}

// coffDict handles the task-modal form: {"bof_file": <uuid>,
// "function_name": "go", "timeout": 30, "coff_arguments": [[t, v], ...]}.
func coffDict(args *agentstructs.PTTaskMessageArgsData, input map[string]any) error {
	var form struct {
		File string `mapstructure:"bof_file"`
		Fn   string `mapstructure:"function_name"`
	}
	if err := mapstructure.Decode(input, &form); err != nil {
		logging.LogError(err, "Failed to decode execute_coff arguments")
		return err
	}
	file, fn, timeout, err := coffFileAndMeta(form.File, form.Fn, input["timeout"])
	if err != nil {
		return err
	}
	normalized, err := normalizeCoffArgs(input["coff_arguments"])
	if err != nil {
		return err
	}
	stored := make([]any, 0, len(normalized))
	for _, a := range normalized {
		stored = append(stored, []any{a.typ, a.val})
	}
	args.AddArg(agentstructs.CommandParameter{
		Name:          "bof_file",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_FILE,
		DefaultValue:  file,
	})
	args.AddArg(agentstructs.CommandParameter{
		Name:          "function_name",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
		DefaultValue:  fn,
	})
	args.AddArg(agentstructs.CommandParameter{
		Name:          "timeout",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
		DefaultValue:  float64(timeout),
	})
	args.AddArg(agentstructs.CommandParameter{
		Name:          "coff_arguments",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_TYPED_ARRAY,
		DefaultValue:  stored,
	})
	return nil
}

// coffLine handles CLI tasking as JSON: {"bof_file": "<uuid>",
// "function_name": "go", "timeout": 30, "coff_arguments": [[t, v], ...]}.
func coffLine(args *agentstructs.PTTaskMessageArgsData, input string) error {
	trimmed := strings.TrimSpace(input)
	usage := fmt.Errorf(`execute_coff needs a BOF: use the task modal or pass {"bof_file": "<mythic-file-uuid>", "function_name": "go", "timeout": 30, "coff_arguments": [["z", "hi"]]}`)
	if !strings.HasPrefix(trimmed, "{") {
		return usage
	}
	var form struct {
		File string `json:"bof_file"`
		Fn   string `json:"function_name"`
	}
	// Decode twice: typed fields via struct, loose ones via map so a
	// timeout number and nested arg pairs keep their JSON shapes.
	var loose map[string]any
	if err := json.Unmarshal([]byte(trimmed), &form); err != nil {
		return usage
	}
	if err := json.Unmarshal([]byte(trimmed), &loose); err != nil {
		return usage
	}
	file, fn, timeout, err := coffFileAndMeta(form.File, form.Fn, loose["timeout"])
	if err != nil {
		return err
	}
	normalized, err := normalizeCoffArgs(loose["coff_arguments"])
	if err != nil {
		return err
	}
	stored := make([]any, 0, len(normalized))
	for _, a := range normalized {
		stored = append(stored, []any{a.typ, a.val})
	}
	args.AddArg(agentstructs.CommandParameter{
		Name:          "bof_file",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_FILE,
		DefaultValue:  file,
	})
	args.AddArg(agentstructs.CommandParameter{
		Name:          "function_name",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
		DefaultValue:  fn,
	})
	args.AddArg(agentstructs.CommandParameter{
		Name:          "timeout",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
		DefaultValue:  float64(timeout),
	})
	args.AddArg(agentstructs.CommandParameter{
		Name:          "coff_arguments",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_TYPED_ARRAY,
		DefaultValue:  stored,
	})
	return nil
}

// coffTask packs the typed BOF arguments into the hex buffer the agent
// loads, defaulting entrypoint and timeout. Forge's forge_bof_* aliases
// land here via reprocessing with the same three parameters.
func coffTask(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
	response := agentstructs.PTTaskCreateTaskingMessageResponse{Success: true, TaskID: taskData.Task.ID}
	fail := func(msg string) agentstructs.PTTaskCreateTaskingMessageResponse {
		response.Error, response.Success = msg, false
		return response
	}
	file, err := fileOrStringArg(taskData, "bof_file")
	if err != nil || file == "" {
		if err != nil {
			logging.LogError(err, "Failed to get bof_file")
		}
		return fail("execute_coff requires a BOF file")
	}
	fn, err := taskData.Args.GetStringArg("function_name")
	if err != nil || fn == "" {
		fn = "go"
	}
	timeout := 30
	if raw, err := taskData.Args.GetArg("timeout"); err == nil {
		timeout = coffTimeout(raw)
	}
	rawArgs, err := taskData.Args.GetArg("coff_arguments")
	if err != nil {
		rawArgs = nil
	}
	normalized, err := normalizeCoffArgs(rawArgs)
	if err != nil {
		return fail(err.Error())
	}
	packed, err := packCoffArgs(normalized)
	if err != nil {
		return fail(err.Error())
	}
	taskData.Args.AddArg(agentstructs.CommandParameter{
		Name:          "function_name",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
		DefaultValue:  fn,
	})
	taskData.Args.AddArg(agentstructs.CommandParameter{
		Name:          "timeout",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
		DefaultValue:  float64(timeout),
	})
	taskData.Args.AddArg(agentstructs.CommandParameter{
		Name:          "coff_arguments",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
		DefaultValue:  packed,
	})
	summary := fmt.Sprintf("-Coff %s -Function %s -Timeout %d", file, fn, timeout)
	response.DisplayParams = &summary
	return response
}

// twinPathArgs parses "<src> <dst>" CLI input or {"source", "destination"}
// JSON for cp/mv.
func twinPathArgs(cmd, input string) (src, dst string, err error) {
	trimmed := strings.TrimSpace(input)
	usage := fmt.Errorf("usage: %s <source> <destination>", cmd)
	if strings.HasPrefix(trimmed, "{") {
		var form struct {
			Source      string `json:"source"`
			Destination string `json:"destination"`
		}
		if err := json.Unmarshal([]byte(trimmed), &form); err != nil {
			return "", "", usage
		}
		if form.Source == "" || form.Destination == "" {
			return "", "", usage
		}
		return form.Source, form.Destination, nil
	}
	fields := strings.Fields(trimmed)
	if len(fields) != 2 {
		return "", "", usage
	}
	return fields[0], fields[1], nil
}

func twinPathLine(cmd string) agentstructs.PtTaskFunctionParseArgString {
	return func(args *agentstructs.PTTaskMessageArgsData, input string) error {
		src, dst, err := twinPathArgs(cmd, input)
		if err != nil {
			return err
		}
		args.AddArg(agentstructs.CommandParameter{
			Name:          "source",
			ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
			DefaultValue:  src,
		})
		args.AddArg(agentstructs.CommandParameter{
			Name:          "destination",
			ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
			DefaultValue:  dst,
		})
		return nil
	}
}

func twinPathDict(args *agentstructs.PTTaskMessageArgsData, input map[string]any) error {
	var form struct {
		Source      string `mapstructure:"source"`
		Destination string `mapstructure:"destination"`
	}
	if err := mapstructure.Decode(input, &form); err != nil {
		logging.LogError(err, "Failed to decode source/destination arguments")
		return err
	}
	if form.Source == "" || form.Destination == "" {
		return fmt.Errorf("need both source and destination paths")
	}
	args.AddArg(agentstructs.CommandParameter{
		Name:          "source",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
		DefaultValue:  form.Source,
	})
	args.AddArg(agentstructs.CommandParameter{
		Name:          "destination",
		ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
		DefaultValue:  form.Destination,
	})
	return nil
}

func twinPathTask(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
	response := agentstructs.PTTaskCreateTaskingMessageResponse{Success: true, TaskID: taskData.Task.ID}
	src, err := taskData.Args.GetStringArg("source")
	if err != nil || src == "" {
		response.Error, response.Success = "need a source path", false
		return response
	}
	dst, err := taskData.Args.GetStringArg("destination")
	if err != nil || dst == "" {
		response.Error, response.Success = "need a destination path", false
		return response
	}
	summary := fmt.Sprintf("%s -> %s", src, dst)
	response.DisplayParams = &summary
	return response
}

// commandSpec is the container-side definition of one agent command.
// To add a command: append a row here, add a handler to the dispatch
// tables in agent_code/tasks.go and agent_code_c/tasks.c, then run
// TestCommandLayersAgree. Builtin commands are always compiled into the
// payload; the rest can be added or removed per payload build.
type commandSpec struct {
	name        string
	help        string
	description string
	mitre       []string
	uiFeatures  []string
	builtin     bool
	suggested   bool
	noArgs      bool
	// params declares the task-modal fields; nil keeps the modal empty
	// (CLI/file-browser tasking only). Parse funcs still run and may
	// overwrite these defaults via AddArg.
	params []agentstructs.CommandParameter
	// Optional overrides; nil keeps the string-passthrough defaults.
	createTasking agentstructs.PtTaskFunctionCreateTasking
	parseString   agentstructs.PtTaskFunctionParseArgString
	parseDict     agentstructs.PtTaskFunctionParseArgDictionary
}

// execAsmParams renders the task modal for execute_assembly: a file picker
// plus the argument string.
func execAsmParams() []agentstructs.CommandParameter {
	return []agentstructs.CommandParameter{
		{
			Name: "assembly_file", ModalDisplayName: "Assembly",
			ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_FILE,
			Description:   "A .NET assembly to execute in-process (already uploaded to Mythic).",
			ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
				{ParameterIsRequired: true, GroupName: "Default", UIModalPosition: 1},
			},
		},
		{
			Name: "assembly_arguments", ModalDisplayName: "Arguments",
			ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
			Description:   "Arguments passed to the assembly entry point.",
			DefaultValue:  "",
			ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
				{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 2},
			},
		},
	}
}

// coffParams renders the task modal for execute_coff: a .o file picker,
// entrypoint, thread timeout and the typed argument array.
func coffParams() []agentstructs.CommandParameter {
	return []agentstructs.CommandParameter{
		{
			Name: "bof_file", ModalDisplayName: "BOF",
			ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_FILE,
			Description:   "A BOF object file (.o) to execute in-process.",
			ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
				{ParameterIsRequired: true, GroupName: "Default", UIModalPosition: 1},
			},
		},
		{
			Name: "function_name", ModalDisplayName: "Function",
			ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
			Description:   "BOF entrypoint symbol.",
			DefaultValue:  "go",
			ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
				{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 2},
			},
		},
		{
			Name: "timeout", ModalDisplayName: "Timeout",
			ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
			Description:   "BOF thread timeout in seconds.",
			DefaultValue:  float64(30),
			ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
				{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 3},
			},
		},
		{
			Name: "coff_arguments", ModalDisplayName: "Arguments",
			ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_TYPED_ARRAY,
			Choices:       []string{"int16", "int32", "string", "wchar", "base64"},
			Description:   "BOF arguments as [type, value] pairs.",
			DefaultValue:  []any{},
			ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
				{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 4},
			},
		},
	}
}

// twinPathParams renders the task modal for cp/mv.
func twinPathParams() []agentstructs.CommandParameter {
	return []agentstructs.CommandParameter{
		{
			Name: "source", ModalDisplayName: "Source",
			ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
			Description:   "Source path.",
			DefaultValue:  "",
			ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
				{ParameterIsRequired: true, GroupName: "Default", UIModalPosition: 1},
			},
		},
		{
			Name: "destination", ModalDisplayName: "Destination",
			ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
			Description:   "Destination path.",
			DefaultValue:  "",
			ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
				{ParameterIsRequired: true, GroupName: "Default", UIModalPosition: 2},
			},
		},
	}
}

// Built in init: load/unload tasking references the specs, so a package
// var initializer would be an initialization cycle.
var commandSpecs []commandSpec

func init() {
	commandSpecs = []commandSpec{
		{name: "shell", help: "shell <command>", description: "shell <command> (cmd.exe /c)",
			mitre: []string{"T1059"}, builtin: true},
		{name: "powershell", help: "powershell <command>", description: "powershell <command> (powershell.exe /c)",
			mitre: []string{"T1059.001"}, builtin: true},
		{name: "sleep", help: "sleep <interval> [jitter]",
			description: "sleep <interval> [jitter] (seconds, jitter percent)", builtin: true},
		{name: "ls", help: "ls [path]", description: "ls [path] (list directory, file browser)",
			mitre: []string{"T1083"}, uiFeatures: []string{"file_browser:list"},
			suggested: true, parseDict: fbPathDict},
		{name: "download", help: "download <path>", description: "download <path> (agent -> Mythic)",
			mitre: []string{"T1030"}, uiFeatures: []string{"file_browser:download"},
			suggested: true, parseDict: fbPathDict},
		{name: "upload", help: `upload {"remote_path": "...", "file": "<uuid>"} (or task modal)`,
			description: "upload a Mythic file to the target (remote_path + file)",
			mitre:       []string{"T1105"}, uiFeatures: []string{"file_browser:upload"},
			suggested:     true,
			createTasking: uploadTask, parseString: uploadLine, parseDict: uploadDict},
		{name: "rm", help: "rm <path>", description: "rm <path> (recursive delete)",
			mitre: []string{"T1070"}, uiFeatures: []string{"file_browser:remove"},
			suggested: true, parseDict: fbPathDict},
		{name: "mkdir", help: "mkdir <path>", description: "mkdir <path> (create directory)",
			suggested: true, parseDict: fbPathDict},
		{name: "ps", help: "ps", description: "ps (list processes, process browser)",
			mitre: []string{"T1057"}, uiFeatures: []string{"process_browser:list"},
			suggested: true, noArgs: true},
		{name: "kill", help: "kill <pid>", description: "kill <pid> (terminate process)",
			mitre: []string{"T1106"}, uiFeatures: []string{"kill", "process_browser:kill"},
			suggested: true, parseString: killLine, parseDict: killDict},
		{name: "execute_assembly", help: `execute_assembly {"assembly_file": "<uuid>", "assembly_arguments": "..."} (or task modal)`,
			description: "execute_assembly (run a .NET assembly in-process via CLR hosting)",
			mitre:       []string{"T1106"},
			suggested:   true, params: execAsmParams(),
			createTasking: execAsmTask, parseString: execAsmLine, parseDict: execAsmDict},
		{name: "execute_coff", help: `execute_coff {"bof_file": "<uuid>", "function_name": "go", "timeout": 30, "coff_arguments": [["z", "hi"]]} (or task modal)`,
			description: "execute_coff (run a BOF object file in-process)",
			mitre:       []string{"T1106"},
			suggested:   true, params: coffParams(),
			createTasking: coffTask, parseString: coffLine, parseDict: coffDict},
		{name: "whoami", help: "whoami", description: "whoami (current user and domain)",
			mitre: []string{"T1033"}, suggested: true, noArgs: true},
		{name: "env", help: "env", description: "env (dump process environment)",
			mitre: []string{"T1082"}, suggested: true, noArgs: true},
		{name: "pwd", help: "pwd", description: "pwd (print working directory)",
			mitre: []string{"T1083"}, suggested: true, noArgs: true},
		{name: "cd", help: "cd <path>", description: "cd <path> (change working directory)",
			mitre: []string{"T1083"}, suggested: true},
		{name: "cp", help: "cp <source> <destination>", description: "cp <source> <destination> (copy file)",
			mitre: []string{"T1005"}, suggested: true, params: twinPathParams(),
			createTasking: twinPathTask, parseString: twinPathLine("cp"), parseDict: twinPathDict},
		{name: "mv", help: "mv <source> <destination>", description: "mv <source> <destination> (move/rename file)",
			mitre: []string{"T1070"}, suggested: true, params: twinPathParams(),
			createTasking: twinPathTask, parseString: twinPathLine("mv"), parseDict: twinPathDict},
		{name: "ipconfig", help: "ipconfig", description: "ipconfig (host and addresses)",
			mitre: []string{"T1016"}, suggested: true, noArgs: true},
		{name: "uptime", help: "uptime", description: "uptime (system uptime)",
			mitre: []string{"T1082"}, suggested: true, noArgs: true},
		{name: "load", help: "load <command>", description: "load <command> (enable at runtime)",
			suggested: true, createTasking: loadTask},
		{name: "unload", help: "unload <command>", description: "unload <command> (disable at runtime)",
			suggested: true, createTasking: unloadTask},
		{name: "exit", help: "exit", description: "exit the agent",
			uiFeatures: []string{"callback_table:exit"}, builtin: true, noArgs: true},
	}
	for _, s := range commandSpecs {
		s.register()
	}
}

// AllCommandNames lists every command the agent implements, in spec order.
func AllCommandNames() []string {
	names := make([]string, 0, len(commandSpecs))
	for _, s := range commandSpecs {
		names = append(names, s.name)
	}
	return names
}

// resolveCommandList validates the operator's command selection: unknown
// names fail the build, and missing builtin (core) commands are appended.
// An empty selection means every known command. It returns the final list
// plus the core commands that were added back.
func resolveCommandList(input []string) (final, added []string, err error) {
	known := map[string]bool{}
	for _, s := range commandSpecs {
		known[s.name] = true
	}
	if len(input) == 0 {
		return AllCommandNames(), nil, nil
	}
	seen := map[string]bool{}
	for _, name := range input {
		if !known[name] {
			return nil, nil, fmt.Errorf("unknown command %q", name)
		}
		if !seen[name] {
			seen[name] = true
			final = append(final, name)
		}
	}
	for _, s := range commandSpecs {
		if s.builtin && !seen[s.name] {
			final = append(final, s.name)
			added = append(added, s.name)
		}
	}
	return final, added, nil
}

func (s commandSpec) register() {
	mitre := s.mitre
	if mitre == nil {
		mitre = []string{}
	}
	uiFeatures := s.uiFeatures
	if uiFeatures == nil {
		uiFeatures = []string{}
	}
	cmd := agentstructs.Command{
		Name:                s.name,
		HelpString:          s.help,
		Description:         s.description,
		Version:             1,
		SupportedUIFeatures: uiFeatures,
		MitreAttackMappings: mitre,
		Author:              "erlikhan",
		CommandAttributes: agentstructs.CommandAttribute{
			CommandIsBuiltin:   s.builtin,
			CommandIsSuggested: s.suggested,
		},
	}
	if s.params != nil {
		cmd.CommandParameters = s.params
	}
	if s.noArgs {
		cmd.TaskFunctionCreateTasking = noArgsTask
		cmd.TaskFunctionParseArgString = noArgsParse
		cmd.TaskFunctionParseArgDictionary = noArgsParseDict
	} else {
		cmd.TaskFunctionCreateTasking = passthroughTask
		cmd.TaskFunctionParseArgString = stringLine
		cmd.TaskFunctionParseArgDictionary = stringDict
		if s.createTasking != nil {
			cmd.TaskFunctionCreateTasking = s.createTasking
		}
		if s.parseString != nil {
			cmd.TaskFunctionParseArgString = s.parseString
		}
		if s.parseDict != nil {
			cmd.TaskFunctionParseArgDictionary = s.parseDict
		}
	}
	agentstructs.AllPayloadData.Get("erlikhan").AddCommand(cmd)
}
