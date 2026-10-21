package agentfunctions

import (
	"encoding/json"
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
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
	// Optional overrides; nil keeps the string-passthrough defaults.
	createTasking agentstructs.PtTaskFunctionCreateTasking
	parseString   agentstructs.PtTaskFunctionParseArgString
	parseDict     agentstructs.PtTaskFunctionParseArgDictionary
}

var commandSpecs = []commandSpec{
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
	{name: "exit", help: "exit", description: "exit the agent",
		uiFeatures: []string{"callback_table:exit"}, builtin: true, noArgs: true},
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

func init() {
	for _, s := range commandSpecs {
		s.register()
	}
}
