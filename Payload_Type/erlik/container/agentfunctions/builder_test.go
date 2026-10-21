package agentfunctions

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func testBuildParams() *agentstructs.BuildParameters {
	p := map[string]any{}
	for _, b := range []string{"garble", "console", "obfu_strings", "obfu_deadcode", "obfu_opaque", "obfu_mba", "obfu_controlflow", "obfu_winapi", "strip", "rename_sections", "pe_stomp", "sanitize", "iso_autorun"} {
		p[b] = false
	}
	p["garble_profile"] = "random"
	p["arch"] = "AMD_x64"
	p["compiler"] = "go"
	p["versioninfo"] = "spoof"
	p["spoof_name"] = "cmd"
	p["goeditor"] = "basic"
	p["pack"] = "none"
	p["sign"] = "none"
	p["package"] = "none"
	p["retries"] = 3.0
	p["tasking_size"] = -1.0
	p["sign_domain"] = ""
	p["sign_cert_pw"] = ""
	p["package_password"] = ""
	p["msi_app_name"] = ""
	p["msi_manufacturer"] = ""
	p["msi_scope"] = ""
	return &agentstructs.BuildParameters{Parameters: p}
}

func testBuildMessage(cryptoMode, encKey string) agentstructs.PayloadBuildMessage {
	return agentstructs.PayloadBuildMessage{
		PayloadUUID: "11111111-2222-3333-4444-555555555555",
		SelectedOS:  agentstructs.SUPPORTED_OS_WINDOWS,
		C2Profiles: []agentstructs.PayloadBuildC2Profile{
			{
				Name: "http",
				Parameters: map[string]any{
					"callback_host":            "https://c2.example.com",
					"callback_port":            float64(443),
					"callback_interval":        float64(10),
					"callback_jitter":          float64(23),
					"post_uri":                 "data",
					"get_uri":                  "index",
					"query_path_name":          "q",
					"headers":                  map[string]any{"User-Agent": "test"},
					"proxy_host":               "",
					"proxy_port":               "",
					"proxy_user":               "",
					"proxy_pass":               "",
					"killdate":                 "",
					"encrypted_exchange_check": false,
					"AESPSK": map[string]any{
						"value":   cryptoMode,
						"enc_key": encKey,
						"dec_key": encKey,
					},
				},
			},
		},
	}
}

// openBlob decrypts an assembled blob the same way the agent does.
func openBlob(t *testing.T, blob, key, nonce string) agentConfig {
	t.Helper()
	ct, err := hex.DecodeString(blob)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := hex.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}
	nb, err := hex.DecodeString(nonce)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(kb)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := gcm.Open(nil, nb, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	var cfg agentConfig
	if err := json.Unmarshal(pt, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestAssembleConfig(t *testing.T) {
	blob, key, nonce, err := assembleConfig(testBuildMessage("aes256_hmac", "a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2U="), 5, 7)
	if err != nil {
		t.Fatal(err)
	}
	cfg := openBlob(t, blob, key, nonce)
	if cfg.CallbackHost != "https://c2.example.com" || cfg.CallbackPort != 443 ||
		cfg.PostURI != "data" || cfg.Crypto != "aes256_hmac" ||
		cfg.PSK != "a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2U=" ||
		cfg.Headers["User-Agent"] != "test" || cfg.Retries != 5 || cfg.TaskingSize != 7 {
		t.Fatalf("config mismatch: %+v", cfg)
	}
}

func TestAssembleConfigNone(t *testing.T) {
	blob, key, nonce, err := assembleConfig(testBuildMessage("none", ""), 3, -1)
	if err != nil {
		t.Fatal(err)
	}
	if cfg := openBlob(t, blob, key, nonce); cfg.Crypto != "none" {
		t.Fatalf("crypto = %q", cfg.Crypto)
	}
}

func TestAssembleConfigRejects(t *testing.T) {
	msg := testBuildMessage("aes256_hmac", "")
	if _, _, _, err := assembleConfig(msg, 3, -1); err == nil || !strings.Contains(err.Error(), "enc_key") {
		t.Fatalf("missing enc_key: got %v", err)
	}
	msg = testBuildMessage("rot13", "")
	if _, _, _, err := assembleConfig(msg, 3, -1); err == nil || !strings.Contains(err.Error(), "unsupported crypto") {
		t.Fatalf("bad crypto: got %v", err)
	}
	msg = testBuildMessage("none", "")
	delete(msg.C2Profiles[0].Parameters, "callback_host")
	if _, _, _, err := assembleConfig(msg, 3, -1); err == nil || !strings.Contains(err.Error(), "callback_host") {
		t.Fatalf("missing host: got %v", err)
	}
	msg = testBuildMessage("none", "")
	msg.C2Profiles = nil
	if _, _, _, err := assembleConfig(msg, 3, -1); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("no profile: got %v", err)
	}
}

func TestParseBuildParams(t *testing.T) {
	opts, err := parseBuildParams(testBuildParams())
	if err != nil {
		t.Fatal(err)
	}
	if opts.garble || opts.console || opts.arch != "AMD_x64" || opts.compiler != "go" || opts.versioninfo != "spoof" ||
		opts.spoofName != "cmd" || opts.goeditor != "basic" || opts.pack != "none" ||
		opts.sign != "none" || opts.retries != 3 || opts.taskingSize != -1 || opts.packaging != "none" {
		t.Fatalf("defaults mismatch: %+v", opts)
	}
}

func TestParseBuildParamsRejects(t *testing.T) {
	cases := []struct {
		name  string
		set   map[string]any
		unset []string
		want  string
	}{
		{"bad arch", map[string]any{"arch": "arm64"}, nil, "arch"},
		{"bad compiler", map[string]any{"compiler": "rustc"}, nil, "compiler"},
		{"native rejects x86", map[string]any{"compiler": "native", "arch": "x86"}, nil, "AMD_x64"},
		{"bad versioninfo", map[string]any{"versioninfo": "vibes"}, nil, "versioninfo"},
		{"custom needs config", map[string]any{"versioninfo": "custom"}, nil, "versioninfo_config"},
		{"clone needs donor", map[string]any{"versioninfo": "clone"}, nil, "versioninfo_donor"},
		{"bad goeditor", map[string]any{"goeditor": "ultra"}, nil, "goeditor"},
		{"bad pack", map[string]any{"pack": "rar"}, nil, "pack"},
		{"bad sign", map[string]any{"sign": "maybe"}, nil, "sign"},
		{"self needs domain", map[string]any{"sign": "self"}, nil, "sign_domain"},
		{"valid needs cert", map[string]any{"sign": "valid"}, nil, "sign_cert"},
		{"bad retries", map[string]any{"retries": 0.0}, nil, "retries"},
		{"bad package", map[string]any{"package": "tar"}, nil, "package"},
		{"autorun needs iso", map[string]any{"iso_autorun": true}, nil, "iso_autorun"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bp := testBuildParams()
			for k, v := range tc.set {
				bp.Parameters[k] = v
			}
			for _, k := range tc.unset {
				delete(bp.Parameters, k)
			}
			if _, err := parseBuildParams(bp); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

// testServiceRoot chdirs into the service root like the container runtime.
func testServiceRoot(t *testing.T) {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir("../.."); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(cwd) })
}

func assertPE(t *testing.T, resp agentstructs.PayloadBuildResponse, suffix string) {
	t.Helper()
	if !resp.Success {
		t.Fatalf("build failed: %s %s", resp.BuildMessage, resp.BuildStdErr)
	}
	if resp.Payload == nil || len(*resp.Payload) < 2 || (*resp.Payload)[0] != 'M' || (*resp.Payload)[1] != 'Z' {
		t.Fatal("payload is not a PE")
	}
	if resp.UpdatedFilename == nil || !strings.HasSuffix(*resp.UpdatedFilename, suffix) {
		t.Fatalf("filename wrong: %v", resp.UpdatedFilename)
	}
}

func TestBuildDefault(t *testing.T) {
	t.Setenv("ERLIK_OFFLINE", "1")
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain needed")
	}
	testServiceRoot(t)
	msg := testBuildMessage("aes256_hmac", "a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2U=")
	msg.BuildParameters = *testBuildParams()
	assertPE(t, build(msg), ".exe")
}

func TestBuildHardened(t *testing.T) {
	t.Setenv("ERLIK_OFFLINE", "1")
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain needed")
	}
	testServiceRoot(t)
	msg := testBuildMessage("none", "")
	bp := testBuildParams()
	for _, b := range []string{"obfu_strings", "obfu_deadcode", "obfu_opaque", "obfu_mba", "obfu_controlflow", "obfu_winapi", "strip", "rename_sections", "pe_stomp", "sanitize", "console"} {
		bp.Parameters[b] = true
	}
	bp.Parameters["goeditor"] = "extended"
	bp.Parameters["versioninfo"] = "random"
	msg.BuildParameters = *bp
	assertPE(t, build(msg), ".exe")
}

func TestBuildSignSelf(t *testing.T) {
	t.Setenv("ERLIK_OFFLINE", "1")
	for _, tool := range []string{"go", "openssl", "osslsigncode"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	testServiceRoot(t)
	msg := testBuildMessage("none", "")
	bp := testBuildParams()
	bp.Parameters["sign"] = "self"
	bp.Parameters["sign_domain"] = "www.example.com"
	msg.BuildParameters = *bp
	assertPE(t, build(msg), ".exe")
}

func TestBuildNative(t *testing.T) {
	t.Setenv("ERLIK_OFFLINE", "1")
	if _, err := exec.LookPath("zig"); err != nil {
		t.Skip("zig needed")
	}
	testServiceRoot(t)
	msg := testBuildMessage("aes256_hmac", "a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2U=")
	bp := testBuildParams()
	bp.Parameters["compiler"] = "native"
	msg.BuildParameters = *bp
	resp := build(msg)
	assertPE(t, resp, ".exe")
	if len(*resp.Payload) > 2_000_000 {
		t.Fatalf("native agent suspiciously large: %d bytes", len(*resp.Payload))
	}
}

// TestMakefileBinaryOutsideMount guards the crash-loop regression:
// Mythic bind-mounts the payload folder over /Mythic, so a binary baked
// at /Mythic/erlik is invisible at runtime (make run -> Error 127).
func TestMakefileBinaryOutsideMount(t *testing.T) {
	raw, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	mk := string(raw)
	if !strings.Contains(mk, "go build -o /${BINARY_NAME}") {
		t.Fatal("build must place the service binary at / (outside /Mythic)")
	}
	if strings.Contains(mk, "/Mythic/${BINARY_NAME}") {
		t.Fatal("binary must never be staged under /Mythic (hidden by bind mount)")
	}
}

func TestBuildPackageZip(t *testing.T) {
	t.Setenv("ERLIK_OFFLINE", "1")
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain needed")
	}
	testServiceRoot(t)
	msg := testBuildMessage("none", "")
	bp := testBuildParams()
	bp.Parameters["package"] = "zip"
	msg.BuildParameters = *bp
	resp := build(msg)
	if !resp.Success {
		t.Fatalf("build failed: %s %s", resp.BuildMessage, resp.BuildStdErr)
	}
	if resp.Payload == nil || len(*resp.Payload) < 2 || (*resp.Payload)[0] != 'P' || (*resp.Payload)[1] != 'K' {
		t.Fatal("payload is not a zip")
	}
	if resp.UpdatedFilename == nil || !strings.HasSuffix(*resp.UpdatedFilename, ".zip") {
		t.Fatalf("filename wrong: %v", resp.UpdatedFilename)
	}
}

func cryptoParam(mode, key string) map[string]any {
	return map[string]any{"value": mode, "enc_key": key, "dec_key": key}
}

func testBuildMessageMQTT() agentstructs.PayloadBuildMessage {
	return agentstructs.PayloadBuildMessage{
		PayloadUUID: "11111111-2222-3333-4444-555555555555",
		SelectedOS:  agentstructs.SUPPORTED_OS_WINDOWS,
		C2Profiles: []agentstructs.PayloadBuildC2Profile{
			{
				Name: "mqtt",
				Parameters: map[string]any{
					"mqtt_server": "broker.example.com", "mqtt_port": "8883",
					"use_ssl": "True", "mqtt_client": "agent1",
					"mqtt_user": "u", "mqtt_pass": "p",
					"mqtt_topic": "base/", "mqtt_mythic": "1", "mqtt_taskcheck": "2",
					"callback_interval": "10", "callback_jitter": "14",
					"killdate": "2027-01-01", "websockets": "False",
					"encrypted_exchange_check": "True",
					"AESPSK":                   cryptoParam("aes256_hmac", "a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2U="),
				},
			},
		},
	}
}

func testBuildMessageDNS() agentstructs.PayloadBuildMessage {
	return agentstructs.PayloadBuildMessage{
		PayloadUUID: "11111111-2222-3333-4444-555555555555",
		SelectedOS:  agentstructs.SUPPORTED_OS_WINDOWS,
		C2Profiles: []agentstructs.PayloadBuildC2Profile{
			{
				Name: "dns",
				Parameters: map[string]any{
					"domains":                  []any{"dns.example.com", "backup.example.com"},
					"dns_server":               "10.0.0.1:53",
					"record_type":              "TXT",
					"domain_rotation":          "round-robin",
					"failover_threshold":       float64(3),
					"max_query_length":         float64(200),
					"max_subdomain_length":     float64(40),
					"callback_interval":        float64(15),
					"callback_jitter":          float64(20),
					"killdate":                 "2027-01-01",
					"encrypted_exchange_check": true,
					"AESPSK":                   cryptoParam("none", ""),
				},
			},
		},
	}
}

func testBuildMessageTeams() agentstructs.PayloadBuildMessage {
	return agentstructs.PayloadBuildMessage{
		PayloadUUID: "11111111-2222-3333-4444-555555555555",
		SelectedOS:  agentstructs.SUPPORTED_OS_WINDOWS,
		C2Profiles: []agentstructs.PayloadBuildC2Profile{
			{
				Name: "msteams",
				Parameters: map[string]any{
					"tenant_id": "ten", "client_id": "cid", "client_secret": "sec",
					"team_id": "team", "channel_id": "chan",
					"webhook_url":       "https://hooks.example.com/hook",
					"callback_interval": "60", "callback_jitter": "10",
					"user_agent": "agent-test",
					"proxy_host": "http://proxy.example.com", "proxy_port": "8080",
					"proxy_user": "pu", "proxy_pass": "pp",
					"killdate": "2027-01-01",
					"AESPSK":   cryptoParam("aes256_hmac", "a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2U="),
				},
			},
		},
	}
}

func TestAssembleConfigMQTT(t *testing.T) {
	blob, key, nonce, err := assembleConfig(testBuildMessageMQTT(), 3, -1)
	if err != nil {
		t.Fatal(err)
	}
	cfg := openBlob(t, blob, key, nonce)
	if cfg.Profile != "mqtt" || cfg.MqttServer != "broker.example.com" || cfg.MqttPort != "8883" ||
		cfg.MqttUseSSL != "True" || cfg.MqttClient != "agent1" || cfg.MqttUser != "u" ||
		cfg.MqttTopic != "base/" || cfg.MqttMythic != "1" || cfg.MqttTaskcheck != "2" ||
		cfg.CallbackInterval != 10 || cfg.CallbackJitter != 14 || cfg.Killdate != "2027-01-01" {
		t.Fatalf("mqtt mismatch: %+v", cfg)
	}
}

func TestAssembleConfigDNS(t *testing.T) {
	blob, key, nonce, err := assembleConfig(testBuildMessageDNS(), 3, -1)
	if err != nil {
		t.Fatal(err)
	}
	cfg := openBlob(t, blob, key, nonce)
	if cfg.Profile != "dns" || len(cfg.Domains) != 2 || cfg.Domains[1] != "backup.example.com" ||
		cfg.DnsServer != "10.0.0.1:53" || cfg.RecordType != "TXT" ||
		cfg.DomainRotation != "round-robin" || cfg.FailoverThreshold != 3 ||
		cfg.MaxQueryLength != 200 || cfg.MaxSubdomainLength != 40 ||
		cfg.CallbackInterval != 15 || cfg.CallbackJitter != 20 || cfg.Crypto != "none" {
		t.Fatalf("dns mismatch: %+v", cfg)
	}
}

func TestAssembleConfigTeams(t *testing.T) {
	blob, key, nonce, err := assembleConfig(testBuildMessageTeams(), 3, -1)
	if err != nil {
		t.Fatal(err)
	}
	cfg := openBlob(t, blob, key, nonce)
	if cfg.Profile != "msteams" || cfg.TenantID != "ten" || cfg.ClientSecret != "sec" ||
		cfg.TeamID != "team" || cfg.ChannelID != "chan" ||
		cfg.WebhookURL != "https://hooks.example.com/hook" || cfg.UserAgent != "agent-test" ||
		cfg.ProxyHost != "http://proxy.example.com" || cfg.ProxyPort != "8080" ||
		cfg.CallbackInterval != 60 || cfg.CallbackJitter != 10 {
		t.Fatalf("teams mismatch: %+v", cfg)
	}
	// Optional numbers fall back to profile defaults when absent.
	msg := testBuildMessageTeams()
	delete(msg.C2Profiles[0].Parameters, "callback_interval")
	delete(msg.C2Profiles[0].Parameters, "callback_jitter")
	blob, key, nonce, err = assembleConfig(msg, 3, -1)
	if err != nil {
		t.Fatal(err)
	}
	cfg = openBlob(t, blob, key, nonce)
	if cfg.CallbackInterval != 60 || cfg.CallbackJitter != 10 {
		t.Fatalf("teams defaults = %d/%d", cfg.CallbackInterval, cfg.CallbackJitter)
	}
}

func TestAssembleConfigRejectsProfiles(t *testing.T) {
	msg := testBuildMessageMQTT()
	msg.C2Profiles[0].Name = "smoke"
	if _, _, _, err := assembleConfig(msg, 3, -1); err == nil || !strings.Contains(err.Error(), "unsupported C2 profile") {
		t.Fatalf("unknown profile: got %v", err)
	}
	msg = testBuildMessageMQTT()
	delete(msg.C2Profiles[0].Parameters, "mqtt_server")
	if _, _, _, err := assembleConfig(msg, 3, -1); err == nil || !strings.Contains(err.Error(), "mqtt_server") {
		t.Fatalf("missing server: got %v", err)
	}
	msg = testBuildMessageDNS()
	msg.C2Profiles[0].Parameters["domains"] = []any{}
	if _, _, _, err := assembleConfig(msg, 3, -1); err == nil || !strings.Contains(err.Error(), "domains") {
		t.Fatalf("empty domains: got %v", err)
	}
	msg = testBuildMessageTeams()
	delete(msg.C2Profiles[0].Parameters, "tenant_id")
	if _, _, _, err := assembleConfig(msg, 3, -1); err == nil || !strings.Contains(err.Error(), "tenant_id") {
		t.Fatalf("missing tenant: got %v", err)
	}
}

func TestCheckProfileSupport(t *testing.T) {
	cases := []struct {
		name     string
		compiler string
		profile  string
		params   map[string]any
		wantErr  string
	}{
		{"http go", "go", "http", map[string]any{}, ""},
		{"http native", "native", "http", map[string]any{}, ""},
		{"mqtt go tls", "go", "mqtt", map[string]any{"use_ssl": "True", "websockets": "False"}, ""},
		{"mqtt native plain", "native", "mqtt", map[string]any{"use_ssl": "False", "websockets": "False"}, ""},
		{"mqtt native tls", "native", "mqtt", map[string]any{"use_ssl": "True"}, "compiler=go"},
		{"mqtt websockets", "go", "mqtt", map[string]any{"websockets": "True"}, "websockets"},
		{"dns native", "native", "dns", map[string]any{}, ""},
		{"teams native", "native", "msteams", map[string]any{}, ""},
		{"bogus", "go", "smoke", map[string]any{}, "unsupported C2 profile"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkProfileSupport(tc.compiler, tc.profile, tc.params)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("want %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestBuildMQTTNativeTLSRejects(t *testing.T) {
	t.Setenv("ERLIK_OFFLINE", "1")
	testServiceRoot(t)
	msg := testBuildMessageMQTT()
	bp := testBuildParams()
	bp.Parameters["compiler"] = "native"
	msg.BuildParameters = *bp
	resp := build(msg)
	if resp.Success {
		t.Fatal("native+mqtt+tls build succeeded")
	}
	if !strings.Contains(resp.BuildStdErr, "compiler=go") {
		t.Fatalf("wrong error: %s", resp.BuildStdErr)
	}
}

func TestBuildMQTT(t *testing.T) {
	t.Setenv("ERLIK_OFFLINE", "1")
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain needed")
	}
	testServiceRoot(t)
	msg := testBuildMessageMQTT()
	msg.BuildParameters = *testBuildParams()
	assertPE(t, build(msg), ".exe")
}

func TestBuildDNSNative(t *testing.T) {
	t.Setenv("ERLIK_OFFLINE", "1")
	if _, err := exec.LookPath("zig"); err != nil {
		t.Skip("zig needed")
	}
	testServiceRoot(t)
	msg := testBuildMessageDNS()
	bp := testBuildParams()
	bp.Parameters["compiler"] = "native"
	msg.BuildParameters = *bp
	resp := build(msg)
	assertPE(t, resp, ".exe")
	if len(*resp.Payload) > 2_000_000 {
		t.Fatalf("native agent suspiciously large: %d bytes", len(*resp.Payload))
	}
}
