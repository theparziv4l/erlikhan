---
title: Erlikhan
---

Erlikhan is a Mythic payload type. The agent talks to the `http`,
`mqtt`, `dns`, and `msteams` C2 profiles, encrypts with the profile PSK
(`aes256_hmac`) or plaintext (`none`), and implements `shell`,
`powershell`, `sleep`, `ls`, `download`, `upload`, `rm`, `mkdir`,
`ps`, `kill`, `load`, `unload`, `exit`. The default build is a Go agent;
`compiler=native` builds the small native C agent instead (zig cc,
no Go runtime).

Profile notes:

- `mqtt`: agent publishes to `mqtt_topic + mqtt_taskcheck`, reads replies
  on `mqtt_topic + mqtt_mythic`. Native supports plain TCP only;
  `use_ssl=True` needs `compiler=go`. `websockets=True` is rejected
  (no websocket transport yet).
- `dns`: chunked `A`/`AAAA`/`TXT` queries against `dns_server`;
  honors `domain_rotation` and `failover_threshold`. Both compilers.
- `msteams`: OAuth2 client credentials, channel messages via Graph API
  (AdaptiveCard webhook send when `webhook_url` is set). Both
  compilers. Use a dedicated channel; foreign messages look like replies.
- `encrypted_exchange_check` is ignored: the agent always uses the
  static profile PSK, same as the `http` behavior.

## Install

The package needs no published image; Mythic builds the container locally:

```bash
sudo ./mythic-cli install folder /path/to/mythic
sudo ./mythic-cli build erlikhan
sudo ./mythic-cli payload start erlikhan
```

Install the profiles alongside it:

```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/mqtt
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/dns
sudo ./mythic-cli install github https://github.com/Whispergate/msteams
```

## Build a payload

Create a payload in the Mythic UI: payload type `erlikhan`, OS Windows,
one C2 profile (`http`, `mqtt`, `dns`, or `msteams`). Output is a
Windows EXE (or the chosen container).

## Build options (web UI)

Every option that applies to an agent build is a build parameter:

| Parameter | Type | Default | Effect |
|---|---|---|---|
| garble | Boolean | false | Garble `-tiny -literals` build |
| garble_profile | ChooseOne | random | fixed / random / aggressive directives |
| console | Boolean | false | Keep console window (else hidden) |
| arch | ChooseOne | AMD_x64 | AMD_x64 / x86 (native is AMD_x64 only) |
| compiler | ChooseOne | go | go / native (64KB C agent via zig cc) |
| versioninfo | ChooseOne | spoof | spoof / random / custom / clone / none |
| spoof_name | ChooseOneCustom | cmd | Windows binary to mimic |
| versioninfo_config | File | — | Versioninfo JSON (custom) |
| versioninfo_donor | File | — | Donor PE (clone) |
| obfu_strings | Boolean | false | Encrypt string literals |
| obfu_deadcode | Boolean | false | Dead code paths |
| obfu_opaque | Boolean | false | Opaque predicates |
| obfu_mba | Boolean | false | Boolean-arithmetic rewrite |
| obfu_controlflow | Boolean | false | Control-flow flattening |
| obfu_winapi | Boolean | false | Hide static API/DLL names |
| goeditor | ChooseOne | basic | basic / extended Go string scrub |
| strip | Boolean | false | strip -s before signing |
| rename_sections | Boolean | false | MSVC-neutral section names |
| pack | ChooseOne | none | none / upx |
| pe_stomp | Boolean | false | Zero Rich/timestamp/debug, spoof linker |
| sanitize | Boolean | false | SanitizePE before signing |
| richheader_donor | File | — | Donor PE for Rich header clone |
| sign | ChooseOne | none | none / self (fake cert) / valid (PFX) |
| sign_domain | String | — | Fake cert domain (self) |
| sign_cert_pw | String | — | PFX password (valid) |
| sign_cert | File | — | PFX cert (valid) |
| clone_cert | File | — | Donor PE for cert clone |
| retries | Number | 3 | Checkin attempts |
| tasking_size | Number | -1 | Tasks per poll (-1 = all) |
| shellcode | Boolean | false | Raw shellcode (.bin) via Donut; needs package=none, sign=none |
| package | ChooseOne | none | none / zip / iso / img / vhd / 7z / msi |
| package_password | String | — | 7z password |
| msi_app_name | String | — | MSI product name |
| msi_manufacturer | String | — | MSI manufacturer |
| msi_scope | String | — | MSI scope |
| iso_autorun | Boolean | false | autorun.inf in ISO packages |

Not exposed (cannot apply to a standalone agent): shellcode-loader
templates (`-Exec`, `-Evasion`, `-noamsi`, `-noetw`, `-sandbox`,
`-time`/`-step`, `-injection`), other loaders (`-Loader`), LOLBins,
triggers, persistence sidecars, maldocs, msix/electron packaging, and
CLI-only plumbing (`-doctor`, `-manifest`, `-verify`, GUI).

With `compiler=native`, the Go-only passes (`garble`,
`garble_profile`, `obfu_*`, `goeditor`) are ignored; versioninfo,
signing, PE post-processing and packaging apply to both compilers.

## Tasking

- `shell <command>` runs `cmd.exe /c`.
- `powershell <command>` runs `powershell.exe /c`.
- `sleep <interval> [jitter]` sets callback seconds and jitter percent.
- `ls [path]` lists a directory (default `.`) and populates the file
  browser.
- `download <path>` pulls a file from the target to Mythic (chunked).
- `upload` pushes a Mythic file to `remote_path` on the target: pick
  the file in the task modal, or from the CLI pass
  `{"remote_path": "...", "file": "<mythic-file-uuid>"}`.
- `rm <path>` recursively deletes a file or directory tree and prunes
  it from the file browser.
- `mkdir <path>` creates a directory with parents.
- `ps` lists processes and populates the process browser. The Go
  agent reports pid/ppid/name; the native C agent adds image path,
  owner, integrity level and start time.
- `kill <pid>` terminates a process.
- `load <command>` / `unload <command>` enable or disable a command
  on a live callback without rebuilding. All handlers stay compiled
  in, so anything can be loaded back; `exit`, `load` and `unload`
  themselves cannot be unloaded.
- `exit` posts a final response and stops the agent.

Executing commands report artifacts (process creation, file
up/down/delete, process kill) to the artifacts view. New callbacks
are stamped with an `erlikhan/<profile> · N commands` description and
their sleep schedule.

File transfers are chunked inside the task (512KB per chunk on `http`
and `mqtt`, 8KB on `dns` and `msteams` where messages are small), so
large files over `dns`/`msteams` are slow but work. The agent is
single-host: file-browser `host` fields are ignored.

## Shellcode output and wrappers

With `shellcode=true` the build converts the finished EXE to raw
position-independent shellcode (`<uuid>.bin`) with Donut, matching the
build arch. Signing and packaging do not apply to shellcode output, so
the build requires `sign=none` and `package=none` with it. The `.bin`
is accepted by `service_wrapper` (select the built payload as the
wrapped payload when creating the wrapper) and by external loaders
such as ScareCrow.

## Adding or removing commands

`shell`, `powershell`, `sleep` and `exit` are builtin: every payload
includes them and they cannot be unselected. Any other command can be
added to or removed from a payload on the command-selection step of the
build; the selected set is baked into the binary and anything outside
it is refused with a "not included in this build" error.

To add a new command, touch one place per layer:

1. `container/agentfunctions/commands.go`: append a row to `commandSpecs`
   (`builtin: true` only for commands every payload must have).
2. `agent_code/tasks.go`: add a row to `commandTable` plus a handler.
3. `agent_code_c/tasks.c`: add a row to `task_table` plus a `task_*`
   handler (both agents implement the same set).
4. Run `go test ./...` in `container/` (`TestCommandLayersAgree` fails
   if the three layers disagree), `GO111MODULE=off go test` in
   `agent_code/`, and the `tasks_test.c` builds under wine.

## Offline route

The same agent builds without Mythic via erlikhan, with the full
pipeline:

```bash
./erlikhan -c2 mythic-http -c2-config mythic.json -nosign
```

`mythic.json` carries the payload UUID, callback host and profile PSK.
Only `payload_uuid`, `callback_host` and `psk` are mandatory; every other
key defaults to the `http` profile values. A `profile` key of `mqtt`,
`dns`, or `msteams` selects that transport instead, with its own
required keys (`mqtt_server`/`mqtt_topic`/..., `domains`/`dns_server`,
or the Entra `tenant_id`/`client_id`/`client_secret`/`team_id`/
`channel_id` set).
