---
title: Erlikhan
---

Erlikhan is a Mythic payload type. The agent talks to the `http`,
`mqtt`, `dns`, and `msteams` C2 profiles, encrypts with the profile PSK
(`aes256_hmac`) or plaintext (`none`), and implements `shell`,
`powershell`, `sleep`, `exit`. The default build is a Go agent;
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
- `exit` posts a final response and stops the agent.

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
