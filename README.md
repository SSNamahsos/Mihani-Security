# MihaniSecurity

**English** · [فارسی (Persian)](README.fa.md)

Open-source Windows anti-malware with real-time **credential and token theft
protection** (Steam, Discord, browser cookies/sessions), on-demand scanning,
behavioral detection, quarantine, Windows Security Center registration, and a
Wails-based GUI. Persian (RTL) and English.

- **Engine**: Go, runs as a Windows service (`MihaniSecurity`, LocalSystem).
- **GUI**: Wails v2 (WebView2), frameless window, 9 themes, EN/FA with RTL.
- **Communication**: named pipe `\\.\pipe\MihaniSecurity` (SDDL restricted to
  System/Administrators/interactive users, client **authenticated** — only the
  GUI binary is accepted as a client), newline-delimited JSON messages.
- **Signatures**: bundled text DB shipped with the installer; users extend it
  from Settings → *Import signature update* (no remote queries).

## Features

- **Token guard** — watches Steam, Discord and browser credential stores;
  a process may only read them if it is the **legitimately signed owner**
  (WinVerifyTrust + publisher allowlist — renaming a stealer to `discord.exe`
  no longer helps); otherwise its memory is verified, the offender is
  terminated and its binary quarantined (when the configured severity allows).
- **Real-time protection** — new-file scanning in Downloads/Temp/protected
  folders, process/command-line monitoring, registry persistence watch,
  outbound-connection beaconing detection. Every monitor can be toggled.
- **Behavioral detection** — persistence rules (Run/RunOnce keys, Winlogon
  shell, IFEO debuggers, AppInit_DLLs, scheduled tasks, startup folders),
  DLL/process injection watch, suspicious command lines, network beaconing.
  Each rule maps to a remediation guide in the UI.
- **On-demand scans** — quick scan (Downloads, Desktop, Temp), full scan,
  custom folder scan; results go through the exact same policy engine as
  real-time detections.
- **Quarantine** — **encrypted store** (per-entry AES-256-GCM, chunked, key
  wrapped with DPAPI and stored beside the store; legacy plaintext entries are
  detected and migrated on restore), with restore/delete and auto-purge by age
  and size. Log entries are redacted before display (Discord/Steam tokens,
  Bearer headers, passwords, PowerShell `-enc` payloads).
- **Self-protection** — on service start the data directory is ACL-hardened
  (SYSTEM/Administrators full, Users read-only, Everyone removed) and the
  service DACL is replaced so non-administrators cannot stop, reconfigure or
  delete the service.
- **Windows Security Center** — optional registration as a default AV
  (Settings → *Register as default antivirus*).
- **Protected assets** — files that must never be deleted or quarantined are
  skipped before any policy is applied. The bundled list protects
  `onlinefix64.dll` and `onlinefix.dll` (online-fix support DLLs shipped with
  offline/cracked games), so a signature false positive can never destroy
  them. User exclusions and process/domain whitelists work on top of this.
- **Settings** — 9 themes, EN/FA (RTL), alert verbosity, per-threat action
  policies (log-only / notify / auto-quarantine / auto-delete), token-guard
  targets, whitelists, exclusions, signature import/reload, WSC registration.

## License

MIT — see [LICENSE](LICENSE).

## Architecture

```
cmd/mihanisecurity-service   service binary: -mode install|uninstall|run
main.go                      Wails GUI binary (embeds frontend/dist)
internal/service             service wrapper + IPC server + monitors
internal/app                 Wails bindings (settings, scans, window mgmt)
internal/ipc                 named-pipe protocol (types + server + client)
internal/detector            engine: signatures, tokens, behavior, beaconing
internal/monitor             filesystem + process/memory monitors
internal/quarantine          AES-256-GCM encrypted quarantine (DPAPI-wrapped key)
internal/config              JSON settings store (%ProgramData%)
internal/logger              rotating zerolog file + verdict redaction
pkg/signatures               signature DB format + matcher (PE import-table aware)
pkg/tokens                   known token/password paths (Discord, Steam, …)
pkg/winapi                   handle/memory primitives + signature verification + self-protection
```

Data lives in `%ProgramData%\MihaniSecurity\` (config, signatures.db,
quarantine, logs).

### Signature DB format

`signatures.db` is line-oriented text:

```
# comments
[HASH] <sha256>|<name>|<severity>|<family>
[PE-STRING] <substring>|<name>|<severity>|<family>
[PE-IMPORT] <dll>|<name>|<severity>|<family>
[YARA-LITE] <name>|<severity>|<family>|<substring>
```

Severity: `low|medium|high|critical`. The bundled pack is
`assets/signatures/signatures.db`; the installer places it at
`{app}\signatures\signatures.db` and the service seeds it into ProgramData on
first run. `PE-IMPORT` matches against the file's **parsed PE import table**
(dos/PE headers, section mapping, import descriptors — not raw byte scans);
files larger than 32 MB are hash-matched only (no string scan).

## Building from source

Requirements: Go ≥ 1.26, Node ≥ 20, Wails v2 CLI, Inno Setup 6 (for the
installer).

The one-shot build is `build.bat` from the repository root. It runs vet +
unit tests, regenerates the app icon (`icon.png` → `build/windows/icon.ico`),
builds the frontend, compiles the GUI with Wails, compiles the service, and
compiles the installer:

```bat
build.bat
:: -> build\bin\MihaniSecurity.exe
:: -> build\bin\mihanisecurity-service.exe
:: -> dist\MihaniSecurity Setup.exe
```

Step by step, the same pipeline is:

```powershell
# 1. Frontend bundle (creates frontend/dist for the go:embed)
cd frontend; npm install; npm run build; cd ..

# 2. Backend checks
go vet ./...
go test ./...

# 3. App icon (icon.png -> build\windows\icon.ico, embedded by Wails)
go run ./build/genicon

# 4. Release binaries (GUI via wails, service via go)
wails build -clean
go build -trimpath -ldflags "-s -w" -o build/bin/mihanisecurity-service.exe ./cmd/mihanisecurity-service

# 5. Installer (Inno Setup)
ISCC installer\MihaniSecurity.iss    # -> dist\MihaniSecurity Setup.exe
```

## Smoke test (no install)

Run the engine in the foreground, then scan an EICAR test file:

```powershell
build\bin\mihanisecurity-service.exe -mode run
# in another shell:
notepad test.txt   # paste: X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
# watch the console log emit a "EICAR Test String" verdict
```

## Service management

```powershell
mihanisecurity-service.exe -mode install      # register + start (admin)
mihanisecurity-service.exe -mode uninstall    # stop + remove (admin)
mihanisecurity-service.exe -mode run          # foreground dev mode
```