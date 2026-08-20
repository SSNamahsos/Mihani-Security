# Mihani-Security — Code Review & Antivirus Gap Analysis

**Repo:** https://github.com/SSNamahsos/Mihani-Security
**Stack:** Go 1.26 · Wails v2 (WebView2) GUI · Windows service (LocalSystem) · named-pipe IPC
**Reviewed:** full tree — `internal/detector`, `internal/monitor`, `internal/service`, `internal/ipc`, `internal/quarantine`, `internal/config`, `pkg/winapi`, `pkg/signatures`, `pkg/tokens`

---

## Verdict (short)

**It is a genuinely well-structured, working *hobby/portfolio-grade* anti-malware tool — not a "real" antivirus yet.**

The code quality is honestly above average: clean layering, real low-level Windows work (not just wrapper theater), sensible concurrency, unit tests, log redaction, a hardened named pipe, and a policy engine that routes both real-time and on-demand detections through the same path. As a **credential/token-theft guard + on-demand scanner + behavioral tripwire**, it's real and it works.

But it is **fundamentally user-mode**, and an antivirus that lives entirely in user mode cannot enforce, cannot self-protect, and cannot reliably intercept. Almost everything below traces back to that one architectural fact.

---

## What it does right (genuine strengths)

- **Real architecture** — LocalSystem service (`kardianos/service`), separate Wails GUI, named pipe IPC with a proper SDDL ACL (`System`/`Administrators` = full, `Interactive Users` = read/write only).
- **Real low-level primitives** — `NtQuerySystemInformation` (process + extended handle table), `ReadProcessMemory` + `VirtualQueryEx` memory scanning, `GetExtendedTcpTable` for TCP/owner-PID, `Thread32First/Next` + `NtQueryInformationThread` start-address query + `VirtualQueryEx` unbacked-memory check for injection detection, `DuplicateHandle` + `NtQueryObject` for handle-name resolution.
- **Multi-layer detection** — signature DB (hash + PE-string + PE-import + "YARA-lite"), static heuristic string scoring (credential/exfil/evasion), behavioral rules (persistence, suspicious command line, download-and-execute, injection), beaconing frequency detector, and a token-guard that watches who opens credential stores.
- **Real remediation pipeline** — quarantine (SHA256, restore/delete, auto-purge by age/size), process termination, per-threat action policies, exclusions/whitelists, protected-asset bypass.
- **Good hygiene** — token/bearer/password redaction in logs, config persistence with default-merge, EICAR end-to-end test signatures, WSC registration hook.

---

## The bad things (weaknesses / what's missing)

### 1. No kernel driver → detection is polling, not interception
- Filesystem monitor uses **fsnotify** (`internal/monitor/monitor_windows.go` → `ReadDirectoryChangesW`), which only watches a handful of folders. Malware that writes anywhere else, or races the watcher, is invisible.
- Process monitor is a **1.5 s ticker** comparing PID lists (`ProcMonitor`). Handles every **8 s**, network every **2 s**, injection every **30 s**, modules every **45 s**. A process can spawn → read a token → exfiltrate → exit between polls.
- Real AVs use a **minifilter driver** (`FltRegisterFilter`) for file I/O and **kernel callbacks** (`PsSetCreateProcessNotifyRoutineEx`, `ObRegisterCallbacks`, `CmRegisterCallbackEx`, `PsSetLoadImageNotifyRoutine`) for process/registry/image events.

### 2. "Block" does not block
- `internal/detector/engine.go` → `enforce()` literally emits:
  `detail = append(detail, "access reported; no kernel-mode deny available")`.
- The token guard's `BlockReads` setting **cannot deny** the read. It detects, then *kills* the offender after the fact. A fast stealer reads the token and exfiltrates before the kill lands. This is the single most misleading feature in the app.

### 3. No self-protection / tamper protection
- Nothing stops malware (or a user) from: `sc stop MihaniSecurity`, deleting `mihanisecurity-service.exe`, editing `%ProgramData%\MihaniSecurity\config.json` (written `0o644`), editing `signatures.db` to whitelist itself, or wiping `Quarantine/index.json`.
- No **PPL** (protected process light), no **AM-PPL**, no **ELAM** driver, no **code signing** on the actual binaries (only the setup exe is mentioned in `deploy/sign.ps1`). Without these it can never be a legitimate Windows default AV and Windows Defender/SmartScreen will treat it as untrusted.

### 4. Named-pipe IPC trusts the client completely
- `pipeSDDL` grants **Interactive Users (IU) = GenericRead|GenericWrite** (`internal/ipc/ipc.go`).
- There is **no authentication or authorization** of messages. Any process running in the user's session — including the malware itself — can connect and issue `settings_set` (disable real-time protection), `verdict_action allow` (whitelist its own name), `wsc_register false`, or `toggle_realtime false`. `verdict_action` in `internal/service/service.go` even lets a caller quarantine arbitrary files and whitelist arbitrary names with **no admin check**.
- Fix: require the client to authenticate (e.g., only the signed GUI binary via process-token/PPID verification), and split privileged commands behind an admin-only channel.

### 5. Signature engine is a toy
- ~55 signatures, all hand-written substrings (`assets/signatures/signatures.db`). No real malware coverage.
- **No automatic updates** — README: "no remote queries"; users must manually `Import signature update`. A real AV updates signatures multiple times a day from a cloud/feed.
- **"YARA-LITE" is just `strings.Contains`** — no condition logic, offsets, regex, or wildcards. The file itself notes "expression language deferred to v2".
- **PE-IMPORT matching is naive**: `containsImport` scans raw bytes for a lowercase DLL name — no PE import-directory parsing, high false-positive rate, misses real import tables.
- **No unpacking / emulation / sandbox** — packed, encrypted, or polymorphic malware is invisible.
- **Hash/string matching reads whole files into RAM** with no size cap in the real-time signature path (`pkg/signatures/signatures.go` → `MatchFile` does `os.ReadFile`). A multi-GB file can spike memory.

### 6. No ransomware / destructive-behavior protection
- No canary files, no bulk-rename/extension-change detection, no entropy-based encryption detection, no rollback/backup, no file-access-rate limiting. Wiper coverage is a few static strings (`vssadmin delete shadows`, `format c:`).

### 7. No heuristic scoring, no ML, no cloud reputation
- Detection is entirely local static strings + a few hand-coded rules. No file reputation, no prevalence/age data, no behavioral ML score, no sandbox verdict, no URL/domain reputation.

### 8. No web / email / script protection
- No URL filtering, no HTTP(S) scanning, no email/attachment scanning, no AMSI hooking (it only *detects* AMSI-bypass strings, it doesn't hook AMSI itself), no Office-macro/VBA scanning, no PowerShell script-block logging integration.

### 9. Limited persistence & LOLBin coverage
- Registry watch covers Run/RunOnce/Winlogon/Environment only. Missing: services, scheduled tasks (string-detect only), WMI event subscriptions, AppInit_DLLs, IFEO debuggers, shell extensions, BITS jobs, Startup folders, DLL search-order hijacking, COM hijacking.

### 10. Quarantine "encryption" is a lie
- `internal/config/config.go` declares `Quarantine.Encrypt bool`, and the README says "encrypted store", but `internal/quarantine/quarantine.go` never reads it — files are stored as **plain renamed `.bin` bytes**. Either implement real per-entry AES encryption or drop the claim.

### 11. Token-guard allow-list is name-based and trivially spoofed
- `IsLegitimateOwner` / `IsWhitelistedProcess` / `trusted()` all match on `filepath.Base(name)`. Rename any stealer to `discord.exe` and it's trusted. Real ownership checks need **signed binary / publisher / path + hash** verification.

### 12. Beaconing detection is narrow
- Keyed on `PID:IP:port`, counts connections over a window, TCP only. No DNS exfiltration detection, no JA3/TLS fingerprint, no domain reputation, no volume-based exfil, no UDP. PID reuse causes misses.

### 13. Performance / resource cost
- `ListProcesses` opens every process (goroutine pool) every 1.5 s; `scanHandles` enumerates the **entire system handle table** every 8 s (`SystemExtendedHandleInformation`); memory scan reads up to **192 MB per process**. Heavy for a real-time agent — expect CPU/battery/latency complaints.

### 14. No self-update, no update channel at all
- No mechanism to update the binaries or signatures automatically. No update server, no signing/verification of updates, no staged rollout.

### 15. Test gaps
- Unit tests exist (config, signatures, quarantine, tokens, behavior, redact, exclusions) — good — but **no integration tests, no service/IPC security tests, no E2E, and most low-level code is `_windows.go` build-tagged** so CI on Linux/macOS can't exercise it.

---

## What to ADD to make it a real antivirus (prioritized)

**Phase 1 — make detection trustworthy (kernel + event-driven)**
1. Write a **minifilter driver** (`FltRegisterFilter`) for all file I/O interception + on-write/on-execute scanning.
2. Add **kernel callbacks** via a small driver or ETW: process create/terminate, image load, registry set, handle operations. Replace all polling monitors with event callbacks.
3. Implement a **real deny/block path** (minifilter `FLT_PREOP` returning `FLT_PREOP_COMPLETE` for access denial) so `BlockReads` actually blocks.
4. Add **AMSI provider** (`IAntimalwareProvider`) to scan PowerShell/VBScript/JScript/macros in memory.
5. Enable **SeDebugPrivilege handling + AM-PPL** and **sign the binaries** (EV cert / Microsoft attestation) so it can run as a protected, trusted default AV.

**Phase 2 — detection breadth**
6. **Replace "YARA-lite" with real YARA** (`github.com/hillu/go-yara`), or at minimum a proper multi-pattern matcher (Aho-Corasick) with offset/regex/condition support.
7. **Parse PE properly** (import table, sections, entropy, overlay) instead of raw-byte substring scans.
8. Add **unpacking/emulation/sandbox** (or at least entropy + packer detection: UPX, Themida, VMProtect signatures).
9. Add **heuristic/ML scoring** (features: entropy, imports, strings, PE anomalies, behavioral events) with a weighted verdict + confidence.
10. Add **cloud reputation** — hash lookup (VirusTotal-like / own backend), URL/domain reputation, prevalence. This also enables **automatic signature + engine updates** (signed, with rollback).

**Phase 3 — modern threat coverage**
11. **Ransomware protection**: canary files, entropy spike detection on bulk writes, file-extension mass-change, backup/rollback via VSS, rate-limited block.
12. **Expanded persistence coverage** (services, scheduled tasks, WMI, IFEO, AppInit, COM, BITS, Startup folders).
13. **Network/DNS protection**: DNS query logging, domain reputation, JA3/TLS fingerprinting, outbound data-volume heuristics, UDP/DNS tunnel detection.
14. **Self-protection**: ACL-harden `%ProgramData%\MihaniSecurity`, protect the service with `ChangeServiceConfig2` + SDDL, PPL the service, watch for `sc stop`/kill attempts and block them from a driver.
15. **Process hollowing / APC / reflective-DLL / shellcode detection** beyond the current single thread-start-address heuristic.

**Phase 4 — trust & operations**
16. **Authenticated IPC** — verify the connecting client is the signed GUI (process token / PPID / image path), restrict privileged commands to admins, never let a random interactive process whitelist or disable.
17. **Real quarantine encryption** (per-entry AES-GCM with key in DPAPI) or remove the claim.
18. **Self-update** with signed payloads + staged rollout + failure rollback.
19. **Telemetry & false-positive management** (anonymous submission of verdicts/samples, suppression tuning).
20. **Integration/E2E tests** + a Windows CI runner; stop relying on `_windows.go` build tags hiding bugs.

---

## Ready-to-use improvement prompt (paste this into any AI/dev)

```
You are a senior Windows security engineer. Review and upgrade "Mihani-Security",
an open-source Go + Wails Windows anti-malware (LocalSystem service, named-pipe IPC,
user-mode only). Keep the existing architecture where sensible, but close the
following gaps, in priority order:

1. KERNEL / EVENT-DRIVEN: Replace all user-mode polling monitors (fsnotify FS watch,
   ticker-based process/handle/network/injection/module scanners) with a minifilter
   driver (file I/O + real deny/block) and kernel callbacks or ETW for process
   create/terminate, image load, and registry writes.

2. REAL BLOCKING: The token guard's "BlockReads" currently only reports and then
   kills the process ("no kernel-mode deny available" in internal/detector/engine.go).
   Make it actually deny access via the minifilter, and add an AMSI provider to scan
   PowerShell/VBScript/JScript/macros.

3. SELF-PROTECTION: Prevent malware from stopping the service, editing
   %ProgramData%\MihaniSecurity\config.json / signatures.db / quarantine index, or
   killing the processes. Add PPL (AM-PPL), ELAM, code signing, and ACL hardening.

4. IPC AUTHENTICATION: The named pipe SDDL grants Interactive Users read/write and
   there is NO message authentication — any process can send settings_set,
   verdict_action allow, or toggle_realtime. Verify the caller is the signed GUI
   (process token/PPID/image path) and gate privileged commands behind admin.

5. SIGNATURES: Replace the ~55-entry substring "YARA-lite" DB with real YARA (or
   Aho-Corasick + offsets/regex/conditions), parse PE import tables/entropy/overlay
   properly, add packer/unpacking detection, and add AUTOMATIC signed signature
   updates (cloud feed, rollback).

6. DETECTION BREADTH: Add heuristic/ML scoring with confidence, cloud file/URL/domain
   reputation, ransomware protection (canary files, entropy/bulk-write detection,
   VSS rollback), expanded persistence coverage (services, scheduled tasks, WMI,
   IFEO, AppInit, COM, BITS, Startup), DNS/JA3/domain reputation, and process
   hollowing / APC / reflective-DLL detection.

7. CORRECTNESS: Quarantine claims "encrypted store" but never encrypts (the
   Quarantine.Encrypt flag is dead code) — implement per-entry AES-GCM with DPAPI key
   or remove the claim. Fix the name-based process whitelist (renaming a stealer to
   "discord.exe" bypasses it) with signed-binary/publisher/path+hash ownership.

8. OPS: Add self-update, telemetry + false-positive tuning, and integration/E2E tests
   on a Windows CI runner.

For each item: implement the change, add tests, update README (EN + FA), and explain
how it survives an adversarial test (a stealer that spawns+exfiltrates in <2s, a
packed/encrypted payload, and a process that tries to disable the service).
```

---

## Key evidence locations (for your own verification)

| Finding | File |
|---|---|
| "no kernel-mode deny available" (block is fake) | `internal/detector/engine.go` (`enforce`, `ActionBlock` case) |
| Polling monitors (tickers) | `internal/monitor/monitor.go` |
| fsnotify-based FS watch | `internal/monitor/monitor_windows.go` |
| Pipe SDDL grants IU read/write, no auth | `internal/ipc/ipc.go` (`pipeSDDL`) |
| `verdict_action` allow/quarantine, no admin check | `internal/service/service.go` |
| Quarantine `Encrypt` flag unused, plain `.bin` copy | `internal/quarantine/quarantine.go` + `internal/config/config.go` |
| Name-based whitelist (`filepath.Base`) | `pkg/tokens/tokens.go`, `internal/detector/detector.go` |
| Substring "YARA-lite", raw-byte PE-import scan | `pkg/signatures/signatures.go` |
| ~55-entry static signature DB, no updates | `assets/signatures/signatures.db`, `internal/service/service.go` |
| Whole-file `os.ReadFile` in signature match | `pkg/signatures/signatures.go` (`MatchFile`) |

---

## Resolution status (v1.0.3)

| # | Finding | Status | Where |
|---|---------|--------|-------|
| 2 | "Block" does not block | **Partial** — honest wording in UI/docs; post-hoc kill remains (no kernel deny possible in user mode) | `internal/detector/engine.go` |
| 3 | No self-protection | **Done (user-mode)** — data dir ACL-hardened at service start (SYSTEM/Admins full, Users read-only, Everyone removed); service DACL replaced so non-admins cannot stop/config/delete. PPL/ELAM require a driver (not feasible here) | `pkg/winapi/selfprotect.go`, `internal/service/service.go` |
| 4 | Named-pipe trusts the client | **Done** — every client connection resolved to its image path (GetNamedPipeClientProcessId); only the GUI exe (or files in the service dir) is accepted; rejections logged | `internal/ipc/auth_windows.go`, `internal/ipc/ipc.go` |
| 5 | Signature engine is a toy (partial items) | **Partial** — PE-IMPORT now parses the real import table (dos/PE headers, section RVA mapping, import descriptors); `MatchFile` has a 32 MB cap (hash-only beyond, streamed). Real YARA, updates, unpacking: out of scope | `pkg/signatures/signatures.go` |
| 9 | Limited persistence coverage | **Done** — added IFEO debugger / SilentProcessExit, AppInit_DLLs, and Startup-folder rules (registry + static cmdline + file-create), with tests | `internal/detector/detector.go`, `internal/detector/fileinspect.go` |
| 10 | Quarantine "encryption" is a lie | **Done** — real per-entry AES-256-GCM (64 KB chunks, random nonce), key wrapped with DPAPI (`key.bin`), `Encrypt` config now honored and default true; legacy plaintext entries detected and migrated on restore; plaintext size + SHA256 stored | `internal/quarantine/crypto.go`, `internal/quarantine/quarantine.go` |
| 11 | Token-guard allow-list is name-based | **Done** — a process claiming a legit owner name now must be **signed** (WinVerifyTrust) with a **matching publisher** (Discord Inc., Valve, Google, Microsoft, Mozilla, Brave, Opera, Vivaldi, Telegram); failures produce a critical "spoofed process" verdict | `pkg/tokens/trusted.go`, `pkg/winapi/signature.go`, `internal/detector/detector.go` |
| 16 | Authenticated IPC | **Done** — client image-path allowlist (see #4) | `internal/ipc/` |
| 1, 6, 7, 8, 12–15, 17–20 | Kernel driver, AMSI, ML, cloud reputation, ransomware, DNS/JA3, PPL, self-update, telemetry, E2E/CI | **Not feasible in this user-mode Go project** — require a signed kernel driver, an update backend, or a CI/CD account. Documented honestly here and in the READMEs | — |

Tests added for: IPC auth, quarantine encryption round-trip + legacy migration, publisher allowlist + signature verification, PE import parsing (against real system DLLs), size-cap hash path, IFEO/AppInit/Startup behavior rules.

---

## Resolution status (v1.0.4)

| # | Finding | Status | Where |
|---|---------|--------|-------|
| — | Closing the GUI stops the dashboard (no tray) | **Done** — closing hides to a native tray icon (dedicated message-loop thread; message-only window `MihaniSecurityTray`); tray menu Open/Exit; `HideWindowOnClose` + `hide_in_tray` config (default true, presence-aware merge for legacy configs). Protection itself always ran in the service and is unaffected by GUI state | `pkg/winapi/tray.go`, `internal/app/app.go`, `internal/config/config.go`, `main.go` |

Tray tests: window creation on a dedicated thread, double-click and menu callbacks delivered through the tray message loop.

---

## Resolution status (v1.0.5)

| # | Finding | Status | Where |
|---|---------|--------|-------|
| - | RT toggle error "not connected" after service restart | **Done** - App.Connect() no longer no-ops when the client object exists but the pipe dropped; it now checks Connected() and reconnects via ConnectRetry. Frontend retries ConnectService with exponential backoff (2s..30s, resets on success). Integration test added: client reconnects after server restart and calls succeed | `internal/app/app.go`, `frontend/index.html`, `internal/ipc/reconnect_test.go` |
| - | Stray "?" rendered top-left of the UI | **Done** - literal "?" bytes before `<!DOCTYPE html>` in `frontend/index.html` removed (quirks-mode + stray text node); dist regenerated; installed exe verified clean | `frontend/index.html` |
