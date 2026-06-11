# Secgurd

**DFIR triage toolkit for remote Windows machine analysis**

```
        R>========================================================<R
          |   ___ ___ ___ ___ _   _ ___ ___                       >>>
          |  / __| __/ __/ __| | | | _ \   \   ===================>>>
          |  \__ \ _| (_| (_ | |_| |   / |) |  ===================>>>
          |  |___/___\___\___|\___/|_|_\___/                      >>>
        R>========================================================<R
              Slayer of threats. Keeper of truth.
```

---

## Overview

Secgurd is a single-file PowerShell DFIR (Digital Forensics and Incident Response) triage tool for fast, read-only analysis of Windows machines you connect into remotely. It collects high-signal forensic artifacts, auto-flags suspicious findings, and packages everything into a portable evidence bundle — without installing anything on the target.

It's built for the first hour of an investigation: *"something looks off on this box — what's actually going on?"* Run it, pull back the zip, and review.

- **One file, no dependencies.** Pure PowerShell 5.1+, no modules to install, nothing to compile.
- **Read-only by default.** Collects and reports; it doesn't change the system (the only write action, `-Cleanup`, requires explicit confirmation).
- **Offline-friendly.** No internet required. No data leaves the host except the evidence zip you collect.
- **Self-contained output.** Timestamped folder + auto-zipped archive, with an optional single-file HTML report.

---

## Why "Secgurd"?

Sigurd is a legendary hero of Norse and Germanic myth — the dragon-slayer who faced Fafnir with precision and courage. Secgurd carries that spirit forward: a tool to help analysts **hunt, detect, and eliminate** malicious activity in modern Windows environments. (And yes — there's a dragon in here somewhere. Try running it with no modules selected.)

---

## Features

**Collection — 14 modules, 40+ collectors:**

| # | Module | Collects |
|---|--------|----------|
| 01 | System info | OS, build, uptime, domain, environment |
| 02 | Users & sessions | accounts, logons, **RDP / remote-access artifacts** |
| 03 | Persistence | run keys, tasks, services, WMI, IFEO, Winlogon, AppInit, accessibility hijacks, **rogue RMM tools** |
| 04 | PowerShell artifacts | history, transcripts, 4104 script-block logs |
| 05 | Network | connections, DNS cache, ARP, shares, firewall rules |
| 06 | Processes | process tree, command lines, unsigned DLLs |
| 07 | Filesystem | temp executables, ADS, recently-modified files |
| 08 | Event logs | account changes, log clearing, log status |
| 09 | Software & Defender | installed apps, patches, Defender status & exclusions |
| 10 | Browser & creds | history file paths, `.ssh`, `.aws`, credential files |
| 11 | LOLBins | certutil, mshta, rundll32, regsvr32 usage |
| 12 | AmCache / ShimCache | execution-artifact locations |
| 13 | Prefetch | `.pf` files, last-run times |
| 14 | Named pipes | active pipes, C2 detection |

**Detection & analysis:**

- **Findings engine** — auto-flags high-signal indicators (HIGH / MED / INFO) as it runs: WMI event consumers, IFEO debugger hijacks, accessibility backdoors, encoded PowerShell, suspicious parent→child process chains, services/tasks running from writable paths, unquoted service paths, rogue remote-access tools, Defender exclusions on temp paths, and more.
- **Rogue RMM detection** — hunts ~18 remote-access tool families (ScreenConnect/ConnectWise, AnyDesk, TeamViewer, Atera, Splashtop, MeshCentral, NetSupport, etc.) and flags suspicious context (writable-path installs, ScreenConnect instance folders + relay host).
- **Local IOC hash matching** — match on-disk binaries against your own list of known-bad MD5 / SHA-1 / SHA-256 hashes. Fully offline; no API key, no third-party disclosure.
- **Event timeline** — chronological merge of logons, log clears, new services, scheduled tasks, and recent file modifications.
- **SHA-256 evidence manifest** — hashes every output file for chain-of-custody / tamper evidence.

**Output:**

- Timestamped output folder, auto-zipped.
- Optional **single-file HTML report** with color-coded, clickable findings that jump to and highlight the exact artifact, plus collapsible per-module sections (with clear "no data" / "error" badges).
- Returns a PowerShell object (folder, zip path, file count, findings, duration) for scripting.

---

## Requirements

- **Windows** with **PowerShell 5.1 or later** (built into Windows 10/11 and Server 2016+).
- **Administrator** is strongly recommended — many artifacts (security event logs, some persistence locations, WMI subscriptions) require elevation for full coverage. Secgurd runs without admin but will collect less and may show "error" badges where access was denied.

---

## Quick start

### Run from a local copy (recommended)

```powershell
# clone once
git clone https://github.com/SicksSens3/secgurd
cd secgurd

# run it (interactive menu appears)
powershell -ExecutionPolicy Bypass -File .\secgurd.ps1
```

To update later, just pull:

```powershell
git pull
```

### Run all modules without the menu

```powershell
.\secgurd.ps1 -Auto
```

### One-liner from GitHub (lab / non-EDR hosts)

```powershell
iex (irm "https://raw.githubusercontent.com/SicksSens3/secgurd/main/secgurd.ps1?v=$(Get-Random)")
```

> The `?v=$(Get-Random)` busts GitHub's ~5-minute raw cache so you always get the latest. **Note:** the download-and-execute pattern of `iex(irm)` is frequently flagged by EDR. For managed endpoints, prefer the file-based run above. See **Running on EDR-managed endpoints** below.

---

## Usage

```
secgurd.ps1 [-Auto] [-Modules 01,03,06] [-OutputPath <dir>] [-NoBanner]
            [-OpenWhenDone] [-HtmlReport] [-WithOwners] [-WithSignatures]
            [-IOCHashes <file>] [-DaysBack <N>] [-Cleanup] [-MakeS1Paste] [-Help]
```

### Parameters

| Flag | Description |
|------|-------------|
| `-Auto` | Run all modules, skip the interactive menu (headless). |
| `-Modules 01,03,06` | Run only the listed module numbers. |
| `-OutputPath <dir>` | Where to write output (default: `%TEMP%\secgurd_<host>_<timestamp>`). |
| `-NoBanner` | Suppress the ASCII banner (useful if glyphs render oddly in a shell). |
| `-OpenWhenDone` | Open the output folder when finished (interactive desktop only). |
| `-HtmlReport` | Also build a single-file `report.html` and open it when done. |
| `-WithOwners` | Resolve process owners (slower; off by default — can stall on domain controllers). |
| `-WithSignatures` | Verify Authenticode signatures of service binaries / loaded DLLs (slower; can stall offline). |
| `-IOCHashes <file>` | Match on-disk binaries against an MD5/SHA-1/SHA-256 IOC hash list. |
| `-DaysBack <N>` | Lookback window in days for time-bounded collectors (default 30). |
| `-Cleanup` | Find and remove previous secgurd output folders (requires typing `DELETE` to confirm). |
| `-MakeS1Paste` | Print a copy/paste-ready version for the SentinelOne remote shell. |
| `-Help` | Show usage and exit. |

### Examples

```powershell
# Full triage with an HTML report
.\secgurd.ps1 -Auto -HtmlReport

# Just persistence + processes + network
.\secgurd.ps1 -Modules 03,06,05

# 90-day lookback for a suspected long-dwell compromise, with IOC matching
.\secgurd.ps1 -Auto -DaysBack 90 -IOCHashes C:\ioc\badhashes.txt

# Clean up old collections
.\secgurd.ps1 -Cleanup
```

---

## The interactive menu

Launching without `-Auto` brings up a menu. **All modules start OFF** — you choose what to run.

| Command | Action |
|---------|--------|
| `1`–`14` | Toggle a module on/off |
| `a` / `n` | Select all / none |
| `qa` / `net` / `ps` | Presets (quick-assess / network / PowerShell) |
| `o` | Toggle: open output folder when done |
| `h` | Toggle: build + open the HTML report |
| `i` | IOC hashes — load from file `[f]`, paste `[p]`, list `[l]`, or turn off `[x]` |
| `l` | Toggle: show the loaded IOC hash list in the menu |
| `d` | Set the lookback window (days) |
| `s` | Make a copy/paste version for the SentinelOne shell |
| `r` | Run the selected modules |
| `?` | Help |
| `q` | Quit |

---

## IOC hash matching

Feed secgurd a list of known-bad hashes and it will hash real on-disk binaries in high-signal locations (Temp, AppData, Public, ProgramData, Downloads, Desktop) plus every running process image, and flag any match as a HIGH finding (written to `00_IOC_MATCHES.txt`).

- **Formats:** MD5 (32 hex), SHA-1 (40 hex), or SHA-256 (64 hex). Mix freely.
- **Delimiters:** one per line, or comma/space/semicolon/pipe separated. `#` comment lines are ignored.
- **Optional labels:** `44d88612...02f,Emotet` attaches a label shown on match.

```
# example IOC list
44d88612fea8a8f36de82e1278abb02f0000000000000000000000000000abcd,Emotet
a1b2c3d4e5f6...
```

Load it via `-IOCHashes C:\ioc\list.txt`, or interactively with the `i` menu command (file or paste). Free hash feeds (e.g. abuse.ch MalwareBazaar) work well — download to *your* box, point secgurd at the file.

---

## Output

Everything lands in a timestamped folder (auto-zipped):

```
secgurd_<HOST>_<timestamp>\
  00_INDEX.txt          file list + run metadata (host, user, admin, lookback, duration)
  00_SUMMARY.txt        findings summary
  00_TIMELINE.txt       chronological event merge
  00_HASHES.txt         SHA-256 of every output file (evidence integrity)
  00_IOC_MATCHES.txt    IOC hash matches (only if IOC list was loaded)
  report.html           single-file report (only with -HtmlReport)
  01_system_info.txt
  02_rdp_remote_access.txt
  03_remote_access_tools.txt
  ... (one .txt per collector)
```

The HTML report groups artifacts by module, color-codes findings by severity, and lets you click a finding to jump straight to the artifact it came from.

---

## Running on EDR-managed endpoints

Secgurd does the same things malware reconnaissance does — enumerate processes, read persistence keys, query WMI, dump event logs. So **EDR may flag or block it**, especially the `iex(irm)` one-liner (download-and-execute is a top behavioral trigger). This is expected; the fix is **authorization, not evasion**.

If you're authorized on the environment:

1. **Run it as a local file**, not the one-liner: `powershell -ExecutionPolicy Bypass -File .\secgurd.ps1`. A local script trips behavioral engines far less than `iex(irm)`.
2. **Allowlist it properly.** For an actively-updated tool, use a **path** or **code-signing-certificate** exclusion — *not* a hash exclusion, which breaks on every edit.
3. **Use your EDR's live-response / remote-script feature** — the sanctioned channel for running IR tooling on managed endpoints.

### SentinelOne remote shell

The S1 remote shell often can't paste, runs non-interactively, and chokes on download-and-run. Secgurd handles this:

- Run secgurd on your own box and press **`s`** (or use `-MakeS1Paste`). It prints a copy/paste-ready block (the whole tool wrapped in a here-string + invoke).
- Copy that block, paste it into the S1 Remote Shell, and the interactive menu appears there.

The script is "wrap-safe" (no internal here-strings), so this paste method works on every version without hand-editing.

---

## Safety & scope

- **Read-only.** Secgurd collects and reports. It does not remediate, quarantine, or modify the system. The single exception, `-Cleanup`, deletes only prior secgurd output folders and requires typing `DELETE` to confirm (and refuses to run unattended).
- **No exfiltration.** Nothing is sent anywhere. The only data that leaves the host is the evidence zip you collect.
- **Absence of findings is not proof of a clean host.** Auto-flagged findings are leads, not verdicts. Review the raw artifacts, and re-run with the right privileges if collectors show "error" badges.
- **Authorization required.** Only run secgurd on systems you are authorized to investigate.

---

## License & disclaimer

Provided as-is, for authorized security and incident-response use only. The authors assume no liability for misuse. Always operate within the scope of your authorization and applicable law.

---

*Slayer of threats. Keeper of truth.*
