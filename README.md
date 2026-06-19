# Secgurd

**DFIR triage toolkit for remote Windows machine analysis**

```
 ᚱ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ᚦ
      ╔═╗ ███████╗███████╗ ██████╗ ██████╗ ██╗   ██╗██████╗ ██████╗
      ║ ╠═██╔════╝██╔════╝██╔════╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗══════╲
(o)═══╣ ║ ███████╗█████╗  ██║     ██║  ███╗██║   ██║██████╔╝██║  ██║═══════▶
      ║ ╠═╚════██║██╔══╝  ██║     ██║   ██║██║   ██║██╔══██╗██║  ██║══════╱
      ╚═╝ ███████║███████╗╚██████╗╚██████╔╝╚██████╔╝██║  ██║██████╔╝
          ╚══════╝╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝

                ≋ Slayer of threats. Keeper of truth. ≋
                    ᛊ  F O R E N S I C   T R I A G E  ᛊ
 ᚦ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ᚱ
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
| 10 | Browser & creds | **per-user browser history + URL analysis (Chrome/Edge/Firefox)**, history file paths, `.ssh`, `.aws`, credential files |
| 11 | LOLBins | certutil, mshta, rundll32, regsvr32 usage |
| 12 | AmCache / ShimCache | execution-artifact locations |
| 13 | Prefetch | `.pf` files, last-run times |
| 14 | Named pipes | active pipes, C2 detection |

**Detection & analysis:**

- **Findings engine** — auto-flags high-signal indicators (HIGH / MED / INFO) as it runs: WMI event consumers, IFEO debugger hijacks, accessibility backdoors, encoded PowerShell, suspicious parent→child process chains, services/tasks running from writable paths, unquoted service paths, rogue remote-access tools, Defender exclusions on temp paths, and more.
- **Rogue RMM detection** — hunts ~18 remote-access tool families (ScreenConnect/ConnectWise, AnyDesk, TeamViewer, Atera, Splashtop, MeshCentral, NetSupport, etc.) and flags suspicious context (writable-path installs, ScreenConnect instance folders + relay host).
- **Browser history URL analysis** — extracts URLs from every user's Chrome, Edge, and Firefox history (read directly from the history DBs plus their `-wal` sidecars, lock-safe, no SQLite engine needed) and flags suspicious ones live as it runs, color-coded by threat level: direct executable/script downloads, raw-IP hosts, known file-drop/C2/exfil infrastructure (Discord CDN, pastebin/raw, transfer.sh, anonfiles, mega, ngrok, `*.workers.dev`, telegram, …), URL shorteners, high-abuse TLDs, punycode hosts, and remote-access-tool references. One output folder per user. (URLs only — per-visit timestamps aren't decoded, to stay dependency-free; each profile's DB last-write time is shown in UTC as coarse timing context.)
- **Local IOC hash matching** — match on-disk binaries against your own list of known-bad MD5 / SHA-1 / SHA-256 hashes. Fully offline; no API key, no third-party disclosure.
- **Targeted find / scoping** — point a run at a single known artifact (`-Find SmartPDF` or the `f` menu option) and every output is reduced to just the items that name, point at, or are signed by that string — across tasks, run keys, services, processes, files and findings. Case-insensitive.
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
OR
Invoke-Expression (Invoke-RestMethod "https://raw.githubusercontent.com/SicksSens3/secgurd/main/secgurd.ps1?v=$(Get-Random)")
```

> The `?v=$(Get-Random)` busts GitHub's ~5-minute raw cache so you always get the latest. **Note:** the download-and-execute pattern of `iex(irm)` is frequently flagged by EDR. For managed endpoints, prefer the file-based run above. See **Running on EDR-managed endpoints** below.

### One-liner for cleanup

```powershell
Remove-Item "$env:TEMP\secgurd*" -Recurse -Force -ErrorAction SilentlyContinue
```

> To check after cleanup run `Get-ChildItem "$env:TEMP" -Filter "secgurd*" -ErrorAction SilentlyContinue; Get-ChildItem "$env:TEMP" -Include "communitysavedIOCS.txt","manualIOCS.txt" -ErrorAction SilentlyContinue`.

---

## Usage

```
secgurd.ps1 [-Auto] [-Modules 01,03,06] [-OutputPath <dir>] [-NoBanner]
            [-OpenWhenDone] [-HtmlReport] [-WithOwners] [-WithSignatures]
            [-WithTaskInfo] [-IOCHashes <file>] [-DaysBack <N>] [-Find <string>]
            [-Cleanup] [-MakeS1Paste] [-Help]
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
| `-WithTaskInfo` | Resolve run times (LastRun/NextRun/LastResult) for **all** scheduled tasks incl. the hundreds of built-in `\Microsoft\*` ones. Off by default — those per-task Task Scheduler calls can take many minutes; without it, run times are resolved only for non-Microsoft tasks (all tasks are still listed). |
| `-IOCHashes <file>` | Match on-disk binaries against an MD5/SHA-1/SHA-256 IOC hash list. |
| `-DaysBack <N>` | Lookback window in days for time-bounded collectors (default 30). |
| `-Find <string>` | Scope **all** output to lines/items containing `<string>` (case-insensitive) — see [Targeted find](#targeted-find--scoping-a-run-to-one-artifact). |
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

# Scope an entire run to one known-bad artifact (e.g. the "SmartPDF" bundler):
# every file keeps only the tasks, run keys, services, processes and paths that mention it
.\secgurd.ps1 -Auto -Find SmartPDF

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
| `f` | Find — scope all output to a name/string (enter a term, or blank to clear) |
| `d` | Set the lookback window (days) |
| `p` | Pastable version for remote shells (single / chunked / compressed) |
| `r` | Run the selected modules |
| `?` | Help |
| `q` | Quit |

---

## IOC hash matching

Secgurd matches real on-disk binaries (in high-signal locations like Temp, AppData, Public, ProgramData, Downloads, Desktop, plus every running process image) against known-bad hashes. There are **two separate sources**, and matches are labeled by which one they came from:

**1. Community list (`communitysavedIOCS.txt`) — auto-loaded, shared, version-controlled.**
This file lives in the repo next to `secgurd.ps1` and is **loaded automatically** on every run, no flags needed. Update it with `git pull` and your runs use the latest community hashes. It's meant as the curated, team-shared baseline.

**2. Hashes you add — case-specific, kept separate.**
Provide your own list via `-IOCHashes C:\path\list.txt` or the interactive `i` menu (file or paste). These never touch the community file, so you can always tell *what you added* from *what was already saved*.

When both are present, secgurd matches against **community hashes + the ones you added**, and writes results to two separate files:

- `00_IOC_MATCHES_community.txt` — hits from the community list
- `00_IOC_MATCHES_manual.txt` — hits from hashes you added

Each finding is tagged `[community]` or `[you added]`.

**Hash formats:** MD5 (32 hex), SHA-1 (40 hex), or SHA-256 (64 hex) — mix freely. One per line, or comma/space/semicolon/pipe separated. `#` comment lines ignored. An optional `,label` after a hash is shown on a match:

```
44d88612fea8a8f36de82e1278abb02f0000000000000000000000000000abcd,Emotet
a1b2c3d4e5f6...
```

Everything is **fully offline** — no API key, no internet on the target. Hashes ride along in the repo (via `git pull`) or are supplied by you.

### Keeping the community list fresh automatically

The repo includes a GitHub Action (`.github/workflows/refresh-iocs.yml`) that, once a day, fetches a free public malware-hash feed (abuse.ch MalwareBazaar) **in GitHub's cloud** and commits the refreshed `communitysavedIOCS.txt` back to the repo. Your endpoints never touch the internet — only GitHub does the fetching. Then your next `git pull` picks up the new hashes. You can also trigger it manually from the repo's **Actions** tab ("Run workflow").

---

## Targeted find — scoping a run to one artifact

Sometimes you already know *what* you're hunting — a named bundler, a dropper filename, a rogue signer — and you don't want to wade through every benign task and registry value to find it. `-Find` (or the `f` menu option) scopes the **entire run** to a single string.

```powershell
# A known trojan/bundler "SmartPDF" is on the box — show only what touches it
.\secgurd.ps1 -Auto -Find SmartPDF
```

With a find filter active, every artifact file keeps only the lines that contain the string — **plus the section header above them** — and drops sections with no hits entirely. So instead of *all* scheduled tasks, you see only the task named after / running `SmartPDF`; instead of *all* run keys, only the value pointing at it; and the same for services, processes, loaded DLLs, file paths, and so on. The auto-flagged **findings** and the **event timeline** are filtered the same way, so `00_SUMMARY.txt` shows only the related leads.

- **Case-insensitive.** `-Find smartpdf`, `SmartPDF`, and `SMARTPDF` all match the same items — capitalization never causes a miss.
- **Matches anywhere on the line** — filename, full path, signer, service name, command line, registry value name or data.
- **Set it any way:** the `-Find <string>` flag (works with `-Auto`, `-Modules`, and the paste versions), or interactively with the `f` menu command (enter a term to scope, or leave it blank to clear and collect everything again).
- The active filter is recorded in `00_INDEX.txt` and `00_SUMMARY.txt` so the scope of the collection is always documented. `00_SUMMARY.txt` also lists, under a **FILES WITH MATCHES** section, exactly which artifacts contained the term and how many instances each had — so you go straight to the files that matter instead of opening dozens of "(no matches…)" files.
- As it runs, each collector's line shows how many matching items it found (e.g. `03_scheduled_tasks.txt … 3 instances found`).

> Find is a **scoping** tool, not a detector — it narrows what's shown, it doesn't decide what's malicious. Clear it (blank `f`, or omit `-Find`) for a full-coverage sweep.

---

## Output

Everything lands in a timestamped folder (auto-zipped):

```
secgurd_<HOST>_<timestamp>\
  00_INDEX.txt          file list + run metadata (host, user, admin, lookback, duration)
  00_SUMMARY.txt        findings summary
  00_TIMELINE.txt       chronological event merge
  00_HASHES.txt         SHA-256 of every output file (evidence integrity)
  00_IOC_MATCHES_community.txt   community IOC matches (if community list present)
  00_IOC_MATCHES_manual.txt      your IOC matches (if you supplied a list)
  report.html           single-file report (only with -HtmlReport)
  01_system_info.txt
  02_rdp_remote_access.txt
  03_remote_access_tools.txt
  10_browser_history.txt          per-user/browser summary + flagged URLs
  10_browser_history\             one subfolder per user (browser history detail)
    <user>\Chrome_Default.txt        flagged URLs + all unique URLs for that profile
    <user>\Edge_Default.txt
    <user>\Firefox_<profile>.txt
  ... (one .txt per collector)
```

Per-user browser-history detail is written under `10_browser_history\<user>\`, one file per browser profile. These subfolder files are included in `00_INDEX.txt` and the `00_HASHES.txt` manifest (both recurse), and in the zip.

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

- Run secgurd on your own box and press **`p`** (or use `-MakeS1Paste`). It offers a single full-text paste, a chunked plain-text paste for size-limited shells, or a compressed single paste — each a copy/paste-ready block (the whole tool wrapped in a here-string + invoke).
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
