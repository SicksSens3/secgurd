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

- **One file, no external dependencies.** Pure PowerShell 5.1+, no modules to install, nothing to compile.
- **Read-only by default.** Collects and reports; it doesn't change the system (the only write action, `-Cleanup`, requires explicit confirmation).
- **Offline-friendly.** No internet required. No data leaves the host except the evidence zip you collect.
- **Self-contained output.** Timestamped folder + auto-zipped archive.

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
| 03 | Persistence | run keys, **RunMRU / ClickFix paste-and-run**, tasks, services, WMI, IFEO, Winlogon, AppInit, accessibility hijacks, **rogue RMM tools** |
| 04 | PowerShell artifacts | history, transcripts, 4104 script-block logs |
| 05 | Network | connections, DNS cache, ARP, shares, firewall rules, **threat-intel host matches (DNS cache vs feeds)** |
| 06 | Processes | process tree, command lines, unsigned DLLs |
| 07 | Filesystem | temp executables, ADS, recently-modified files |
| 08 | Event logs | account changes, log clearing, log status |
| 09 | Software & Defender | installed apps, **per-user AppData / all-hive PUP & clone-browser detection**, patches, Defender status & exclusions |
| 10 | Browser & creds | **per-user browser history + URL analysis (Chrome/Edge/Firefox)**, **squat-domain watchlist cross-ref**, history file paths, `.ssh`, `.aws`, credential files |
| 11 | LOLBins | certutil, mshta, rundll32, regsvr32 usage |
| 12 | AmCache / ShimCache | execution-artifact locations |
| 13 | Prefetch | `.pf` files, last-run times |
| 14 | Named pipes | active pipes, C2 detection |

**Detection & analysis:**

- **Findings engine** — auto-flags high-signal indicators (HIGH / MED / INFO) as it runs: WMI event consumers, IFEO debugger hijacks, accessibility backdoors, encoded PowerShell, suspicious parent→child process chains, services/tasks running from writable paths, unquoted service paths, rogue remote-access tools, Defender exclusions on temp paths, and more.
- **WMI subscription triage (noise-suppressed)** — WMI `FilterToConsumerBindings` are classic fileless persistence, but the built-in **SCM Event Log** subscription (and monitoring agents like SCOM) ship on healthy boxes and would otherwise fire HIGH on *every* run. Secgurd auto-suppresses bindings whose consumer is an `NTEventLogEventConsumer` (log-only, can't execute code) plus an editable name allowlist (`$script:WmiBenignNames`), and only raises **HIGH** for the *unrecognized* bindings — especially the `CommandLine`/`ActiveScript` consumers actually used for persistence. Suppressed ones are still listed in `03_wmi_persistence.txt` for transparency.
- **Rogue RMM detection** — hunts ~18 remote-access tool families (ScreenConnect/ConnectWise, AnyDesk, TeamViewer, Atera, Splashtop, MeshCentral, NetSupport, etc.) and flags suspicious context (writable-path installs, ScreenConnect instance folders + relay host).
- **RunMRU / ClickFix triage** — reads the Win+R Run-dialog history (`HKCU\...\Explorer\RunMRU`) from **every user hive, including logged-off users' `NTUSER.DAT`** (mounted with admin), most-recent-first. "ClickFix" / paste-and-run lures (fake CAPTCHA, "verify you're human", "fix this error") get a user to paste an obfuscated one-liner into Run; because it is user-driven it never appears in the autorun keys, so it is often the only registry trace of initial access. Flags HIGH on interpreter / fetch / decode / hidden patterns (`powershell -w hidden`, `mshta`, `curl|iex`, `certutil`, `FromBase64String`, `http(s)://`, …) and MED on unusually long pasted commands.
- **Browser history URL analysis** — extracts URLs from every user's Chrome, Edge, and Firefox history (read directly from the history DBs plus their `-wal` sidecars, lock-safe, no SQLite engine needed) and flags suspicious ones live as it runs, color-coded by threat level: direct executable/script downloads, **raw *public*-IP hosts** (private/LAN IPs like `10.x` / `192.168.x` are ignored), known file-drop/C2/exfil infrastructure (Discord CDN, pastebin/raw, transfer.sh, anonfiles, mega, ngrok, `*.workers.dev`, telegram, …), URL shorteners, high-abuse TLDs, punycode hosts, and remote-access-tool references. One output folder per user. To keep the post-run **FINDINGS list uncluttered, individual browser URLs are not added to it** (a few HIGH/MED are echoed live during the scan for awareness, and a single aggregate finding points you to the files) — but **every** flagged URL of every severity is written in full to the per-user files. (URLs only — per-visit timestamps aren't decoded, to stay dependency-free; each profile's DB last-write time is shown in UTC as coarse timing context.)
- **Per-user PUP / clone-browser detection** — walks every user's AppData (Local/Roaming/LocalLow) and every user registry hive — including **logged-off users' `NTUSER.DAT`**, which it mounts then unloads — to catch adware / potentially-unwanted apps that install per-user and skip Add/Remove Programs. Flags the Chromium-"clone" layout (`<App>\Application\<ver>\...\Installer\setup.exe`) and updater/dock families (`<App>` + `<App>Updater`/`AutoUpdate`/`Dock`), plus self-registered `Software\<Name>` keys carrying an `UninstallString`/`InstallerProgress` value. Catches infections sitting in **other** users' profiles that a current-user-only scan misses (mounting logged-off hives needs admin).
- **Local IOC hash matching** — match on-disk binaries against your own list of known-bad MD5 / SHA-1 / SHA-256 hashes. Fully offline; no API key, no third-party disclosure.
- **Targeted find / scoping** — point a run at a single known artifact (`-Find SmartPDF` or the `f` menu option) and every output is reduced to just the items that name, point at, or are signed by that string — across tasks, run keys, services, processes, files and findings. Case-insensitive.
- **Event timeline** — chronological merge of logons, log clears, new services, scheduled tasks, and recent file modifications.
- **SHA-256 evidence manifest** — hashes every output file for chain-of-custody / tamper evidence.

**Output:**

- Timestamped output folder, auto-zipped.
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
Remove-Item "$env:TEMP\secgurd*", "$env:TEMP\communitysavedIOCS.txt", "$env:TEMP\communitysavedMALURLS.txt", "$env:TEMP\squat_domains.txt", "$env:TEMP\manualIOCS.txt", "$env:TEMP\secgurd_s1_*.txt" -Recurse -Force -ErrorAction SilentlyContinue
```

> This clears everything secgurd (or the compressed S1 paste) can leave in `%TEMP%`: the `secgurd_<host>_<timestamp>` output folder, the unpacked `secgurd.ps1`, the S1 paste files, and the IOC-hash / malicious-URL lists. `"$env:TEMP\secgurd*"` already covers `secgurd.ps1` and the `secgurd_s1_*.txt` files, so those entries are belt-and-suspenders.
>
> To check after cleanup run `Get-ChildItem "$env:TEMP" -Filter "secgurd*" -ErrorAction SilentlyContinue; Get-ChildItem "$env:TEMP" -Include "communitysavedIOCS.txt","communitysavedMALURLS.txt","squat_domains.txt","manualIOCS.txt" -ErrorAction SilentlyContinue`.

---

## Usage

```
secgurd.ps1 [-Auto] [-Modules 01,03,06] [-OutputPath <dir>] [-NoBanner]
            [-OpenWhenDone] [-WithOwners] [-WithSignatures] [-WithTaskInfo]
            [-IOCHashes <file>] [-DaysBack <N>] [-Find <string>]
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
| `-WithOwners` | Resolve process owners (slower; off by default — can stall on domain controllers). |
| `-WithSignatures` | Verify Authenticode signatures of service binaries / loaded DLLs (slower; can stall offline). |
| `-WithTaskInfo` | Resolve run times (LastRun/NextRun/LastResult) for **all** scheduled tasks incl. the hundreds of built-in `\Microsoft\*` ones. Off by default — those per-task Task Scheduler calls can take many minutes; without it, run times are resolved only for non-Microsoft tasks (all tasks are still listed). |
| `-IOCHashes <file>` | Match on-disk binaries against an MD5/SHA-1/SHA-256 IOC hash list (your own/manual list). |
| `-CommunityIOCHashes <file>` | Explicit path to the community hash list (otherwise auto-found next to the script). |
| `-CommunityMalUrls <file>` | Explicit path to the community malicious-URL list (otherwise auto-found next to the script). |
| `-SquatDomains <file>` | Explicit path to the openSquat squat-domain watchlist (otherwise auto-found next to the script). |
| `-DaysBack <N>` | Lookback window in days for time-bounded collectors (default 30). |
| `-Find <string>` | Scope **all** output to lines/items containing `<string>` (case-insensitive) — see [Targeted find](#targeted-find--scoping-a-run-to-one-artifact). |
| `-Cleanup` | Remove **all** secgurd artifacts from `%TEMP%` — the script itself, output folders + zips, S1 paste files, and the IOC / malicious-URL / squat-domain / manual lists (requires typing `DELETE` to confirm). Also available as the `cleanup` menu command. |
| `-MakeS1Paste` | Copy the compressed (gzip+Base64) "everything" paste (script + IOC / malicious-URL / squat-domain lists) for the remote shell. For the script-only / lists-only variants, use the interactive `p` menu. |
| `-Help` | Show usage and exit. |

### Examples

```powershell
# Full triage, no menu
.\secgurd.ps1 -Auto

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
| `deps` | Dependencies sub-menu — manage all three external data lists in one place: **IOC hashes**, **malicious URLs** (URLhaus), and **squat domains** (openSquat). Pick `[1]`/`[2]`/`[3]` to load from file `[f]`, paste `[p]`, list `[l]`, or toggle `[x]`. |
| `f` | Find — scope all output to a name/string (enter a term, or blank to clear) |
| `d` | Set the lookback window (days) |
| `p` | Pastable (compressed gzip+Base64) version for remote shells — `[1]` everything, `[2]` dependency lists only (IOC + URL + squat), `[3]` script only |
| `r` | Run the selected modules |
| `?` | Help |
| `q` | Quit |
| `cleanup` | Remove **all** secgurd artifacts from `%TEMP%` (script, output folders + zips, S1 paste files, IOC / malicious-URL / squat-domain / manual lists) — type-to-confirm, then exit. Same as `-Cleanup`. |

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

## Community malicious-URL matching

Alongside the hash list, secgurd carries a community **malicious-URL** list (`communitysavedMALURLS.txt`) built from the free abuse.ch **[URLhaus](https://urlhaus.abuse.ch/)** feed — URLs currently serving malware. Like the hash list it is **auto-loaded** on every run from the file next to `secgurd.ps1` (no flags needed; use `-CommunityMalUrls <file>` to point at an explicit path). In the interactive menu the **`u`** command mirrors `i`: load from a file `[f]`, paste `[p]`, list `[l]`, or toggle matching on/off `[x]`.

**Where it's used.** Module 10 (Browser & creds) extracts every URL from Chrome/Edge/Firefox history and triages it. Any visited URL that appears on the feed — by **exact URL** or by **host** (payload URLs rotate their paths, so the host is the durable signal) — is flagged **HIGH** with reason *"listed on the community malicious-URL feed (URLhaus)"*. That flag then feeds the end-of-run **browser-alert correlation**, so a hit that also matches a file on disk is escalated in `00_BROWSER_ALERTS.txt`. Module 05 also matches the machine's **DNS client cache** host set against this feed (see *DNS-cache intel matching* below) — catching **any** process's callouts, not just browser traffic.

**Curated watchlist (hand-maintained).** Separate from the auto-refreshed feed, `secgurd.ps1` carries two small lists you edit directly (near `Test-SuspiciousUrl`) to pin things you keep seeing:

- `$script:WatchlistHosts` — specific known-bad domains (e.g. `rdxgo.click`). A visited host that equals one, or is a subdomain of it (`foo.rdxgo.click`), is flagged **HIGH**.
- `$script:WatchlistTlds` — abuse-prone TLDs on top of the built-in list (e.g. `beer`). Any host under one is flagged **MED**.

These are checked right alongside the built-in URL heuristics, so no feed refresh or flags are needed — just add a line to the array.

**Format:** one `<url>,<label>` per line. The label (threat/tags from URLhaus) is comma-free, so the URL is everything before the **last** comma (URLs themselves can contain commas). `#` comment lines are ignored:

```
http://185.220.101.45/win/update.exe,LummaStealer
https://evil-cdn.example/a,b,c/payload,CobaltStrike
```

### Keeping the malicious-URL list fresh automatically

The GitHub Action `.github/workflows/refresh-malurls.yml` runs daily (06:30 UTC, just after the hash refresh) and manually from the **Actions** tab. It fetches the URLhaus "online" export **in GitHub's cloud**, keeps the URL plus its threat/tags label, and commits the refreshed `communitysavedMALURLS.txt` back to the repo. Your next `git pull` picks up the new URLs — the endpoints never touch the internet. It also rides along inside the compressed SentinelOne paste, so an air-gapped box gets the current URL feed too.

**The feed is aggressively filtered to stay small.** The raw URLhaus export is ~15k URLs, but ~87% of them are things secgurd **already flags on its own heuristics** — so listing them adds nothing. The Action drops every entry the tool would already catch (direct payload downloads like `.exe`/`.dll`/`.ps1`, raw-IP hosts, GitHub-hosted content, known C2/file-drop infrastructure, URL shorteners, high-abuse TLDs, punycode), keeps only URLs added in the last **90 days**, and emits **one representative URL per host** (module 10 matches on host too, so extra URLs on an already-listed host are redundant). What survives — a few hundred hosts — is the real value-add: confirmed-malicious sites on *otherwise normal-looking* domains that the heuristics would miss. Tune the window via `MAXAGE_DAYS` in the workflow.

---

## Squat-domain watchlist (openSquat)

A third auto-loaded list, `squat_domains.txt`, holds **look-alike / typosquat domains impersonating your own brand**. It's built by [openSquat](https://github.com/atenreiro/opensquat), which scans newly-registered domains for typosquats (`exmaple-brand.com`), homoglyphs, and combosquats (`example-brand-login.com`) of the terms you list in **`keywords.txt`** at the repo root. Like the other lists it is **auto-loaded** from beside `secgurd.ps1` (or via `-SquatDomains <file>`), rides along in the compressed S1 paste, and is cleaned up by the cleanup command.

**Where it's used.** Module 10 checks **every browser-history host and every download-origin host** (module 03 BITS jobs + module 07 `Zone.Identifier` streams) against the watchlist — an exact host match or any subdomain of a watchlisted entry. A hit raises a **HIGH** finding (*"matches openSquat squat-domain watchlist"*), is written to **`10_squat_watchlist.txt`** (listing user / browser / URL / matched domain), and flows into the end-of-run `00_BROWSER_ALERTS.txt` correlation. Matches are deduped per user+host so a heavily-visited squat host is reported once. Module 05 additionally matches the **DNS client cache** against the watchlist (see below), so a squat domain resolved by *any* process — not just a browser — is caught.

### DNS-cache intel matching (module 05)

Beyond browser history, secgurd cross-references the machine's **DNS client cache** (`Get-DnsClientCache`) against both the URLhaus host set and the squat watchlist, writing `05_intel_host_matches.txt`. A cached resolution of a listed host means *something* on the box looked it up — regardless of which process or browser. If that host's resolved IP is **also present in an active TCP connection**, the match is annotated as a **live session** to known-bad infrastructure (the strongest signal short of a payload on disk). Each hit is a **HIGH** finding. This reuses data module 05 already collects, so it adds no meaningful scan time.

**Setup:** edit `keywords.txt` with your organisation's real brand/product terms (one per line, just the word — not the TLD; `#` comments and blank lines ignored). The starter file ships with placeholders you must replace.

### Keeping the squat watchlist fresh automatically

The GitHub Action `.github/workflows/refresh-squat-domains.yml` runs daily (06:15 UTC) and manually from the **Actions** tab. It installs openSquat in GitHub's cloud, runs it over `keywords.txt` in **free mode** (confidence level 1 — no API key needed), and commits the refreshed `squat_domains.txt` back to the repo only if it changed. Your next `git pull` picks up the new domains — the endpoints never touch the internet.

**Kept lean for the paste.** `squat_domains.txt` rides inside the compressed SentinelOne paste, which has to stay small, so the Action prunes and caps it: it drops domains secgurd **already flags on its own heuristics** (punycode hosts, high-abuse TLDs) so the watchlist never duplicates a built-in detection, then de-dupes, sorts, and hard-caps the count (500 — a backstop; openSquat overwrites the file each run, so a large result means the keywords are too generic). At runtime the reverse guard also holds: if a visited host is on the squat list **and** trips a built-in heuristic, only the squat alert fires (it's the more specific "impersonates your brand" signal), and repeat visits to the same host collapse to one correlation entry — so no double-alerting in `00_BROWSER_ALERTS.txt`.

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
  01_system_info.txt
  02_rdp_remote_access.txt
  03_remote_access_tools.txt
  03_runmru_clickfix.txt          RunMRU / Win+R history (ClickFix paste-and-run flags)
  09_appdata_app_installs.txt     per-user AppData app installs (PUP / clone-browser flags)
  09_user_hive_software.txt       self-registered software across all user hives (incl. logged-off)
  10_browser_history.txt          per-user/browser summary + flagged URLs
  10_browser_history\             one subfolder per user (browser history detail)
    <user>\Chrome_Default.txt        flagged URLs + all unique URLs for that profile
    <user>\Edge_Default.txt
    <user>\Firefox_<profile>.txt
  ... (one .txt per collector that produced data)
```

Per-user browser-history detail is written under `10_browser_history\<user>\`, one file per browser profile. These subfolder files are included in `00_INDEX.txt` and the `00_HASHES.txt` manifest (both recurse), and in the zip.

**Empty / no-data collectors are skipped.** A collector **does not write a file** when it produces no real data — only section headers, `(none found)` placeholders, a `(no matches for '…')` result under `-Find`, or an error. This keeps the folder from filling with empty artifacts (e.g. no `RunMRU` file when there are no RunMRU entries). A collector that produces **actual information is always kept**, even with no flagged findings — e.g. the scheduled-tasks list or a user's browsing history. `00_INDEX.txt` reports how many collectors were skipped for no data and lists any collector **errors** (logged centrally there instead of as per-file `ERROR` artifacts). The `00_*` summaries are always written.

---

## Running on EDR-managed endpoints

Secgurd does the same things malware reconnaissance does — enumerate processes, read persistence keys, query WMI, dump event logs. So **EDR may flag or block it**, especially the `iex(irm)` one-liner (download-and-execute is a top behavioral trigger). This is expected; the fix is **authorization, not evasion**.

If you're authorized on the environment:

1. **Run it as a local file**, not the one-liner: `powershell -ExecutionPolicy Bypass -File .\secgurd.ps1`. A local script trips behavioral engines far less than `iex(irm)`.
2. **Allowlist it properly.** For an actively-updated tool, use a **path** or **code-signing-certificate** exclusion — *not* a hash exclusion, which breaks on every edit.
3. **Use your EDR's live-response / remote-script feature** — the sanctioned channel for running IR tooling on managed endpoints.

### SentinelOne remote shell

The S1 remote shell often can't paste, runs non-interactively, and chokes on download-and-run. Secgurd handles this:

- Run secgurd on your own box and press **`p`**. Every option is a single compressed (gzip+Base64) block that auto-**compacts** a copy of the source before packing (see below), so the paste is as small as possible:
  - **[1] Everything** — script + all dependency lists (IOC hashes + malicious URLs + squat domains), in one block.
  - **[2] Dependency lists only** — just `communitysavedIOCS.txt` / `communitysavedMALURLS.txt` / `squat_domains.txt`.
  - **[3] Script only** — just `secgurd.ps1` (smallest block).
- **If [1] is too big** for your shell's paste limit (the community IOC list is the bulk), paste **[2]** first, then **[3]**: [2] drops the lists into `%TEMP%`, and [3] unpacks `secgurd.ps1` and runs it — the wrapper picks up whatever lists are already in `%TEMP%`, so IOC / URL / squat matching works. (You can also just paste **[3]** on its own to run the script with no dependency lists.)
- Copy the block, paste it into the S1 Remote Shell, press Enter, and the interactive menu appears there.

Each option runs secgurd **in the current shell as an in-memory scriptblock** — never a child `powershell.exe`. This matters in the S1 shell: it repaints the banner/menu on the first Enter (a child process doesn't), and it runs even when the endpoint's execution policy has script files disabled (execution policy only restricts `.ps1` *files*, not scriptblocks). The script is also "wrap-safe" (no internal here-strings), so the paste can't break itself.

**Auto-compaction.** Rather than maintaining a second minified script, the compressed paste shrinks a *copy* of secgurd's own source on the fly, right before gzip+Base64, via `Compress-Source`. It runs three behavior-preserving passes over the source, using PowerShell's own tokenizer so strings are never touched: (1) strip all comments, (2) alias common cmdlets in command position (`Get-ChildItem`->`gci`, `Where-Object`->`?`, `ForEach-Object`->`%`, `Select-Object`->`select`, `Get-ItemProperty`->`gp`, `Format-Table`->`ft`, ...), and (3) remove indentation and blank lines. It **fails safe** — on any tokenizer error it returns the source unchanged, so compaction can never produce a broken paste. Variable renaming is intentionally **not** done: variable names appear inside expandable strings and `$script:` scope / `param()` binding make an automatic rename unsafe, and gzip already collapses repeated names so shortening them saves almost nothing after compression (comments and whitespace are the real win). `secgurd.ps1` stays the single, human-readable source of truth; only the pasted payload is compacted. The run prints the before/after character count.

---

## Safety & scope

- **Read-only.** Secgurd collects and reports. It does not remediate, quarantine, or modify the system. The single exception, `-Cleanup` (or the `cleanup` menu command), deletes only secgurd's own artifacts under `%TEMP%` and requires typing `DELETE` to confirm (and refuses when it can't read that confirmation).
- **No exfiltration.** Nothing is sent anywhere. The only data that leaves the host is the evidence zip you collect.
- **Absence of findings is not proof of a clean host.** Auto-flagged findings are leads, not verdicts. Review the raw artifacts, and re-run with the right privileges if collectors show "error" badges.
- **Authorization required.** Only run secgurd on systems you are authorized to investigate.

---

## License & disclaimer

Provided as-is, for authorized security and incident-response use only. The authors assume no liability for misuse. Always operate within the scope of your authorization and applicable law.

---

*Slayer of threats. Keeper of truth.*
