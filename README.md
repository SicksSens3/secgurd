# Secgurd

**DFIR triage toolkit for remote Windows machine analysis**

```
 ᚱ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ᚦ
      ╔═╗ ███████╗███████╗ ██████╗ ██████╗ ██╗   ██╗██████╗ ██████╗
      ║ ╠═██╔════╝██╔════╝██╔════╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗══════╲
(o)═══╣ ║ ███████╗█████╗  ██║     ██║  ███╗██║   ██║██████╔╝██║  ██║═══════>
      ║ ╠═╚════██║██╔══╝  ██║     ██║   ██║██║   ██║██╔══██╗██║  ██║══════╱
      ╚═╝ ███████║███████╗╚██████╗╚██████╔╝╚██████╔╝██║  ██║██████╔╝
          ╚══════╝╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝

            ≋ A shield to his friends, a terror to his foes. ≋
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
- **EDR-safe artifacts.** Live indicators pulled from a compromised host (encoded commands, malicious URLs, ClickFix/RunMRU one-liners, WMI script payloads) are *defanged* when written — `hxxp://` for URLs, a middle-dot inside high-signal tokens — so an on-host EDR (SentinelOne/Sophos) won't quarantine the evidence and kill the scan mid-run. Detection always runs on the raw value first; only the copy on disk is defanged, and it stays fully readable.

---

## Why "Secgurd"?

Sigurd is a legendary hero of Norse and Germanic myth — the dragon-slayer who faced Fafnir with precision and courage. Secgurd carries that spirit forward: a tool to help analysts **hunt, detect, and eliminate** malicious activity in modern Windows environments. (And yes — there's a dragon in here somewhere. Try running it with no modules selected.)

---

## Features

**Collection — 14 modules, 40+ collectors:**

| # | Module | Collects |
|---|--------|----------|
| 01 | System info | OS, build, uptime, domain, environment |
| 02 | Users & sessions | accounts (**with SIDs**), **all-profiles SID→account map (local + domain)**, logons, **RDP / remote-access artifacts** |
| 03 | Persistence | run keys, **RunMRU / ClickFix paste-and-run** (index + **verbatim full command text**), tasks, services, WMI, IFEO, Winlogon, AppInit, accessibility hijacks, **rogue RMM tools** |
| 04 | PowerShell artifacts | history, transcripts, 4104 script-block logs |
| 05 | Network | connections, DNS cache, ARP, shares, firewall rules, **threat-intel host matches (DNS cache vs feeds)** |
| 06 | Processes | process tree, command lines, unsigned DLLs, **masquerade / drop-path / suspicious-command-line flags** |
| 07 | Filesystem | temp executables, ADS, recently-modified files |
| 08 | Event logs | account changes, log clearing, log status |
| 09 | Software & Defender | installed apps, **per-user AppData / all-hive PUP & clone-browser detection**, patches, Defender status & exclusions |
| 10 | Browser & creds | **per-user browser history + URL analysis (Chrome/Edge/Firefox)**, **squat-domain watchlist cross-ref**, extensions, **notification / Web Push permissions**, history file paths, `.ssh`, `.aws`, credential files |
| 11 | LOLBins | certutil, mshta, rundll32, regsvr32 usage (4688), **+ cred-dump / hive-theft / obfuscation command-line flags** |
| 12 | AmCache / ShimCache | execution-artifact locations |
| 13 | Prefetch | `.pf` files, last-run times |
| 14 | Named pipes | active pipes, C2 detection |

**Detection & analysis:**

- **Findings engine** — auto-flags high-signal indicators (HIGH / MED / INFO) as it runs: WMI event consumers, IFEO debugger hijacks, accessibility backdoors, encoded PowerShell, suspicious parent→child process chains, services/tasks running from writable paths, unquoted service paths, rogue remote-access tools, Defender exclusions on temp paths, and more. **Defender posture is judged in context**: “real-time protection is off” is routine on a host where SentinelOne (or any third-party AV/EDR) owns protection, and alarming on a bare one — so secgurd first establishes whether anything else is actually protecting the box, using three independent signals (Defender’s own `AMRunningMode`, which reports *Passive* / *SxS Passive* / *EDR Block* when it steps back; Security Center’s `AntiVirusProduct` registry, workstation SKUs only; and a running AV/EDR service, which covers Server where Security Center doesn’t exist). With another product present, Defender being off is **INFO** and stated plainly. With **nothing** else detected it is **HIGH** — *“this host may be unprotected”* — which is the case actually worth waking up for, and the one a blanket HIGH on every managed endpoint trains you to ignore. Attacker-added **exclusions** and threat-detection history are flagged at full severity either way; those matter whichever product is primary.
- **Grouped menu and grouped findings, one taxonomy** — the collection modules are shown under six headings (System & identity · Persistence & scripting · Network · Host state · Browser & credentials · Execution traces), three across, so the menu is no taller than the old flat list but each block now says what it is *for*. Every group is a **contiguous id range**, so the ids read `01 → 14` straight down without a single module being renumbered. Ranges toggle: `06-09` selects all of Host state; `03,07,10` still works, and a terminal under ~96 columns falls back to one module per row rather than wrapping. `00_SUMMARY.txt` and the on-screen recap use **the same six headings**, so a finding files itself under the heading its module sits under — no separate theme map to invent or maintain. Groups lead with their worst finding, then by how many HIGHs they hold, then menu order. **This also fixes a real ordering bug**: findings were sorted with a plain `Sort-Object`, which is alphabetical, so `HIGH` `INFO` `MED` — every INFO finding outranked every MED one in the file you open first.
- **Results browser (`v`)** — read findings and artifacts **inside secgurd, in colour**, instead of pulling the zip back and opening plain `.txt` files. Offered by one keypress the moment a scan ends, and reachable any time from the menu. Drills **findings → artifact → paged view**, with `/text` search inside a file, an artifact list grouped by the same six module headings (marking which files actually have findings), and a **scan picker** that lists every earlier `secgurd_*` run on the host with its finding tally — so *“this box had 0 HIGH last week and 4 today”* is one keypress rather than two zips opened by hand. Navigation is **`Read-Host` only** — type a number, press Enter — because the SentinelOne remote shell supports that but **not** raw key capture, and a viewer that only worked on a local desktop would miss the case it exists for. Two keys mean one thing everywhere: `b` up a level, `q` out of the browser; a breadcrumb heads every screen since there is no cursor or scrollbar to show depth. It is **read-only** — the `.txt` files, zip and hash manifest are written exactly as before, and colour is applied on screen only, so nothing new lands on disk to trip an on-host EDR.
- **Structured finding detail** — a finding stays a **single headline line** (severity sorting, the `{file:…}` locator, and the `-Find` filter all parse it line-wise), but can carry an aligned `Label : Value` block rendered beneath it — on screen and in `00_SUMMARY.txt`. The label column self-sizes to the widest label in that block, so every finding aligns without a hard-coded width. ScreenConnect detections use it: the headline names the tenant and the verdict, and the block carries relay, instance id, install/download and last-used times, client binary, service state and folder — a column you scan down rather than a 200-character sentence you unpick.
- **Process & command-line heuristics** — over running processes (module 06) and historical `4688` execution (module 11): **masqueraded system processes** (e.g. an `svchost.exe`/`lsass.exe` running from outside `System32`), processes executing from **drop locations** (Temp / Public / Downloads / Desktop / Recycle Bin), and command lines matching **credential-dumping** (`comsvcs MiniDump`, `procdump … lsass`, `nanodump`, `sekurlsa`), **shadow-copy / SAM-SYSTEM-NTDS theft** (`vssadmin create shadow`, `reg save hklm\sam`, `esentutl …ntds.dit`), **LOLBin download/proxy-exec** (`regsvr32 …/i:http scrobj`, `mshta http`, `wmic process call create`, `bitsadmin /transfer`), and **obfuscated / download-and-exec** one-liners (`-enc`, `FromBase64String`, `IEX`, `DownloadString`, `-w hidden`). Autorun **values** carrying the same download-exec/obfuscation patterns are flagged as ClickFix-style persistence.
- **WMI subscription triage (noise-suppressed)** — WMI `FilterToConsumerBindings` are classic fileless persistence, but the built-in **SCM Event Log** subscription (and monitoring agents like SCOM) ship on healthy boxes and would otherwise fire HIGH on *every* run. Secgurd auto-suppresses bindings whose consumer is an `NTEventLogEventConsumer` (log-only, can't execute code) plus an editable name allowlist (`$script:WmiBenignNames`), and only raises **HIGH** for the *unrecognized* bindings — especially the `CommandLine`/`ActiveScript` consumers actually used for persistence. Suppressed ones are still listed in `03_wmi_persistence.txt` for transparency.
- **Rogue RMM detection** — hunts ~19 remote-access tool families (ScreenConnect/ConnectWise, AnyDesk, TeamViewer, Atera, Splashtop, MeshCentral, NetSupport, **NinjaOne/NinjaRMM**, Pulseway, Kaseya, Syncro, etc.) and flags suspicious context (writable-path installs, ScreenConnect instance folders + relay host). **Every ScreenConnect instance is labelled and timed** rather than listed as a bare 16-hex-digit id: the deployment **name** comes from the console-defined custom fields (Company / Site / Department) that ScreenConnect bakes into the service ImagePath as repeated `&c=` parameters, falling back to the relay-host tenant when no service is present; alongside it you get the **relay**, the **instance id**, when the client was **downloaded onto the host** (instance-folder and client-binary creation times, UTC), and when it was last used. An instance folder with **no readable `user.config` is still judged** on its relay and still raises a finding — previously it produced no output and no finding at all, so an attacker instance caught mid-install could slip through silently.
- **RunMRU / ClickFix triage** — reads the Win+R Run-dialog history (`HKCU\...\Explorer\RunMRU`) from **every user hive, including logged-off users' `NTUSER.DAT`** (mounted with admin), most-recent-first. "ClickFix" / paste-and-run lures (fake CAPTCHA, "verify you're human", "fix this error") get a user to paste an obfuscated one-liner into Run; because it is user-driven it never appears in the autorun keys, so it is often the only registry trace of initial access. Flags HIGH on interpreter / fetch / decode / hidden patterns (`powershell -w hidden`, `mshta`, `curl|iex`, `certutil`, `FromBase64String`, `http(s)://`, …) and MED on unusually long pasted commands. Each row cites the **full `HKU\<SID>\…\Explorer\RunMRU` key path** — built from the profile's real SID, even for a logged-off hive mounted under a temporary name — so the source key is directly navigable; decode the SID to an account via module 02's SID→account map.
- **Browser history URL analysis** — extracts URLs from every user's Chrome, Edge, and Firefox history (read directly from the history DBs plus their `-wal` sidecars, lock-safe, no SQLite engine needed) and flags suspicious ones live as it runs, color-coded by threat level: direct executable/script downloads, **raw *public*-IP hosts** (private/LAN IPs like `10.x` / `192.168.x` are ignored), known file-drop/C2/exfil infrastructure (Discord CDN, pastebin/raw, transfer.sh, anonfiles, mega, ngrok, `*.workers.dev`, telegram, …), URL shorteners, high-abuse TLDs, punycode hosts, and remote-access-tool references. One output folder per user. To keep the post-run **FINDINGS list uncluttered, individual browser URLs are not added to it** (a few HIGH/MED are echoed live during the scan for awareness, and a single aggregate finding points you to the files) — but **every** flagged URL of every severity is written in full to the per-user files. **Flagged URLs carry a decoded last-visit timestamp** (UTC), so a detection can be lined up against the moment an alert fired. Staying dependency-free, the time is read straight out of the raw SQLite record rather than via a SQLite engine: the row header is located by anchoring on the URL text and validated against the URL's own length, then the first column that decodes to a plausible date is taken. It **fails safe in both directions** — an entry that doesn't decode cleanly reads `time unknown` rather than a guessed date, and Firefox schema drift between versions degrades to `time unknown` instead of a wrong one; the profile's DB last-write time stays as the coarse fallback. Only *flagged* URLs are decoded (a busy profile holds tens of thousands, and decoding them all would cost far more scan time than it's worth). Each per-user file also gets a time-ordered **FLAGGED URLS BY TIME** view, and `00_BROWSER_ALERTS.txt` opens with an **ALERT TIMELINE**. Detections are scoped to a **7-day window** by default (`-BrowserDaysBack`, or the `t` > `b` menu); only a *decoded* time can put a detection outside it, so one whose date wouldn't decode is kept and counted rather than silently dropped. Each profile additionally lists the **SEARCH QUERIES** typed into Google / Bing / DuckDuckGo / Yahoo / Brave / Ecosia / Startpage / Yandex / Baidu with their times, deduplicated to the most recent — the view that lines up with a lure timeline ("searched *adobe reader download* at 14:03, landed on the fake installer at 14:04").
- **Notification / Web Push permission audit** — a site granted the browser notification permission can raise **native OS toasts**, which is the delivery engine behind the fake-antivirus scareware wave (*“Windows Defender found 5 threats … Delete Viruses”*, arriving *“via Microsoft Edge”*). Because the toast is drawn by Windows rather than inside a web page, the user’s “don’t trust the browser” instinct never fires — and the durable artifact is the **permission grant**, which outlives the toast and the session that created it. secgurd reads each Chromium profile’s `Preferences` JSON and lists **every** origin it finds — not just live grants. Reading only `…exceptions.notifications` misses the most incriminating case of all: when Chrome/Edge’s own safety checks judge a site abusive they **revoke the grant** and move the origin into `abusive_notification_permissions` / `disruptive_notification_permissions`, so a scareware site can vanish from the grant list *precisely because it misbehaved*. All seven sibling keys are read — the grant list plus `abusive_`/`disruptive_notification_permissions`, `suspicious_notification_ids`, `notification_permission_review`, Edge’s `edge_notification_referrer_chain_blocked`, and `notification_interactions` (origins that actually **displayed** notifications, which survives a permission reset). A `Source` column says which key each row came from, and anything the browser itself flagged is a HIGH finding whether or not a grant still exists. Live grants show ALLOW/BLOCK, because a normal user has very few, so any unexpected origin is worth an eyeball on its own. Origins with a **live Web Push subscription** (`push_messaging_application_id_map`) are marked separately — stronger evidence than a bare grant, since the site is actively wired up to push. ALLOW grants are cross-checked against the same heuristics used on browser history (URLhaus feed, curated watchlist, abuse TLDs, punycode, squat watchlist) **plus a machine-generated-subdomain check** that catches throwaway spam infrastructure like `d9p0dsqnaffc739qnmo0.pzma-adguard.com` — long, digit-bearing, vowel-starved labels that no human chose. Firefox keeps these in `permissions.sqlite` (`moz_perms`) and isn’t covered.
- **Per-user PUP / clone-browser detection** — walks every user's AppData (Local/Roaming/LocalLow) and every user registry hive — including **logged-off users' `NTUSER.DAT`**, which it mounts then unloads — to catch adware / potentially-unwanted apps that install per-user and skip Add/Remove Programs. Flags the Chromium-"clone" layout (`<App>\Application\<ver>\...\Installer\setup.exe`) and updater/dock families (`<App>` + `<App>Updater`/`AutoUpdate`/`Dock`), plus self-registered `Software\<Name>` keys carrying an `UninstallString`/`InstallerProgress` value. Catches infections sitting in **other** users' profiles that a current-user-only scan misses (mounting logged-off hives needs admin). Findings and the `09_user_hive_software.txt` rows now cite the **full `HKU\<SID>\…` registry path** — built from the profile's *real* SID, even for a mounted logged-off hive (whose live key is a temporary mount point) — so a flagged key is directly navigable. Module 02 carries a **SID→account map** (`Get-CimInstance Win32_UserProfile`, covering **domain/AD** profiles that `Get-LocalUser` never lists) so any SID seen here — local or domain — can be decoded back to a user.
- **Local IOC hash matching** — match on-disk binaries against your own list of known-bad MD5 / SHA-1 / SHA-256 hashes. Fully offline; no API key, no third-party disclosure. The auto-refreshed community list (abuse.ch MalwareBazaar) is filtered to **Windows PE / script** samples, so it stays relevant to what secgurd actually scans instead of carrying Linux/IoT/Android samples that can never match.
- **Heuristic flags written to file** — the `06_process_tree.txt` heuristics section writes each flag (masquerade / drop-path / suspicious command line) into the file itself, so the saved artifact matches the live scan screen instead of the alert only scrolling past.
- **Targeted find / scoping** — point a run at one or more known artifacts (`-Find "SmartPDF, evil.exe"` or the `f` menu option) and every output is reduced to just the items that name, point at, or are signed by any of those terms — across tasks, run keys, services, processes, files and findings. Comma-separated terms are OR'd; matches are wrapped in `>>> <<<` in the saved files and colour-highlighted live on screen. Case-insensitive.
- **Findings point to their file** — every auto-flagged finding leads with the exact artifact `.txt` it came from (in `00_SUMMARY.txt` and the end-of-run recap), and `00_SUMMARY.txt` carries a `FILES WITH FINDINGS` index — so you jump straight to the file with the detail instead of guessing which one to open.
- **Event timeline** — chronological merge of logons, log clears, new services, scheduled tasks, and recent file modifications.
- **SHA-256 evidence manifest** — hashes every output file for chain-of-custody / tamper evidence.

**Output:**

- Timestamped output folder, auto-zipped.
- Returns a PowerShell object (folder, zip path, file count, findings, duration) for scripting.

---

## Repository layout

```
secgurd.ps1                       the entire tool (single file, human-readable source of truth)
README.md
dependencies/                     external data the tool auto-loads (git-pulled; refreshed by Actions)
  communitysavedIOCS.txt            community malware-hash feed (abuse.ch MalwareBazaar)
  communitysavedMALURLS.txt         community malicious-URL feed (abuse.ch URLhaus)
  squat_domains.txt                 brand look-alike / typosquat domains (openSquat output)
  keywords.txt                      your brand terms - openSquat INPUT (edit this)
  Dependencies.txt                  manifest of the data files (for external tooling)
.github/workflows/                daily refresh Actions (run in GitHub's cloud, commit back)
  refresh-iocs.yml
  refresh-malurls.yml
  refresh-squat-domains.yml
```

The `dependencies/` folder is a **repo-only** convenience for keeping the root tidy. On an endpoint the data files sit **flat next to `secgurd.ps1`** (the S1 paste unpacks them into `%TEMP%`), and secgurd resolves either layout automatically — see *[Where secgurd looks](#ioc-hash-matching)* under IOC hash matching.

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

> This clears everything secgurd (or the compressed S1 paste) can leave in `%TEMP%`: the `secgurd_<host>_<timestamp>` output folder, the unpacked `secgurd.ps1`, the S1 paste files, and the IOC-hash / malicious-URL / squat-domain / manual lists. `"$env:TEMP\secgurd*"` already covers `secgurd.ps1` and the `secgurd_s1_*.txt` files, so those entries are belt-and-suspenders. (On an endpoint the lists sit flat in `%TEMP%`, so cleanup matches bare filenames — not the repo's `dependencies/` folder.)
>
> To check after cleanup run `Get-ChildItem "$env:TEMP" -Filter "secgurd*" -ErrorAction SilentlyContinue; Get-ChildItem "$env:TEMP" -Include "communitysavedIOCS.txt","communitysavedMALURLS.txt","squat_domains.txt","manualIOCS.txt" -ErrorAction SilentlyContinue`.

---

## Usage

```
secgurd.ps1 [-Auto] [-Modules 01,03,06] [-OutputPath <dir>] [-NoBanner]
            [-OpenWhenDone] [-WithOwners] [-WithSignatures] [-WithTaskInfo]
            [-IOCHashes <file>] [-CommunityIOCHashes <file>] [-CommunityMalUrls <file>]
            [-SquatDomains <file>] [-DaysBack <N>] [-BrowserDaysBack <N>]
            [-Find <terms>]
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
| `-CommunityIOCHashes <file>` | Explicit path to the community hash list (otherwise auto-found in `dependencies/` or beside the script). |
| `-CommunityMalUrls <file>` | Explicit path to the community malicious-URL list (otherwise auto-found in `dependencies/` or beside the script). |
| `-SquatDomains <file>` | Explicit path to the openSquat squat-domain watchlist (otherwise auto-found in `dependencies/` or beside the script). |
| `-DaysBack <N>` | Lookback window in days for time-bounded collectors (default 30). |
| `-BrowserDaysBack <N>` | Lookback window for module 10's browser detections and search queries (default 7). Separate from `-DaysBack` because history goes back months and only the days around an alert matter. A flagged URL whose visit time can't be decoded is kept regardless, and counted. Also settable from the Time windows sub-menu (`t` > `b`). |
| `-Find <terms>` | Scope **all** output to lines/items containing **any** of the comma-separated `<terms>` (case-insensitive); matches are highlighted — see [Targeted find](#targeted-find--scoping-a-run-to-one-artifact). |
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

# Scope an entire run to one or more known-bad artifacts (comma-separated, OR-matched):
# every file keeps only the tasks, run keys, services, processes and paths that mention any of them
.\secgurd.ps1 -Auto -Find "SmartPDF, evil.exe"

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
| `d` | Dependencies sub-menu — manage all three external data lists in one place: **IOC hashes**, **malicious URLs** (URLhaus), and **squat domains** (openSquat). Pick `[1]`/`[2]`/`[3]` to load from file `[f]`, paste `[p]`, list `[l]`, or toggle `[x]`. |
| `f` | Find — scope all output to a name/string (enter a term, or blank to clear) |
| `t` | **Time windows** sub-menu — the two lookback windows in one place: `[t]` scan lookback (event logs, file collectors, timeline) and `[b]` browser history (module 10 detections + search queries). Each shows its current value, accepts 1–3650, and blank keeps it; `Enter` returns to the main menu. They're separate because browser history goes back months, so the scan window would drown the alert you're trying to match. |
| `p` | Pastable for remote shells. Compressed gzip+Base64, fully offline: `[1]` everything, `[2]` dependency lists only (IOC + URL + squat), `[3]` script only. Or `[4]` **web launcher** — a one-line `iex (irm …)` that pulls the latest script **and** dependency lists from GitHub (needs internet on the target). |
| `r` | Run the selected modules |
| `?` | Help |
| `q` | Quit |
| `cleanup` | Remove **all** secgurd artifacts from `%TEMP%` (script, output folders + zips, S1 paste files, IOC / malicious-URL / squat-domain / manual lists) — type-to-confirm, then exit. Same as `-Cleanup`. |

> On entry the logo appears on its own splash screen — the Sigurd inscription, a one-line operator stamp (endpoint · user · privilege · version), blood dripping off the sword tip, and a `Press ENTER to HUNT` prompt. A keypress clears it and drops into the menu, which shows the same banner statically. The drip animates only on a local interactive console wide and tall enough to hold the whole splash unscrolled (so the sword tip stays put under it) — on remote/redirected/ISE hosts or a small window it silently falls back to the static splash, so it never affects input.

### When a scan finishes

The end of a run is a **menu, not a dead end** — `[v]` browse results, `[m]` back to the module menu, `[o]` open the output folder, `Enter` to exit. It **loops**, so looking at two things doesn't drop you out at the first one.

`[m]` **re-runs secgurd** rather than resuming. The collectors execute as inline script body, so there is no earlier point to jump back to — "back to the menu" can only mean starting again. It carries your original switches across (above all the dependency paths, since a relaunch without them would silently scan with **no IOC / URL / squat matching at all**) but deliberately drops `-Auto`, `-Modules` and `-OutputPath`, so you land on the menu and pick a new set into a **fresh timestamped folder**. Merging into the finished one would overwrite `00_SUMMARY.txt` with only the second run's findings and quietly lose the first; the scan picker in `[v]` lists both runs, so keeping them separate costs nothing.

Two details make this work in the shell it was written for. **Interactivity is judged the same way the module menu judges it** — `[Environment]::UserInteractive` *alone* is false under SYSTEM, which is exactly what a remote-shell session is, so gating on it by itself hid this menu in the entire environment it exists for. The check now refuses only when stdin is redirected **and** the session is non-interactive: a genuinely input-less pipeline that would deadlock on `Read-Host`. And **`[m]` finds its own source** — a dotted `.ps1` knows its path, the compressed paste stages a copy in `%TEMP%`, and a purely in-memory run (`iex`, where `$PSCommandPath` is `$null`) recovers the running scriptblock's own text and re-invokes *that*, in memory. Writing a copy of secgurd to disk just to re-run it would add EDR surface and leave a file behind to clean up. The recovered text is sanity-gated on length and content first; if it doesn't look like secgurd it is dropped and `[m]` is simply not offered.


### Reading results: colour, sections and record blocks

**Severity has one palette, defined once.** HIGH is brick red, **MED is yellow** (`38;2;232;196;66`),
INFO is neutral grey, and a verdict of *clean* is green. The table used to be hand-written in five
places and the copies had drifted: MED rendered as tan in the results browser but as bright
`Yellow` during the live scan - the same severity in two colours in one session - and two count
rows had no MED colour at all, so a scan with 12 MED findings looked exactly as quiet as one with
zero. MED's 16-colour fallback is **`DarkYellow`, not `Yellow`**, because `Yellow` is already the
`[n]` selector colour and the selector sits directly beside the tag: on a 16-colour host they were
literally indistinguishable.

**Findings and artifacts are sectioned by a severity rail.** Each of the six groups is drawn with a
coloured `|` running down its left edge. The **group heading** takes the colour of the worst finding
in that group - red where a HIGH lives, yellow for MED-only, green where nothing was flagged - so you
can find the section that matters before any of its rows have been read. Below the heading each
**row's rail takes that row's own severity**, which turns the left edge into a severity gutter you
can scan straight down. Per-group tallies sit on the heading. It is ASCII `|`, never a box-drawing character: those mojibake in a remote shell running a
non-UTF8 codepage, which is the shell this tool exists for. Colour is never the *only* signal - the
literal `[HIGH]` / `[MED ]` / `[INFO]` tag and the numeric tally stay in the text, so stripping
colour entirely still leaves a readable screen.

**Wide artifacts are record blocks, not table rows.** `Format-Table -Wrap` turns out to be inert in
the saved files: `Save-Output` writes with `Out-File -Width 4096`, so a row only wraps past 4096
columns - every wide table landed on disk as one enormous physical line and what looked like
wrapping was the viewer doing it at an arbitrary column. The worst offenders now emit one aligned
`label : value` block per record, wrapped with a hanging indent so a long value stays inside its own
field:

```
  Donna / Edge / Profile 2
  ..............................................................
    Google Docs Offline                                  v1.101.1
      id      : ghbmnnjooekpmoecnnnilnnbdlolhkhi
      update  : hxxps://clients2.google.com/service/update2/crx
      perms   : alarms, storage, unlimitedStorage, offscreen,
                https://docs.google.com/*, https://drive.google.com/*
```

Because the change is in the **writer**, the `.txt` on disk improves as well as the coloured browser
view - and `Write-ArtifactLine` already colourises `label : value` rows, so the browser lights these
up for free. Converted so far:

| Artifact | What was wrong |
|---|---|
| `10_browser_extensions.txt` | eight columns; a 32-char id, a ~50-char update URL and a 100+ char permission list made a ~250-char row |
| `04_ps_event_log.txt` | the complete script-block text in a single cell |
| `06_processes.txt` | image path **and** command line, both unbounded, in one row |
| `06_process_tree.txt` | the command line pushed the parent/child columns - the artifact's whole purpose - off to the right |
| `03_scheduled_tasks.txt` | eight columns including two datetimes and a joined command line, over every task on the host |
| `03_services.txt` | `PathName` is a quoted binary path with arguments, routinely past 120 characters |

Labels are capped at 19 characters, because that is the longest one `Write-ArtifactLine` will
recognise and colour. Narrow tables stay tables - nothing that already fits gets churned.

**The artifacts list is ordered for looking, not for triage.** It defaults to fixed module order
(`00` -> `14`, with `REPORT` pinned first) rather than severity, because the reason you open this
screen is usually to check what the findings engine did *not* flag - and severity order buries
exactly those files at the bottom. Fixed order also means a file sits in the same place every run,
which is what makes it findable from memory. **`[s]`** switches to severity order for when you do
want the loud ones first. Each row splits the filename so the repeated `NN_` prefix and `.txt`
suffix dim out and the distinctive middle stays bright - `browser_extensions` reads at a glance
where `10_browser_extensions.txt` has to be parsed - and file sizes pick their own unit so the
column never mixes `112 KB` with `1,204 KB`.

**The pager wraps and pages by screen rows.** A 4096-character line used to soft-wrap into dozens of
rows, so a "page" of 22 lines could scroll hundreds of rows past before stopping. Page height is now
measured in wrapped rows, and continuations carry a hanging indent so they stay visibly subordinate
to their own line instead of starting at column zero looking like a new record.

---

## IOC hash matching

Secgurd matches real on-disk binaries (in high-signal locations like Temp, AppData, Public, ProgramData, Downloads, Desktop, plus every running process image) against known-bad hashes. There are **two separate sources**, and matches are labeled by which one they came from:

**1. Community list (`dependencies/communitysavedIOCS.txt`) — auto-loaded, shared, version-controlled.**
This file lives in the repo's **`dependencies/`** folder (alongside the malicious-URL and squat lists) and is **loaded automatically** on every run, no flags needed. Update it with `git pull` and your runs use the latest community hashes. It's meant as the curated, team-shared baseline.

> **Where secgurd looks:** for each list it checks (1) an explicit `-Community*/-SquatDomains` path, then (2) the `dependencies/` folder next to the script (the repo/clone layout), then (3) **flat beside the script** — which is where the compressed S1 paste unpacks them (into `%TEMP%`, next to `secgurd.ps1`) — and finally (4) **`%TEMP%` itself**, where the `[4]` web launcher stages the pulled lists for an in-memory `iex (irm …)` run that has no script folder to resolve against. So the folder keeps the repo tidy while paste and web-launcher endpoint runs are unaffected.

**2. Hashes you add — case-specific, kept separate.**
Provide your own list via `-IOCHashes C:\path\list.txt` or the **Dependencies** menu (`d` → `[1] IOC hashes`, then load `[f]` / paste `[p]`). These never touch the community file, so you can always tell *what you added* from *what was already saved*.

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

The repo includes a GitHub Action (`.github/workflows/refresh-iocs.yml`) that, once a day, fetches a free public malware-hash feed (abuse.ch MalwareBazaar) **in GitHub's cloud** and commits the refreshed `dependencies/communitysavedIOCS.txt` back to the repo. Your endpoints never touch the internet — only GitHub does the fetching. Then your next `git pull` picks up the new hashes. You can also trigger it manually from the repo's **Actions** tab ("Run workflow").

---

## Community malicious-URL matching

Alongside the hash list, secgurd carries a community **malicious-URL** list (`dependencies/communitysavedMALURLS.txt`) built from the free abuse.ch **[URLhaus](https://urlhaus.abuse.ch/)** feed — URLs currently serving malware. Like the hash list it is **auto-loaded** on every run from the `dependencies/` folder (no flags needed; use `-CommunityMalUrls <file>` to point at an explicit path). Manage it from the **Dependencies** menu (`d` → `[2] Malicious URLs`): load from a file `[f]`, paste `[p]`, list `[l]`, or toggle matching on/off `[x]`.

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

The GitHub Action `.github/workflows/refresh-malurls.yml` runs daily (06:30 UTC, just after the hash refresh) and manually from the **Actions** tab. It fetches the URLhaus "online" export **in GitHub's cloud**, keeps the URL plus its threat/tags label, and commits the refreshed `dependencies/communitysavedMALURLS.txt` back to the repo. Your next `git pull` picks up the new URLs — the endpoints never touch the internet. It also rides along inside the compressed SentinelOne paste, so an air-gapped box gets the current URL feed too.

**The feed is aggressively filtered to stay small.** The raw URLhaus export is ~15k URLs, but ~87% of them are things secgurd **already flags on its own heuristics** — so listing them adds nothing. The Action drops every entry the tool would already catch (direct payload downloads like `.exe`/`.dll`/`.ps1`, raw-IP hosts, GitHub-hosted content, known C2/file-drop infrastructure, URL shorteners, high-abuse TLDs, punycode), keeps only URLs added in the last **90 days**, and emits **one representative URL per host** (module 10 matches on host too, so extra URLs on an already-listed host are redundant). What survives — a few hundred hosts — is the real value-add: confirmed-malicious sites on *otherwise normal-looking* domains that the heuristics would miss. Tune the window via `MAXAGE_DAYS` in the workflow.

---

## Squat-domain watchlist (openSquat)

A third auto-loaded list, `dependencies/squat_domains.txt`, holds **look-alike / typosquat domains impersonating your own brand**. It's built by [openSquat](https://github.com/atenreiro/opensquat), which scans newly-registered domains for typosquats (`exmaple-brand.com`), homoglyphs, and combosquats (`example-brand-login.com`) of the terms you list in **`dependencies/keywords.txt`**. Like the other lists it is **auto-loaded** from the `dependencies/` folder (or via `-SquatDomains <file>`), rides along in the compressed S1 paste, and is cleaned up by the cleanup command.

**Where it's used.** Module 10 checks **every browser-history host and every download-origin host** (module 03 BITS jobs + module 07 `Zone.Identifier` streams) against the watchlist — an exact host match or any subdomain of a watchlisted entry. A hit raises a **HIGH** finding (*"matches openSquat squat-domain watchlist"*), is written to **`10_squat_watchlist.txt`** (listing user / browser / URL / matched domain), and flows into the end-of-run `00_BROWSER_ALERTS.txt` correlation. Matches are deduped per user+host so a heavily-visited squat host is reported once. Module 05 additionally matches the **DNS client cache** against the watchlist (see below), so a squat domain resolved by *any* process — not just a browser — is caught.

### DNS-cache intel matching (module 05)

Beyond browser history, secgurd cross-references the machine's **DNS client cache** (`Get-DnsClientCache`) against both the URLhaus host set and the squat watchlist, writing `05_intel_host_matches.txt`. A cached resolution of a listed host means *something* on the box looked it up — regardless of which process or browser. If that host's resolved IP is **also present in an active TCP connection**, the match is annotated as a **live session** to known-bad infrastructure (the strongest signal short of a payload on disk). Each hit is a **HIGH** finding. This reuses data module 05 already collects, so it adds no meaningful scan time.

**Setup:** edit `dependencies/keywords.txt` with your organisation's real brand/product terms (one per line, just the word — not the TLD; `#` comments and blank lines ignored). The starter file ships with placeholders you must replace.

### Keeping the squat watchlist fresh automatically

The GitHub Action `.github/workflows/refresh-squat-domains.yml` runs daily (06:15 UTC) and manually from the **Actions** tab. It installs openSquat in GitHub's cloud, runs it over `dependencies/keywords.txt` in **free mode** (confidence level 1 — no API key needed), and commits the refreshed `dependencies/squat_domains.txt` back to the repo only if it changed. Your next `git pull` picks up the new domains — the endpoints never touch the internet.

**Kept lean for the paste.** `squat_domains.txt` rides inside the compressed SentinelOne paste, which has to stay small, so the Action prunes and caps it: it drops domains secgurd **already flags on its own heuristics** (punycode hosts, high-abuse TLDs) so the watchlist never duplicates a built-in detection, then de-dupes, sorts, and hard-caps the count (500 — a backstop; the list is **cumulative** so hitting the cap means the keywords are too generic or it's simply grown a long while). At runtime the reverse guard also holds: if a visited host is on the squat list **and** trips a built-in heuristic, only the squat alert fires (it's the more specific "impersonates your brand" signal), and repeat visits to the same host collapse to one correlation entry — so no double-alerting in `00_BROWSER_ALERTS.txt`.

---

## Targeted find — scoping a run to one artifact

Sometimes you already know *what* you're hunting — a named bundler, a dropper filename, a rogue signer — and you don't want to wade through every benign task and registry value to find it. `-Find` (or the `f` menu option) scopes the **entire run** to one or more strings; separate multiple terms with commas and a line is kept if it contains **any** of them.

```powershell
# A known bundler "SmartPDF" and a dropper "evil.exe" are on the box — show only what touches either
.\secgurd.ps1 -Auto -Find "SmartPDF, evil.exe"
```

With a find filter active, every artifact file keeps only the lines that contain one of the terms — **plus the section header above them** — and drops sections with no hits entirely. So instead of *all* scheduled tasks, you see only the task named after / running `SmartPDF`; instead of *all* run keys, only the value pointing at it; and the same for services, processes, loaded DLLs, file paths, and so on. The auto-flagged **findings** and the **event timeline** are filtered the same way, so `00_SUMMARY.txt` shows only the related leads.

- **Case-insensitive.** `-Find smartpdf`, `SmartPDF`, and `SMARTPDF` all match the same items — capitalization never causes a miss.
- **Matches anywhere on the line** — filename, full path, signer, service name, command line, registry value name or data.
- **Multiple terms, OR-matched.** Comma-separate them (`-Find "SmartPDF, evil.exe, .top"`); a line is kept if it contains **any** term. Terms are trimmed and de-duplicated.
- **Matches stand out.** Each hit is wrapped in `>>> <<<` in the saved `.txt` files (greppable, survives copy-paste) and colour-highlighted on the live scan screen.
- **Set it any way:** the `-Find <terms>` flag (works with `-Auto`, `-Modules`, and the paste versions), or interactively with the `f` menu command (enter one or more comma-separated terms to scope, or leave it blank to clear and collect everything again).
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

**Artifacts never silently truncate.** Two things guarantee it. Saved output is written with an explicit `-Width 4096` — `Out-File` otherwise inherits the host console width, and falls back to **80 columns when there is no console** (a redirected pipeline, a remote shell, a scheduled task), which was quietly clipping wide table rows in the saved file. And every `Format-Table` carries `-Wrap`, so a value too long for its column **wraps onto further lines instead of being cut off with an ellipsis**. Evidence you can't read is worse than a long line. Where a value is the whole point of the artifact — a pasted ClickFix one-liner — it isn't put in a table at all: `03_runmru_clickfix.txt` renders a short index table and then prints each command **verbatim and unwrapped in its own block**, so it can be copied back as a single string.

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

- Run secgurd on your own box and press **`p`**. Options **[1]–[3]** are a single compressed (gzip+Base64) block that auto-**compacts** a copy of the source before packing (see below), so the paste is as small as possible:
  - **[1] Everything** — script + all dependency lists (IOC hashes + malicious URLs + squat domains), in one block.
  - **[2] Dependency lists only** — just `communitysavedIOCS.txt` / `communitysavedMALURLS.txt` / `squat_domains.txt`.
  - **[3] Script only** — just `secgurd.ps1` (smallest block).
  - **[4] Web launcher** — the plain `iex (irm …)` one-liner with the dependency pull prepended: it fetches all three dependency lists into `%TEMP%` and then runs the latest `secgurd.ps1` straight from GitHub, in-memory. Always the newest version (raw refreshes a branch push within ~5 min; the `?v=<random>` only defeats a client/proxy cache, not raw's own CDN). Needs outbound HTTPS on the target — unlike [1]–[3], which are fully offline. If an old/hardened host fails the fetch with a TLS error, prefix `[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;` once.
- **If [1] is too big** for your shell's paste limit (the community IOC list is the bulk), paste **[2]** first, then **[3]**: [2] drops the lists into `%TEMP%`, and [3] unpacks `secgurd.ps1` and runs it — the wrapper picks up whatever lists are already in `%TEMP%`, so IOC / URL / squat matching works. (You can also just paste **[3]** on its own to run the script with no dependency lists.)
- Copy the block, paste it into the S1 Remote Shell, press Enter, and the interactive menu appears there.

Each option runs secgurd **in the current shell as an in-memory scriptblock** — never a child `powershell.exe`. This matters in the S1 shell: it repaints the banner/menu on the first Enter (a child process doesn't), and it runs even when the endpoint's execution policy has script files disabled (execution policy only restricts `.ps1` *files*, not scriptblocks). The script is also "wrap-safe" (no internal here-strings), so the paste can't break itself.

**Paste-only stripping.** Before compaction, the paste build also drops functions that a *pasted* run can never reach: the paste generator itself (`Show-S1Compressed` and `Compress-Source` — the payload was carrying its own builder) and the dependency-*loading* UI, since the IOC / malicious-URL / squat lists ride along inside the paste already. That is **~7,200 characters, about 7%** of the paste. The interactive **menu deliberately stays** — the paste stub invokes secgurd without `-Auto`, so an analyst lands on the menu and picks modules there. Call sites resolve these through `Get-Command` and invoke the returned command object, so a stripped build hides the option instead of erroring. The pass **refuses to drop any function still called from code it is keeping**, so a future edit that starts using one of them can't silently break the paste — and, like every other pass, the result is re-parsed and discarded if it doesn't come back clean.

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

*A shield to his friends, a terror to his foes.*
— Völsunga Saga, ch. 22
