#Requires -Version 5.1

<#
.SYNOPSIS
    secgurd - Windows DFIR Triage Tool
.DESCRIPTION
    Slayer of threats. Keeper of truth.
    Collects key forensic artifacts from a live Windows system over a remote session.
    Named for Sigurd, slayer of Fafnir. No external dependencies.
.PARAMETER OutputPath
    Where artifacts are written. Defaults to a timestamped folder under %TEMP%.
.PARAMETER Auto
    Skip the interactive menu and run ALL modules. Use for unattended/scripted runs.
.PARAMETER Modules
    Run only specific modules, e.g. -Modules 03,04,11. Implies non-interactive.
.PARAMETER NoBanner
    Suppress the ASCII banner (quieter logs).
.PARAMETER OpenWhenDone
    Open the output folder in Explorer when collection finishes (interactive only).
.PARAMETER Cleanup
    Delete all secgurd output folders and zips from %TEMP%. Lists items, shows total
    size, and requires typing DELETE to confirm. Does nothing else.
.PARAMETER WithOwners
    Resolve the owning account for each process in 06_process_tree. This adds a per-process
    WMI call and can be slow on busy or domain-joined hosts, so it is off by default.
.PARAMETER WithSignatures
    Verify Authenticode signatures of service binaries and loaded DLLs. This does a full
    trust-chain check per file and can stall for seconds each on an offline host, so it is
    off by default. Without it, secgurd flags binaries by location and modification time.
.PARAMETER WithTaskInfo
    Resolve run-time info (LastRun / NextRun / LastResult) for EVERY scheduled task, including
    the hundreds of built-in \Microsoft\* tasks. Get-ScheduledTaskInfo makes a per-task call to
    the Task Scheduler service, so doing it for all tasks can take many minutes (or stall) on a
    busy or remote host. Off by default: secgurd still lists every task, but only resolves run
    times for non-Microsoft tasks (the ones that matter in triage).
.PARAMETER IOCHashes
    Path to a file of known-bad hashes (MD5, SHA-1, or SHA-256; one per line, optional
    ",label"). secgurd
    hashes on-disk binaries in high-signal locations (Temp, AppData, Public, Downloads, and
    running processes) and flags any that match. Fully offline - no API key or internet.
.PARAMETER DaysBack
    Lookback window in days for all time-bounded collectors (event logs, recently-modified
    files, the timeline, and new-account / modified-binary findings). Default 30. Use a
    larger value (e.g. 90) for suspected long-dwell compromises, smaller for fresh incidents.
.PARAMETER Find
    A name or string to filter ALL collected output by (case-insensitive). When set, every
    artifact file keeps only the lines that contain the string - and the section header above
    them - so you see just the items named after, pointing at, or signed by that string. Use it
    to scope a run to a single known-bad artifact, e.g. -Find SmartPDF surfaces only the
    scheduled tasks, run keys, services, processes and files that reference SmartPDF. Findings
    are filtered the same way. Leave unset to collect everything (default).
.PARAMETER Help
    Show usage and exit.
.EXAMPLE
    & .\secgurd.ps1
    Launches the interactive module.
.EXAMPLE
    Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/<you>/secgurd/main/secgurd.ps1)
    Pull from GitHub and run on a remoted machine.
.EXAMPLE
    .\secgurd.ps1 -Auto -OutputPath C:\Cases\IR-0042
    Run everything, no menu, custom output path.
.EXAMPLE
    .\secgurd.ps1 -Modules 03,04,06,11
    Run only persistence, PowerShell, processes, and LOLBins.
.EXAMPLE
    .\secgurd.ps1 -Cleanup
    Remove all secgurd output from TEMP (asks you to type DELETE first).
.NOTES
    Run as Administrator for full coverage.
    Works over WinRM / PSRemoting sessions.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:TEMP\secgurd_$(hostname)_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [switch]$NoBanner,
    [switch]$Auto,
    [string[]]$Modules,
    [switch]$OpenWhenDone,
    [switch]$Cleanup,
    [switch]$WithOwners,
    [switch]$WithSignatures,
    [switch]$WithTaskInfo,
    [string]$IOCHashes,
    [string]$CommunityIOCHashes,
    [string]$CommunityMalUrls,
    [string]$SquatDomains,
    [int]$DaysBack = 30,
    [string]$Find,
    [switch]$MakeS1Paste,
    [switch]$Help
)

# -- Glyph expander: source stays pure ASCII; real Unicode built at runtime --
function Ex {
    param([string]$s)
    $map = @{
        '00' = [char]0x2500
        '01' = [char]0x2501
        '02' = [char]0x2588
        '03' = [char]0x2550
        '04' = [char]0x2551
        '05' = [char]0x255D
        '06' = [char]0x2557
        '07' = [char]0x2554
        '08' = [char]0x255A
        '09' = [char]0x2014
        '10' = [char]0x00B7
        '11' = [char]0x16B1
        '12' = [char]0x16A6
        '13' = [char]0x224B
        '14' = [char]0x002B
        '15' = [char]0x2560
        '16' = [char]0x0021
        '17' = [char]0x003E
        '18' = [char]0x2572
        '19' = [char]0x2563
        '20' = [char]0x25B6
        '21' = [char]0x2571
        '22' = [char]0x16CA
        '23' = [char]0x0078
        '24' = [char]0x0021
        '25' = [char]0x002A
        '26' = [char]0x2514
        '27' = [char]0x002A
    }
    foreach ($k in $map.Keys) { $s = $s.Replace('^' + $k, $map[$k]) }
    return $s
}

$script:secgurdVersion = 'v1.4'

# ---------------------------------------------

#  SETUP

# ---------------------------------------------

$ErrorActionPreference = 'SilentlyContinue'
$script:RunStart = Get-Date
$script:Findings = [System.Collections.Generic.List[string]]::new()
$script:CollectedCount = 0
$script:ErrorCount = 0
$script:SkippedCount = 0
$script:EmptySkipped = 0   # collectors that produced no data - file not written (avoids bloat)
$script:ErrorDetails = [System.Collections.Generic.List[string]]::new()  # collector errors, logged in 00_INDEX (no per-file ERROR artifacts)
$script:ProceedWithRun = $false
$script:OpenFolderWhenDone = [bool]$OpenWhenDone
$script:RunLineActive = $false
$script:WithOwners = [bool]$WithOwners
$script:WithSignatures = [bool]$WithSignatures
$script:WithTaskInfo = [bool]$WithTaskInfo
$script:IOCHashFile = $null
$script:IOCHashSet = $null
$script:IOCHashCount = 0
# Community IOC list: auto-loaded from communitysavedIOCS.txt next to the script (refreshed
# via git pull). Kept SEPARATE from the manual set above so matches can be labeled by source.
$script:CommunityHashSet = $null
$script:CommunityHashCount = 0
$script:CommunityHashFile = $null
# Community malicious-URL list: auto-loaded from communitysavedMALURLS.txt next to the script
# (refreshed via git pull from abuse.ch URLhaus). Module 10 checks browser-history URLs against
# these. We keep TWO sets: exact full-URL matches (strongest) and host-only matches (payload
# URLs rotate paths, so the host is the durable signal).
$script:MalUrlSet = $null       # normalized full URLs (lowercased, trailing slash trimmed)
$script:MalUrlHostSet = $null   # hosts extracted from those URLs
$script:MalUrlCount = 0
$script:MalUrlFile = $null
$script:MalUrlBackup = $null    # stashed sets when the 'u' menu toggles matching OFF (so it can flip back ON)
# Squat-domain watchlist: auto-loaded from squat_domains.txt next to the script (refreshed via
# git pull from the openSquat GitHub Action). Module 10 checks every browser-history host and
# download-origin host against it - a hit is a look-alike/typosquat of one of the org's brand terms.
$script:SquatDomainSet = $null    # normalized watchlist domains (lowercased, www./scheme/path stripped)
$script:SquatDomainCount = 0
$script:SquatDomainFile = $null
$script:SquatMatches = New-Object System.Collections.Generic.List[object]   # module-10 hits, for 10_squat_watchlist.txt
$script:SquatSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)  # dedupe key: "user|host"
# Browser flagging: module 10 records every flagged URL here (user/browser/host/severity/reason)
# so the post-collection correlation step (after IOC matching) can cross-reference these hosts
# with on-disk artifacts and write 00_BROWSER_ALERTS.txt.
$script:BrowserFlagged = New-Object System.Collections.Generic.List[object]
# Dedupe guard for the above: keyed "user|host|reason" so the same host isn't flagged twice with
# the same reason (repeat visits, or a heuristic + dependency-list hit on one host). Squat matches
# additionally take precedence over generic heuristics for the same URL (see module 10).
$script:BrowserFlaggedSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
# Download origins (module 07 Zone.Identifier streams + module 03 BITS jobs): file -> URL.
# The end-of-run correlation folds suspicious origins into 00_BROWSER_ALERTS.txt.
$script:DownloadSources = New-Object System.Collections.Generic.List[object]
# Trusted binary locations that sit under otherwise-writable roots (e.g. ProgramData) but are
# legitimate OS/vendor software. We exempt these from "writable path" findings so we don't flag
# Windows Defender (which lives in ProgramData\Microsoft\Windows Defender\Platform\<ver>\ and
# updates that version folder constantly), OneDrive's per-user installs, etc. Anything genuinely
# dropped into Temp/AppData/Downloads is still flagged.
$script:TrustedPathRx = '(?i)\\(Windows Defender|Windows Defender Advanced Threat Protection)\\Platform\\|' +
    '(?i)\\Microsoft\\Windows Defender\\|' +
    '(?i)\\Microsoft OneDrive\\|' +
    '(?i)\\Microsoft\\OneDrive\\|' +
    '(?i)OneDrive.*\.exe|' +
    '(?i)\\Packages\\Microsoft\.|' +
    '(?i)\\Microsoft\\EdgeUpdate\\|' +
    '(?i)\\Microsoft\\EdgeWebView\\'
# Lookback window (days) for all time-bounded collectors. Clamp to a sane 1..3650 range.
if ($DaysBack -lt 1) { $DaysBack = 1 }
if ($DaysBack -gt 3650) { $DaysBack = 3650 }
$script:DaysBack = $DaysBack

# Optional output filter: when set, every artifact (and finding) is reduced to only the
# lines/items that contain this string. Seeded from -Find; also settable in the menu via 'f'.
$script:FindFilter = $null
$script:LastFilterMatchCount = 0
$script:FindFileCounts = @{}   # filename -> matched-item count, for the find summary section
if ($Find -and $Find.Trim()) { $script:FindFilter = $Find.Trim() }

# Force UTF-8 output so box-drawing chars render correctly

try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
try { $OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

# Prevent signature checks (Get-AuthenticodeSignature) from stalling on offline/slow hosts:
# disable online certificate revocation (CRL/OCSP) lookups so they never block on network.
try { [System.Net.ServicePointManager]::CheckCertificateRevocationList = $false } catch {}

# Detect ANSI/VT support (Windows 10+ console, Windows Terminal, modern hosts).
# Lets us do bold + bright colors that Write-Host's -ForegroundColor can't.
$script:ESC = [char]27
$script:AnsiOK = $false
try {
    if ($Host.UI.SupportsVirtualTerminal -or $env:WT_SESSION -or
        [int](Get-ItemProperty 'HKCU:\Console' -Name VirtualTerminalLevel -ErrorAction SilentlyContinue).VirtualTerminalLevel -ge 1) {
        $script:AnsiOK = $true
    }
} catch {}

function Write-Flair {
    # Bold + colored line. Falls back to plain colored Write-Host if no ANSI.
    param([string]$Text, [string]$Ansi = '1;33', [string]$Fallback = 'Yellow')
    if ($script:AnsiOK) {
        Write-Host ("{0}[{1}m{2}{0}[0m" -f $script:ESC, $Ansi, $Text)
    } else {
        Write-Host $Text -ForegroundColor $Fallback
    }
}

function Wc {
    # Write a colored segment with NO newline. Uses ANSI true-color when available
    # (lets us do real orange), otherwise falls back to a 16-color -ForegroundColor.
    param([string]$Text, [string]$Ansi, [string]$Fallback)
    if ($script:AnsiOK) {
        Write-Host ("{0}[{1}m{2}{0}[0m" -f $script:ESC, $Ansi, $Text) -NoNewline
    } else {
        Write-Host $Text -ForegroundColor $Fallback -NoNewline
    }
}

# Alert red. HIGH findings / alerts print in a darker "brick" red - true-color when the terminal
# supports it (Write-Host's -ForegroundColor can't do arbitrary RGB), with DarkRed as the
# 16-color fallback. Centralized here so the shade is easy to retune in one place.
$script:BrickAnsi = '38;2;168;42;34'   # brick red, RGB (168,42,34) - darker/less neon than plain Red
$script:BrickCon  = 'DarkRed'          # fallback ConsoleColor when ANSI/VT is unavailable
function Write-Alert {
    # Write a line (or segment with -NoNewline) in the alert brick-red.
    param([string]$Text, [switch]$NoNewline)
    if ($script:AnsiOK) {
        Write-Host ("{0}[{1}m{2}{0}[0m" -f $script:ESC, $script:BrickAnsi, $Text) -NoNewline:$NoNewline
    } else {
        Write-Host $Text -ForegroundColor $script:BrickCon -NoNewline:$NoNewline
    }
}

# ---------------------------------------------

#  secgurd BANNER

# ---------------------------------------------

function Show-secgurdBanner {
    # Color palette

    $gold   = 'Yellow'
    $hilt   = 'White'
    $pommel = 'Yellow'
    $tip    = 'Red'
    $dim    = 'DarkGray'
    $info   = 'Gray'
    $ok     = 'Green'
    $warn   = 'Yellow'
    $cyan   = 'Cyan'

    Write-Host ""
    Write-Host (Ex " ^11^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^12") -ForegroundColor $dim
    Write-Host ""

    # Row 0 - top of crossguard + title row 0

    Write-Host (Ex "      ^07^03^06 ") -ForegroundColor $hilt -NoNewline
    Write-Host (Ex "^02^02^02^02^02^02^02^06^02^02^02^02^02^02^02^06 ^02^02^02^02^02^02^06 ^02^02^02^02^02^02^06 ^02^02^06   ^02^02^06^02^02^02^02^02^02^06 ^02^02^02^02^02^02^06") -ForegroundColor $gold

    # Row 1 - upper guard + title row 1 + upper blade edge

    Write-Host (Ex "      ^04 ^15^03") -ForegroundColor $hilt -NoNewline
    Write-Host (Ex "^02^02^07^03^03^03^03^05^02^02^07^03^03^03^03^05^02^02^07^03^03^03^03^05^02^02^07^03^03^03^03^05 ^02^02^04   ^02^02^04^02^02^07^03^03^02^02^06^02^02^07^03^03^02^02^06") -ForegroundColor $gold -NoNewline
    Write-Host (Ex "^03^03^03^03^03^03^18") -ForegroundColor $tip

    # Row 2 - pommel + grip + guard slot + title row 2 + blade through middle + tip

    Write-Host "(" -ForegroundColor $hilt -NoNewline
    Write-Host "o" -ForegroundColor $pommel -NoNewline
    Write-Host (Ex ")^03^03^03^19 ^04 ") -ForegroundColor $hilt -NoNewline
    Write-Host (Ex "^02^02^02^02^02^02^02^06^02^02^02^02^02^06  ^02^02^04     ^02^02^04  ^02^02^02^06^02^02^04   ^02^02^04^02^02^02^02^02^02^07^05^02^02^04  ^02^02^04") -ForegroundColor $gold -NoNewline
    Write-Host (Ex "^03^03^03^03^03^03^03^20") -ForegroundColor $tip

    # Row 3 - lower guard + title row 3 + lower blade edge

    Write-Host (Ex "      ^04 ^15^03") -ForegroundColor $hilt -NoNewline
    Write-Host (Ex "^08^03^03^03^03^02^02^04^02^02^07^03^03^05  ^02^02^04     ^02^02^04   ^02^02^04^02^02^04   ^02^02^04^02^02^07^03^03^02^02^06^02^02^04  ^02^02^04") -ForegroundColor $gold -NoNewline
    Write-Host (Ex "^03^03^03^03^03^03^21") -ForegroundColor $tip

    # Row 4 - bottom of crossguard + title row 4

    Write-Host (Ex "      ^08^03^05 ") -ForegroundColor $hilt -NoNewline
    Write-Host (Ex "^02^02^02^02^02^02^02^04^02^02^02^02^02^02^02^06^08^02^02^02^02^02^02^06^08^02^02^02^02^02^02^07^05^08^02^02^02^02^02^02^07^05^02^02^04  ^02^02^04^02^02^02^02^02^02^07^05") -ForegroundColor $gold

    # Row 5 - title row 5

    Write-Host (Ex "          ^08^03^03^03^03^03^03^05^08^03^03^03^03^03^03^05 ^08^03^03^03^03^03^05 ^08^03^03^03^03^03^05  ^08^03^03^03^03^03^05 ^08^03^05  ^08^03^05^08^03^03^03^03^03^05") -ForegroundColor $gold

    Write-Host ""
    Write-Flair (Ex "                ^13 Slayer of threats. Keeper of truth. ^13") '1;91' 'Red'
    Write-Host (Ex "                    ^22  F O R E N S I C   T R I A G E  ^22") -ForegroundColor $dim
    Write-Host ""
    Write-Host (Ex " ^12^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^11") -ForegroundColor $dim
    Write-Host ""

    # System info card

    $hostName  = $env:COMPUTERNAME
    $userName  = "$env:USERDOMAIN\$env:USERNAME"
    $isAdmin   = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $privLabel = if ($isAdmin) { 'ADMINISTRATOR' } else { 'STANDARD USER' }
    $privColor = if ($isAdmin) { $ok } else { $warn }
    $timeNow   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    Write-Host "  Host :  " -ForegroundColor $dim -NoNewline
    Write-Host ("{0,-22}" -f $hostName) -ForegroundColor $cyan -NoNewline
    Write-Host "Priv  :  " -ForegroundColor $dim -NoNewline
    Write-Host $privLabel -ForegroundColor $privColor

    Write-Host "  User :  " -ForegroundColor $dim -NoNewline
    Write-Host ("{0,-22}" -f $userName) -ForegroundColor $warn -NoNewline
    Write-Host "Version:  " -ForegroundColor $dim -NoNewline
    Write-Host $script:secgurdVersion -ForegroundColor $info

    Write-Host "  Time :  " -ForegroundColor $dim -NoNewline
    Write-Host ("{0,-22}" -f $timeNow) -ForegroundColor $info -NoNewline
    Write-Host "Output:  " -ForegroundColor $dim -NoNewline
    Write-Host $OutputPath -ForegroundColor $info

    Write-Host ""
    Write-Host (Ex " ^12^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^11") -ForegroundColor $dim
    Write-Host ""

    if (-not $isAdmin) {
        Write-Host (Ex "  ^16  Running without admin privileges ^09 some artifacts will be unavailable.") -ForegroundColor $warn
        Write-Host ""
    }
}

function Show-Help {
    Write-Host ""
    Write-Host (Ex "  secgurd $($script:secgurdVersion) ^09 Windows DFIR Triage") -ForegroundColor Cyan
    Write-Host (Ex "  ^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00") -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  USAGE" -ForegroundColor White
    Write-Host "    .\secgurd.ps1 [options]" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  OPTIONS" -ForegroundColor White
    Write-Host "    -Auto                 Run all modules, skip the menu (unattended)" -ForegroundColor Gray
    Write-Host "    -Modules 03,04,11     Run only specific modules" -ForegroundColor Gray
    Write-Host "    -OutputPath <path>    Custom output folder" -ForegroundColor Gray
    Write-Host "    -NoBanner             Suppress the ASCII banner" -ForegroundColor Gray
    Write-Host "    -OpenWhenDone         Open output folder in Explorer when finished" -ForegroundColor Gray
    Write-Host "    -Cleanup              Delete all secgurd output from TEMP (type-to-confirm)" -ForegroundColor Gray
    Write-Host "    -WithOwners           Include process owners in 06_process_tree (slower)" -ForegroundColor Gray
    Write-Host "    -WithSignatures       Verify Authenticode signatures (slow, may stall offline)" -ForegroundColor Gray
    Write-Host "    -WithTaskInfo         Resolve run times for ALL tasks incl. Microsoft (slow; off by default)" -ForegroundColor Gray
    Write-Host "    -IOCHashes <file>     Match on-disk binaries vs an MD5/SHA-1/SHA-256 IOC list" -ForegroundColor Gray
    Write-Host "    -CommunityIOCHashes <file>  Explicit path to the community hash list (else auto-found next to script)" -ForegroundColor Gray
    Write-Host "    -CommunityMalUrls <file>    Explicit path to the community malicious-URL list (else auto-found next to script)" -ForegroundColor Gray
    Write-Host "    -SquatDomains <file>        Explicit path to the openSquat squat-domain watchlist (else auto-found next to script)" -ForegroundColor Gray
    Write-Host "    -DaysBack <N>         Lookback window for time-bounded collectors (default 30)" -ForegroundColor Gray
    Write-Host "    -Find <string>        Filter ALL output to lines/items containing <string> (e.g. SmartPDF)" -ForegroundColor Gray
    Write-Host "    -MakeS1Paste          Copy a compressed (gzip+Base64) paste-ready version for the S1 shell" -ForegroundColor Gray
    Write-Host "    -Help                 Show this help" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  MENU COMMANDS" -ForegroundColor White
    Write-Host "    01-14                 Toggle a module on/off (space/comma-separate many)" -ForegroundColor Gray
    Write-Host "    a / n                 Select all / none" -ForegroundColor Gray
    Write-Host "    qa / net / ps         Apply a preset" -ForegroundColor Gray
    Write-Host "    o                     Toggle: open output folder when done" -ForegroundColor Gray
    Write-Host "    deps                  Dependencies sub-menu: IOC hashes / malicious URLs / squat domains (load/paste/list/toggle)" -ForegroundColor Gray
    Write-Host "    d                     Set lookback window in days (time-bounded collectors)" -ForegroundColor Gray
    Write-Host "    f                     Find/filter: scope all output to a name/string (blank clears)" -ForegroundColor Gray
    Write-Host "    p                     Pastable version for remote shells - single/chunked/compressed" -ForegroundColor Gray
    Write-Host "    r                     Run selected modules" -ForegroundColor Gray
    Write-Host "    q                     Quit" -ForegroundColor Gray
    Write-Host "    cleanup               Remove ALL secgurd artifacts from TEMP (type-to-confirm)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  REMOTE ONE-LINER" -ForegroundColor White
    Write-Host "    iex (irm https://raw.githubusercontent.com/<you>/secgurd/main/secgurd.ps1)" -ForegroundColor Gray
    Write-Host ""
}

if ($Help) {
    if (-not $NoBanner) { Show-secgurdBanner }
    Show-Help
    return
}

# ---------------------------------------------
#  CLEANUP MODE  (-Cleanup)
# ---------------------------------------------

function Invoke-Cleanup {
    param([switch]$SkipBanner)   # menu path shows its own compact banner, so skip the big one
    # Finds EVERY secgurd artifact under %TEMP% and deletes them, gated behind a type-to-confirm
    # prompt so it can't fire accidentally. Targets: the script itself (secgurd.ps1, e.g. the copy
    # unpacked on an endpoint), output folders (secgurd_<host>_<ts>) and their .zip archives, the
    # SentinelOne paste text files (secgurd_s1_*.txt), and the auto-loaded lists
    # (communitysavedIOCS.txt, communitysavedMALURLS.txt, squat_domains.txt, manualIOCS.txt).
    if (-not $NoBanner -and -not $SkipBanner) { Show-secgurdBanner }

    $patterns = @(
        'secgurd*'                      # secgurd.ps1 + secgurd_<host>_<ts> folders + .zip + secgurd_s1_*.txt
        'communitysavedIOCS.txt'
        'communitysavedMALURLS.txt'
        'squat_domains.txt'
        'manualIOCS.txt'
    )
    $items = @(foreach ($p in $patterns) { Get-ChildItem (Join-Path $env:TEMP $p) -Force -ErrorAction SilentlyContinue }) |
        Sort-Object FullName -Unique

    Write-Host ""
    Write-Host "  CLEANUP - remove ALL secgurd artifacts from this machine" -ForegroundColor Cyan
    Write-Host "  ----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Location: $env:TEMP" -ForegroundColor DarkGray
    Write-Host ""

    if (-not $items) {
        Write-Host "  Nothing to clean - no secgurd artifacts found in TEMP." -ForegroundColor Green
        Write-Host ""
        return
    }

    # List what would be deleted, with sizes
    $totalBytes = 0
    foreach ($it in $items) {
        if ($it.PSIsContainer) {
            $size = (Get-ChildItem $it.FullName -Recurse -Force -ErrorAction SilentlyContinue |
                     Measure-Object -Property Length -Sum).Sum
            $kind = 'folder'
        } else {
            $size = $it.Length
            $kind = 'file  '
        }
        $totalBytes += [int64]$size
        Write-Host ("   {0}  {1,-50} {2,8:N0} KB" -f $kind, $it.Name, ($size/1KB)) -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host ("  {0} item(s), {1:N1} MB total" -f $items.Count, ($totalBytes/1MB)) -ForegroundColor White
    Write-Host ""

    # Non-interactive safety: refuse only when we genuinely can't read the type-to-confirm input
    # (redirected stdin in a non-interactive session). The S1 remote shell (ServerRemoteHost) IS
    # interactive - it supports Read-Host - so we allow it there, matching the menu's behavior.
    $canRead = $true
    try { if ([Console]::IsInputRedirected -and -not [Environment]::UserInteractive) { $canRead = $false } } catch {}
    if (-not $canRead) {
        Write-Host "  Refusing to delete in a non-interactive session." -ForegroundColor Yellow
        Write-Host "  Run interactively, or delete manually:" -ForegroundColor DarkGray
        Write-Host "    Remove-Item `"`$env:TEMP\secgurd*`",`"`$env:TEMP\communitysaved*.txt`",`"`$env:TEMP\manualIOCS.txt`" -Recurse -Force -ErrorAction SilentlyContinue" -ForegroundColor DarkGray
        Write-Host ""
        return
    }

    # Two-step type-to-confirm
    Write-Flair "  This permanently deletes the items above. This cannot be undone." '1;91' 'Red'
    Write-Host ""
    Write-Host "  To confirm, type:  " -ForegroundColor DarkGray -NoNewline
    Write-Host "DELETE" -ForegroundColor Yellow -NoNewline
    Write-Host "  (any case; anything else cancels)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  > " -ForegroundColor DarkGray -NoNewline
    $confirm = Read-Host

    # Case-insensitive (and whitespace-tolerant): DELETE / delete / Delete all confirm.
    if ("$confirm".Trim() -ne 'DELETE') {
        Write-Host ""
        Write-Host "  Cancelled - nothing was deleted." -ForegroundColor Green
        Write-Host ""
        return
    }

    $removed = 0; $failed = 0
    foreach ($it in $items) {
        try {
            Remove-Item $it.FullName -Recurse -Force -ErrorAction Stop
            $removed++
        } catch {
            Write-Host "  [!] Could not remove: $($it.Name) - $($_.Exception.Message)" -ForegroundColor Yellow
            $failed++
        }
    }
    Write-Host ""
    Write-Host "  Removed $removed item(s)." -ForegroundColor Green -NoNewline
    if ($failed -gt 0) { Write-Host "  ($failed failed - may be in use)" -ForegroundColor Yellow }
    else { Write-Host "" }
    Write-Flair "  The hoard is scattered. Cleanup complete." '1;92' 'Green'
    Write-Host ""
}

if ($Cleanup) {
    Invoke-Cleanup
    return
}

if (-not $NoBanner) { Show-secgurdBanner }

$script:ModuleCatalogue = @(
    [PSCustomObject]@{ Id='01'; Name='System info';          Desc='os, build, uptime, domain, env' }
    [PSCustomObject]@{ Id='02'; Name='Users & sessions';     Desc='accounts, logons, rdp in/out' }
    [PSCustomObject]@{ Id='03'; Name='Persistence';          Desc='run keys, runmru/clickfix, tasks, services, wmi, ifeo, rmm, bits' }
    [PSCustomObject]@{ Id='04'; Name='PowerShell artifacts'; Desc='history, transcripts, 4104, secrets' }
    [PSCustomObject]@{ Id='05'; Name='Network';              Desc='connections, dns, arp, shares, fw' }
    [PSCustomObject]@{ Id='06'; Name='Processes';            Desc='proctree, cmdlines, odd-path dlls' }
    [PSCustomObject]@{ Id='07'; Name='Filesystem';           Desc='temp exes, ads, download origins, recycle bin' }
    [PSCustomObject]@{ Id='08'; Name='Event logs';           Desc='account changes, log clearing' }
    [PSCustomObject]@{ Id='09'; Name='Software & defender';  Desc='installed apps, patches, defender posture' }
    [PSCustomObject]@{ Id='10'; Name='Browser & creds';      Desc='history+url analysis, extensions, .ssh/.aws' }
    [PSCustomObject]@{ Id='11'; Name='LOLBins';              Desc='certutil, mshta, rundll32 in 4688' }
    [PSCustomObject]@{ Id='12'; Name='AmCache / ShimCache';  Desc='execution artifact locations' }
    [PSCustomObject]@{ Id='13'; Name='Prefetch';             Desc='.pf files, last run times' }
    [PSCustomObject]@{ Id='14'; Name='Named pipes';          Desc='active pipes, c2 detection' }
)

$script:Presets = @{
    'qa'  = @{ Label='Quick attack triage'; Modules=@('03','04','06','11'); Desc='persistence, ps, procs, lolbins' }
    'net' = @{ Label='Network-focused';     Modules=@('05','06','14');      Desc='conn, procs, named pipes' }
    'ps'  = @{ Label='PowerShell forensics'; Modules=@('04');               Desc='ps history & transcripts' }
}

$script:SelectedModules = @{}
foreach ($m in $script:ModuleCatalogue) { $script:SelectedModules[$m.Id] = $false }

# ---------------------------------------------

#  INTERACTIVE MENU

# ---------------------------------------------

function ConvertFrom-IOCText {
    # Parse free-form IOC text into a hashtable: UPPERCASE-hash -> label.
    # Accepts hashes separated by commas, spaces, newlines, semicolons, or pipes - so you
    # can paste 'hash, hash, hash' OR one-per-line OR any mix. A token of 32 (MD5), 40 (SHA-1),
    # or 64 (SHA-256) hex chars is a hash; if the NEXT token isn't itself a hash, it's treated
    # as that hash's label.
    param([string]$Text)
    $set = @{}
    if (-not $Text) { return $set }
    $hashRx = '^[0-9A-F]{32}$|^[0-9A-F]{40}$|^[0-9A-F]{64}$'
    # strip comment lines first
    $clean = ($Text -split "`r?`n" | Where-Object { -not $_.TrimStart().StartsWith('#') }) -join "`n"
    # tokenize on commas / whitespace / semicolons / pipes
    $tokens = $clean -split '[,;\s|]+' | Where-Object { $_ -ne '' }
    for ($i = 0; $i -lt $tokens.Count; $i++) {
        $t = $tokens[$i].Trim().ToUpper()
        if ($t -match $hashRx) {
            # peek at the next token; if it's NOT a hash, use it as this hash's label
            $label = ''
            if ($i + 1 -lt $tokens.Count -and $tokens[$i+1].ToUpper() -notmatch $hashRx) {
                $label = $tokens[$i+1].Trim()
                $i++   # consume the label token
            }
            $set[$t] = $label
        }
    }
    return $set
}

function Import-IOCHashes {
    # Load known-bad SHA-256 hashes from a FILE. Delegates parsing to ConvertFrom-IOCText so
    # the file can use any delimiter (one-per-line, comma-separated, "hash,label", etc.).
    param([string]$Path)
    try { return ConvertFrom-IOCText (Get-Content $Path -Raw -ErrorAction Stop) }
    catch { return @{} }
}

function Get-MalUrlHost {
    # Minimal, self-contained host extraction for the malicious-URL loader. Kept separate from
    # Get-UrlHost (defined much later in the file) so this can run during early script setup,
    # before that function exists. Lowercases, drops scheme/userinfo/port/path. Returns '' on miss.
    param([string]$Url)
    if (-not $Url) { return '' }
    $h = $Url.Trim().ToLower()
    $h = $h -replace '^[a-z][a-z0-9+.-]*://', ''   # strip scheme
    $h = ($h -split '[/?#]', 2)[0]                 # drop path/query/fragment
    if ($h -match '@') { $h = ($h -split '@', 2)[-1] }  # drop userinfo
    $h = ($h -split ':', 2)[0]                      # drop port
    return $h.Trim('.')
}

function Get-NormalizedDomain {
    # Normalize a domain watchlist entry OR a host for comparison: lowercase, defensively strip any
    # leading scheme / userinfo / port / path, and drop a leading 'www.'. Returns '' if unusable.
    # (openSquat writes bare domains, but we normalize anyway so a stray scheme/path never slips in.)
    param([string]$Value)
    if (-not $Value) { return '' }
    $d = $Value.Trim().ToLower()
    $d = $d -replace '^[a-z][a-z0-9+.-]*://', ''   # strip scheme
    $d = ($d -split '[/?#]', 2)[0]                 # drop path/query/fragment
    if ($d -match '@') { $d = ($d -split '@', 2)[-1] }  # drop userinfo
    $d = ($d -split ':', 2)[0]                      # drop port
    $d = $d -replace '^www\.', ''                   # drop leading www.
    return $d.Trim('.')
}

function Import-SquatDomains {
    # Load the squat-domain watchlist from a FILE (squat_domains.txt, openSquat output). One domain
    # per line; blank lines and '#' comment lines are skipped; each entry is normalized and deduped
    # into a HashSet[string] (OrdinalIgnoreCase). Returns the set (empty on any read error).
    param([string]$Path)
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    try { $lines = Get-Content -LiteralPath $Path -ErrorAction Stop }
    catch { return $set }
    foreach ($line in $lines) {
        $t = $line.Trim()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        $d = Get-NormalizedDomain $t
        if ($d) { [void]$set.Add($d) }
    }
    return $set
}

function Test-SquatHost {
    # Return the matched watchlist domain if $HostName is on the squat watchlist - either an exact
    # match, or a subdomain of a watched entry (login.example-brand.com matches example-brand.com) -
    # else $null. Case-insensitive. (Param is $HostName, NOT $Host: $Host is a PowerShell automatic.)
    param([string]$HostName)
    if (-not $HostName -or -not $script:SquatDomainSet -or $script:SquatDomainSet.Count -eq 0) { return $null }
    $h = Get-NormalizedDomain $HostName
    if (-not $h) { return $null }
    if ($script:SquatDomainSet.Contains($h)) { return $h }
    foreach ($d in $script:SquatDomainSet) {
        if ($h.EndsWith('.' + $d)) { return $d }
    }
    return $null
}

function ConvertFrom-MalUrlText {
    # Parse malicious-URL text into @{ Urls = <HashSet full-url>; Hosts = <HashSet host> }.
    # Accepts the file format ("<url>,<label>" per line - the label is comma-free, so the URL is
    # everything before the LAST comma, since URLs themselves may contain commas) AND pasted
    # bare-URL lists (one per line, or several space-separated on a comma-free line). '#' lines
    # are ignored.
    param([string]$Text)
    $urls  = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $hosts = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    if (-not $Text) { return @{ Urls = $urls; Hosts = $hosts } }
    foreach ($line in ($Text -split "`r?`n")) {
        $t = $line.Trim()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        # A comma-free line may hold several space-separated bare URLs; a line WITH a comma is a
        # single "<url>,<label>" entry (URLs can contain commas, so we split on the LAST one).
        if ($t.Contains(',')) {
            $comma = $t.LastIndexOf(',')
            $entries = @($t.Substring(0, $comma).Trim())
        } else {
            $entries = @($t -split '\s+')
        }
        foreach ($u in $entries) {
            if ($u -notmatch '^(?i)https?://') { continue }
            $norm = $u.ToLower().TrimEnd('/')
            [void]$urls.Add($norm)
            $mh = Get-MalUrlHost $u
            if ($mh) { [void]$hosts.Add($mh) }
        }
    }
    return @{ Urls = $urls; Hosts = $hosts }
}

function Import-MalUrls {
    # Load community malicious URLs from a FILE (communitysavedMALURLS.txt, abuse.ch URLhaus feed).
    # Delegates parsing to ConvertFrom-MalUrlText. Returns @{ Urls; Hosts } (empty on error).
    param([string]$Path)
    try { return ConvertFrom-MalUrlText (Get-Content -LiteralPath $Path -Raw -ErrorAction Stop) }
    catch {
        return @{
            Urls  = (New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase))
            Hosts = (New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase))
        }
    }
}

function Show-MalUrlList {
    # Print the currently-loaded community malicious URLs (capped at 50 for readability).
    if (-not $script:MalUrlSet -or $script:MalUrlCount -le 0) {
        Write-Host ""
        Write-Host "  No malicious URLs loaded." -ForegroundColor DarkGray
        Write-Host ""
        return
    }
    Write-Host ""
    Write-Host "  " -NoNewline
    Write-Host (Ex "[^14] ") -ForegroundColor Green -NoNewline
    Write-Host "COMMUNITY malicious URLs" -ForegroundColor White -NoNewline
    Write-Host "   source: $($script:MalUrlFile)" -ForegroundColor DarkGray
    Write-Host "  $('-' * 64)" -ForegroundColor DarkGray
    $n = 0
    foreach ($u in ($script:MalUrlSet | Sort-Object)) {
        $n++
        $short = if ($u.Length -gt 72) { $u.Substring(0, 69) + '...' } else { $u }
        Write-Host ("   {0,3}. " -f $n) -ForegroundColor DarkGray -NoNewline
        Write-Host $short -ForegroundColor Gray
        if ($n -ge 50) {
            Write-Host ("        ... and $($script:MalUrlCount - 50) more") -ForegroundColor DarkGray
            break
        }
    }
    Write-Host "  $('-' * 64)" -ForegroundColor DarkGray
    Write-Host "  $($script:MalUrlCount) URL(s), $($script:MalUrlHostSet.Count) unique host(s)." -ForegroundColor DarkGray
    Write-Host "  Matched against browser-history URLs in module 10 at run time." -ForegroundColor DarkGray
    Write-Host ""
}

function Show-IOCList {
    # Print the currently-loaded IOC hashes, grouped by source (community vs. ones you added).
    $haveComm = ($script:CommunityHashSet -and $script:CommunityHashCount -gt 0)
    $haveMan  = ($script:IOCHashSet -and $script:IOCHashCount -gt 0)
    if (-not $haveComm -and -not $haveMan) {
        Write-Host ""
        Write-Host "  No IOC hashes loaded." -ForegroundColor DarkGray
        Write-Host ""
        return
    }

    # Inner helper to print one source's hashes (capped at 50 for readability).
    $printSet = {
        param($title, $set, $count, $src)
        Write-Host ""
        Write-Host "  " -NoNewline
        Write-Host (Ex "[^14] ") -ForegroundColor Green -NoNewline
        Write-Host $title -ForegroundColor White -NoNewline
        Write-Host "   source: $src" -ForegroundColor DarkGray
        Write-Host "  $('-' * 64)" -ForegroundColor DarkGray
        $n = 0
        foreach ($h in ($set.Keys | Sort-Object)) {
            $n++
            $label = $set[$h]
            $algo = switch ($h.Length) { 32 {'MD5'} 40 {'SHA1'} 64 {'SHA256'} default {'?'} }
            $short = if ($h.Length -gt 40) { $h.Substring(0,16) + '...' + $h.Substring($h.Length-8) } else { $h }
            Write-Host ("   {0,3}. " -f $n) -ForegroundColor DarkGray -NoNewline
            Write-Host ("{0,-7}" -f $algo) -ForegroundColor DarkCyan -NoNewline
            Write-Host $short -ForegroundColor Gray -NoNewline
            if ($label) { Write-Host "  [$label]" -ForegroundColor DarkCyan } else { Write-Host "" }
            if ($n -ge 50) {
                Write-Host ("        ... and $($count - 50) more") -ForegroundColor DarkGray
                break
            }
        }
        Write-Host "  $('-' * 64)" -ForegroundColor DarkGray
        Write-Host "  $count hash(es)." -ForegroundColor DarkGray
    }

    if ($haveComm) { & $printSet 'COMMUNITY hashes (from communitysavedIOCS.txt)' $script:CommunityHashSet $script:CommunityHashCount $script:CommunityHashFile }
    if ($haveMan)  { & $printSet 'HASHES YOU ADDED' $script:IOCHashSet $script:IOCHashCount $script:IOCHashFile }
    Write-Host ""
    Write-Host "  Both lists are matched against on-disk binaries at run time." -ForegroundColor DarkGray
    Write-Host ""
}

function Compress-Source {
    # Shrink a PowerShell source string for the compressed remote-shell paste WITHOUT changing what
    # it does. Three safe passes only:
    #   1) strip comments       - tokenizer-classified, so a '#' inside a string is never touched
    #   2) alias common cmdlets - only in command position, from a curated Win-PS-5.1 alias map
    #   3) strip indentation + blank lines - only when the source has NO multi-line string literals
    # Variable renaming is deliberately NOT done: names live inside expandable strings, and $script:
    # scope + param() binding make an automatic rename unsafe - and gzip already collapses repeated
    # names, so the post-compression saving would be negligible anyway. On ANY tokenizer error, or if
    # a pass can't be proven safe, the input is returned unchanged: a correct big paste beats a
    # broken small one.
    param([string]$Text)
    if (-not $Text) { return $Text }

    $errs = $null
    $toks = $null
    try { $toks = [System.Management.Automation.PSParser]::Tokenize($Text, [ref]$errs) } catch { return $Text }
    if (-not $toks -or ($errs -and $errs.Count)) { return $Text }

    # Curated map: long cmdlet -> shortest alias guaranteed to exist in Windows PowerShell 5.1.
    $alias = @{
        'Get-ChildItem'    = 'gci'
        'Get-ItemProperty' = 'gp'
        'Get-Item'         = 'gi'
        'Get-Content'      = 'gc'
        'Get-Command'      = 'gcm'
        'Where-Object'     = '?'
        'ForEach-Object'   = '%'
        'Select-Object'    = 'select'
        'Sort-Object'      = 'sort'
        'Measure-Object'   = 'measure'
        'Format-Table'     = 'ft'
        'Format-List'      = 'fl'
    }

    # Any multi-line string literal? If so, touching line whitespace would corrupt its contents, so
    # we skip pass 3. secgurd is written without them, but this keeps the helper safe if that changes.
    $hasMultiLineStr = $false
    foreach ($t in $toks) {
        if ($t.Type -eq 'String' -and $t.Content -and $t.Content.Contains("`n")) { $hasMultiLineStr = $true; break }
    }

    # Pass 1+2: offset-based edits (remove comments, apply aliases). Apply END-first so earlier
    # offsets stay valid as we mutate the buffer.
    $edits = New-Object System.Collections.Generic.List[object]
    foreach ($t in $toks) {
        if ($t.Type -eq 'Comment') {
            $edits.Add([PSCustomObject]@{ S = $t.Start; L = $t.Length; R = '' })
        } elseif ($t.Type -eq 'Command' -and $alias.ContainsKey($t.Content)) {
            $edits.Add([PSCustomObject]@{ S = $t.Start; L = $t.Length; R = $alias[$t.Content] })
        }
    }
    $sb = New-Object System.Text.StringBuilder($Text)
    foreach ($e in ($edits | Sort-Object S -Descending)) {
        [void]$sb.Remove($e.S, $e.L)
        if ($e.R) { [void]$sb.Insert($e.S, $e.R) }
    }
    $out = $sb.ToString()

    # Pass 3: strip indentation + blank lines. Skipped when a multi-line string exists (see above).
    if (-not $hasMultiLineStr) {
        $keep = New-Object System.Collections.Generic.List[string]
        foreach ($ln in ($out -split "`r?`n")) {
            $tr = $ln.Trim()
            if ($tr -ne '') { [void]$keep.Add($tr) }
        }
        $out = ($keep -join "`n")
    }
    return $out
}

function Show-S1Compressed {
    # Compressed SINGLE paste (Compress-Source -> gzip -> Base64), one block, decompressed on the
    # target. -Mode controls what rides along:
    #   'all'    - secgurd.ps1 + community IOC + malicious-URL + squat-domain lists + your manual list
    #   'script' - secgurd.ps1 ONLY (smallest; add the dependency lists later with the 'lists' block)
    #   'lists'  - dependency lists ONLY (IOC + malicious-URL + squat, no script) - paste after a
    #              'script' block to drop the intel next to secgurd.ps1 in %TEMP% and re-run with it
    # The wrapper writes each bundled file to %TEMP% and, if secgurd.ps1 is present there, runs it
    # in-session (scriptblock, so a Restricted execution policy can't block it) passing whatever
    # IOC/URL lists exist in %TEMP% - so the pieces compose no matter which order you paste them.
    # NOTE: uses FromBase64String + GzipStream decode (stronger pattern than plain text). If your
    # EDR flags it, fall back to the chunked plain-text option [2].
    param([ValidateSet('all', 'script', 'lists')][string]$Mode = 'all')

    $includeScript    = ($Mode -eq 'all' -or $Mode -eq 'script')
    $includeCommunity = ($Mode -eq 'all' -or $Mode -eq 'lists')
    $includeManual    = ($Mode -eq 'all')

    $MK = ('<' * 3) + 'SG' + 'FILE' + ':'
    $END = ('>' * 3)
    $container = New-Object System.Text.StringBuilder
    $bundled = @()
    $origLen = 0
    $newLen = 0

    if ($includeScript) {
        $src = $null
        if ($PSCommandPath -and (Test-Path $PSCommandPath)) {
            try { $src = Get-Content -LiteralPath $PSCommandPath -Raw -ErrorAction Stop } catch {}
        }
        if (-not $src) {
            try { $src = $MyInvocation.MyCommand.ScriptBlock.Ast.Extent.Text } catch {}
        }
        if (-not $src) {
            Write-Host "  Could not read secgurd's own source to build the compressed paste." -ForegroundColor Yellow
            return
        }
        # Compact the source before packing (strip comments/indentation/blanks, alias cmdlets) so the
        # paste comes out smaller. Compress-Source fails safe (returns source unchanged on any error).
        $origLen = $src.Length
        try { $src = Compress-Source $src } catch {}
        $newLen = $src.Length
        [void]$container.AppendLine($MK + 'secgurd.ps1' + $END)
        [void]$container.Append($src)
        if (-not $src.EndsWith("`n")) { [void]$container.AppendLine('') }
        $bundled += 'secgurd.ps1'
    }

    if ($includeCommunity) {
        # community IOC list (rides along so the air-gapped box gets current IOCs)
        if ($script:CommunityHashFile -and (Test-Path $script:CommunityHashFile)) {
            try {
                $cTxt = Get-Content -LiteralPath $script:CommunityHashFile -Raw -ErrorAction Stop
                [void]$container.AppendLine($MK + 'communitysavedIOCS.txt' + $END)
                [void]$container.Append($cTxt)
                if (-not $cTxt.EndsWith("`n")) { [void]$container.AppendLine('') }
                $bundled += "communitysavedIOCS.txt ($($script:CommunityHashCount) hashes)"
            } catch {}
        }
        # community malicious-URL list (rides along so the air-gapped box gets current URLhaus URLs)
        if ($script:MalUrlFile -and (Test-Path $script:MalUrlFile)) {
            try {
                $uTxt = Get-Content -LiteralPath $script:MalUrlFile -Raw -ErrorAction Stop
                [void]$container.AppendLine($MK + 'communitysavedMALURLS.txt' + $END)
                [void]$container.Append($uTxt)
                if (-not $uTxt.EndsWith("`n")) { [void]$container.AppendLine('') }
                $bundled += "communitysavedMALURLS.txt ($($script:MalUrlCount) URLs)"
            } catch {}
        }
        # squat-domain watchlist (rides along so the air-gapped box gets the current openSquat list)
        if ($script:SquatDomainFile -and (Test-Path $script:SquatDomainFile)) {
            try {
                $sqTxt = Get-Content -LiteralPath $script:SquatDomainFile -Raw -ErrorAction Stop
                [void]$container.AppendLine($MK + 'squat_domains.txt' + $END)
                [void]$container.Append($sqTxt)
                if (-not $sqTxt.EndsWith("`n")) { [void]$container.AppendLine('') }
                $bundled += "squat_domains.txt ($($script:SquatDomainCount) domains)"
            } catch {}
        }
    }

    if ($includeManual) {
        # manual list (whatever you loaded via -IOCHashes / the i menu)
        if ($script:IOCHashFile -and (Test-Path $script:IOCHashFile)) {
            try {
                $mTxt = Get-Content -LiteralPath $script:IOCHashFile -Raw -ErrorAction Stop
                [void]$container.AppendLine($MK + 'manualIOCS.txt' + $END)
                [void]$container.Append($mTxt)
                if (-not $mTxt.EndsWith("`n")) { [void]$container.AppendLine('') }
                $bundled += "manualIOCS.txt ($($script:IOCHashCount) hashes)"
            } catch {}
        }
    }

    if ($bundled.Count -eq 0) {
        Write-Host ""
        Write-Host "  Nothing to pack for this option." -ForegroundColor Yellow
        if ($Mode -eq 'lists') {
            Write-Host "  No community IOC / malicious-URL / squat-domain list is loaded to bundle." -ForegroundColor DarkGray
        }
        Write-Host ""
        return
    }

    # Gzip-compress the whole container, then Base64-encode.
    $bytes = [Text.Encoding]::UTF8.GetBytes($container.ToString())
    $ms = New-Object System.IO.MemoryStream
    $gz = New-Object System.IO.Compression.GzipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
    $gz.Write($bytes, 0, $bytes.Length)
    $gz.Close()
    $b64 = [Convert]::ToBase64String($ms.ToArray())
    $ms.Dispose()

    # The paste block: decompress the container, split on markers, write each file to %TEMP%,
    # then run secgurd.ps1. Manual list (if present) is passed via -IOCHashes; the community
    # list is auto-loaded because it sits next to secgurd.ps1 in %TEMP%.
    # The target rebuilds the marker from fragments at runtime (same as the pack side) so the
    # literal full marker never appears in this script's own source.
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('$b=')
    [void]$sb.Append("'$b64'")
    [void]$sb.Append('; $g=[IO.Compression.GzipStream]::new([IO.MemoryStream]::new([Convert]::FromBase64String($b)),[IO.Compression.CompressionMode]::Decompress); ')
    [void]$sb.Append('$o=[IO.MemoryStream]::new(); $g.CopyTo($o); $t=[Text.Encoding]::UTF8.GetString($o.ToArray()); ')
    # rebuild marker + end-token from fragments (mirrors the pack side)
    [void]$sb.Append('$mk=(''<''*3)+''SG''+''FILE''+'':''; $en=(''>''*3); ')
    [void]$sb.Append('$parts=$t -split [regex]::Escape($mk); $wrote=@(); ')
    [void]$sb.Append('foreach($p in $parts){ if(-not $p){continue}; ')
    [void]$sb.Append('$nl=$p.IndexOf($en); if($nl -lt 0){continue}; ')
    [void]$sb.Append('$fn=$p.Substring(0,$nl); $body=$p.Substring($nl+$en.Length); if($body.StartsWith("`r`n")){$body=$body.Substring(2)}elseif($body.StartsWith("`n")){$body=$body.Substring(1)}; ')
    [void]$sb.Append('$fp=Join-Path $env:TEMP $fn; [IO.File]::WriteAllText($fp,$body); $wrote+=("{0} ({1:N0} bytes)" -f $fn,(Get-Item $fp).Length) }; ')
    [void]$sb.Append('Write-Host ""; Write-Host ("  unpacked to {0}:" -f $env:TEMP) -ForegroundColor Cyan; foreach($w in $wrote){ Write-Host "    + $w" -ForegroundColor DarkGray }; Write-Host ""; ')
    [void]$sb.Append('$man=Join-Path $env:TEMP "manualIOCS.txt"; ')
    [void]$sb.Append('$com=Join-Path $env:TEMP "communitysavedIOCS.txt"; ')
    [void]$sb.Append('$mal=Join-Path $env:TEMP "communitysavedMALURLS.txt"; ')
    [void]$sb.Append('$sq=Join-Path $env:TEMP "squat_domains.txt"; ')
    [void]$sb.Append('$sg=Join-Path $env:TEMP "secgurd.ps1"; ')
    # Run secgurd IN THE CURRENT SESSION (like the single-paste option) rather than spawning a
    # child powershell.exe: in the SentinelOne remote shell a child interactive process doesn't
    # repaint on the first Enter - it leaves the pasted text on screen and only shows the prompt.
    # We execute it as a SCRIPTBLOCK built from the file text (not `& $sg`, which loads a .ps1
    # FILE and is blocked by a Restricted execution policy). Execution policy only gates script
    # files, never in-memory scriptblocks - so this runs even where "running scripts is disabled".
    # Clear-Host first wipes the pasted block; IOC lists are passed via splatting.
    [void]$sb.Append('$sgArgs=@{}; if(Test-Path $com){$sgArgs["CommunityIOCHashes"]=$com}; if(Test-Path $mal){$sgArgs["CommunityMalUrls"]=$mal}; if(Test-Path $sq){$sgArgs["SquatDomains"]=$sq}; if(Test-Path $man){$sgArgs["IOCHashes"]=$man}; ')
    # Run secgurd only if it's actually in %TEMP% (it is right after a script/all paste; for a
    # lists-only paste it may not be yet). Otherwise the files are just staged for the next run.
    [void]$sb.Append('if(Test-Path $sg){ Clear-Host; & ([ScriptBlock]::Create([IO.File]::ReadAllText($sg))) @sgArgs } else { Write-Host "  Lists staged in %TEMP%. Now paste the [3] SCRIPT ONLY block to run secgurd - it will pick these up." -ForegroundColor Yellow }')
    $block = $sb.ToString()

    # Mode-specific labels / fallback filename (all names match the secgurd_s1_* cleanup glob).
    switch ($Mode) {
        'script' { $title = 'Compressed single paste  (script only)';                    $outName = 'secgurd_s1_script.txt' }
        'lists'  { $title = 'Compressed single paste  (dependency lists only: IOC + malicious-URL + squat)'; $outName = 'secgurd_s1_lists.txt' }
        default  { $title = 'Compressed single paste  (script + all IOC/URL/squat lists)';      $outName = 'secgurd_s1_compressed.txt' }
    }

    # Save a file fallback.
    $outFile = Join-Path $env:TEMP $outName
    $wrote = $false
    try { $block | Out-File -FilePath $outFile -Encoding UTF8 -Force; $wrote = $true } catch {}

    # Copy to clipboard.
    $copied = $false
    if (Get-Command Set-Clipboard -ErrorAction SilentlyContinue) {
        try { Set-Clipboard -Value $block -ErrorAction Stop; $copied = $true } catch {}
    }
    if (-not $copied) { try { $block | clip.exe; $copied = $true } catch {} }

    Clear-Host
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor DarkGray
    Write-Host "   $title" -ForegroundColor Cyan
    Write-Host "  ============================================================" -ForegroundColor DarkGray
    $kb = [Math]::Round($block.Length / 1KB)
    if ($copied) {
        Write-Host (Ex "  [^14] Copied to clipboard") -ForegroundColor Green -NoNewline
        Write-Host "  (~$kb KB, one paste)" -ForegroundColor DarkGray
    } else {
        Write-Host (Ex "  ^16 Clipboard not available - use the saved file below.") -ForegroundColor Yellow
    }
    if ($origLen -gt 0 -and $newLen -lt $origLen) {
        $pct = [Math]::Round((1 - ($newLen / $origLen)) * 100)
        Write-Host ("  Source compacted before packing: {0:N0} -> {1:N0} chars (-{2}%)" -f $origLen, $newLen, $pct) -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host "  Bundled into the paste:" -ForegroundColor Gray
    foreach ($b in $bundled) { Write-Host "    - $b" -ForegroundColor DarkGray }
    Write-Host ""
    if ($Mode -eq 'lists') {
        Write-Host "  Paste this into the S1 shell FIRST to drop the community lists into %TEMP%, then" -ForegroundColor Gray
        Write-Host "  paste the [3] SCRIPT ONLY block - it runs secgurd and picks these lists up. (If" -ForegroundColor Gray
        Write-Host "  secgurd.ps1 is already in %TEMP%, this re-runs it with the lists right away.)" -ForegroundColor Gray
    } elseif ($Mode -eq 'script') {
        Write-Host "  Paste this into the S1 shell and press Enter - it unpacks secgurd.ps1 into %TEMP%" -ForegroundColor Gray
        Write-Host "  and runs it. For the community IOC/URL lists, paste [2] BEFORE this one." -ForegroundColor Gray
    } else {
        Write-Host "  Paste the single block into the S1 shell and press Enter. It unpacks" -ForegroundColor Gray
        Write-Host "  secgurd + the IOC list(s) into %TEMP% and runs it - IOC matching works" -ForegroundColor Gray
        Write-Host "  offline, no git pull needed on the target." -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "  NOTE: gzip+Base64 decode. If your EDR flags it, use option [2] instead." -ForegroundColor DarkGray
    Write-Host ""
    if ($wrote) {
        Write-Host "  Also saved to: $outFile" -ForegroundColor DarkGray
        Write-Host ""
    }
}

function Show-SquatList {
    # Print the currently-loaded squat-domain watchlist (capped at 50 for readability).
    if (-not $script:SquatDomainSet -or $script:SquatDomainCount -le 0) {
        Write-Host ""
        Write-Host "  No squat domains loaded." -ForegroundColor DarkGray
        Write-Host ""
        return
    }
    Write-Host ""
    Write-Host "  " -NoNewline
    Write-Host (Ex "[^14] ") -ForegroundColor Green -NoNewline
    Write-Host "SQUAT-DOMAIN WATCHLIST" -ForegroundColor White -NoNewline
    Write-Host "   source: $($script:SquatDomainFile)" -ForegroundColor DarkGray
    Write-Host "  $('-' * 64)" -ForegroundColor DarkGray
    $n = 0
    foreach ($d in ($script:SquatDomainSet | Sort-Object)) {
        $n++
        Write-Host ("   {0,3}. " -f $n) -ForegroundColor DarkGray -NoNewline
        Write-Host $d -ForegroundColor Gray
        if ($n -ge 50) {
            Write-Host ("        ... and $($script:SquatDomainCount - 50) more") -ForegroundColor DarkGray
            break
        }
    }
    Write-Host "  $('-' * 64)" -ForegroundColor DarkGray
    Write-Host "  $($script:SquatDomainCount) domain(s). Matched against module-10 hosts at run time." -ForegroundColor DarkGray
    Write-Host ""
}

function Invoke-IOCDependency {
    # Manage the IOC hash list (the manual set you add; the community list auto-loads separately).
    # Returns a status message string for the Dependencies menu to echo (or $null).
    $iocLoaded = ($script:IOCHashSet -and $script:IOCHashCount -gt 0)
    Write-Host ""
    Write-Host "  IOC hash matching" -ForegroundColor Cyan -NoNewline
    if ($iocLoaded) {
        Write-Host "  ($($script:IOCHashCount) manual hashes loaded)" -ForegroundColor Green
    } else {
        Write-Host "  (no manual list - community list auto-loads separately)" -ForegroundColor DarkGray
    }
    Write-Host "    [f] " -ForegroundColor Yellow -NoNewline; Write-Host "load hashes from a file" -ForegroundColor White
    Write-Host "    [p] " -ForegroundColor Yellow -NoNewline; Write-Host "paste hashes (comma, space, or newline separated)" -ForegroundColor White
    Write-Host "    [l] " -ForegroundColor Yellow -NoNewline; Write-Host "list / show loaded hashes" -ForegroundColor White
    if ($iocLoaded) { Write-Host "    [x] " -ForegroundColor Yellow -NoNewline; Write-Host "turn manual IOC matching off" -ForegroundColor White }
    Write-Host "  > " -ForegroundColor DarkGray -NoNewline
    $how = (Read-Host).Trim().ToLower()

    if ($how -eq 'x') {
        if ($iocLoaded) {
            $script:IOCHashFile = $null; $script:IOCHashSet = $null; $script:IOCHashCount = 0
            return "IOC hash matching: OFF"
        }
        return "Nothing to turn off - no manual hashes loaded."
    }
    if ($how -eq 'l') {
        Clear-Host; Show-secgurdBannerCompact
        if ($iocLoaded -or $script:CommunityHashCount -gt 0) {
            Show-IOCList
        } else {
            Write-Host ""
            Write-Host "  No hashes loaded." -ForegroundColor Yellow
            Write-Host "  Use [f] to load from a file or [p] to paste some first." -ForegroundColor DarkGray
            Write-Host ""
        }
        Write-Host "  Press Enter to continue..." -ForegroundColor DarkGray; Read-Host | Out-Null
        return $null
    }

    $loaded = @{}; $src = ''
    if ($how -eq 'f') {
        Write-Host "  Path to hash list file:" -ForegroundColor Cyan
        Write-Host "  > " -ForegroundColor DarkGray -NoNewline
        $iocPath = (Read-Host).Trim('"').Trim()
        if ($iocPath -and (Test-Path $iocPath)) { $loaded = Import-IOCHashes $iocPath; $src = $iocPath }
        else { return "File not found - IOC matching not enabled." }
    } elseif ($how -eq 'p') {
        Write-Host "  Paste hashes, then press Enter (commas/spaces/newlines all OK):" -ForegroundColor Cyan
        Write-Host "  > " -ForegroundColor DarkGray -NoNewline
        $loaded = ConvertFrom-IOCText (Read-Host); $src = '(pasted)'
    } else {
        return "Cancelled - pick f, p, l, or x."
    }

    if ($loaded.Count -gt 0) {
        $script:IOCHashFile = $src; $script:IOCHashSet = $loaded; $script:IOCHashCount = $loaded.Count
        Clear-Host; Show-secgurdBannerCompact; Show-IOCList
        Write-Host "  Press Enter to continue..." -ForegroundColor DarkGray; Read-Host | Out-Null
        return "IOC hash matching: ON ($($loaded.Count) hashes)"
    }
    return "No valid hashes found (need MD5/SHA-1/SHA-256 hex values)."
}

function Invoke-MalUrlDependency {
    # Manage the community malicious-URL list (URLhaus). Returns a status message (or $null).
    $malLoaded = ($script:MalUrlSet -and $script:MalUrlCount -gt 0)
    Write-Host ""
    Write-Host "  Community malicious-URL matching" -ForegroundColor Cyan -NoNewline
    if ($malLoaded) {
        Write-Host "  ($($script:MalUrlCount) URLs loaded)" -ForegroundColor Green
    } else {
        Write-Host "  (none loaded)" -ForegroundColor DarkGray
    }
    Write-Host "  Browser-history URLs (module 10) are checked against this list; a hit on the" -ForegroundColor DarkGray
    Write-Host "  full URL or its host is flagged HIGH. Auto-loaded from communitysavedMALURLS.txt." -ForegroundColor DarkGray
    Write-Host "    [f] " -ForegroundColor Yellow -NoNewline; Write-Host "load URLs from a file" -ForegroundColor White
    Write-Host "    [p] " -ForegroundColor Yellow -NoNewline; Write-Host "paste URLs (space-separated, or one per line)" -ForegroundColor White
    Write-Host "    [l] " -ForegroundColor Yellow -NoNewline; Write-Host "list / show loaded URLs" -ForegroundColor White
    if ($malLoaded) { Write-Host "    [x] " -ForegroundColor Yellow -NoNewline; Write-Host "turn URL matching off" -ForegroundColor White }
    elseif ($script:MalUrlBackup) { Write-Host "    [x] " -ForegroundColor Yellow -NoNewline; Write-Host "turn URL matching back on" -ForegroundColor White }
    Write-Host "  > " -ForegroundColor DarkGray -NoNewline
    $how = (Read-Host).Trim().ToLower()

    if ($how -eq 'x') {
        if ($malLoaded) {
            $script:MalUrlBackup = @{ Urls=$script:MalUrlSet; Hosts=$script:MalUrlHostSet; Count=$script:MalUrlCount; File=$script:MalUrlFile }
            $script:MalUrlSet = $null; $script:MalUrlHostSet = $null; $script:MalUrlCount = 0; $script:MalUrlFile = $null
            return "Community malicious-URL matching: OFF"
        } elseif ($script:MalUrlBackup) {
            $script:MalUrlSet     = $script:MalUrlBackup.Urls
            $script:MalUrlHostSet = $script:MalUrlBackup.Hosts
            $script:MalUrlCount   = $script:MalUrlBackup.Count
            $script:MalUrlFile    = $script:MalUrlBackup.File
            $script:MalUrlBackup  = $null
            return "Community malicious-URL matching: ON ($($script:MalUrlCount) URLs)"
        }
        return "Nothing to toggle - no URLs loaded."
    }
    if ($how -eq 'l') {
        Clear-Host; Show-secgurdBannerCompact
        if ($malLoaded) {
            Show-MalUrlList
        } else {
            Write-Host ""
            Write-Host "  No URLs loaded." -ForegroundColor Yellow
            Write-Host "  Use [f] to load from a file or [p] to paste some first." -ForegroundColor DarkGray
            Write-Host ""
        }
        Write-Host "  Press Enter to continue..." -ForegroundColor DarkGray; Read-Host | Out-Null
        return $null
    }

    $loaded = $null; $src = ''
    if ($how -eq 'f') {
        Write-Host "  Path to malicious-URL list file:" -ForegroundColor Cyan
        Write-Host "  > " -ForegroundColor DarkGray -NoNewline
        $malPath = (Read-Host).Trim('"').Trim()
        if ($malPath -and (Test-Path $malPath)) { $loaded = Import-MalUrls $malPath; $src = $malPath }
        else { return "File not found - URL matching not changed." }
    } elseif ($how -eq 'p') {
        Write-Host "  Paste URLs (space-separated, or one per line), then press Enter:" -ForegroundColor Cyan
        Write-Host "  > " -ForegroundColor DarkGray -NoNewline
        $loaded = ConvertFrom-MalUrlText (Read-Host); $src = '(pasted)'
    } else {
        return "Cancelled - pick f, p, l, or x."
    }

    if ($loaded -and $loaded.Urls.Count -gt 0) {
        $script:MalUrlFile    = $src
        $script:MalUrlSet     = $loaded.Urls
        $script:MalUrlHostSet = $loaded.Hosts
        $script:MalUrlCount   = $loaded.Urls.Count
        $script:MalUrlBackup  = $null
        Clear-Host; Show-secgurdBannerCompact; Show-MalUrlList
        Write-Host "  Press Enter to continue..." -ForegroundColor DarkGray; Read-Host | Out-Null
        return "Community malicious-URL matching: ON ($($script:MalUrlCount) URLs)"
    }
    return "No valid URLs found (need http:// or https:// entries)."
}

function Invoke-SquatDependency {
    # Manage the openSquat squat-domain watchlist. Returns a status message (or $null).
    $sqLoaded = ($script:SquatDomainSet -and $script:SquatDomainCount -gt 0)
    Write-Host ""
    Write-Host "  Squat-domain watchlist (openSquat)" -ForegroundColor Cyan -NoNewline
    if ($sqLoaded) {
        Write-Host "  ($($script:SquatDomainCount) domains loaded)" -ForegroundColor Green
    } else {
        Write-Host "  (none loaded)" -ForegroundColor DarkGray
    }
    Write-Host "  Module 10 flags any browser-history / download-origin host that matches a" -ForegroundColor DarkGray
    Write-Host "  watchlisted look-alike domain. Auto-loaded from squat_domains.txt." -ForegroundColor DarkGray
    Write-Host "    [f] " -ForegroundColor Yellow -NoNewline; Write-Host "load domains from a file" -ForegroundColor White
    Write-Host "    [l] " -ForegroundColor Yellow -NoNewline; Write-Host "list / show loaded domains" -ForegroundColor White
    if ($sqLoaded) { Write-Host "    [x] " -ForegroundColor Yellow -NoNewline; Write-Host "turn squat matching off" -ForegroundColor White }
    Write-Host "  > " -ForegroundColor DarkGray -NoNewline
    $how = (Read-Host).Trim().ToLower()

    if ($how -eq 'x') {
        if ($sqLoaded) {
            $script:SquatDomainSet = $null; $script:SquatDomainCount = 0; $script:SquatDomainFile = $null
            return "Squat-domain matching: OFF"
        }
        return "Nothing to turn off - no domains loaded."
    }
    if ($how -eq 'l') {
        Clear-Host; Show-secgurdBannerCompact
        if ($sqLoaded) {
            Show-SquatList
        } else {
            Write-Host ""
            Write-Host "  No squat domains loaded." -ForegroundColor Yellow
            Write-Host "  Use [f] to load a squat_domains.txt file first." -ForegroundColor DarkGray
            Write-Host ""
        }
        Write-Host "  Press Enter to continue..." -ForegroundColor DarkGray; Read-Host | Out-Null
        return $null
    }
    if ($how -eq 'f') {
        Write-Host "  Path to squat-domain list file:" -ForegroundColor Cyan
        Write-Host "  > " -ForegroundColor DarkGray -NoNewline
        $sqPath = (Read-Host).Trim('"').Trim()
        if ($sqPath -and (Test-Path $sqPath)) {
            $set = Import-SquatDomains $sqPath
            if ($set.Count -gt 0) {
                $script:SquatDomainSet = $set; $script:SquatDomainCount = $set.Count; $script:SquatDomainFile = $sqPath
                Clear-Host; Show-secgurdBannerCompact; Show-SquatList
                Write-Host "  Press Enter to continue..." -ForegroundColor DarkGray; Read-Host | Out-Null
                return "Squat-domain matching: ON ($($set.Count) domains)"
            }
            return "No valid domains found in that file."
        }
        return "File not found - squat watchlist unchanged."
    }
    return "Cancelled - pick f, l, or x."
}

function Invoke-DependenciesMenu {
    # Grouped management of secgurd's external data dependencies: the community IOC-hash list, the
    # community malicious-URL list, and the squat-domain watchlist. Loops until the operator backs
    # out. Returns the last status message for the main menu to echo (or $null).
    $msg = $null
    # One status/selectable row: mark, key, label, note.
    $row = {
        param($key, $on, $label, $note)
        $mk  = if ($on) { (Ex "[^14]") } else { '[ ]' }
        $clr = if ($on) { 'Green' } else { 'DarkGray' }
        Write-Host "   " -NoNewline
        Write-Host $mk -ForegroundColor $clr -NoNewline
        Write-Host "  " -NoNewline
        Write-Host ("{0,-4}" -f $key) -ForegroundColor Yellow -NoNewline
        Write-Host ("{0,-38}" -f $label) -ForegroundColor White -NoNewline
        Write-Host $note -ForegroundColor DarkGray
    }
    while ($true) {
        Clear-Host; Show-secgurdBannerCompact
        Write-Host ""
        if ($msg) { Write-Host "   $msg" -ForegroundColor Cyan; Write-Host ""; $msg = $null }
        Write-Host "  DEPENDENCIES - external data lists secgurd matches against" -ForegroundColor Cyan
        Write-Host "  Each auto-loads from beside secgurd.ps1 (git pull) and rides along in the S1 paste." -ForegroundColor DarkGray
        Write-Host ""

        $commOn = ($script:CommunityHashCount -gt 0); $iocOn = [bool]$script:IOCHashFile
        $p = @()
        if ($commOn) { $p += "community $($script:CommunityHashCount)" }
        if ($iocOn)  { $p += "you-added $($script:IOCHashCount)" }
        $note1 = if ($p.Count) { "($($p -join ' + ') hashes)" } else { '(none loaded)' }
        & $row '1' ($commOn -or $iocOn) 'IOC hashes (on-disk binaries)' $note1

        $note2 = if ($script:MalUrlCount -gt 0) { "($($script:MalUrlCount) URLs)" } else { '(none loaded)' }
        & $row '2' ($script:MalUrlCount -gt 0) 'Malicious URLs - URLhaus (module 10)' $note2

        $note3 = if ($script:SquatDomainCount -gt 0) { "($($script:SquatDomainCount) domains)" } else { '(none loaded)' }
        & $row '3' ($script:SquatDomainCount -gt 0) 'Squat domains - openSquat (module 10)' $note3

        Write-Host ""
        Write-Host "    [1/2/3] manage a list    [b] back to main menu" -ForegroundColor DarkGray
        Write-Host "  > " -ForegroundColor DarkGray -NoNewline
        $choice = (Read-Host).Trim().ToLower()
        switch ($choice) {
            '1' { $msg = Invoke-IOCDependency }
            '2' { $msg = Invoke-MalUrlDependency }
            '3' { $msg = Invoke-SquatDependency }
            default {
                if ($choice -in @('b', 'q', 'back', '')) { return $msg }
                $msg = "Pick 1, 2, 3, or b."
            }
        }
    }
}

function Show-ModuleMenu {
    # Show the interactive menu whenever we can read keyboard input. We intentionally do NOT
    # treat S1's remote shell (ServerRemoteHost) as non-interactive - it supports Read-Host
    # fine. Use -Auto (or -Modules) for true headless runs; that path never reaches this
    # function. The only case we still guard is a genuinely input-less pipeline (e.g. content
    # piped straight into powershell with a redirected/closed stdin), which would deadlock on
    # Read-Host - detected by attempting a non-blocking check below.

    $canRead = $true
    try {
        # If stdin is redirected AND not a console, Read-Host can't get input -> would hang.
        if ([Console]::IsInputRedirected -and -not [Environment]::UserInteractive) {
            $canRead = $false
        }
    } catch {
        # [Console] may be unavailable in some hosts; assume we can read and let the menu try.
        $canRead = $true
    }

    if (-not $canRead) {
        Write-Host ""
        Write-Host (Ex "  ^16  No interactive input available ^09 running all modules.") -ForegroundColor Yellow
        Write-Host (Ex "       (use -Auto for headless runs, or -Modules to pick specific ones)") -ForegroundColor DarkGray
        Write-Host ""
        foreach ($m in $script:ModuleCatalogue) { $script:SelectedModules[$m.Id] = $true }
        $script:ProceedWithRun = $true
        return
    }

    $pendingMsg = $null
    while ($true) {
        Write-Host ""
        if ($pendingMsg) {
            Write-Host "   $pendingMsg" -ForegroundColor Cyan
            Write-Host ""
            $pendingMsg = $null
        }
        Write-Host "  " -NoNewline
        Write-Host "Select modules to run." -ForegroundColor White -NoNewline
        Write-Host "  [" -ForegroundColor DarkGray -NoNewline
        Write-Host " number " -ForegroundColor Yellow -NoNewline
        Write-Host (Ex "] toggle  ^10  [") -ForegroundColor DarkGray -NoNewline
        Write-Host " a " -ForegroundColor Yellow -NoNewline
        Write-Host (Ex "] all  ^10  [") -ForegroundColor DarkGray -NoNewline
        Write-Host " n " -ForegroundColor Yellow -NoNewline
        Write-Host (Ex "] none  ^10  [") -ForegroundColor DarkGray -NoNewline
        Write-Host " r " -ForegroundColor Green -NoNewline
        Write-Host (Ex "] run  ^10  [") -ForegroundColor DarkGray -NoNewline
        Write-Host " ? " -ForegroundColor Yellow -NoNewline
        Write-Host (Ex "] help  ^10  [") -ForegroundColor DarkGray -NoNewline
        Write-Host " q " -ForegroundColor Red -NoNewline
        Write-Host (Ex "] quit  ^10  [ ") -ForegroundColor DarkGray -NoNewline
        Write-Host "cleanup" -ForegroundColor Cyan -NoNewline
        Write-Host " ] clean_files" -ForegroundColor DarkGray -NoNewline
        Write-Host ""
        Write-Host (Ex "     ^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00  collection modules  ^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00") -ForegroundColor DarkGray
        Write-Host ""

        foreach ($m in $script:ModuleCatalogue) {
            $on = $script:SelectedModules[$m.Id]
            $mark = if ($on) { (Ex "[^14]") } else { '[ ]' }
            $markColor = if ($on) { 'Green' } else { 'DarkGray' }
            $nameColor = if ($on) { 'White' } else { 'DarkGray' }
            Write-Host "   " -NoNewline
            Write-Host $mark -ForegroundColor $markColor -NoNewline
            Write-Host "  " -NoNewline
            Write-Host $m.Id -ForegroundColor Yellow -NoNewline
            Write-Host ("  {0,-22}" -f $m.Name) -ForegroundColor $nameColor -NoNewline
            Write-Host $m.Desc -ForegroundColor DarkGray
        }

        Write-Host ""
        Write-Host (Ex "     ^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00  presets  ^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00") -ForegroundColor DarkGray
        Write-Host ""

        foreach ($key in 'qa','net','ps') {
            $p = $script:Presets[$key]
            Write-Host "         " -NoNewline
            Write-Host ("{0,-4}" -f $key) -ForegroundColor Yellow -NoNewline
            Write-Host ("{0,-30}" -f $p.Label) -ForegroundColor White -NoNewline
            Write-Host ("modules " + ($p.Modules -join ', ')) -ForegroundColor DarkGray
        }

        Write-Host ""
        Write-Host (Ex "     ^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00  options  ^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00") -ForegroundColor DarkGray
        Write-Host ""

        $ofOn   = $script:OpenFolderWhenDone
        $ofMark = if ($ofOn) { (Ex "[^14]") } else { '[ ]' }
        $ofClr  = if ($ofOn) { 'Green' } else { 'DarkGray' }
        Write-Host "   " -NoNewline
        Write-Host $ofMark -ForegroundColor $ofClr -NoNewline
        Write-Host "  " -NoNewline
        Write-Host ("{0,-4}" -f 'o') -ForegroundColor Yellow -NoNewline
        Write-Host ("{0,-36}" -f 'Open output folder when done') -ForegroundColor White -NoNewline
        Write-Host "(local/RDP only)" -ForegroundColor DarkGray

        # Single grouped entry for all three external data lists (IOC hashes, malicious URLs, squat
        # domains). 'deps' opens a sub-menu to view/load/toggle each - see Invoke-DependenciesMenu.
        $hashOn = (($script:CommunityHashCount -gt 0) -or [bool]$script:IOCHashFile)
        $depAny = ($hashOn -or ($script:MalUrlCount -gt 0) -or ($script:SquatDomainCount -gt 0))
        $depMark = if ($depAny) { (Ex "[^14]") } else { '[ ]' }
        $depClr  = if ($depAny) { 'Green' } else { 'DarkGray' }
        $depParts = @()
        if ($hashOn)                        { $depParts += "$($script:CommunityHashCount + $script:IOCHashCount) hashes" }
        if ($script:MalUrlCount -gt 0)      { $depParts += "$($script:MalUrlCount) URLs" }
        if ($script:SquatDomainCount -gt 0) { $depParts += "$($script:SquatDomainCount) squat" }
        $depNote = if ($depParts.Count) { "($($depParts -join ', '))" } else { '(none loaded)' }
        Write-Host "   " -NoNewline
        Write-Host $depMark -ForegroundColor $depClr -NoNewline
        Write-Host "  " -NoNewline
        Write-Host ("{0,-4}" -f 'deps') -ForegroundColor Yellow -NoNewline
        Write-Host ("{0,-36}" -f 'Dependencies (IOC / URL / squat lists)') -ForegroundColor White -NoNewline
        Write-Host $depNote -ForegroundColor DarkGray

        $fOn   = [bool]$script:FindFilter
        $fMark = if ($fOn) { (Ex "[^14]") } else { '[ ]' }
        $fClr  = if ($fOn) { 'Green' } else { 'DarkGray' }
        $fNote = if ($fOn) { "(filtering to '$($script:FindFilter)')" } else { '(off - shows everything)' }
        Write-Host "   " -NoNewline
        Write-Host $fMark -ForegroundColor $fClr -NoNewline
        Write-Host "  " -NoNewline
        Write-Host ("{0,-4}" -f 'f') -ForegroundColor Yellow -NoNewline
        Write-Host ("{0,-36}" -f 'Find: filter all output by name') -ForegroundColor White -NoNewline
        Write-Host $fNote -ForegroundColor DarkGray

        Write-Host "   " -NoNewline
        Write-Host (Ex "[^17]") -ForegroundColor DarkCyan -NoNewline
        Write-Host "  " -NoNewline
        Write-Host ("{0,-4}" -f 'd') -ForegroundColor Yellow -NoNewline
        Write-Host ("{0,-36}" -f 'Lookback window (days)') -ForegroundColor White -NoNewline
        Write-Host "(currently $($script:DaysBack)d)" -ForegroundColor DarkGray

        Write-Host "   " -NoNewline
        Write-Host (Ex "[^17]") -ForegroundColor DarkCyan -NoNewline
        Write-Host "  " -NoNewline
        Write-Host ("{0,-4}" -f 'p') -ForegroundColor Yellow -NoNewline
        Write-Host ("{0,-36}" -f 'Pastable version for remote shells') -ForegroundColor White -NoNewline
        Write-Host "(copy/paste for S1 shell)" -ForegroundColor DarkGray

        Write-Host ""
        Write-Host (Ex "     ^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00") -ForegroundColor DarkGray
        Write-Host ""

        $count = ($script:SelectedModules.Values | Where-Object { $_ }).Count
        $total = $script:ModuleCatalogue.Count
        $est = [int]($count * 3.2)
        Write-Host "   " -NoNewline
        Write-Host "$count / $total selected" -ForegroundColor White -NoNewline
        Write-Host (Ex "   ^10   ") -ForegroundColor DarkGray -NoNewline
        Write-Host "est. runtime ~${est} sec" -ForegroundColor White

        Write-Host ""
        Write-Host "   > " -ForegroundColor DarkGray -NoNewline
        $userInput = Read-Host

        if ([string]::IsNullOrWhiteSpace($userInput)) { continue }
        $cmd = $userInput.Trim().ToLower()

        if ($cmd -eq 'q' -or $cmd -eq 'quit' -or $cmd -eq 'exit') {
            Write-Host ""
            Write-Flair (Ex "   ^13 Sigurd sheathes the blade. Farewell. ^13") '1;91' 'Red'
            Write-Host ""
            $script:ProceedWithRun = $false
            return
        }

        if ($cmd -eq 'cleanup') {
            # Run the same cleanup available via -Cleanup, then exit (files may now be gone).
            Clear-Host
            Show-secgurdBannerCompact
            Invoke-Cleanup -SkipBanner
            Write-Host "   Press Enter to exit..." -ForegroundColor DarkGray
            Read-Host | Out-Null
            $script:ProceedWithRun = $false
            return
        }

        if ($cmd -eq '?' -or $cmd -eq 'help') {
            Clear-Host
            Show-secgurdBannerCompact
            Show-Help
            Write-Host "   Press Enter to return to the menu..." -ForegroundColor DarkGray
            Read-Host | Out-Null
            Clear-Host
            Show-secgurdBannerCompact
            continue
        }

        if ($cmd -eq 'o') {
            $script:OpenFolderWhenDone = -not $script:OpenFolderWhenDone
            $state = if ($script:OpenFolderWhenDone) { 'ON' } else { 'OFF' }
            $pendingMsg = "Open output folder when done: $state"
            Clear-Host; Show-secgurdBannerCompact
            continue
        }

        if ($cmd -eq 'deps' -or $cmd -eq 'dep' -or $cmd -eq 'dependencies') {
            $pendingMsg = Invoke-DependenciesMenu
            Clear-Host; Show-secgurdBannerCompact
            continue
        }

        if ($cmd -eq 'f') {
            Write-Host ""
            Write-Host "  Find / filter all output by a name or string." -ForegroundColor Cyan
            Write-Host "  Every artifact keeps only the lines that contain it (plus the section" -ForegroundColor DarkGray
            Write-Host "  header above them), and findings are filtered the same way. Case-insensitive." -ForegroundColor DarkGray
            if ($script:FindFilter) {
                Write-Host "  Currently filtering to: '$($script:FindFilter)'" -ForegroundColor Green
            }
            Write-Host "  Enter a string (e.g. SmartPDF), or blank to clear and show everything:" -ForegroundColor Cyan
            Write-Host "  > " -ForegroundColor DarkGray -NoNewline
            $fIn = (Read-Host).Trim()
            if ($fIn -eq '') {
                if ($script:FindFilter) {
                    $script:FindFilter = $null
                    $pendingMsg = "Find filter cleared - all output will be collected."
                } else {
                    $pendingMsg = "Find filter still off - all output will be collected."
                }
            } else {
                $script:FindFilter = $fIn
                $pendingMsg = "Find filter set: all output scoped to '$fIn'."
            }
            Clear-Host; Show-secgurdBannerCompact
            continue
        }

        if ($cmd -eq 'd') {
            Write-Host ""
            Write-Host "  Lookback window in days (how far back time-bounded collectors reach):" -ForegroundColor Cyan
            Write-Host "  Current: $($script:DaysBack)d    pick 1-3650, or Enter to keep" -ForegroundColor DarkGray
            Write-Host "  > " -ForegroundColor DarkGray -NoNewline
            $dIn = (Read-Host).Trim()
            if ($dIn -eq '') {
                $pendingMsg = "Lookback unchanged: $($script:DaysBack)d"
            } elseif ($dIn -match '^\d+$') {
                $val = [int]$dIn
                if ($val -lt 1) { $val = 1 }
                if ($val -gt 3650) { $val = 3650 }
                $script:DaysBack = $val
                $pendingMsg = "Lookback window set to $($script:DaysBack)d"
            } else {
                $pendingMsg = "Not a number - lookback unchanged ($($script:DaysBack)d)"
            }
            Clear-Host; Show-secgurdBannerCompact
            continue
        }

        if ($cmd -eq 'p') {
            Write-Host ""
            Write-Host "  Remote-shell paste (compressed - gzip+Base64, one block):" -ForegroundColor Cyan
            Write-Host "    [1] " -ForegroundColor Yellow -NoNewline
            Write-Host "EVERYTHING (script + IOC/URL/squat dependency lists)" -ForegroundColor White
            Write-Host ""
            Write-Host "    [2] " -ForegroundColor Yellow -NoNewline
            Write-Host "DEPENDENCY LISTS ONLY (IOC + malicious-URLs + squat)" -ForegroundColor White
            Write-Host "        " -NoNewline
            Write-Host "^ run this BEFORE [3] if you want the dependency lists" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "    [3] " -ForegroundColor Yellow -NoNewline
            Write-Host "SCRIPT ONLY" -ForegroundColor White
            Write-Host "  > " -ForegroundColor DarkGray -NoNewline
            $sMode = (Read-Host).Trim()
            if ($sMode -eq '2') {
                Show-S1Compressed -Mode lists
            } elseif ($sMode -eq '3') {
                Show-S1Compressed -Mode script
            } else {
                Show-S1Compressed -Mode all
            }
            Write-Host "  Press Enter to return to the menu..." -ForegroundColor DarkGray
            Read-Host | Out-Null
            Clear-Host; Show-secgurdBannerCompact
            continue
        }

        if ($cmd -eq 'r' -or $cmd -eq 'run') {
            if ($count -eq 0) {
                Clear-Host
                Show-secgurdBannerCompact
                Show-DeadDragon
                Write-Host "   Press Enter to return to the menu..." -ForegroundColor DarkGray
                Read-Host | Out-Null
                Clear-Host; Show-secgurdBannerCompact
                continue
            }
            $script:ProceedWithRun = $true
            return
        }

        if ($cmd -eq 'a' -or $cmd -eq 'all') {
            foreach ($m in $script:ModuleCatalogue) { $script:SelectedModules[$m.Id] = $true }
            $pendingMsg = (Ex "^14 All modules selected.")
            Clear-Host; Show-secgurdBannerCompact
            continue
        }

        if ($cmd -eq 'n' -or $cmd -eq 'none') {
            foreach ($m in $script:ModuleCatalogue) { $script:SelectedModules[$m.Id] = $false }
            $pendingMsg = (Ex "^23 All modules deselected.")
            Clear-Host; Show-secgurdBannerCompact
            continue
        }

        if ($script:Presets.ContainsKey($cmd)) {
            foreach ($m in $script:ModuleCatalogue) { $script:SelectedModules[$m.Id] = $false }
            foreach ($id in $script:Presets[$cmd].Modules) { $script:SelectedModules[$id] = $true }
            $pendingMsg = (Ex "^25 Preset applied: $($script:Presets[$cmd].Label) (modules $($script:Presets[$cmd].Modules -join ', '))")
            Clear-Host; Show-secgurdBannerCompact
            continue
        }

        # parse module numbers   supports "03" or "3" or multiple "1 3 5"

        $tokens = $cmd -split '[\s,]+' | Where-Object { $_ }
        $toggledAny = $false
        $unknown = @()
        foreach ($t in $tokens) {
            $id = if ($t -match '^\d+$') { '{0:D2}' -f [int]$t } else { $t }
            if ($script:SelectedModules.ContainsKey($id)) {
                $script:SelectedModules[$id] = -not $script:SelectedModules[$id]
                $toggledAny = $true
            } else {
                $unknown += $t
            }
        }

        if ($toggledAny) {
            if ($unknown.Count -gt 0) {
                $pendingMsg = "Toggled. Ignored unknown: $($unknown -join ', ')"
            }
            Clear-Host; Show-secgurdBannerCompact
        } else {
            $pendingMsg = (Ex "^16  Unknown command: '$cmd'  ^09  type ? for help.")
            Clear-Host; Show-secgurdBannerCompact
        }
    }
}

function Show-secgurdBannerCompact {
    Write-Host ""
    Write-Host (Ex " ^11^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^12") -ForegroundColor DarkGray
    Write-Host (Ex "      ^07^03^06 ") -ForegroundColor White -NoNewline
    Write-Host (Ex "^02^02^02^02^02^02^02^06^02^02^02^02^02^02^02^06 ^02^02^02^02^02^02^06 ^02^02^02^02^02^02^06 ^02^02^06   ^02^02^06^02^02^02^02^02^02^06 ^02^02^02^02^02^02^06") -ForegroundColor Yellow
    Write-Host (Ex "      ^04 ^15^03") -ForegroundColor White -NoNewline
    Write-Host (Ex "^02^02^07^03^03^03^03^05^02^02^07^03^03^03^03^05^02^02^07^03^03^03^03^05^02^02^07^03^03^03^03^05 ^02^02^04   ^02^02^04^02^02^07^03^03^02^02^06^02^02^07^03^03^02^02^06") -ForegroundColor Yellow -NoNewline
    Write-Host (Ex "^03^03^03^03^03^03^18") -ForegroundColor Red
    Write-Host "(" -ForegroundColor White -NoNewline
    Write-Host "o" -ForegroundColor Yellow -NoNewline
    Write-Host (Ex ")^03^03^03^19 ^04 ") -ForegroundColor White -NoNewline
    Write-Host (Ex "^02^02^02^02^02^02^02^06^02^02^02^02^02^06  ^02^02^04     ^02^02^04  ^02^02^02^06^02^02^04   ^02^02^04^02^02^02^02^02^02^07^05^02^02^04  ^02^02^04") -ForegroundColor Yellow -NoNewline
    Write-Host (Ex "^03^03^03^03^03^03^03^20") -ForegroundColor Red
    Write-Host (Ex "      ^04 ^15^03") -ForegroundColor White -NoNewline
    Write-Host (Ex "^08^03^03^03^03^02^02^04^02^02^07^03^03^05  ^02^02^04     ^02^02^04   ^02^02^04^02^02^04   ^02^02^04^02^02^07^03^03^02^02^06^02^02^04  ^02^02^04") -ForegroundColor Yellow -NoNewline
    Write-Host (Ex "^03^03^03^03^03^03^21") -ForegroundColor Red
    Write-Host (Ex "      ^08^03^05 ") -ForegroundColor White -NoNewline
    Write-Host (Ex "^02^02^02^02^02^02^02^04^02^02^02^02^02^02^02^06^08^02^02^02^02^02^02^06^08^02^02^02^02^02^02^07^05^08^02^02^02^02^02^02^07^05^02^02^04  ^02^02^04^02^02^02^02^02^02^07^05") -ForegroundColor Yellow
    Write-Host (Ex "          ^08^03^03^03^03^03^03^05^08^03^03^03^03^03^03^05 ^08^03^03^03^03^03^05 ^08^03^03^03^03^03^05  ^08^03^03^03^03^03^05 ^08^03^05  ^08^03^05^08^03^03^03^03^03^05") -ForegroundColor Yellow
    Write-Host (Ex " ^12^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^11") -ForegroundColor DarkGray
}

function Show-DeadDragon {
    # Easter egg: shown when the user hits 'run' with zero modules selected.
    # Knight = white, dragon-fire (bottom-left flame cluster) = red/orange, worm = green.
    Write-Host ""
    Wc '                            ' '38;2;70;160;75' 'DarkGreen'
    Wc '==(W{==========-' '38;2;245;245;245' 'White'
    Wc '      /===-' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '                              ' '38;2;70;160;75' 'DarkGreen'
    Wc '||' '38;2;245;245;245' 'White'
    Wc '  ' '38;2;70;160;75' 'DarkGreen'
    Wc '(.--.)' '38;2;245;245;245' 'White'
    Wc '         /===-_---~~~~~~~~~------____' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '                              ' '38;2;70;160;75' 'DarkGreen'
    Wc '| \_,|**|,__' '38;2;245;245;245' 'White'
    Wc '      |===-~___                _,-'' `' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '                 -==\\        ' '38;2;70;160;75' 'DarkGreen'
    Wc '`\ '' `--''   ),' '38;2;245;245;245' 'White'
    Wc '    `//~\\   ~~~~`---.___.-~~' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '             ______-==|        ' '38;2;70;160;75' 'DarkGreen'
    Wc '/`\_. .__/\ \' '38;2;245;245;245' 'White'
    Wc '    | |  \\           _-~`' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '       __--~~~  ,-/-==\\      ' '38;2;70;160;75' 'DarkGreen'
    Wc '(   | .  |~~~~|' '38;2;245;245;245' 'White'
    Wc '   | |   `\        ,''' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '    _-~       /''    |  \\     ' '38;2;70;160;75' 'DarkGreen'
    Wc ')__/==0==-\<>/' '38;2;245;245;245' 'White'
    Wc '   / /      \      /' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '  .''        /       |   \\      ' '38;2;70;160;75' 'DarkGreen'
    Wc '/~\___/~~\/' '38;2;245;245;245' 'White'
    Wc '  /'' /        \   /''' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc ' /  ____  /         |    \`\.__' '38;2;70;160;75' 'DarkGreen'
    Wc '/-~~   \  |' '38;2;245;245;245' 'White'
    Wc '_/''  /          \/''' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '/-''~    ~~~~~---__  |     ~-/~         ' '38;2;70;160;75' 'DarkGreen'
    Wc '( )' '38;2;245;245;245' 'White'
    Wc '   /''        _--~`' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '                  \_|      /        _) ' '38;2;70;160;75' 'DarkGreen'
    Wc '| ;' '38;2;245;245;245' 'White'
    Wc '  ),   __--~~' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '                    ''~~--_/      _-~/- ' '38;2;70;160;75' 'DarkGreen'
    Wc '|/' '38;2;245;245;245' 'White'
    Wc ' \   ''-~ \' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '                   {\__--_/}    / \\_>-' '38;2;70;160;75' 'DarkGreen'
    Wc '|)' '38;2;245;245;245' 'White'
    Wc '<__\      \' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '                   /''   (_/  _-~  | |__>--<__|      |' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '                  |   _/) )-~     | |__>--<__|      |' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '                  / /~ ,_/       / /__>---<__/      |' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '                 o-o _//        /-~_>---<__-~      /' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '                 (^(~          /~_>---<__-      _-~' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '                ' '38;2;70;160;75' 'DarkGreen'
    Wc ',/|' '38;2;225;55;45' 'Red'
    Wc '           /__>--<__/     _-~' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '             ' '38;2;70;160;75' 'DarkGreen'
    Wc ',//(''(' '38;2;225;55;45' 'Red'
    Wc '          |__>--<__|     /                  .----_' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '            ' '38;2;70;160;75' 'DarkGreen'
    Wc '(' '38;2;225;55;45' 'Red'
    Wc ' ' '38;2;70;160;75' 'DarkGreen'
    Wc '(' '38;2;225;55;45' 'Red'
    Wc ' ' '38;2;70;160;75' 'DarkGreen'
    Wc '''))' '38;2;225;55;45' 'Red'
    Wc '          |__>--<__|    |                 /'' _---_~\' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '         ' '38;2;70;160;75' 'DarkGreen'
    Wc '`' '38;2;225;55;45' 'Red'
    Wc '-' '38;2;255;150;30' 'Yellow'
    Wc '))' '38;2;225;55;45' 'Red'
    Wc ' ' '38;2;70;160;75' 'DarkGreen'
    Wc '))' '38;2;225;55;45' 'Red'
    Wc ' ' '38;2;70;160;75' 'DarkGreen'
    Wc '(' '38;2;225;55;45' 'Red'
    Wc '           |__>--<__|    |               /''  /     ~\`\' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '        ' '38;2;70;160;75' 'DarkGreen'
    Wc ',/,''//(' '38;2;225;55;45' 'Red'
    Wc ' ' '38;2;70;160;75' 'DarkGreen'
    Wc '(' '38;2;225;55;45' 'Red'
    Wc '             \__>--<__\    \            /''  //        ||' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '      ' '38;2;70;160;75' 'DarkGreen'
    Wc ',(' '38;2;225;55;45' 'Red'
    Wc ' ' '38;2;70;160;75' 'DarkGreen'
    Wc '(' '38;2;225;55;45' 'Red'
    Wc ' ' '38;2;70;160;75' 'DarkGreen'
    Wc '((,' '38;2;225;55;45' 'Red'
    Wc ' ' '38;2;70;160;75' 'DarkGreen'
    Wc '))' '38;2;225;55;45' 'Red'
    Wc '              ~-__>--<_~-_  ~--____---~'' _/''/        /''' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '    ' '38;2;70;160;75' 'DarkGreen'
    Wc '`' '38;2;225;55;45' 'Red'
    Wc '~' '38;2;255;150;30' 'Yellow'
    Wc '/' '38;2;225;55;45' 'Red'
    Wc '  ' '38;2;70;160;75' 'DarkGreen'
    Wc ')`' '38;2;225;55;45' 'Red'
    Wc ' ' '38;2;70;160;75' 'DarkGreen'
    Wc ')' '38;2;225;55;45' 'Red'
    Wc ' ' '38;2;70;160;75' 'DarkGreen'
    Wc ',/|' '38;2;225;55;45' 'Red'
    Wc '                 ~-_~>--<_/-__       __-~ _/' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '  ' '38;2;70;160;75' 'DarkGreen'
    Wc '._' '38;2;225;55;45' 'Red'
    Wc '-~' '38;2;255;150;30' 'Yellow'
    Wc '//(' '38;2;225;55;45' 'Red'
    Wc ' ' '38;2;70;160;75' 'DarkGreen'
    Wc ')/' '38;2;225;55;45' 'Red'
    Wc ' ' '38;2;70;160;75' 'DarkGreen'
    Wc '))' '38;2;225;55;45' 'Red'
    Wc ' ' '38;2;70;160;75' 'DarkGreen'
    Wc '`' '38;2;225;55;45' 'Red'
    Wc '                    ~~-''_/_/ /~~~~~~~__--~' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '   ' '38;2;70;160;75' 'DarkGreen'
    Wc ';''(' '38;2;225;55;45' 'Red'
    Wc ' ' '38;2;70;160;75' 'DarkGreen'
    Wc ''')/' '38;2;225;55;45' 'Red'
    Wc ' ' '38;2;70;160;75' 'DarkGreen'
    Wc ',)(' '38;2;225;55;45' 'Red'
    Wc '                              ~~~~~~~~~~' '38;2;70;160;75' 'DarkGreen'
    Write-Host ""
    Wc '  ' '38;2;70;160;75' 'DarkGreen'
    Wc '''' '38;2;225;55;45' 'Red'
    Wc ' ' '38;2;70;160;75' 'DarkGreen'
    Wc ''')' '38;2;225;55;45' 'Red'
    Wc ' ' '38;2;70;160;75' 'DarkGreen'
    Wc '''(' '38;2;225;55;45' 'Red'
    Wc ' ' '38;2;70;160;75' 'DarkGreen'
    Wc '(/' '38;2;225;55;45' 'Red'
    Write-Host ""
    Wc '    ' '38;2;70;160;75' 'DarkGreen'
    Wc '''' '38;2;225;55;45' 'Red'
    Wc '   ' '38;2;70;160;75' 'DarkGreen'
    Wc '''' '38;2;225;55;45' 'Red'
    Wc '  ' '38;2;70;160;75' 'DarkGreen'
    Wc '`' '38;2;225;55;45' 'Red'
    Write-Host ""
    Write-Host ""
    Write-Flair "        The Dragon still lives! Choose a module to hunt." '1;91' 'Red'
    Write-Host ""
}

# ---------------------------------------------

#  COMMUNITY IOC LIST (auto-loaded from the script folder)

# ---------------------------------------------

# Look for the community list. Priority: an explicit -CommunityIOCHashes path (used by the
# bundled S1 paste so it doesn't depend on $PSScriptRoot resolving), then communitysavedIOCS.txt
# sitting next to secgurd.ps1 (the normal git-pull case). Kept separate from the manual list.
$communityFile = $null
if ($CommunityIOCHashes -and (Test-Path $CommunityIOCHashes)) {
    $communityFile = $CommunityIOCHashes
} else {
    $scriptDir = $null
    if ($PSScriptRoot) { $scriptDir = $PSScriptRoot }
    elseif ($PSCommandPath) { $scriptDir = Split-Path -Parent $PSCommandPath }
    if ($scriptDir) {
        $cand = Join-Path $scriptDir 'communitysavedIOCS.txt'
        if (Test-Path $cand) { $communityFile = $cand }
    }
}
if ($communityFile) {
    $cset = Import-IOCHashes $communityFile
    if ($cset.Count -gt 0) {
        $script:CommunityHashSet   = $cset
        $script:CommunityHashCount = $cset.Count
        $script:CommunityHashFile  = $communityFile
    }
}

# Community malicious-URL list. Same discovery order as the community hash list: explicit
# -CommunityMalUrls path (used by the bundled S1 paste), else communitysavedMALURLS.txt next to
# the script (the normal git-pull case). Feeds module 10's browser-history URL triage.
$malUrlFile = $null
if ($CommunityMalUrls -and (Test-Path $CommunityMalUrls)) {
    $malUrlFile = $CommunityMalUrls
} else {
    $scriptDir2 = $null
    if ($PSScriptRoot) { $scriptDir2 = $PSScriptRoot }
    elseif ($PSCommandPath) { $scriptDir2 = Split-Path -Parent $PSCommandPath }
    if ($scriptDir2) {
        $cand2 = Join-Path $scriptDir2 'communitysavedMALURLS.txt'
        if (Test-Path $cand2) { $malUrlFile = $cand2 }
    }
}
if ($malUrlFile) {
    $mset = Import-MalUrls $malUrlFile
    if ($mset.Urls.Count -gt 0) {
        $script:MalUrlSet     = $mset.Urls
        $script:MalUrlHostSet = $mset.Hosts
        $script:MalUrlCount   = $mset.Urls.Count
        $script:MalUrlFile    = $malUrlFile
    }
}

# Squat-domain watchlist. Same discovery order as the community lists: explicit -SquatDomains path
# (used by the bundled S1 paste), else squat_domains.txt next to the script (the normal git-pull
# case, refreshed by the openSquat GitHub Action). Feeds module 10's host cross-referencing.
$squatFile = $null
if ($SquatDomains -and (Test-Path $SquatDomains)) {
    $squatFile = $SquatDomains
} else {
    $scriptDir3 = $null
    if ($PSScriptRoot) { $scriptDir3 = $PSScriptRoot }
    elseif ($PSCommandPath) { $scriptDir3 = Split-Path -Parent $PSCommandPath }
    if ($scriptDir3) {
        $cand3 = Join-Path $scriptDir3 'squat_domains.txt'
        if (Test-Path $cand3) { $squatFile = $cand3 }
    }
}
if ($squatFile) {
    $sqset = Import-SquatDomains $squatFile
    if ($sqset.Count -gt 0) {
        $script:SquatDomainSet   = $sqset
        $script:SquatDomainCount = $sqset.Count
        $script:SquatDomainFile  = $squatFile
    }
}

# ---------------------------------------------

#  S1 PASTE-VERSION GENERATOR (CLI)

# ---------------------------------------------

if ($MakeS1Paste) {
    # Generate the compressed (gzip+Base64) "everything" paste - script + community IOC/URL lists.
    # For the smaller script-only / lists-only variants, use the interactive 'p' menu.
    Show-S1Compressed -Mode all
    return
}

# ---------------------------------------------

#  MODULE SELECTION DRIVER

# ---------------------------------------------

if ($Modules) {
    # CLI-specified module list overrides everything
    foreach ($m in $script:ModuleCatalogue) { $script:SelectedModules[$m.Id] = $false }
    foreach ($id in $Modules) {
        $key = if ($id -match '^\d+$') { '{0:D2}' -f [int]$id } else { $id }
        if ($script:SelectedModules.ContainsKey($key)) { $script:SelectedModules[$key] = $true }
    }
}
elseif ($Auto) {
    # -Auto skips the menu and runs everything.
    foreach ($m in $script:ModuleCatalogue) { $script:SelectedModules[$m.Id] = $true }
}
else {
    # Interactive menu (default). Use a script-scope flag so we never depend on
    # capturing the function's output stream (Write-Host is safe, but this is bulletproof).
    $script:ProceedWithRun = $false
    Show-ModuleMenu | Out-Null
    if (-not $script:ProceedWithRun) { return }
    Clear-Host
    Show-secgurdBannerCompact
}

# ---------------------------------------------

#  PRE-FLIGHT: verify output path is writable

# ---------------------------------------------

try {
    $null = New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop
    $probe = Join-Path $OutputPath '.secgurd_write_test'
    Set-Content -Path $probe -Value 'ok' -ErrorAction Stop
    Remove-Item $probe -Force -ErrorAction SilentlyContinue
} catch {
    Write-Host ""
    Write-Host (Ex "  ^23 ERROR: Cannot write to output path:") -ForegroundColor Red
    Write-Host "    $OutputPath" -ForegroundColor Red
    Write-Host "    $($_.Exception.Message)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Try a different path:  -OutputPath C:\Temp\secgurd" -ForegroundColor Yellow
    Write-Host ""
    return
}

# Count how many artifact blocks belong to selected modules (for progress display)

$script:TotalArtifacts = 0
$script:DoneArtifacts  = 0

function Read-RecycleI {
    # Parse a Recycle Bin $I metadata file (dependency-free raw byte read). Layout:
    #   off 0  : 8-byte version (Win10 = 2, Vista/7/8 = 1)
    #   off 8  : 8-byte original file size (Int64 LE)
    #   off 16 : 8-byte deletion time (Windows FILETIME LE)
    #   off 24 : version 1 -> fixed 520-byte (260 UTF-16LE char) original path;
    #            version 2 -> 4-byte path length (chars incl. null), then that many UTF-16LE chars.
    # Returns @{OriginalPath; OriginalSize; DeletedTime} or $null.
    param([string]$Path)
    try { $b = [System.IO.File]::ReadAllBytes($Path) } catch { return $null }
    if ($b.Length -lt 24) { return $null }
    $ver  = [System.BitConverter]::ToInt64($b, 0)
    $size = [System.BitConverter]::ToInt64($b, 8)
    $ft   = [System.BitConverter]::ToInt64($b, 16)
    $delTime = $null
    try { $delTime = [System.DateTime]::FromFileTime($ft) } catch {}
    $origPath = ''
    if ($ver -eq 2 -and $b.Length -ge 28) {
        $nChars = [System.BitConverter]::ToInt32($b, 24)
        $byteLen = ($nChars - 1) * 2
        if ($byteLen -gt 0 -and (28 + $byteLen) -le $b.Length) {
            $origPath = [System.Text.Encoding]::Unicode.GetString($b, 28, $byteLen)
        }
    } else {
        $avail = $b.Length - 24
        $take = [Math]::Min(520, $avail)
        if ($take -gt 0) { $origPath = ([System.Text.Encoding]::Unicode.GetString($b, 24, $take)).Split([char]0)[0] }
    }
    return [PSCustomObject]@{ OriginalPath = $origPath; OriginalSize = $size; DeletedTime = $delTime }
}

function Get-EventData {
    # Flatten a Windows event's EventData into a name->value hashtable. Locale-independent and
    # robust to field-position changes across event-log schema versions (unlike $_.Properties[n],
    # which silently returns the wrong field if positions shift). Returns @{} on any parse error.
    param($Event)
    $h = @{}
    try {
        $x = [xml]$Event.ToXml()
        foreach ($n in $x.Event.EventData.Data) { if ($n.Name) { $h[$n.Name] = $n.'#text' } }
    } catch {}
    return $h
}

function Write-Section {
    param([string]$Title)
    $line = "=" * 60
    "$line`n  $Title`n$line"
}

function Add-Finding {
    param([string]$Severity, [string]$Module, [string]$Message, [string]$Artifact = '', [switch]$Quiet, [switch]$NoRecord, [string]$HighlightUrl = '')
    # Severity: HIGH / MED / INFO. Artifact (optional) is the exact .txt filename this
    # finding points at, so the HTML report can highlight just that file (not the whole module).
    # We encode it inside the stored string as {file:NAME} and strip it before display.
    # -Quiet    : record the finding (00_SUMMARY + HTML) but do NOT echo it to the live scan screen.
    # -NoRecord : echo it live but do NOT add it to the consolidated FINDINGS list / 00_SUMMARY /
    #             HTML - used for high-volume, low-persistence items (e.g. browser URLs) that would
    #             clutter the post-run findings list but are still worth seeing scroll by.

    # When a find filter is active, suppress findings whose message doesn't mention the term,
    # so the summary stays scoped to the hunted artifact (e.g. only SmartPDF-related flags).
    if ($script:FindFilter -and $Message.IndexOf($script:FindFilter, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        return
    }

    if (-not $NoRecord) {
        $tag = if ($Artifact) { " {file:$Artifact}" } else { '' }
        $script:Findings.Add("[$Severity] ($Module) $Message$tag")
    }
    if ($Quiet) { return }   # recorded to summary/HTML, but not echoed to the scan screen
    # If a transient "running..." line is on screen, move to a fresh line first
    # so the finding doesn't get tangled with it.
    if ($script:RunLineActive) {
        Write-Host ""
        $script:RunLineActive = $false
    }
    Write-Host (Ex "       ^26^00 ") -ForegroundColor DarkGray -NoNewline

    # Print one segment in the severity colour (HIGH = brick-red, MED = yellow, else gray).
    $writeSev = {
        param($t)
        if ($Severity -eq 'HIGH') { Write-Alert $t -NoNewline }
        else { Write-Host $t -ForegroundColor $(if ($Severity -eq 'MED') { 'Yellow' } else { 'DarkGray' }) -NoNewline }
    }

    if ($HighlightUrl -and $Message.Contains($HighlightUrl)) {
        # Colour the URL mauve (#d7afff) so it stands out; the rest stays severity-coloured, making
        # it easy to pick out exactly which URL - and where in the line - the finding is about.
        $idx  = $Message.IndexOf($HighlightUrl)
        & $writeSev $Message.Substring(0, $idx)
        Wc $HighlightUrl '38;2;170;130;230' 'Magenta'   # #aa82e6 purple / mauve (NoNewline)
        & $writeSev $Message.Substring($idx + $HighlightUrl.Length)
        Write-Host ""   # end the line
    }
    elseif ($Severity -eq 'HIGH') {
        # brick-red alert (true-color when supported, DarkRed fallback)
        Write-Alert $Message
    } else {
        $color = if ($Severity -eq 'MED') { 'Yellow' } else { 'DarkGray' }
        Write-Host $Message -ForegroundColor $color
    }
}

function Add-BrowserFlag {
    # Record a flagged browser/download host for the end-of-run 00_BROWSER_ALERTS correlation,
    # de-duplicated by (user, host, reason). Without this, a host visited via many URLs - or one
    # caught by both a built-in heuristic AND a dependency list - would produce multiple identical
    # correlation rows. Squat precedence is handled at the call site (module 10 skips the heuristic
    # add when the same URL is a squat hit), so this only collapses genuine repeats.
    param([string]$User, [string]$Browser, [string]$HostName, [string]$Severity, [string]$Reason, [string]$Url)
    $key = "$User|$HostName|$Reason".ToLower()
    if ($script:BrowserFlaggedSeen.Add($key)) {
        [void]$script:BrowserFlagged.Add([PSCustomObject]@{ User=$User; Browser=$Browser; Host=$HostName; Severity=$Severity; Reason=$Reason; Url=$Url })
    }
}

function Get-AllUserHives {
    # Enumerate every real user profile and expose its registry hive for inspection.
    # Loaded hives (the user is logged on) are used in place under HKEY_USERS\<SID>; a logged-off
    # user's NTUSER.DAT is mounted under a temp HKU key (needs admin) so their per-user keys can be
    # read too. Returns:  Hives = list of {Sid, Acct, Base, Mounted};  Mounted = temp mount-point
    # names the caller MUST pass to Dismount-UserHives in a finally;  OfflineSkipped = #mount failures.
    $profiles = @{}
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue | ForEach-Object {
        $sid = $_.PSChildName
        $pip = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
        if ($pip) { $profiles[$sid] = $pip }
    }
    $loaded = @{}
    Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | ForEach-Object { $loaded[$_.PSChildName] = $true }

    $hives = New-Object System.Collections.Generic.List[object]
    $mounted = New-Object System.Collections.Generic.List[string]
    $skipped = 0
    $idx = 0
    foreach ($sid in $profiles.Keys) {
        if ($sid -match '^S-1-5-(18|19|20)$') { continue }   # SYSTEM / LocalService / NetworkService
        $acct = try { (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { $profiles[$sid] }
        if ($loaded.ContainsKey($sid)) {
            $hives.Add([PSCustomObject]@{ Sid=$sid; Acct=$acct; Base="Registry::HKEY_USERS\$sid"; Mounted=$false })
        } else {
            $dat = Join-Path $profiles[$sid] 'NTUSER.DAT'
            if (Test-Path $dat) {
                $mp = "secgurd_hive_$idx"; $idx++
                reg load "HKU\$mp" "$dat" | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    $mounted.Add($mp)
                    $hives.Add([PSCustomObject]@{ Sid=$sid; Acct=$acct; Base="Registry::HKEY_USERS\$mp"; Mounted=$true })
                } else {
                    $skipped++
                }
            }
        }
    }
    [PSCustomObject]@{ Hives=$hives; Mounted=$mounted; OfflineSkipped=$skipped }
}

function Dismount-UserHives {
    # Unmount hives that Get-AllUserHives mounted. Release .NET registry handles first, or
    # 'reg unload' fails with "hive is in use by another process".
    param($Mounted)
    if (-not $Mounted) { return }
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    foreach ($mp in $Mounted) { reg unload "HKU\$mp" | Out-Null }
}


function Select-FilteredOutput {
    # Reduce already-rendered artifact text to just the lines containing $Term, keeping the
    # Write-Section header (the "===" / title / "===" triple) above any section that has a hit.
    # Sections with no matching line are dropped entirely. Matching is case-insensitive and
    # treats $Term literally (no wildcard/regex interpretation). Returns an array of lines;
    # if nothing matched anywhere, a single "(no matches...)" line so the file isn't blank.
    param([string[]]$Lines, [string]$Term)

    $out = New-Object System.Collections.Generic.List[string]
    $pendingHeader = $null      # the 3-line Write-Section header awaiting a match below it
    $sectionEmitted = $false    # has the current section's header already been flushed?
    $lastWasItem = $false       # was the previous emitted line a matched item (not a header)?
    $matchCount = 0             # number of matched content lines (the "instances" we report)

    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $ln = $Lines[$i]
        # Detect a Write-Section header: a bar line, a title, then another bar line.
        if ($ln -match '^={10,}$' -and ($i + 2) -lt $Lines.Count -and $Lines[$i + 2] -match '^={10,}$') {
            $pendingHeader = @($Lines[$i], $Lines[$i + 1], $Lines[$i + 2])
            $sectionEmitted = $false
            $i += 2
            continue
        }
        if ($ln.IndexOf($Term, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            if ($pendingHeader -and -not $sectionEmitted) {
                if ($out.Count -gt 0) { $out.Add('') }   # blank line between emitted sections
                foreach ($h in $pendingHeader) { $out.Add($h) }
                $sectionEmitted = $true
                $lastWasItem = $false                    # header -> first item: no blank between
            } elseif ($lastWasItem) {
                $out.Add('')                             # blank line between consecutive items
            }
            $out.Add($ln)
            $lastWasItem = $true
            $matchCount++
        }
    }

    # Expose the count so the caller (Save-Output) can show "N instance(s) found" on the run line.
    $script:LastFilterMatchCount = $matchCount
    if ($matchCount -eq 0) { return ,@("(no matches for '$Term')") }
    return $out.ToArray()
}

function Test-OutputHasData {
    # Decide whether a rendered artifact actually contains data worth writing, so the output
    # folder isn't littered with files that hold only section headers and "(none found)" style
    # placeholders. Returns $true if any substantive line exists. Treated as NON-data: blank
    # lines, Write-Section header triples (bar / title / bar), separator rules, and lines that
    # are entirely a parenthetical note like "(none found)" / "(key not found)". Anything else
    # (a table row, a Format-List value, a real message) counts as data.
    param([string[]]$Lines)
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $ln = $Lines[$i]
        if ($ln -match '^={10,}$' -and ($i + 2) -lt $Lines.Count -and $Lines[$i + 2] -match '^={10,}$') {
            $i += 2; continue   # skip the 3-line section header
        }
        $t = $ln.Trim()
        if ($t -eq '') { continue }              # blank
        if ($t -match '^[-=]{3,}$') { continue } # separator / stray bar
        if ($t -match '^\(.*\)$') { continue }   # parenthetical placeholder, e.g. "(none found)"
        return $true                             # a real data line
    }
    return $false
}

function Save-Output {
    param([string]$FileName, [scriptblock]$Block)

    # Extract module ID from filename (e.g. "03_persistence_registry.txt"   "03")

    $moduleId = if ($FileName -match '^(\d{2})_') { $matches[1] } else { $null }
    if ($moduleId -and -not $script:SelectedModules[$moduleId]) {
        $script:SkippedCount++
        return  # module not selected, skip silently

    }

    $script:DoneArtifacts++
    $progress = "[{0,2}/{1,2}]" -f $script:DoneArtifacts, $script:TotalArtifacts

    $file = Join-Path $OutputPath $FileName
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    # Print a transient "running" line so slow modules never look frozen.
    Write-Host "  $progress " -ForegroundColor DarkGray -NoNewline
    Write-Host (Ex "[^17] ") -ForegroundColor Cyan -NoNewline
    Write-Host ("{0,-42}" -f $FileName) -ForegroundColor Gray -NoNewline
    Write-Host "running..." -ForegroundColor DarkGray -NoNewline
    $script:RunLineActive = $true

    $findCount = 0
    try {
        $result = & $Block
        if ($script:FindFilter) {
            # Render to text exactly as it would land on disk, then keep only the lines that
            # contain the filter term (with their section headers). Render to one string and
            # split on newlines (Out-String -Stream leaves Write-Section's embedded newlines
            # un-split); wide width so table rows aren't truncated and a far-column match still
            # counts.
            $rendered = @(($result | Out-String -Width 4096) -split "`r`n|`r|`n")
            $result = Select-FilteredOutput -Lines $rendered -Term $script:FindFilter
            $findCount = $script:LastFilterMatchCount   # matched items in THIS artifact
            $script:FindFileCounts[$FileName] = $findCount
            $checkLines = $result
        } else {
            $checkLines = @(($result | Out-String -Width 4096) -split "`r`n|`r|`n")
        }

        # Skip writing artifacts that hold no real data (just headers / "(none found)" notes) so
        # the output folder isn't bloated with empty files. Under a find filter this also drops
        # no-match artifacts. Errors (below) and the 00_* summaries are always written.
        if (-not (Test-OutputHasData $checkLines)) {
            $sw.Stop()
            if ($script:RunLineActive) { Write-Host "`r" -NoNewline }
            Write-Host "  $progress " -ForegroundColor DarkGray -NoNewline
            Write-Host "[-] " -ForegroundColor DarkGray -NoNewline
            Write-Host ("{0,-42}" -f $FileName) -ForegroundColor DarkGray -NoNewline
            Write-Host "no data - not written    " -ForegroundColor DarkGray
            $script:RunLineActive = $false
            $script:EmptySkipped++
            return
        }

        $result | Out-File -FilePath $file -Encoding UTF8 -Force
        $sw.Stop()
        $secs = ('{0,6:N1}s' -f ($sw.ElapsedMilliseconds / 1000))
        if ($script:RunLineActive) {
            # running line still on screen - overwrite it in place
            Write-Host "`r" -NoNewline
        } else {
            # findings were printed beneath; just emit the result on a fresh line
        }
        Write-Host "  $progress " -ForegroundColor DarkGray -NoNewline
        Write-Host (Ex "[^14] ") -ForegroundColor Green -NoNewline
        Write-Host ("{0,-42}" -f $FileName) -ForegroundColor Gray -NoNewline
        if ($script:FindFilter) {
            # With a find string active, show how many matching items this artifact had.
            Write-Host "$secs" -ForegroundColor DarkGray -NoNewline
            $word = if ($findCount -eq 1) { 'instance' } else { 'instances' }
            $clr  = if ($findCount -gt 0) { 'Yellow' } else { 'DarkGray' }
            Write-Host ("   {0} {1} found    " -f $findCount, $word) -ForegroundColor $clr
        } else {
            Write-Host "$secs        " -ForegroundColor DarkGray
        }
        $script:RunLineActive = $false
        $script:CollectedCount++
    } catch {
        $sw.Stop()
        # No-bloat policy: don't write a per-collector ERROR file. Record the error centrally
        # (listed in 00_INDEX) and flag it on the run screen instead.
        $script:ErrorDetails.Add(("{0} - {1}" -f $FileName, ($_.Exception.Message -replace '\s+', ' ')))
        if ($script:RunLineActive) { Write-Host "`r" -NoNewline }
        Write-Host "  $progress " -ForegroundColor DarkGray -NoNewline
        Write-Host "[!] " -ForegroundColor Yellow -NoNewline
        Write-Host "$FileName (error - not written)   " -ForegroundColor DarkGray
        $script:RunLineActive = $false
        $script:ErrorCount++
    }
}

# Pre-count selected artifacts so the [n/total] progress is accurate.
# Count is derived DYNAMICALLY from this script's own 'Save-Output "NN_..."' lines, grouped
# by module id, so it can never drift when collectors are added or removed.

$script:ArtifactsPerModule = @{}
try {
    $selfText = Get-Content -LiteralPath $PSCommandPath -Raw -ErrorAction Stop
} catch {
    # When run via iex(irm) there is no file on disk; fall back to the invocation text.
    $selfText = $MyInvocation.MyCommand.Definition
}
[regex]::Matches($selfText, '(?m)^\s*Save-Output\s+"(\d{2})_') | ForEach-Object {
    $mid = $_.Groups[1].Value
    if ($script:ArtifactsPerModule.ContainsKey($mid)) { $script:ArtifactsPerModule[$mid]++ }
    else { $script:ArtifactsPerModule[$mid] = 1 }
}

$script:TotalArtifacts = (
    $script:SelectedModules.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object {
        $mid = $_.Key
        if ($script:ArtifactsPerModule.ContainsKey($mid)) { $script:ArtifactsPerModule[$mid] } else { 0 }
    } | Measure-Object -Sum
).Sum
if (-not $script:TotalArtifacts) { $script:TotalArtifacts = 1 }

Write-Host ""
Write-Host (Ex "     ^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00  running triage  ^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00") -ForegroundColor DarkGray
if ($script:FindFilter) {
    Write-Host ""
    Write-Host (Ex "  ^17 find filter active ^09 output scoped to '$($script:FindFilter)' (case-insensitive)") -ForegroundColor Cyan
}
Write-Host ""

# ---------------------------------------------

#  1. SYSTEM INFO

# ---------------------------------------------

Save-Output "01_system_info.txt" {
    Write-Section "SYSTEM INFORMATION"
    Get-ComputerInfo | Select-Object CsName, OsName, OsVersion, OsBuildNumber,
        OsInstallDate, OsLastBootUpTime, CsDomain, CsWorkgroup,
        CsNumberOfLogicalProcessors, CsTotalPhysicalMemory,
        TimeZone, LogonServer
}

Save-Output "01_env_variables.txt" {
    Write-Section "ENVIRONMENT VARIABLES"
    Get-ChildItem Env: | Sort-Object Name
}

# ---------------------------------------------

#  2. USER & SESSION INFO

# ---------------------------------------------

Save-Output "02_local_users.txt" {
    Write-Section "LOCAL USERS"
    $localUsers = Get-LocalUser
    $localUsers | Select-Object Name, Enabled, LastLogon, PasswordLastSet,
        PasswordNeverExpires, Description | Format-Table -AutoSize

    # Flag users whose password was set within the lookback window (a decent proxy for creation)

    $recentUsers = $localUsers | Where-Object {
        $_.PasswordLastSet -and $_.PasswordLastSet -gt (Get-Date).AddDays(-$script:DaysBack)
    }
    foreach ($u in $recentUsers) {
        Add-Finding 'MED' '02' (Ex "Local user '$($u.Name)' password set <$($script:DaysBack)d ago ($($u.PasswordLastSet.ToString('yyyy-MM-dd'))) ^09 possible new account") '02_local_users.txt'
    }

    Write-Section "LOCAL GROUPS & MEMBERS"
    Get-LocalGroup | ForEach-Object {
        $g = $_.Name
        "`n--- $g ---"
        $members = Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue
        $members | Select-Object Name, ObjectClass, PrincipalSource
        # Flag local (non-default) accounts in Administrators

        if ($g -eq 'Administrators') {
            foreach ($mem in $members) {
                if ($mem.PrincipalSource -eq 'Local' -and $mem.Name -notmatch '\\(Administrator|Domain Admins)$') {
                    Add-Finding 'MED' '02' "Local account in Administrators group: $($mem.Name)" '02_local_users.txt'
                }
            }
        }
    }
}

Save-Output "02_logged_on_users.txt" {
    Write-Section "CURRENTLY LOGGED ON USERS (quser)"
    quser 2>&1

    Write-Section "WHOAMI /ALL"
    whoami /all 2>&1
}

Save-Output "02_logon_history.txt" {
    Write-Section "LOGON EVENTS (4624/4625/4634 - last 200)"
    Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id      = 4624, 4625, 4634
    } -MaxEvents 200 -ErrorAction SilentlyContinue |
    ForEach-Object {
        $d = Get-EventData $_
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            Id          = $_.Id
            User        = $d['TargetUserName']
            LogonType   = $d['LogonType']
            SourceIP    = $d['IpAddress']
        }
    } |
    Format-Table -AutoSize
}

Save-Output "02_rdp_remote_access.txt" {
    # Remote-access / lateral-movement artifacts: who connected via RDP, where this host
    # connected OUT to, and whether RDP is exposed. Logon type 10 = RemoteInteractive (RDP).

    Write-Section "RDP IS ENABLED?"
    # fDenyTSConnections = 0 means RDP is ON.
    $ts = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
    $rdpOn = ($ts.fDenyTSConnections -eq 0)
    "fDenyTSConnections : $($ts.fDenyTSConnections)   (0 = RDP enabled)"
    "RDP enabled        : $rdpOn"
    # Network Level Authentication state
    $nla = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
    "UserAuthentication : $($nla.UserAuthentication)   (1 = NLA required)"
    $rdpPort = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue).PortNumber
    "RDP PortNumber     : $rdpPort"
    if ($rdpOn -and $nla.UserAuthentication -eq 0) {
        Add-Finding 'MED' '02' "RDP is enabled with Network Level Authentication OFF (weaker exposure)" '02_rdp_remote_access.txt'
    }
    if ($rdpPort -and $rdpPort -ne 3389) {
        Add-Finding 'INFO' '02' "RDP listening on non-standard port $rdpPort" '02_rdp_remote_access.txt'
    }

    Write-Section "INBOUND RDP LOGONS (type 10 RemoteInteractive, within $($script:DaysBack)d)"
    $rdpLogons = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'; Id = 4624; StartTime = (Get-Date).AddDays(-$script:DaysBack)
    } -MaxEvents 1000 -ErrorAction SilentlyContinue |
        ForEach-Object {
            $d = Get-EventData $_
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                User        = $d['TargetUserName']
                Domain      = $d['TargetDomainName']
                LogonType   = $d['LogonType']
                SourceIP    = $d['IpAddress']
                SourceHost  = $d['WorkstationName']
            }
        } |
        Where-Object { $_.LogonType -eq '10' } |
        Select-Object TimeCreated, User, Domain, SourceIP, SourceHost
    if ($rdpLogons) {
        $rdpLogons | Format-Table -AutoSize
        $srcIps = ($rdpLogons | Select-Object -ExpandProperty SourceIP -Unique) -join ', '
        Add-Finding 'MED' '02' (Ex "$(@($rdpLogons).Count) inbound RDP logon(s) from: $srcIps ^09 review for lateral movement") '02_rdp_remote_access.txt'
    } else {
        "(no inbound RDP logons in the lookback window)"
    }

    Write-Section "FAILED RDP-RELATED LOGONS (4625 type 10)"
    Get-WinEvent -FilterHashtable @{
        LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddDays(-$script:DaysBack)
    } -MaxEvents 500 -ErrorAction SilentlyContinue |
        ForEach-Object {
            $d = Get-EventData $_
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                User        = $d['TargetUserName']
                LogonType   = $d['LogonType']
                SourceIP    = $d['IpAddress']
            }
        } |
        Where-Object { $_.LogonType -eq '10' } |
        Select-Object TimeCreated, User, SourceIP |
        Format-Table -AutoSize

    Write-Section "TERMINALSERVICES SESSION EVENTS (connect / reconnect / disconnect)"
    # 21=logon, 22=shell start, 24=disconnect, 25=reconnect, 1149=network connection (pre-auth)
    Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
        StartTime = (Get-Date).AddDays(-$script:DaysBack)
    } -MaxEvents 200 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, @{N='Detail';E={($_.Message -replace '\s+',' ').Trim()}} |
        Format-Table -AutoSize -Wrap

    Write-Section "RDP CONNECTION ATTEMPTS (RemoteConnectionManager 1149 - source user/IP)"
    Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
        Id = 1149
        StartTime = (Get-Date).AddDays(-$script:DaysBack)
    } -MaxEvents 200 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, @{N='Detail';E={($_.Message -replace '\s+',' ').Trim()}} |
        Format-Table -AutoSize -Wrap

    Write-Section "OUTBOUND RDP DESTINATIONS (this host connected OUT to)"
    # Cached under each user's HKU hive: Terminal Server Client\Servers + Default MRU.
    # We read the loaded HKEY_USERS hives so we catch all profiles, not just the current one.
    $foundDest = $false
    Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | ForEach-Object {
        $sid = $_.PSChildName
        if ($sid -match '_Classes$') { return }
        $serversKey = "Registry::HKEY_USERS\$sid\Software\Microsoft\Terminal Server Client\Servers"
        if (Test-Path $serversKey) {
            Get-ChildItem $serversKey -ErrorAction SilentlyContinue | ForEach-Object {
                $foundDest = $true
                $hint = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).UsernameHint
                [PSCustomObject]@{ SID = $sid; Destination = $_.PSChildName; UsernameHint = $hint }
            }
        }
        $mruKey = "Registry::HKEY_USERS\$sid\Software\Microsoft\Terminal Server Client\Default"
        if (Test-Path $mruKey) {
            $mru = Get-ItemProperty $mruKey -ErrorAction SilentlyContinue
            $mru.PSObject.Properties | Where-Object { $_.Name -like 'MRU*' } | ForEach-Object {
                $foundDest = $true
                [PSCustomObject]@{ SID = $sid; Destination = $_.Value; UsernameHint = '(MRU)' }
            }
        }
    } | Format-Table -AutoSize
    if (-not $foundDest) { "(no cached outbound RDP destinations found)" }

    Write-Section "RDP BITMAP CACHE FILES (evidence of past RDP sessions)"
    # bcache/Cache files prove RDP was used even if logs rolled; we list presence, not content.
    $bmFound = $false
    Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $cacheDir = Join-Path $_.FullName 'AppData\Local\Microsoft\Terminal Server Client\Cache'
        if (Test-Path $cacheDir) {
            Get-ChildItem $cacheDir -File -ErrorAction SilentlyContinue | ForEach-Object {
                $bmFound = $true
                [PSCustomObject]@{ User = $cacheDir.Split('\')[2]; File = $_.Name; Size = $_.Length; Modified = $_.LastWriteTime }
            }
        }
    } | Format-Table -AutoSize
    if (-not $bmFound) { "(no RDP bitmap cache files found)" }
}

# ---------------------------------------------

#  3. PERSISTENCE

# ---------------------------------------------

Save-Output "03_persistence_registry.txt" {
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SYSTEM\CurrentControlSet\Services',  # services

        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',  # AppInit_DLLs

        'HKCU:\SOFTWARE\Classes\mscfile\shell\open\command',           # Eventvwr bypass

        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )

    foreach ($key in $runKeys) {
        Write-Section $key
        if (Test-Path $key) {
            Get-ItemProperty -Path $key | Format-List
        } else {
            "  (key not found)"
        }
    }
}

Save-Output "03_runmru_clickfix.txt" {
    Write-Section "RUN DIALOG HISTORY - RunMRU (ClickFix / paste-and-run triage)"
    "The Win+R Run dialog records each command a user typed into HKCU\...\Explorer\RunMRU. 'ClickFix'"
    "and 'paste-and-run' lures (fake CAPTCHA / 'verify you are human' / 'fix this error') trick a user"
    "into pasting an attacker command here - usually a heavily obfuscated one-liner: powershell -w"
    "hidden, mshta, curl|iex, certutil, FromBase64String, etc. Because it is USER-driven it never"
    "lands in the autorun/persistence keys above, so this is often the ONLY registry trace of initial"
    "access. Read from EVERY user hive (loaded + logged-off NTUSER.DAT mounted with admin)."
    ""

    # Hallmark of a malicious Run entry = a script interpreter and/or a fetch/decode/hidden pattern.
    $badRx = '(?i)(powershell|pwsh|cmd(\.exe)?|%comspec%|comspec|mshta|wscript|cscript|rundll32|' +
        'regsvr32|certutil|bitsadmin|curl|wget|msiexec|forfiles|installutil|-enc(odedcommand)?|' +
        'frombase64string|iex\b|invoke-expression|invoke-webrequest|invoke-restmethod|downloadstring|' +
        'downloadfile|-nop\b|-noni|-w(indowstyle)?\s+hidden|hidden|http[s]?://|ftp://|\.hta\b|scrobj|' +
        'start-process|new-object\s+net\.webclient)'

    $hv = Get-AllUserHives
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($h in $hv.Hives) {
            $rk = "$($h.Base)\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
            if (-not (Test-Path $rk)) { continue }
            $props = Get-ItemProperty $rk -ErrorAction SilentlyContinue
            if (-not $props) { continue }
            # MRUList gives most-recent-first order; each value is a single letter (a, b, c, ...).
            $order = "$($props.MRUList)"
            $letters = if ($order) { [char[]]$order } else {
                $props.PSObject.Properties.Name | Where-Object { $_ -match '^[a-z]$' }
            }
            $rank = 0
            foreach ($ltr in $letters) {
                $slot = [string]$ltr
                $val = [string]$props.$slot
                if (-not $val) { continue }
                $rank++
                # RunMRU stores 'command\1'; the trailing \1 is a field separator - strip it.
                $cmd = $val -replace '\\1$', ''
                $suspicious = $cmd -match $badRx
                $longish = $cmd.Length -ge 200          # pasted ClickFix one-liners are typically very long
                $sev = if ($suspicious) { 'HIGH' } elseif ($longish) { 'MED' } else { 'INFO' }
                $rows.Add([PSCustomObject]@{
                    Account = $h.Acct
                    Order   = $rank
                    Slot    = $slot
                    Sev     = $sev
                    Command = $cmd
                })
                if ($sev -eq 'HIGH') {
                    $short = if ($cmd.Length -gt 160) { $cmd.Substring(0,160) + '...' } else { $cmd }
                    Add-Finding 'HIGH' '03' (Ex "RunMRU (Win+R) command looks like ClickFix/paste-and-run ($($h.Acct)) ^17 $short") '03_runmru_clickfix.txt'
                } elseif ($sev -eq 'MED') {
                    Add-Finding 'MED' '03' (Ex "Unusually long RunMRU (Win+R) command ($($h.Acct)) - review for paste-and-run") '03_runmru_clickfix.txt'
                }
            }
        }
    } finally {
        Dismount-UserHives $hv.Mounted
    }

    "Hives examined: $($hv.Hives.Count)  (offline mounted: $($hv.Mounted.Count); offline skipped: $($hv.OfflineSkipped))"
    ""
    if ($rows.Count) {
        $rows | Sort-Object @{E={ switch ($_.Sev) { 'HIGH' {0} 'MED' {1} default {2} } }}, Account, Order |
            Format-Table Account, Order, Slot, Sev, Command -AutoSize -Wrap
    } else {
        "(no RunMRU / Run-dialog history found in any user hive)"
    }
}

Save-Output "03_scheduled_tasks.txt" {
    # Enumerate tasks ONCE and reuse - Get-ScheduledTask is comparatively expensive and was
    # previously called three times (once per section), tripling the enumeration cost.
    $allTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue)

    Write-Section "SCHEDULED TASKS (non-Microsoft)"
    $allTasks |
        Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
        Select-Object TaskName, TaskPath, State,
            @{N='Actions';E={($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '}},
            @{N='Triggers';E={($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join '; '}} |
        Format-Table -AutoSize

    Write-Section "ALL SCHEDULED TASKS (full detail)"
    # Get-ScheduledTaskInfo makes a per-task round-trip to the Task Scheduler service. Running it
    # for every one of the hundreds of built-in \Microsoft\* tasks is what made this collector
    # crawl (10+ min) or stall on a contended/remote host. By default we resolve run-time info
    # ONLY for non-Microsoft tasks - the ones that matter in triage - and list Microsoft tasks
    # without it (LastRun shows "(skipped)"). Pass -WithTaskInfo to force full info for all.
    $allTasks | ForEach-Object {
        $isMs = $_.TaskPath -like '\Microsoft\*'
        $info = if ($script:WithTaskInfo -or -not $isMs) { $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue } else { $null }
        [PSCustomObject]@{
            Name       = $_.TaskName
            Path       = $_.TaskPath
            State      = $_.State
            LastRun    = if ($info) { $info.LastRunTime } elseif ($isMs) { '(skipped)' } else { $null }
            NextRun    = if ($info) { $info.NextRunTime } else { $null }
            LastResult = if ($info) { $info.LastTaskResult } else { $null }
            Actions    = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
            Author     = $_.Principal.UserId
        }
    } | Format-Table -AutoSize

    Write-Section "SUSPICIOUS TASK ACTIONS (writable path / encoded / lolbin)"
    # Flag tasks whose action runs from a writable location or uses a download/encoded pattern.
    $suspectTasks = foreach ($t in $allTasks) {
        foreach ($act in $t.Actions) {
            $cmd = "$($act.Execute) $($act.Arguments)".Trim()
            if (-not $cmd) { continue }
            $badLoc = ($cmd -match '(?i)\\(Temp|AppData|Users\\Public|ProgramData)\\') -and ($cmd -notmatch $script:TrustedPathRx)
            $badCmd = $cmd -match '(?i)(-enc(odedcommand)?|frombase64string|downloadstring|downloadfile|-w(indowstyle)?\s+hidden|iex|invoke-expression|mshta|bitsadmin|certutil\s+-urlcache|regsvr32.*scrobj)'
            if ($badLoc -or $badCmd) {
                $reason = @()
                if ($badLoc) { $reason += 'writable-path' }
                if ($badCmd) { $reason += 'suspicious-command' }
                $sev = if ($badCmd) { 'HIGH' } else { 'MED' }
                Add-Finding $sev '03' (Ex "Scheduled task '$($t.TaskName)' action looks suspicious ($($reason -join ', '))") '03_scheduled_tasks.txt'
                [PSCustomObject]@{
                    Task   = $t.TaskName
                    Path   = $t.TaskPath
                    Reason = ($reason -join ', ')
                    Action = $cmd
                }
            }
        }
    }
    if ($suspectTasks) { $suspectTasks | Format-Table -AutoSize -Wrap } else { "(none found)" }
}

Save-Output "03_services.txt" {
    Write-Section "ALL SERVICES"
    Get-Service | Select-Object Name, DisplayName, Status, StartType |
        Sort-Object Status, Name | Format-Table -AutoSize

    Write-Section "RUNNING SERVICES WITH BINARY PATH"
    Get-CimInstance Win32_Service |
        Where-Object { $_.State -eq 'Running' } |
        Select-Object Name, DisplayName, StartMode, State, PathName, StartName |
        Format-Table -AutoSize

    Write-Section "RECENTLY MODIFIED SERVICE BINARIES (within $($script:DaysBack) days)"
    Get-CimInstance Win32_Service | ForEach-Object {
        # Extract binary path   handles quoted "C:\Path with spaces\svc.exe -arg"

        # and unquoted C:\Windows\System32\svc.exe -k netsvcs

        $raw = $_.PathName
        $path = $null
        if ($raw -match '^"([^"]+)"') {
            $path = $matches[1]
        } elseif ($raw -match '^(\S+\.(?:exe|dll))') {
            $path = $matches[1]
        } elseif ($raw -match '^(.+?\.(?:exe|dll))\s') {
            $path = $matches[1]
        } else {
            $path = $raw
        }
        if ($path -and (Test-Path $path)) {
            $f = Get-Item $path -ErrorAction SilentlyContinue
            if ($f -and $f.LastWriteTime -gt (Get-Date).AddDays(-$script:DaysBack)) {
                # Reduce false positives from normal software patching:
                #  - skip well-known auto-updater services (Chrome/Edge/Google/OneDrive/ClickToRun...)
                #  - a binary in a legitimate location (Program Files / System32) that's merely
                #    recently-modified is almost always a routine update, so we DON'T raise a
                #    finding for it - we only record it in the table below. We DO flag it when it
                #    lives in a writable/unusual path, or (under -WithSignatures) fails to verify.
                $svcNameLc = ($_.Name).ToLower()
                $autoUpdater = $svcNameLc -match 'clicktorun|onedrive|edgeupdate|gupdate|googleupdate|chromeelevation|edgeelevation|brave|mozilla|adobearmservice|teamsmachineinstaller|widevine|dropbox'
                $inTrustedLoc = $path -match '(?i)^[A-Z]:\\(Program Files( \(x86\))?|Windows\\(System32|SysWOW64|WinSxS))\\'
                # exempt legit software that lives under writable roots (Defender, OneDrive, ...)
                $isTrustedPath = $path -match $script:TrustedPathRx
                $inWritableLoc = ($path -match '(?i)\\(Temp|AppData|Users\\Public|ProgramData|Downloads|Desktop)\\') -and (-not $isTrustedPath)

                $sigStatus = 'NotChecked'
                $signer = ''
                if ($script:WithSignatures) {
                    $sig = (Get-AuthenticodeSignature $path -ErrorAction SilentlyContinue)
                    $sigStatus = $sig.Status
                    $signer = $sig.SignerCertificate.Subject
                }

                if (-not $autoUpdater -and -not $isTrustedPath) {
                    if ($inWritableLoc) {
                        # recently-modified service binary in a writable path - genuinely suspicious
                        Add-Finding 'HIGH' '03' (Ex "Service binary in writable path, modified <$($script:DaysBack)d: $($_.Name) ^17 $path") '03_services.txt'
                    } elseif ($script:WithSignatures -and $sigStatus -ne 'Valid') {
                        # invalid/missing signature on a recently-modified service binary
                        Add-Finding 'HIGH' '03' (Ex "Service binary not validly signed, modified <$($script:DaysBack)d: $($_.Name) ^17 $path") '03_services.txt'
                    } elseif (-not $inTrustedLoc) {
                        # modified, not an auto-updater, not in a standard trusted location
                        Add-Finding 'MED' '03' (Ex "Service binary modified <$($script:DaysBack)d (non-standard path): $($_.Name) ^17 $path") '03_services.txt'
                    }
                    # else: trusted location + not an updater -> recorded in table, no finding (routine patch)
                }
                [PSCustomObject]@{
                    Service      = $_.Name
                    Path         = $path
                    LastModified = $f.LastWriteTime
                    SigStatus    = $sigStatus
                    Signer       = $signer
                }
            }
        }
    } | Format-Table -AutoSize

    Write-Section "SUSPICIOUS SERVICE PATHS (location / unquoted)"
    # Two classic red flags:
    #  1) service binary living in a user-writable spot (Temp, AppData, Public, ProgramData)
    #  2) an unquoted ImagePath that contains a space -> unquoted service path hijack (T1574.009)
    $suspectSvc = foreach ($svc in (Get-CimInstance Win32_Service)) {
        $raw = $svc.PathName
        if (-not $raw) { continue }
        # isolate the executable path portion
        $p = $null
        if ($raw -match '^"([^"]+)"') { $p = $matches[1] }
        elseif ($raw -match '^(\S+\.(?:exe|dll))') { $p = $matches[1] }
        elseif ($raw -match '^(.+?\.(?:exe|dll))\s') { $p = $matches[1] }
        else { $p = $raw }

        $badLoc = ($p -match '(?i)\\(Temp|AppData|Users\\Public|ProgramData)\\') -and ($p -notmatch $script:TrustedPathRx)
        # unquoted + has a space before the .exe and isn't already quoted
        $unquoted = ($raw -notmatch '^\s*"') -and ($p -match '\s') -and ($raw -match '\.exe')
        if ($badLoc -or $unquoted) {
            $reason = @()
            if ($badLoc)   { $reason += 'writable-location' }
            if ($unquoted) { $reason += 'unquoted-path' }
            if ($badLoc) {
                Add-Finding 'HIGH' '03' (Ex "Service '$($svc.Name)' runs from a writable path ^17 $p") '03_services.txt'
            }
            if ($unquoted) {
                Add-Finding 'MED' '03' (Ex "Service '$($svc.Name)' has an unquoted path with spaces (hijackable): $raw") '03_services.txt'
            }
            [PSCustomObject]@{
                Service  = $svc.Name
                Reason   = ($reason -join ', ')
                ImagePath= $raw
                StartName= $svc.StartName
            }
        }
    }
    if ($suspectSvc) { $suspectSvc | Format-Table -AutoSize -Wrap } else { "(none found)" }
}

Save-Output "03_startup_items.txt" {
    Write-Section "STARTUP FOLDER - ALL USERS"
    $paths = @(
        "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($p in $paths) {
        "`n--- $p ---"
        if (Test-Path $p) {
            Get-ChildItem $p -Force | Select-Object Name, LastWriteTime, FullName
        } else { "  (not found)" }
    }
}

# Known-benign WMI event-subscription names (allowlist). A __FilterToConsumerBinding is a classic
# fileless-persistence technique, so secgurd flags them - but a few ship with a healthy Windows box
# by default (the built-in SCM Event Log subscription, above all) or come from legitimate management
# agents, and would otherwise fire HIGH on EVERY run. Names here (regex, case-insensitive) are
# suppressed from the HIGH finding. Add your environment's known-good subscriptions (e.g. SCOM /
# monitoring agents) so the finding stays signal-only. NOTE: on top of this list, any binding whose
# consumer is an NTEventLogEventConsumer is auto-suppressed too - that consumer type only writes to
# the event log and cannot execute code, unlike the CommandLine/ActiveScript consumers attackers use.
$script:WmiBenignNames = @(
    'SCM Event ?Log (Consumer|Filter|Provider)'   # Windows default: Service Control Manager event log
    'BVT(Filter|Consumer)'                          # legacy Windows build-verification-test subscription
    'TSLogon(Filter|Consumer)'                      # Terminal Services logon
    'RmAssist.*(Filter|Consumer)'                   # Windows Remote Assistance
    # --- add your management/monitoring agents below, e.g.: ---
    # 'Microsoft Monitoring Agent'                  # SCOM
    # 'HealthService.*'
)

Save-Output "03_wmi_persistence.txt" {
    Write-Section "WMI EVENT SUBSCRIPTIONS"

    Write-Section "  EventFilters"
    Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue |
        Select-Object Name, Query, QueryLanguage | Format-List

    Write-Section "  EventConsumers"
    $consumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue
    $consumers | Select-Object * | Format-List

    Write-Section "  FilterToConsumerBindings"
    $bindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue
    $bindings | Select-Object * | Format-List

    if ($bindings) {
        # Split bindings into suspicious vs known-benign so the default/agent subscriptions that
        # exist on every box don't fire HIGH on every run. A binding is benign when its consumer
        # is an NTEventLogEventConsumer (log-only, can't execute) OR its consumer/filter name is
        # on the allowlist above. Everything else - especially CommandLine/ActiveScript consumers,
        # the ones used for real persistence - is still surfaced HIGH.
        $suspBindings   = New-Object System.Collections.Generic.List[string]
        $benignBindings = New-Object System.Collections.Generic.List[string]
        foreach ($bnd in $bindings) {
            $consRef   = [string]$bnd.Consumer
            $filtRef   = [string]$bnd.Filter
            $consClass = if ($consRef -match '(\w+EventConsumer)') { $matches[1] } else { '' }
            $cName     = if ($consRef -match 'Name="([^"]+)"')     { $matches[1] } else { $consRef }
            $fName     = if ($filtRef -match 'Name="([^"]+)"')     { $matches[1] } else { $filtRef }

            $isBenign = ($consClass -eq 'NTEventLogEventConsumer')
            if (-not $isBenign) {
                foreach ($pat in $script:WmiBenignNames) {
                    if ($cName -match $pat -or $fName -match $pat) { $isBenign = $true; break }
                }
            }
            $desc = "$cName <- $fName" + $(if ($consClass) { " [$consClass]" } else { '' })
            if ($isBenign) { $benignBindings.Add($desc) } else { $suspBindings.Add($desc) }
        }

        Write-Section "  Binding triage"
        "  Suspicious (review): $($suspBindings.Count)   |   Suppressed as known-benign: $($benignBindings.Count)"
        if ($suspBindings.Count -gt 0) {
            ""
            "  SUSPICIOUS bindings:"
            $suspBindings | ForEach-Object { "    ! $_" }
        }
        if ($benignBindings.Count -gt 0) {
            ""
            "  Suppressed (default/allowlisted - not flagged):"
            $benignBindings | ForEach-Object { "    - $_" }
        }

        if ($suspBindings.Count -gt 0) {
            Add-Finding 'HIGH' '03' (Ex "$($suspBindings.Count) unrecognized WMI event consumer binding(s) ^09 classic fileless persistence, review carefully") '03_wmi_persistence.txt'
        } elseif ($benignBindings.Count -gt 0) {
            Add-Finding 'INFO' '03' "$($benignBindings.Count) WMI event consumer binding(s), all known-benign (default/allowlisted) - no action" '03_wmi_persistence.txt'
        }
    }
}

Save-Output "03_com_hijacking_check.txt" {
    Write-Section "HKCU COM HIJACKS (CLSIDs shadowing HKLM\CLSID - actual hijack signal)"
    # Real COM hijack: an HKCU CLSID entry that ALSO exists under HKLM\CLSID

    # (HKCU shadows HKLM at runtime). Vanilla HKCU CLSIDs without HKLM counterparts

    # are usually app-specific user customizations, not malicious.

    if (Test-Path 'HKCU:\SOFTWARE\Classes\CLSID') {
        $hkcuClsids = Get-ChildItem 'HKCU:\SOFTWARE\Classes\CLSID' -ErrorAction SilentlyContinue
        $hijacks = foreach ($key in $hkcuClsids) {
            $clsid = Split-Path -Leaf $key.PSPath
            $hklmPath = "HKLM:\SOFTWARE\Classes\CLSID\$clsid"
            if (Test-Path $hklmPath) {
                # Check if HKCU has InprocServer32 / LocalServer32 (the hijack vector)

                $hkcuInproc  = Get-ItemProperty "HKCU:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32" -ErrorAction SilentlyContinue
                $hkcuLocal   = Get-ItemProperty "HKCU:\SOFTWARE\Classes\CLSID\$clsid\LocalServer32" -ErrorAction SilentlyContinue
                if ($hkcuInproc -or $hkcuLocal) {
                    [PSCustomObject]@{
                        CLSID         = $clsid
                        HKCU_InprocDll = $hkcuInproc.'(default)'
                        HKCU_LocalExe  = $hkcuLocal.'(default)'
                    }
                }
            }
        }
        if ($hijacks) {
            $hijacks | Format-Table -AutoSize
        } else {
            (Ex "  (no HKCU CLSIDs shadow HKLM\CLSID ^09 clean)")
        }
    } else { "  (no HKCU CLSID hive)" }
}

Save-Output "03_dll_search_order.txt" {
    Write-Section "SAFEDLLSEARCHMODE"
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' |
        Select-Object SafeDllSearchMode | Format-List

    Write-Section "CWDIllegalInDllSearch"
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' |
        Select-Object CWDIllegalInDllSearch | Format-List
}

Save-Output "03_advanced_persistence.txt" {
    # High-signal persistence vectors beyond run keys / tasks / services.

    Write-Section "IMAGE FILE EXECUTION OPTIONS (debugger hijacks)"
    # A 'Debugger' value under an IFEO subkey makes Windows launch that program instead of
    # the named exe - classic stealth persistence + the sticky-keys backdoor mechanism.
    $ifeoRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    Get-ChildItem $ifeoRoot -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($props.Debugger -or $props.GlobalFlag -or $props.VerifierDlls) {
            [PSCustomObject]@{
                Image       = $_.PSChildName
                Debugger    = $props.Debugger
                GlobalFlag  = $props.GlobalFlag
                VerifierDlls= $props.VerifierDlls
            }
            if ($props.Debugger) {
                Add-Finding 'HIGH' '03' (Ex "IFEO debugger hijack on $($_.PSChildName) ^17 $($props.Debugger)") '03_advanced_persistence.txt'
            }
        }
    } | Format-Table -AutoSize

    Write-Section "ACCESSIBILITY BINARY HIJACKS (sethc / utilman / osk / magnify)"
    # Login-screen backdoors: replacing or IFEO-redirecting these gives pre-auth SYSTEM shell.
    # NOTE: legitimate Microsoft accessibility binaries routinely have an internal
    # OriginalFilename that differs from the on-disk name (e.g. magnify.exe -> ScreenMagnifier),
    # so that is NOT a reliable signal and we do not flag on it. The real backdoor indicators
    # are: (a) an IFEO debugger set on the binary, or (b) the file failing to verify as a
    # validly-signed Microsoft binary (only checked under -WithSignatures, since signature
    # verification can stall offline).
    $accTargets = 'sethc.exe','utilman.exe','osk.exe','magnify.exe','narrator.exe','displayswitch.exe','atbroker.exe'
    foreach ($a in $accTargets) {
        $p = Join-Path $env:SystemRoot "System32\$a"
        if (Test-Path $p) {
            $f = Get-Item $p -ErrorAction SilentlyContinue
            $sigInfo = '(not checked - use -WithSignatures)'
            $suspectSig = $false
            if ($script:WithSignatures) {
                try {
                    $sig = Get-AuthenticodeSignature -FilePath $p -ErrorAction SilentlyContinue
                    $sigInfo = "$($sig.Status) / $($sig.SignerCertificate.Subject)"
                    # suspicious if signature isn't valid, or signer isn't Microsoft
                    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft') {
                        $suspectSig = $true
                    }
                } catch { $sigInfo = 'signature check failed' }
            }
            [PSCustomObject]@{
                Binary       = $a
                LastModified = $f.LastWriteTime
                Signature    = $sigInfo
            }
            if ($suspectSig) {
                Add-Finding 'HIGH' '03' (Ex "Accessibility binary not validly Microsoft-signed: $a ^09 possible replacement") '03_advanced_persistence.txt'
            }
            # flag an IFEO debugger specifically on an accessibility binary (the classic backdoor)
            $accDbg = (Get-ItemProperty (Join-Path $ifeoRoot $a) -ErrorAction SilentlyContinue).Debugger
            if ($accDbg) {
                Add-Finding 'HIGH' '03' (Ex "Accessibility backdoor: IFEO debugger on $a ^17 $accDbg") '03_advanced_persistence.txt'
            }
        }
    }

    Write-Section "WINLOGON (Shell / Userinit / Notify)"
    # Shell should be 'explorer.exe'; Userinit should be 'C:\Windows\system32\userinit.exe,'.
    # Extra entries here run at every interactive logon.
    $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
    $wl | Select-Object Shell, Userinit, Taskman, AppSetup, GinaDLL | Format-List
    if ($wl.Shell -and $wl.Shell -notmatch '^explorer\.exe\s*$') {
        Add-Finding 'HIGH' '03' (Ex "Winlogon Shell is not default explorer.exe: $($wl.Shell)") '03_advanced_persistence.txt'
    }
    if ($wl.Userinit -and $wl.Userinit -notmatch 'userinit\.exe,?\s*$') {
        Add-Finding 'HIGH' '03' (Ex "Winlogon Userinit has extra entries: $($wl.Userinit)") '03_advanced_persistence.txt'
    }

    Write-Section "APPINIT_DLLS (loads into every GUI process)"
    $appInitRows = foreach ($hive in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
                         'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
        $w = Get-ItemProperty $hive -ErrorAction SilentlyContinue
        if ($w) {
            [PSCustomObject]@{
                Hive            = $hive
                AppInit_DLLs    = $w.AppInit_DLLs
                LoadAppInit_DLLs= $w.LoadAppInit_DLLs
            }
            if ($w.AppInit_DLLs -and $w.AppInit_DLLs.Trim() -ne '') {
                Add-Finding 'HIGH' '03' (Ex "AppInit_DLLs set (loads into every process): $($w.AppInit_DLLs)") '03_advanced_persistence.txt'
            }
        }
    }
    $appInitRows | Format-Table -AutoSize

    Write-Section "LSA SECURITY/AUTHENTICATION PACKAGES"
    # Rogue Security/Authentication packages = credential-theft persistence (e.g. mimilib).
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue |
        Select-Object 'Security Packages', 'Authentication Packages', 'Notification Packages' | Format-List
}

Save-Output "03_remote_access_tools.txt" {
    # Hunt for remote-access / RMM tools (ScreenConnect, AnyDesk, TeamViewer, Atera, Splashtop,
    # etc.). Attackers drop these as a stealthy backdoor - they are signed, legitimate software,
    # so the TOOL existing is not the finding; the CONTEXT is (writable-path install, portable
    # exe, unexpected tool for this org, ScreenConnect instance folders). MITRE T1219.

    # name fragments -> friendly product. Matched against services, processes, paths, reg keys.
    $rmm = @(
        @{ Pat='screenconnect|connectwise';   Name='ScreenConnect / ConnectWise Control' }
        @{ Pat='anydesk';                      Name='AnyDesk' }
        @{ Pat='teamviewer';                   Name='TeamViewer' }
        @{ Pat='ateraagent|atera';             Name='Atera' }
        @{ Pat='splashtop';                    Name='Splashtop' }
        @{ Pat='meshagent|meshcentral';        Name='MeshCentral / MeshAgent' }
        @{ Pat='netsupport';                   Name='NetSupport Manager' }
        @{ Pat='logmein|lmiignition';          Name='LogMeIn' }
        @{ Pat='gotoassist|gotomypc';          Name='GoTo (GoToAssist/MyPC)' }
        @{ Pat='remoteutilities|rutserv';      Name='Remote Utilities' }
        @{ Pat='dwagent|dwservice';            Name='DWService' }
        @{ Pat='ammyy';                        Name='Ammyy Admin' }
        @{ Pat='rustdesk';                     Name='RustDesk' }
        @{ Pat='tightvnc|ultravnc|realvnc|tigervnc'; Name='VNC variant' }
        @{ Pat='pulseway';                     Name='Pulseway' }
        @{ Pat='kaseya|agentmon';              Name='Kaseya VSA' }
        @{ Pat='syncro|kabuto';                Name='Syncro' }
        @{ Pat='quickassist';                  Name='Quick Assist' }
    )
    $writable = '(?i)\\(Temp|AppData|Users\\Public|ProgramData|Downloads|Desktop)\\'

    function Test-RMM { param($text) foreach ($r in $rmm) { if ($text -match $r.Pat) { return $r.Name } } return $null }

    Write-Section "RMM-RELATED SERVICES"
    $svcHits = foreach ($svc in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
        $hay = "$($svc.Name) $($svc.DisplayName) $($svc.PathName)"
        $prod = Test-RMM $hay
        if ($prod) {
            $path = $null
            if ($svc.PathName -match '^"([^"]+)"') { $path = $matches[1] }
            elseif ($svc.PathName -match '^(\S+\.exe)') { $path = $matches[1] }
            $badLoc = ($svc.PathName -match $writable) -and ($svc.PathName -notmatch $script:TrustedPathRx)
            if ($badLoc) {
                Add-Finding 'HIGH' '03' (Ex "Remote-access tool '$prod' service runs from a writable path ^17 $($svc.PathName)") '03_remote_access_tools.txt'
            } else {
                Add-Finding 'MED' '03' (Ex "Remote-access tool present: $prod (service $($svc.Name)) ^09 confirm it is authorized") '03_remote_access_tools.txt'
            }
            [PSCustomObject]@{ Product=$prod; Service=$svc.Name; State=$svc.State; StartMode=$svc.StartMode; Path=$svc.PathName }
        }
    }
    if ($svcHits) { $svcHits | Format-Table -AutoSize -Wrap } else { "(no RMM-related services found)" }

    Write-Section "RMM-RELATED RUNNING PROCESSES"
    $procHits = foreach ($p in (Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
        $hay = "$($p.Name) $($p.ExecutablePath) $($p.CommandLine)"
        $prod = Test-RMM $hay
        if ($prod) {
            if ($p.ExecutablePath -and $p.ExecutablePath -match $writable) {
                Add-Finding 'HIGH' '03' (Ex "Remote-access tool '$prod' running from a writable path ^17 $($p.ExecutablePath)") '03_remote_access_tools.txt'
            }
            [PSCustomObject]@{ Product=$prod; PID=$p.ProcessId; Process=$p.Name; Path=$p.ExecutablePath }
        }
    }
    if ($procHits) { $procHits | Format-Table -AutoSize -Wrap } else { "(no RMM-related processes running)" }

    Write-Section "RMM-RELATED INSTALL PATHS"
    $searchRoots = @(
        "$env:ProgramFiles", "${env:ProgramFiles(x86)}", "$env:ProgramData",
        "$env:PUBLIC", "$env:SystemRoot\Temp"
    ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
    $pathHits = foreach ($root in $searchRoots) {
        Get-ChildItem $root -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $prod = Test-RMM $_.Name
            if ($prod) { [PSCustomObject]@{ Product=$prod; Folder=$_.FullName; Created=$_.CreationTime } }
        }
    }
    if ($pathHits) { $pathHits | Format-Table -AutoSize -Wrap } else { "(no RMM install folders in common locations)" }

    Write-Section "RMM-RELATED REGISTRY KEYS (services + uninstall entries)"
    $regRoots = @(
        'HKLM:\SYSTEM\CurrentControlSet\Services',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $regHits = foreach ($rr in $regRoots) {
        if (Test-Path $rr) {
            Get-ChildItem $rr -ErrorAction SilentlyContinue | ForEach-Object {
                $dn = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DisplayName
                $prod = Test-RMM "$($_.PSChildName) $dn"
                if ($prod) { [PSCustomObject]@{ Product=$prod; Key=$_.PSChildName; DisplayName=$dn; Hive=($rr -replace 'HKLM:\\','') } }
            }
        }
    }
    if ($regHits) { $regHits | Format-Table -AutoSize -Wrap } else { "(no RMM-related registry keys)" }

    Write-Section "SCREENCONNECT CLIENT ARTIFACTS (instance folders + user.config)"
    # ScreenConnect drops 'ScreenConnect Client (instanceID)' folders and a user.config that
    # maps the C2/relay host -> IP. Multiple distinct instance IDs = multiple deployments.
    $scFound = $false
    $scRoots = @(
        "$env:ProgramFiles", "${env:ProgramFiles(x86)}",
        "$env:SystemRoot\SysWOW64\config\systemprofile\AppData\Local",
        "$env:SystemRoot\System32\config\systemprofile\AppData\Local"
    )
    Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $scRoots += (Join-Path $_.FullName 'AppData\Local')
        $scRoots += (Join-Path $_.FullName 'AppData\Roaming')
        $scRoots += (Join-Path $_.FullName 'Documents\ConnectWiseControl')
    }
    foreach ($r in ($scRoots | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique)) {
        Get-ChildItem $r -Directory -ErrorAction SilentlyContinue -Filter 'ScreenConnect Client*' | ForEach-Object {
            $scFound = $true
            "Instance folder: $($_.FullName)   (created $($_.CreationTime))"
            $cfg = Join-Path $_.FullName 'user.config'
            if (Test-Path $cfg) {
                "  user.config present - contains the configured relay/C2 host mapping:"
                try {
                    Select-String -Path $cfg -Pattern 'https?://|\b\d{1,3}(\.\d{1,3}){3}\b|\.controlhub\.|\.screenconnect\.' -ErrorAction SilentlyContinue |
                        Select-Object -First 10 | ForEach-Object { "    $($_.Line.Trim())" }
                } catch {}
                Add-Finding 'HIGH' '03' (Ex "ScreenConnect client instance found: $($_.Name) ^09 verify relay host in user.config is authorized") '03_remote_access_tools.txt'
            }
        }
    }
    if (-not $scFound) { "(no ScreenConnect client instance folders found)" }
}

Save-Output "03_bits_jobs.txt" {
    # BITS (Background Intelligent Transfer Service) jobs. Windows uses BITS for updates, but it's
    # abused (MITRE T1197) for BOTH stealthy downloads and persistence: a job can carry a
    # SetNotifyCmdLine that runs a program when the transfer completes, and the job survives
    # reboots and re-attempts on a schedule - persistence that does NOT appear in Run keys, tasks,
    # or services. We list every job (all users) with source URL(s)/destination/owner/state,
    # surface NotifyCmdLine via bitsadmin (Get-BitsTransfer can't), and pull recent BITS event-log
    # activity. Suspicious source URLs are fed into the download/browser correlation, so a BITS
    # pull of e.g. pdf-fast.com/PDFast.exe also lands in 00_BROWSER_ALERTS.txt.

    Write-Section "ACTIVE BITS JOBS (Get-BitsTransfer -AllUsers)"
    $haveBits = Get-Command Get-BitsTransfer -ErrorAction SilentlyContinue
    if ($haveBits) {
        $jobs = @(Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue)
        if ($jobs.Count) {
            $writable = '(?i)\\(Temp|AppData|Users\\Public|ProgramData|Downloads|Desktop)\\'
            foreach ($j in $jobs) {
                $files = @($j.FileList)
                $srcList = ($files | ForEach-Object { $_.RemoteName }) -join ' ; '
                $dstList = ($files | ForEach-Object { $_.LocalName }) -join ' ; '
                [PSCustomObject]@{
                    JobId       = $j.JobId
                    DisplayName = $j.DisplayName
                    Owner       = $j.OwnerAccount
                    State       = $j.JobState
                    Created     = $j.CreationTime
                    Source      = $srcList
                    Destination = $dstList
                } | Format-List

                foreach ($f in $files) {
                    $u = $f.RemoteName; $d = $f.LocalName
                    if ($u -match '(?i)^https?://\d{1,3}(\.\d{1,3}){3}') {
                        Add-Finding 'HIGH' '03' (Ex "BITS job '$($j.DisplayName)' downloads from a raw IP ^17 $u") '03_bits_jobs.txt'
                    }
                    if ($d -and ($d -match $writable) -and ($d -notmatch $script:TrustedPathRx)) {
                        Add-Finding 'HIGH' '03' (Ex "BITS job '$($j.DisplayName)' writes to a writable path ^17 $d") '03_bits_jobs.txt'
                    }
                    # feed the source URL + destination filename into the download correlation
                    if ($u) {
                        $leaf = if ($d) { Split-Path -Leaf $d } else { '' }
                        [void]$script:DownloadSources.Add([PSCustomObject]@{ User=$j.OwnerAccount; FileLeaf=$leaf; ReferrerUrl=''; HostUrl=$u; Source='BITS job' })
                    }
                }
            }
        } else {
            "(no active BITS jobs)"
        }
    } else {
        "(Get-BitsTransfer not available on this host)"
    }

    Write-Section "BITS JOBS incl. NotifyCmdLine (bitsadmin /list /allusers /verbose)"
    # bitsadmin is deprecated but is the only built-in that prints NotifyCmdLine - THE persistence
    # indicator (a command line executed when the job completes).
    $ba = Join-Path $env:SystemRoot 'System32\bitsadmin.exe'
    if (Test-Path $ba) {
        $raw = (& $ba /list /allusers /verbose 2>&1 | Out-String)
        $raw
        foreach ($line in ($raw -split "`r?`n")) {
            if ($line -match '(?i)NotifyCmdLine:\s*(.+\S)') {
                $ncl = $matches[1].Trim()
                if ($ncl -and $ncl -notmatch '(?i)^\{?none\}?$') {
                    Add-Finding 'HIGH' '03' (Ex "BITS job has a NotifyCmdLine (runs on completion) ^17 $ncl") '03_bits_jobs.txt'
                }
            }
        }
    } else {
        "(bitsadmin.exe not present)"
    }

    Write-Section "BITS-CLIENT EVENT LOG (recent transfers, within $($script:DaysBack)d)"
    Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-Bits-Client/Operational'
        StartTime = (Get-Date).AddDays(-$script:DaysBack)
    } -MaxEvents 200 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, @{N='Detail';E={($_.Message -replace '\s+',' ').Trim()}} |
        Format-Table -AutoSize -Wrap
}

# ---------------------------------------------

#  4. POWERSHELL ARTIFACTS

# ---------------------------------------------

Save-Output "04_ps_history.txt" {
    Write-Section "POWERSHELL HISTORY (ALL USERS)"
    # PowerShell history routinely contains secrets typed on the command line (passwords, API
    # keys, tokens, connection strings). We deliberately do NOT redact - a responder needs the
    # raw evidence - but we (a) print a standing caution and (b) raise a finding when secret-
    # looking lines are present, since this file ends up in the off-host zip.
    "NOTE: command history can contain PLAINTEXT secrets (passwords / keys / tokens /"
    "connection strings). Treat this artifact as sensitive when copying it off-host."
    ""
    $histPaths = Get-ChildItem 'C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt' -Force -ErrorAction SilentlyContinue
    $secretRx = '(?i)(password|passwd|\bpwd\b|secret|api[_-]?key|access[_-]?key|client[_-]?secret|\btoken\b|bearer\s|authorization|ConvertTo-SecureString|-AsPlainText|connectionstring|AKIA[0-9A-Z]{12,}|BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY)'
    $secretHits = 0
    foreach ($h in $histPaths) {
        "`n`n===== $($h.FullName) ====="
        $content = Get-Content $h.FullName -ErrorAction SilentlyContinue
        foreach ($line in $content) { if ($line -match $secretRx) { $secretHits++ } }
        $content
    }
    if (-not $histPaths) { "  (no PSReadLine history files found)" }
    if ($secretHits -gt 0) {
        Add-Finding 'MED' '04' "PowerShell history has $secretHits line(s) that look like secrets (passwords/keys/tokens) - 04_ps_history.txt is sensitive, handle the output accordingly" '04_ps_history.txt'
    }
}

Save-Output "04_ps_transcripts.txt" {
    Write-Section "POWERSHELL TRANSCRIPT FILES"
    # Transcripts are always named 'PowerShell_transcript.<host>.<rand>.<timestamp>.txt'.
    # Filter by that pattern at the filesystem level (fast) instead of enumerating every .txt.
    $transcriptDirs = @(
        'C:\Transcripts',
        'C:\Windows\Temp',
        $env:TEMP,
        "$env:SystemDrive\Users\*\Documents"   # default transcript location when enabled per-user
    )
    $found = $false
    foreach ($dir in $transcriptDirs) {
        if (-not (Test-Path $dir)) { continue }
        $files = Get-ChildItem -Path $dir -Filter 'PowerShell_transcript*.txt' -Recurse -ErrorAction SilentlyContinue -Force
        foreach ($f in $files) {
            $found = $true
            "`n===== $($f.FullName) ====="
            Get-Content $f.FullName -TotalCount 50 -ErrorAction SilentlyContinue
            "... ($(($f.Length/1KB).ToString('F1')) KB total)"
        }
    }
    if (-not $found) { "  (no transcript files found)" }
}

Save-Output "04_ps_logging_config.txt" {
    Write-Section "POWERSHELL LOGGING CONFIGURATION"
    $keys = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription',
        'HKLM:\SOFTWARE\Microsoft\Windows\PowerShell\1\ShellIds\Microsoft.PowerShell'
    )
    foreach ($k in $keys) {
        "`n--- $k ---"
        if (Test-Path $k) { Get-ItemProperty $k | Format-List }
        else { "  (not configured)" }
    }
}

Save-Output "04_ps_event_log.txt" {
    Write-Section "POWERSHELL SCRIPT BLOCK LOGS (Event 4104 - last 500)"
    $sb4104 = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-PowerShell/Operational'
        Id      = 4104
    } -MaxEvents 500 -ErrorAction SilentlyContinue
    $sb4104 | Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Message}} | Format-List

    # Findings hook: flag obfuscation / encoded-command markers in script-block logs.
    $suspectPS = 0
    $patterns = @(
        '-enc(odedcommand)?\b', 'FromBase64String', '-w(indowstyle)?\s+hidden',
        'IEX\b', 'Invoke-Expression', 'DownloadString', 'DownloadFile', 'Net\.WebClient',
        'Invoke-WebRequest.*-OutFile', 'bypass', '-nop\b', 'New-Object\s+Net', 'Reflection\.Assembly'
    )
    $rx = [string]::Join('|', $patterns)
    foreach ($e in $sb4104) {
        if ($e.Message -match $rx) { $suspectPS++ }
    }
    if ($suspectPS -gt 0) {
        Add-Finding 'MED' '04' "$suspectPS script-block log(s) contain obfuscation/download markers (enc, IEX, DownloadString, hidden) - review 04_ps_event_log.txt" '04_ps_event_log.txt'
    }

    Write-Section "POWERSHELL OPERATIONAL EVENTS (last 200)"
    Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 200 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, LevelDisplayName, Message |
        Format-Table -AutoSize
}

# ---------------------------------------------

#  5. NETWORK

# ---------------------------------------------

Save-Output "05_network_connections.txt" {
    Write-Section "ACTIVE NETWORK CONNECTIONS"
    netstat -anob 2>&1

    Write-Section "TCP CONNECTIONS WITH PROCESS"
    Get-NetTCPConnection | ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            State       = $_.State
            LocalAddr   = "$($_.LocalAddress):$($_.LocalPort)"
            RemoteAddr  = "$($_.RemoteAddress):$($_.RemotePort)"
            PID         = $_.OwningProcess
            ProcessName = $proc.Name
            ProcessPath = $proc.Path
        }
    } | Sort-Object State | Format-Table -AutoSize
}

Save-Output "05_dns_cache.txt" {
    Write-Section "DNS CLIENT CACHE"
    Get-DnsClientCache | Select-Object Entry, RecordName, RecordType, Status, DataLength, Data |
        Format-Table -AutoSize
}

Save-Output "05_intel_host_matches.txt" {
    Write-Section "THREAT-INTEL HOST MATCHES (DNS cache + active connections vs loaded lists)"
    "Cross-references this machine's DNS client cache against the loaded threat-intel lists - the"
    "community malicious-URL feed (URLhaus host set) and the openSquat squat-domain watchlist. A"
    "cached resolution of a listed host means something on the box looked it up; if that host's"
    "resolved IP is ALSO in an active TCP connection, it's a live session to known-bad infrastructure."
    "Unlike module 10 (browser history), this catches ANY process's network activity, not just browsers."
    ""
    $haveMal   = ($script:MalUrlHostSet -and $script:MalUrlHostSet.Count -gt 0)
    $haveSquat = ($script:SquatDomainSet -and $script:SquatDomainCount -gt 0)
    if (-not $haveMal -and -not $haveSquat) {
        "No intel lists loaded (communitysavedMALURLS.txt / squat_domains.txt not present or empty)."
        "Nothing to match - load them via the Dependencies ('deps') menu or the -CommunityMalUrls /"
        "-SquatDomains parameters."
        return
    }
    $loadedDesc = @()
    if ($haveMal)   { $loadedDesc += "$($script:MalUrlHostSet.Count) URLhaus host(s)" }
    if ($haveSquat) { $loadedDesc += "$($script:SquatDomainCount) squat domain(s)" }
    "Lists loaded: $($loadedDesc -join '  +  ')"
    ""

    # Active PUBLIC remote IPs - lets us mark a matched host as 'actively connected'.
    $activeIPs = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    try {
        Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Where-Object { $_.RemoteAddress -and $_.RemoteAddress -notin @('0.0.0.0', '127.0.0.1', '::', '::1') } |
            ForEach-Object { [void]$activeIPs.Add($_.RemoteAddress) }
    } catch {}

    $cache = @()
    try { $cache = @(Get-DnsClientCache -ErrorAction SilentlyContinue) } catch {}

    $intelMatches = New-Object System.Collections.Generic.List[object]
    $seenHost = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($e in $cache) {
        $recName = $e.RecordName
        if (-not $recName) { continue }
        $normHost = $recName.ToLower().Trim('.')
        if (-not $normHost) { continue }

        # Which list does this cached host hit? URLhaus exact host, else squat (exact/subdomain).
        $list = $null
        if ($haveMal -and $script:MalUrlHostSet.Contains($normHost)) {
            $list = 'URLhaus malicious-URL feed'
        } elseif ($haveSquat) {
            $sq = Test-SquatHost $normHost
            if ($sq) { $list = "openSquat squat watchlist ($sq)" }
        }
        if (-not $list) { continue }
        if (-not $seenHost.Add($normHost)) { continue }   # one row per host

        # Resolved IP(s) for this host from the cache, and whether any is an active connection.
        $ips = @($cache |
            Where-Object { $_.RecordName -and ($_.RecordName.ToLower().Trim('.') -eq $normHost) -and $_.Data -match '^(\d{1,3}\.){3}\d{1,3}$|:' } |
            ForEach-Object { $_.Data } | Sort-Object -Unique)
        $active = $false
        foreach ($ip in $ips) { if ($activeIPs.Contains($ip)) { $active = $true; break } }

        $intelMatches.Add([PSCustomObject]@{ Host = $normHost; List = $list; IPs = ($ips -join ', '); Active = $active })
        $activeNote = if ($active) { ' - ACTIVE CONNECTION to a resolved IP' } else { '' }
        Add-Finding 'HIGH' '05' (Ex "DNS cache resolved a listed host: $normHost ^09 $list$activeNote") '05_intel_host_matches.txt'
    }

    if ($intelMatches.Count -eq 0) {
        "No DNS-cache host matched the loaded lists."
        return
    }
    Write-Section "MATCHES ($($intelMatches.Count))"
    foreach ($m in ($intelMatches | Sort-Object @{E={$_.Active};Descending=$true}, Host)) {
        $m.Host
        "    list        : $($m.List)"
        if ($m.IPs) { "    resolved IP : $($m.IPs)" }
        "    active conn : $(if ($m.Active) { 'YES - live TCP session to a resolved IP' } else { 'no' })"
        ""
    }
}

Save-Output "05_arp_hosts.txt" {
    Write-Section "ARP TABLE"
    Get-NetNeighbor | Format-Table -AutoSize

    Write-Section "HOSTS FILE"
    Get-Content "$env:SystemRoot\System32\drivers\etc\hosts"
}

Save-Output "05_network_shares.txt" {
    Write-Section "NETWORK SHARES"
    Get-SmbShare | Format-Table -AutoSize

    Write-Section "MAPPED DRIVES"
    Get-SmbMapping -ErrorAction SilentlyContinue | Format-Table -AutoSize
    net use 2>&1
}

Save-Output "05_firewall_rules.txt" {
    Write-Section "FIREWALL PROFILE STATUS"
    Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table

    Write-Section "INBOUND ALLOW RULES (program-specific)"
    # PERF: calling Get-NetFirewallApplicationFilter/PortFilter per-rule is extremely slow
    # (one CIM query each). Instead pull ALL filters once and build lookup tables keyed by
    # InstanceID, then join. Turns minutes into a second or two.
    Write-Progress -Activity "Firewall rules" -Status "Querying rules and filters..." -PercentComplete 10
    $rules   = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue
    $appAll  = Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
    $portAll = Get-NetFirewallPortFilter -ErrorAction SilentlyContinue

    Write-Progress -Activity "Firewall rules" -Status "Indexing filters..." -PercentComplete 50
    $appByRule  = @{}
    foreach ($a in $appAll)  { if ($a.InstanceID) { $appByRule[$a.InstanceID]  = $a } }
    $portByRule = @{}
    foreach ($p in $portAll) { if ($p.InstanceID) { $portByRule[$p.InstanceID] = $p } }

    Write-Progress -Activity "Firewall rules" -Status "Joining..." -PercentComplete 80
    $rules | ForEach-Object {
        $id = $_.InstanceID
        $prog = $appByRule[$id].Program
        if ($prog -and $prog -ne 'Any') {
            [PSCustomObject]@{
                DisplayName = $_.DisplayName
                Enabled     = $_.Enabled
                Profile     = $_.Profile
                Action      = $_.Action
                Program     = $prog
                LocalPorts  = $portByRule[$id].LocalPort
            }
        }
    } | Format-Table -AutoSize
    Write-Progress -Activity "Firewall rules" -Completed
}

# ---------------------------------------------

#  6. PROCESSES & LOADED MODULES

# ---------------------------------------------

Save-Output "06_processes.txt" {
    Write-Section "RUNNING PROCESSES"
    # Pull Win32_Process once into a hashtable instead of querying per-process

    $cmdLineByPid = @{}
    Get-CimInstance Win32_Process | ForEach-Object { $cmdLineByPid[[int]$_.ProcessId] = $_.CommandLine }

    Get-Process | Select-Object Id, Name, CPU, WorkingSet,
        @{N='Path';E={$_.Path}},
        @{N='StartTime';E={$_.StartTime}},
        @{N='CommandLine';E={$cmdLineByPid[[int]$_.Id]}} |
        Sort-Object CPU -Descending | Format-Table -AutoSize

    Write-Section "PROCESSES WITH NO IMAGE PATH (suspicious)"
    Get-Process | Where-Object { -not $_.Path } |
        Select-Object Id, Name, CPU, WorkingSet | Format-Table -AutoSize
}

Save-Output "06_process_tree.txt" {
    Write-Section "PROCESS PARENT-CHILD TREE"
    # The high-value triage data is the parent/child tree + command lines, which come from a
    # single fast Get-CimInstance call. Per-process owner resolution (GetOwner) is a separate
    # WMI round-trip EACH and can stall on a domain controller, so it is OFF by default and
    # enabled with -WithOwners. Without it this block returns in well under a second.
    $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    $byPid = @{}
    foreach ($p in $procs) { $byPid[[int]$p.ProcessId] = $p }

    $resolveOwners = $script:WithOwners
    $ownerByPid = @{}
    if ($resolveOwners) {
        foreach ($p in $procs) {
            try {
                $r = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue
                if ($r -and $r.ReturnValue -eq 0 -and $r.User) {
                    $ownerByPid[[int]$p.ProcessId] = if ($r.Domain) { "$($r.Domain)\$($r.User)" } else { $r.User }
                }
            } catch {}
        }
    }

    $procs | ForEach-Object {
        $proc = $_
        $parent = $byPid[[int]$proc.ParentProcessId]
        $row = [ordered]@{
            PID         = $proc.ProcessId
            PPID        = $proc.ParentProcessId
            Name        = $proc.Name
            ParentName  = if ($parent) { $parent.Name } else { '<none>' }
            CommandLine = $proc.CommandLine
        }
        if ($resolveOwners) { $row.Owner = $ownerByPid[[int]$proc.ProcessId] }
        [PSCustomObject]$row
    } | Sort-Object PPID, PID | Format-Table -AutoSize

    if (-not $resolveOwners) {
        "`n(Process owners omitted for speed. Re-run with -WithOwners to include them.)"
    }

    # Findings hook: flag classic suspicious parent -> child chains (office/script host
    # spawning a shell or LOLBin = common initial-access / execution pattern).
    Write-Section "SUSPICIOUS PARENT-CHILD CHAINS"
    $shells = 'powershell.exe','pwsh.exe','cmd.exe','wscript.exe','cscript.exe','mshta.exe','rundll32.exe','regsvr32.exe','certutil.exe','bitsadmin.exe'
    $badParents = 'winword.exe','excel.exe','powerpnt.exe','outlook.exe','msaccess.exe','mspub.exe','visio.exe','onenote.exe','wmiprvse.exe','mshta.exe','wscript.exe','cscript.exe','eqnedt32.exe'
    $hits = @()
    foreach ($p in $procs) {
        $parent = $byPid[[int]$p.ParentProcessId]
        if (-not $parent) { continue }
        $pn = ($p.Name).ToLower()
        $par = ($parent.Name).ToLower()
        if (($badParents -contains $par) -and ($shells -contains $pn)) {
            $hits += [PSCustomObject]@{
                Parent      = $parent.Name
                Child       = $p.Name
                ChildPID    = $p.ProcessId
                CommandLine = $p.CommandLine
            }
        }
    }
    if ($hits.Count -gt 0) {
        $hits | Format-Table -AutoSize -Wrap
        $chainDesc = ($hits | ForEach-Object { "$($_.Parent)->$($_.Child)" } | Select-Object -Unique) -join ', '
        Add-Finding 'HIGH' '06' (Ex "Suspicious process chain(s): $chainDesc ^09 common malicious spawn pattern") '06_process_tree.txt'
    } else {
        "(none detected among currently-running processes)"
    }
}

Save-Output "06_loaded_dlls.txt" {
    Write-Section "LOADED DLLs FROM UNUSUAL LOCATIONS"
    # Get-AuthenticodeSignature does a full trust-chain verification per file and can stall
    # for seconds EACH on an offline host (WinVerifyTrust revocation behavior isn't fully
    # suppressible from PowerShell). Across hundreds of DLLs that freezes the run.
    #
    # FAST DEFAULT (offline-safe, no signature calls): flag DLLs loaded from locations that
    # are unusual for system binaries - the high-signal indicator for malicious DLLs anyway.
    # Signed-binary verification is opt-in via -WithSignatures.
    $systemRoots = @(
        "$env:SystemRoot\System32",
        "$env:SystemRoot\SysWOW64",
        "$env:SystemRoot\WinSxS",
        "$env:SystemRoot\Microsoft.NET",
        "${env:ProgramFiles}",
        "${env:ProgramFiles(x86)}"
    ) | Where-Object { $_ }

    $pairs = New-Object System.Collections.Generic.List[object]
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        $proc = $_
        try {
            foreach ($m in $proc.Modules) {
                if (-not $m.FileName) { continue }
                $inSystem = $false
                foreach ($root in $systemRoots) {
                    if ($m.FileName.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { $inSystem = $true; break }
                }
                if (-not $inSystem) {
                    $pairs.Add([PSCustomObject]@{
                        PID     = $proc.Id
                        Process = $proc.Name
                        Module  = $m.ModuleName
                        Path    = $m.FileName
                    })
                }
            }
        } catch {}
    }

    if ($script:WithSignatures) {
        Write-Section "  (verifying signatures - this can be slow)"
        $sigCache = @{}
        $pairs | Select-Object -ExpandProperty Path -Unique | ForEach-Object {
            try { $sigCache[$_] = (Get-AuthenticodeSignature -FilePath $_ -ErrorAction SilentlyContinue).Status }
            catch { $sigCache[$_] = 'Unknown' }
        }
        $pairs | Select-Object PID, Process, Module, Path, @{N='SigStatus';E={$sigCache[$_.Path]}} |
            Sort-Object Process, Module | Format-Table -AutoSize
    } else {
        if ($pairs.Count -gt 0) {
            $pairs | Sort-Object Process, Module | Format-Table -AutoSize
            "`nNOTE: DLLs above load from non-standard paths (outside System32/Program Files)."
            "Run with -WithSignatures to add Authenticode trust status (slower, may stall offline)."
        } else {
            "  (no DLLs loaded from unusual locations)"
        }
    }
}

# ---------------------------------------------

#  7. FILE SYSTEM ARTIFACTS

# ---------------------------------------------

Save-Output "07_recently_modified_system32.txt" {
    Write-Section "RECENTLY MODIFIED FILES IN SYSTEM32 (within $($script:DaysBack) days)"
    Get-ChildItem "$env:SystemRoot\System32" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-$script:DaysBack) } |
        Select-Object Name, LastWriteTime, Length, FullName |
        Sort-Object LastWriteTime -Descending | Format-Table -AutoSize
}

Save-Output "07_temp_executables.txt" {
    Write-Section "EXECUTABLES IN TEMP DIRECTORIES"
    $tempPaths = @($env:TEMP, $env:TMP, 'C:\Windows\Temp', 'C:\Users\Public')
    foreach ($p in $tempPaths) {
        "`n--- $p ---"
        Get-ChildItem $p -Recurse -Include '*.exe','*.dll','*.bat','*.ps1','*.vbs','*.js','*.cmd','*.msi','*.hta' -ErrorAction SilentlyContinue |
            Select-Object Name, LastWriteTime, Length, FullName |
            Sort-Object LastWriteTime -Descending | Format-Table -AutoSize
    }
}

Save-Output "07_downloads_desktop.txt" {
    Write-Section "RECENT FILES IN DOWNLOADS & DESKTOP (ALL USERS)"
    $targets = @('Downloads','Desktop','Documents')
    Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $user = $_.Name
        foreach ($folder in $targets) {
            $path = Join-Path $_.FullName $folder
            if (Test-Path $path) {
                $files = Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-$script:DaysBack) } |
                    Sort-Object LastWriteTime -Descending |
                    Select-Object -First 50
                if ($files) {
                    "`n--- $user\$folder ---"
                    $files | Select-Object Name, LastWriteTime, Length | Format-Table -AutoSize
                }
            }
        }
    }
}

Save-Output "07_alternate_data_streams.txt" {
    Write-Section "ALTERNATE DATA STREAMS (suspicious - user content folders)"
    # Scope to Desktop/Downloads/Documents only   full -Recurse on C:\Users takes 5-30 min.

    $scanFolders = @('Desktop', 'Downloads', 'Documents')
    $results = foreach ($userDir in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
        foreach ($sub in $scanFolders) {
            $p = Join-Path $userDir.FullName $sub
            if (Test-Path $p) {
                Get-ChildItem $p -Recurse -File -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        $file = $_
                        Get-Item $file.FullName -Stream * -ErrorAction SilentlyContinue |
                            Where-Object { $_.Stream -notmatch '^\$DATA$|^Zone\.Identifier$' } |
                            ForEach-Object {
                                [PSCustomObject]@{
                                    File   = $file.FullName
                                    Stream = $_.Stream
                                    Length = $_.Length
                                }
                            }
                    }
            }
        }
    }
    if ($results) { $results | Format-Table -AutoSize }
    else { "  (no suspicious alternate data streams found in user content folders)" }
}

Save-Output "07_download_origins.txt" {
    Write-Section "DOWNLOAD ORIGINS (Zone.Identifier ReferrerUrl / HostUrl)"
    "When a file is downloaded, Windows records where it came from in a Zone.Identifier alternate"
    "data stream (ReferrerUrl = the page, HostUrl = the actual file URL). This is on-disk proof of"
    "a download's source - it survives even if browser history is cleared, and it's the file-side"
    "mirror of the browser URL flagging. Scoped to Downloads/Desktop/Documents for all users."
    "Suspicious origins are also folded into 00_BROWSER_ALERTS.txt by the correlation step."
    ""
    $scanFolders = @('Downloads','Desktop','Documents')
    $exts = @('.exe','.dll','.scr','.ps1','.bat','.cmd','.vbs','.js','.jse','.wsf','.hta','.msi',
        '.com','.lnk','.iso','.img','.7z','.zip','.rar','.gz','.jar','.apk',
        '.docm','.xlsm','.pptm','.doc','.xls','.ppt','.pdf')
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($userDir in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
        $user = $userDir.Name
        foreach ($sub in $scanFolders) {
            $p = Join-Path $userDir.FullName $sub
            if (-not (Test-Path $p)) { continue }
            Get-ChildItem $p -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $exts -contains $_.Extension.ToLower() } |
                ForEach-Object {
                    $zi = Get-Content -LiteralPath $_.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue
                    if (-not $zi) { return }
                    $ref = ''; $hostUrl = ''
                    foreach ($ln in $zi) {
                        if ($ln -match '(?i)^ReferrerUrl=(.+)$') { $ref = $matches[1].Trim() }
                        elseif ($ln -match '(?i)^HostUrl=(.+)$') { $hostUrl = $matches[1].Trim() }
                    }
                    if ($ref -or $hostUrl) {
                        [void]$rows.Add([PSCustomObject]@{ User=$user; File=$_.FullName; FileLeaf=$_.Name; ReferrerUrl=$ref; HostUrl=$hostUrl })
                        [void]$script:DownloadSources.Add([PSCustomObject]@{ User=$user; FileLeaf=$_.Name; ReferrerUrl=$ref; HostUrl=$hostUrl; Source='Zone.Identifier' })
                    }
                }
        }
    }
    if ($rows.Count) {
        foreach ($r in $rows) {
            "FILE : $($r.File)"
            if ($r.HostUrl)     { "  HostUrl     : $($r.HostUrl)" }
            if ($r.ReferrerUrl) { "  ReferrerUrl : $($r.ReferrerUrl)" }
            ""
        }
        "Total downloaded files with a recorded origin: $($rows.Count)"
    } else {
        "(no Zone.Identifier download-origin data found in user content folders)"
    }
}

Save-Output "07_recycle_bin.txt" {
    Write-Section "RECYCLE BIN CONTENTS (deleted-but-recoverable, per user SID)"
    "A normal delete only moves the file into C:\`$Recycle.Bin\<SID>\ and renames it: the `$I file"
    "holds the original path/size/deletion-time, the paired `$R file is the recovered content"
    "(same suffix). Shift+Delete and secure-wipe bypass this. Recovered `$R binaries are also"
    "hashed against the IOC lists in the matching step below."
    ""
    $rbRoot = Join-Path $env:SystemDrive '$Recycle.Bin'
    if (-not (Test-Path $rbRoot)) { "(no `$Recycle.Bin on $env:SystemDrive)"; return }
    $any = $false
    foreach ($sidDir in (Get-ChildItem $rbRoot -Directory -Force -ErrorAction SilentlyContinue)) {
        $sid = $sidDir.Name
        $iFiles = Get-ChildItem $sidDir.FullName -Force -ErrorAction SilentlyContinue -Filter '$I*'
        if (-not $iFiles) { continue }
        $any = $true
        $acct = $sid
        try { $acct = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value } catch {}
        "`n--- SID $sid  ($acct) ---"
        $rows = foreach ($i in $iFiles) {
            $meta = Read-RecycleI $i.FullName
            if (-not $meta) { continue }
            $rName = '$R' + $i.Name.Substring(2)   # $IXXXX.ext -> $RXXXX.ext (avoids -replace $-group ambiguity)
            $rPath = Join-Path $sidDir.FullName $rName
            $rExists = Test-Path -LiteralPath $rPath
            if ($meta.OriginalPath -match '(?i)\.(exe|dll|scr|ps1|bat|cmd|vbs|js|hta|msi)$' -and
                $meta.OriginalPath -match '(?i)\\(Temp|AppData|Users\\Public|ProgramData|Downloads|Desktop)\\') {
                Add-Finding 'MED' '07' (Ex "Deleted executable in Recycle Bin (from a writable path): $($meta.OriginalPath)") '07_recycle_bin.txt'
            }
            [PSCustomObject]@{
                OriginalPath = $meta.OriginalPath
                Deleted      = if ($meta.DeletedTime) { $meta.DeletedTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '?' }
                SizeKB       = if ($meta.OriginalSize) { '{0:N0}' -f ($meta.OriginalSize/1KB) } else { '?' }
                Recovered    = if ($rExists) { $rPath } else { '(missing)' }
            }
        }
        if ($rows) { $rows | Format-Table -AutoSize -Wrap }
    }
    if (-not $any) { "(Recycle Bin is empty for all users, or not accessible)" }
}

# ---------------------------------------------

#  8. EVENT LOG ARTIFACTS

# ---------------------------------------------

Save-Output "08_security_events.txt" {
    $eventIds = @{
        4720 = 'User account created'
        4722 = 'User account enabled'
        4724 = 'Password reset attempt'
        4728 = 'Member added to global group'
        4732 = 'Member added to local group'
        4756 = 'Member added to universal group'
        4698 = 'Scheduled task created'
        4702 = 'Scheduled task updated'
        4657 = 'Registry value modified'
        4688 = 'New process created'
        4697 = 'Service installed'
        7045 = 'New service installed (System)'
        1102 = 'Audit log cleared'
        4719 = 'Audit policy changed'
    }

    foreach ($id in $eventIds.Keys | Sort-Object) {
        Write-Section "Event $id - $($eventIds[$id]) (last 50, within $($script:DaysBack)d)"
        $logName = if ($id -ge 7000) { 'System' } else { 'Security' }
        Get-WinEvent -FilterHashtable @{ LogName = $logName; Id = $id; StartTime = (Get-Date).AddDays(-$script:DaysBack) } -MaxEvents 50 -ErrorAction SilentlyContinue |
            Select-Object TimeCreated, Id, Message | Format-List
    }
}

Save-Output "08_cleared_logs.txt" {
    Write-Section "EVENT LOG CLEAR HISTORY"
    $sec1102 = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=1102]]" -MaxEvents 100 -ErrorAction SilentlyContinue
    $sys104  = Get-WinEvent -LogName System -FilterXPath "*[System[EventID=104]]" -MaxEvents 100 -ErrorAction SilentlyContinue
    if ($sec1102) {
        Add-Finding 'HIGH' '08' (Ex "Security log was CLEARED ($($sec1102.Count) event(s) 1102) ^09 possible anti-forensics") '08_cleared_logs.txt'
    }
    if ($sys104) {
        Add-Finding 'MED' '08' "A System/application log was cleared ($($sys104.Count) event(s) 104)" '08_cleared_logs.txt'
    }
    $sec1102 | Select-Object TimeCreated, Message | Format-List
    $sys104  | Select-Object TimeCreated, Message | Format-List
}

Save-Output "08_event_log_status.txt" {
    Write-Section "EVENT LOG STATUS (size & last written)"
    Get-EventLog -List | Select-Object Log, MaximumKilobytes, Entries, OverflowAction, MinimumRetentionDays |
        Format-Table -AutoSize

    Write-Section "WEVTUTIL LOG STATUS"
    wevtutil el | ForEach-Object {
        $info = wevtutil gl $_ 2>&1
        if ($info -match 'enabled: true') {
            [PSCustomObject]@{ Log = $_; Info = ($info -join ' ') }
        }
    } | Format-Table -AutoSize
}

# ---------------------------------------------

#  9. INSTALLED SOFTWARE & PATCHES

# ---------------------------------------------

Save-Output "09_installed_software.txt" {
    Write-Section "INSTALLED SOFTWARE (Add/Remove Programs)"
    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $regPaths | ForEach-Object {
        Get-ItemProperty $_ -ErrorAction SilentlyContinue
    } | Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation |
        Sort-Object InstallDate -Descending | Format-Table -AutoSize
}

Save-Output "09_appdata_app_installs.txt" {
    Write-Section "PER-USER APP INSTALLS UNDER AppData (all users)"
    "Apps installed into a user's AppData need no admin rights and often skip Add/Remove Programs,"
    "so AppData is a favorite home for adware / PUPs / 'clone' browsers. The standard software scan"
    "(09_installed_software) won't list them. This walks EVERY user's Local / Roaming / LocalLow,"
    "lists folders that contain an executable, and FLAGS two high-signal PUP patterns:"
    "   - a Chromium-style  <App>\Application\<version>\(...\Installer\setup.exe)  under a non-vendor name"
    "   - an updater/dock family:  <App> plus <App>Updater / <App>AutoUpdate / <App>Dock"
    ""

    # Legit per-user vendors/folders: still listed if they hold exes, but never flagged.
    $good = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($g in 'Microsoft','Google','Google Chrome','Mozilla','BraveSoftware','Packages','Temp',
        'Programs','SquirrelTemp','Adobe','JetBrains','JetBrains Toolbox','Docker','Postman','Slack',
        'discord','Zoom','GitHub Desktop','GitHubDesktop','obsidian','Notion','1Password','Spotify',
        'Dropbox','NVIDIA','NVIDIA Corporation','ConnectedDevicesPlatform','CrashDumps','D3DSCache',
        'ElevatedDiagnostics','Comms','Publishers','VirtualStore','WinGet','pip','Yarn','pnpm','npm',
        'ms-playwright','python','TileDataLayer') { [void]$good.Add($g) }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($userDir in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
        $user = $userDir.Name
        foreach ($base in 'Local','Roaming','LocalLow') {
            $root = Join-Path $userDir.FullName "AppData\$base"
            if (-not (Test-Path $root)) { continue }
            $dirs = @(Get-ChildItem $root -Directory -Force -ErrorAction SilentlyContinue)
            if (-not $dirs) { continue }
            # Sibling names for cheap family detection (case-insensitive).
            $names = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($d in $dirs) { [void]$names.Add($d.Name) }

            foreach ($d in $dirs) {
                $name = $d.Name

                # --- Chromium-clone layout: <App>\Application\<ver>\ with an exe (+/- Installer\setup.exe).
                #     Bounded lookups only (never a deep recurse of AppData).
                $cloneHit = $false; $cloneVer = ''
                $appDir = Join-Path $d.FullName 'Application'
                if (Test-Path $appDir) {
                    foreach ($v in (Get-ChildItem $appDir -Directory -Force -ErrorAction SilentlyContinue)) {
                        if ($v.Name -notmatch '^\d+(\.\d+)+$') { continue }
                        $hasExe = [bool](Get-ChildItem $v.FullName -Filter *.exe -File -Force -ErrorAction SilentlyContinue | Select-Object -First 1)
                        $hasSetup = Test-Path (Join-Path $v.FullName 'Installer\setup.exe')
                        if ($hasExe -or $hasSetup) { $cloneHit = $true; $cloneVer = $v.Name; break }
                    }
                }

                # --- Updater / dock family (name-only; no disk hit).
                $famHit = $false
                foreach ($suf in 'Updater','Update','AutoUpdate','Dock') {
                    if ($names.Contains($name + $suf)) { $famHit = $true; break }
                    if ($name -match "(?i)$suf`$") {
                        $bnm = $name -replace "(?i)$suf`$", ''
                        if ($bnm -and $names.Contains($bnm)) { $famHit = $true; break }
                    }
                }

                # Only surface folders that are actually app installs (hold an exe or are part of a family).
                $topExe = Get-ChildItem $d.FullName -Filter *.exe -File -Force -ErrorAction SilentlyContinue | Select-Object -First 1
                if (-not $cloneHit -and -not $topExe -and -not $famHit) { continue }

                $isGood = $good.Contains($name)
                $flag = ($cloneHit -or $famHit) -and -not $isGood
                $reason = @()
                if ($cloneHit) { $reason += "chromium-layout(Application\$cloneVer)" }
                if ($famHit)   { $reason += 'updater/dock-family' }

                $rows.Add([PSCustomObject]@{
                    User    = $user
                    Where   = "AppData\$base"
                    Folder  = $name
                    Flag    = if ($flag) { 'FLAG' } elseif ($isGood) { '(known)' } else { '' }
                    Signals = ($reason -join ', ')
                    Path    = $d.FullName
                })

                if ($flag) {
                    Add-Finding 'HIGH' '09' (Ex "Possible PUP/clone app in AppData: $user\$base\$name ($($reason -join ', ')) ^17 $($d.FullName)") '09_appdata_app_installs.txt'
                }
            }
        }
    }

    if ($rows.Count) {
        $rows | Sort-Object @{E={ if ($_.Flag -eq 'FLAG') { 0 } else { 1 } }}, User, Where |
            Format-Table User, Where, Folder, Flag, Signals, Path -AutoSize -Wrap
    } else {
        "(no per-user AppData application folders with executables found)"
    }
}

Save-Output "09_user_hive_software.txt" {
    Write-Section "PER-USER SOFTWARE REGISTRATION (all user hives, incl. logged-off)"
    "PUPs / adware often register directly under HKCU\Software\<Name> (carrying an UninstallString"
    "or InstallerProgress value) rather than the standard Uninstall path, and drop a companion"
    "<Name>Updater key. The Add/Remove scan reads only HKLM + the CURRENT user's hive, so it misses"
    "these on other users. This walks EVERY user hive - loaded ones under HKEY_USERS, and logged-off"
    "users' NTUSER.DAT which it mounts (mounting needs admin; skipped otherwise) - then unloads them."
    ""

    # Enumerate every user hive (loaded + logged-off mounted); helper handles reg load.
    $hv = Get-AllUserHives
    $hives = $hv.Hives
    $mounted = $hv.Mounted
    $skippedOffline = $hv.OfflineSkipped

    $rows = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($h in $hives) {
            # (1) Self-registered Software\<Name> keys carrying an uninstaller/installer footprint.
            $swKey = "$($h.Base)\Software"
            if (Test-Path $swKey) {
                $subs = @(Get-ChildItem $swKey -ErrorAction SilentlyContinue)
                $subNames = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($s in $subs) { [void]$subNames.Add($s.PSChildName) }
                foreach ($s in $subs) {
                    $name = $s.PSChildName
                    $vals = Get-ItemProperty $s.PSPath -ErrorAction SilentlyContinue
                    $uninst = $vals.UninstallString
                    $hasProg = ($vals.PSObject.Properties.Name -contains 'InstallerProgress')
                    if (-not $uninst -and -not $hasProg) { continue }   # not a self-registered installer key
                    $hasUpdater = $false
                    foreach ($suf in 'Updater','Update','AutoUpdate') { if ($subNames.Contains($name + $suf)) { $hasUpdater = $true; break } }
                    $inAppData = $uninst -match '(?i)\\AppData\\(Local|Roaming|LocalLow)\\'
                    $sev = if ($hasUpdater -and $inAppData) { 'HIGH' } elseif ($hasUpdater -or $inAppData) { 'MED' } else { 'INFO' }
                    $rows.Add([PSCustomObject]@{
                        Account = $h.Acct
                        Sev     = $sev
                        Updater = if ($hasUpdater) { 'yes' } else { '' }
                        Key     = "Software\$name"
                        Detail  = $uninst
                    })
                    if ($sev -ne 'INFO') {
                        $tags = @(); if ($hasUpdater) { $tags += '+updater' }; if ($inAppData) { $tags += 'AppData' }
                        Add-Finding $sev '09' (Ex "Self-registered app key: HKU\...\Software\$name ($($h.Acct))$(if($tags){' ['+($tags -join ',')+']'})") '09_user_hive_software.txt'
                    }
                }
            }
            # (2) Per-user Add/Remove entries (Uninstall) - not covered by the HKLM/HKCU scan.
            foreach ($un in "$($h.Base)\Software\Microsoft\Windows\CurrentVersion\Uninstall",
                            "$($h.Base)\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall") {
                if (-not (Test-Path $un)) { continue }
                Get-ChildItem $un -ErrorAction SilentlyContinue | ForEach-Object {
                    $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                    if (-not $p.DisplayName) { return }
                    $loc = "$($p.InstallLocation) $($p.UninstallString)"
                    $inAppData = $loc -match '(?i)\\AppData\\(Local|Roaming|LocalLow)\\'
                    $rows.Add([PSCustomObject]@{
                        Account = $h.Acct
                        Sev     = if ($inAppData) { 'MED' } else { 'INFO' }
                        Updater = ''
                        Key     = "Uninstall\$($_.PSChildName)"
                        Detail  = "$($p.DisplayName) | $($p.UninstallString)"
                    })
                    if ($inAppData) {
                        Add-Finding 'MED' '09' (Ex "Per-user app installed under AppData: '$($p.DisplayName)' ($($h.Acct))") '09_user_hive_software.txt'
                    }
                }
            }
            # (3) Per-user Run / RunOnce entries pointing into writable paths (missed by the current-user run scan).
            foreach ($rk in "$($h.Base)\Software\Microsoft\Windows\CurrentVersion\Run",
                            "$($h.Base)\Software\Microsoft\Windows\CurrentVersion\RunOnce") {
                if (-not (Test-Path $rk)) { continue }
                $rp = Get-ItemProperty $rk -ErrorAction SilentlyContinue
                if (-not $rp) { continue }
                $rp.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                    $val = [string]$_.Value
                    $badLoc = ($val -match '(?i)\\(AppData|Temp|Users\\Public|ProgramData)\\') -and ($val -notmatch $script:TrustedPathRx)
                    if ($badLoc) {
                        $rows.Add([PSCustomObject]@{ Account=$h.Acct; Sev='HIGH'; Updater=''; Key="Run\$($_.Name)"; Detail=$val })
                        Add-Finding 'HIGH' '09' (Ex "Per-user Run entry from a writable path: '$($_.Name)' ($($h.Acct)) ^17 $val") '09_user_hive_software.txt'
                    }
                }
            }
        }
    } finally {
        Dismount-UserHives $mounted
    }

    "Hives examined: $($hives.Count)  (offline mounted: $($mounted.Count); offline skipped: $skippedOffline)"
    $isAdminNow = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdminNow) {
        "NOTE: not elevated - logged-off users' hives could not be mounted. Run as Administrator for full coverage."
    }
    ""
    if ($rows.Count) {
        $rows | Sort-Object @{E={ switch ($_.Sev) { 'HIGH' {0} 'MED' {1} default {2} } }}, Account |
            Format-Table Account, Sev, Updater, Key, Detail -AutoSize -Wrap
    } else {
        "(no per-user self-registered software / AppData installs found)"
    }
}

Save-Output "09_patches.txt" {
    Write-Section "INSTALLED HOTFIXES / PATCHES"
    Get-HotFix | Sort-Object InstalledOn -Descending | Format-Table -AutoSize
}

Save-Output "09_defender_status.txt" {
    # Microsoft Defender posture. Answers two key triage questions:
    #   1) Did AV already detect something? (threat history)
    #   2) Has an attacker weakened protection or hidden a path? (exclusions / disabled features)
    $haveMp = Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue

    if (-not $haveMp) {
        "Defender cmdlets (Get-MpComputerStatus) not available on this host."
        "Defender may be absent, replaced by another AV, or running on Server core without the module."
        return
    }

    Write-Section "PROTECTION STATUS"
    $st = Get-MpComputerStatus -ErrorAction SilentlyContinue
    $st | Select-Object AMRunningMode, RealTimeProtectionEnabled, AntivirusEnabled,
        BehaviorMonitorEnabled, IoavProtectionEnabled, OnAccessProtectionEnabled,
        TamperProtectionSource, IsTamperProtected, AntivirusSignatureLastUpdated,
        QuickScanAge, FullScanAge | Format-List

    # Flag disabled core protections
    if ($st) {
        if ($st.RealTimeProtectionEnabled -eq $false) {
            Add-Finding 'HIGH' '09' "Defender real-time protection is DISABLED" '09_defender_status.txt'
        }
        if ($st.AntivirusEnabled -eq $false) {
            Add-Finding 'MED' '09' "Defender antivirus is disabled (another AV may be active)" '09_defender_status.txt'
        }
        if ($st.IsTamperProtected -eq $false) {
            Add-Finding 'INFO' '09' "Defender tamper protection is off" '09_defender_status.txt'
        }
    }

    Write-Section "EXCLUSIONS (paths / extensions / processes)"
    # Attacker-added exclusions are a top hiding technique - e.g. excluding C:\Temp.
    $pref = Get-MpPreference -ErrorAction SilentlyContinue
    if ($pref) {
        "ExclusionPath:"
        if ($pref.ExclusionPath) { $pref.ExclusionPath | ForEach-Object { "  $_" } } else { "  (none)" }
        "ExclusionExtension:"
        if ($pref.ExclusionExtension) { $pref.ExclusionExtension | ForEach-Object { "  $_" } } else { "  (none)" }
        "ExclusionProcess:"
        if ($pref.ExclusionProcess) { $pref.ExclusionProcess | ForEach-Object { "  $_" } } else { "  (none)" }
        ""
        "DisableRealtimeMonitoring : $($pref.DisableRealtimeMonitoring)"
        "DisableScriptScanning     : $($pref.DisableScriptScanning)"
        "MAPSReporting             : $($pref.MAPSReporting)"
        "SubmitSamplesConsent      : $($pref.SubmitSamplesConsent)"

        # Flag suspicious exclusions (writable/temp locations)
        foreach ($ex in $pref.ExclusionPath) {
            if ($ex -match '(?i)\\(Temp|AppData|Users\\Public|ProgramData|Downloads)\b' -or $ex -match '(?i)^[A-Z]:\\$') {
                Add-Finding 'HIGH' '09' (Ex "Defender exclusion on a writable/temp path: $ex ^09 common malware-hiding spot") '09_defender_status.txt'
            }
        }
        if ($pref.DisableRealtimeMonitoring -eq $true) {
            Add-Finding 'HIGH' '09' "Defender real-time monitoring disabled via preference" '09_defender_status.txt'
        }
    }

    Write-Section "THREAT DETECTION HISTORY"
    $threats = Get-MpThreatDetection -ErrorAction SilentlyContinue | Sort-Object InitialDetectionTime -Descending
    if ($threats) {
        $threats | Select-Object ThreatID, @{N='Detected';E={$_.InitialDetectionTime}},
            @{N='Resources';E={($_.Resources -join '; ')}} | Format-Table -AutoSize -Wrap
        Add-Finding 'HIGH' '09' "$(@($threats).Count) Defender threat detection(s) in history - review 09_defender_status.txt" '09_defender_status.txt'
    } else {
        "(no detections recorded, or history cleared)"
    }
}

# ---------------------------------------------

#  10. BROWSER & CREDENTIAL ARTIFACTS

# ---------------------------------------------

Save-Output "10_browser_artifacts.txt" {
    Write-Section "BROWSER HISTORY FILE LOCATIONS"
    $profiles = @{
        'Chrome'  = 'C:\Users\*\AppData\Local\Google\Chrome\User Data\*\History'
        'Edge'    = 'C:\Users\*\AppData\Local\Microsoft\Edge\User Data\*\History'
        'Firefox' = 'C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\places.sqlite'
    }
    foreach ($browser in $profiles.Keys) {
        "`n--- $browser ---"
        $files = Get-ChildItem $profiles[$browser] -ErrorAction SilentlyContinue
        if ($files) {
            $files | Select-Object FullName, LastWriteTime, Length | Format-Table -AutoSize
        } else { "  (not found)" }
    }
}

function Get-UrlsFromHistoryFile {
    # Dependency-free URL extraction from a browser history database (Chrome/Edge 'History' or
    # Firefox 'places.sqlite'). We DON'T parse SQLite (that would need an external engine and
    # break secgurd's no-dependencies rule); instead we read the raw file - opened with shared
    # ReadWrite so an open browser's lock can't block us - and regex out the http(s) URL strings
    # stored as UTF-8 text inside it. We also scan the '-wal' write-ahead-log sidecar, so the most
    # recent visits (not yet checkpointed into the main DB while the browser is open) aren't
    # missed. Returns a HashSet of unique URLs, or $null if nothing could be read.
    param([string]$Path)
    $urls = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
    $rx = [regex]"(?i)https?://[^\s""'<>\\)(\]\[}{\x00-\x1f]{4,2048}"
    $anyRead = $false
    foreach ($p in @($Path, "$Path-wal")) {     # main DB + write-ahead log
        if (-not (Test-Path -LiteralPath $p)) { continue }
        try {
            $fs = [System.IO.File]::Open($p, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        } catch {
            continue   # locked exclusively / access denied
        }
        try {
            $len = $fs.Length
            if ($len -le 0 -or $len -gt 80MB) { continue }   # history DBs are far smaller; cap RAM use
            $buf = New-Object byte[] ([int]$len)
            $read = 0
            while ($read -lt $len) {
                $n = $fs.Read($buf, $read, [int]($len - $read))
                if ($n -le 0) { break }
                $read += $n
            }
        } catch {
            continue
        } finally {
            $fs.Close()
        }
        $anyRead = $true
        # Latin1 maps each byte to one char, so binary stays intact and ASCII URLs match cleanly.
        $text = [System.Text.Encoding]::GetEncoding(28591).GetString($buf)
        foreach ($m in $rx.Matches($text)) {
            $u = $m.Value.TrimEnd('.', ',', ';', ')', '>', '"', "'", '!', '`')
            if ($u.Length -ge 8) { [void]$urls.Add($u) }
        }
    }
    if (-not $anyRead) { return $null }
    return $urls
}

function Get-UrlHost {
    # Pull the host (domain) out of a URL with no [uri] dependency (some malformed URLs throw
    # under [uri], and we want this to never fail mid-scan). Returns lowercase host or ''.
    param([string]$Url)
    if ($Url -match '^[a-z]+://([^/:\s]+)') { return $matches[1].ToLower() }
    return ''
}

function Test-LookalikeDomain {
    # Conservative typo-squat / impersonation check on a host. Returns a reason string for a hit,
    # else $null. Designed to catch the PDFast-style pattern (pdf-fast.com, adobe-reader-download
    # .com, zoom-install.net) WITHOUT flagging legitimate vendor or company domains.
    #
    # Rule (deliberately narrow to keep false positives low): we only look at the registrable
    # label (the part before the public suffix, e.g. 'pdf-fast' in 'pdf-fast.com'). It is flagged
    # only when that label CONTAINS A HYPHEN and either:
    #   (a) pairs a known brand/software word with a lure/action word (adobe-reader, zoom-install,
    #       chrome-update, pdf-download...), or
    #   (b) contains a brand word AND splits into 3+ hyphen segments (adobe-reader-download).
    # Plain hyphenated business domains (my-company-intranet, jira-prod) won't trip it unless they
    # carry a brand+lure combination, and legit brand domains (no hyphen) are never flagged here.
    param([string]$UrlHost)
    if (-not $UrlHost) { return $null }
    $h = $UrlHost.ToLower()
    # registrable label = the label just left of the public suffix. Handle the common
    # two-label ccTLD suffixes (.co.uk, .com.au ...) so e.g. 'pdf-fast.co.uk' resolves to
    # 'pdf-fast', not 'co'. (Not a full public-suffix list, just the high-traffic ones.)
    $parts = $h.Split('.')
    if ($parts.Count -lt 2) { return $null }
    $twoLabelSuffix = @('co.uk','com.au','com.br','co.nz','co.jp','co.za','com.mx','co.in',
        'com.sg','com.hk','org.uk','net.au','gov.uk','co.kr','com.tw','com.cn','co.il',
        'com.tr','com.ua','com.ar','com.co','com.pl','com.ph','com.my','co.id')
    $label = $parts[$parts.Count - 2]
    if ($parts.Count -ge 3) {
        $lastTwo = $parts[$parts.Count - 2] + '.' + $parts[$parts.Count - 1]
        if ($twoLabelSuffix -contains $lastTwo) { $label = $parts[$parts.Count - 3] }
    }
    if ($label -notmatch '-') { return $null }   # only hyphenated labels are candidates

    $brandWords = @('pdf','adobe','acrobat','microsoft','office','windows','update','java',
        'zoom','teams','chrome','firefox','edge','google','docusign','dropbox','onedrive',
        'outlook','excel','word','flash','reader','antivirus','defender','login','secure',
        'account','support','wallet','crypto','meta','paypal','amazon','apple','netflix')
    $tailWords  = @('install','installer','setup','download','downloads','update','updater',
        'fast','free','online','viewer','reader','converter','player','app','client','tool',
        'now','latest','official','win','x64','x86','crack','patch','activator')

    $segs = $label.Split('-') | Where-Object { $_ -ne '' }
    $hasBrand = $false; $hasTail = $false
    foreach ($s in $segs) {
        if ($brandWords -contains $s) { $hasBrand = $true }
        if ($tailWords  -contains $s) { $hasTail = $true }
    }
    if ($hasBrand -and $hasTail) {
        return "lookalike domain (brand + lure word): $h"
    }
    if ($hasBrand -and $segs.Count -ge 3) {
        return "lookalike domain (brand word in 3+ part hyphenated host): $h"
    }
    return $null
}

# ---------------------------------------------
#  CURATED MALICIOUS-DOMAIN WATCHLIST (hand-maintained)
# ---------------------------------------------
# Small, hand-picked list you edit directly - separate from the auto-refreshed URLhaus feed
# (communitysavedMALURLS.txt). Use it to pin domains/TLDs you keep seeing to a firm verdict.
#
#   $script:WatchlistHosts - specific known-bad domains/hosts. A browser-history URL whose host
#     equals one of these, OR is a subdomain of it (foo.rdxgo.click matches rdxgo.click), is
#     flagged HIGH. Lower-case, no scheme, no path.
#   $script:WatchlistTlds  - abuse-prone TLDs to flag on top of the built-in list. Just the
#     label, no leading dot. These flag MED (a whole TLD is a broad signal, not one host).
$script:WatchlistHosts = @(
    'rdxgo.click'
    # add more known-bad domains here, one per line, e.g. 'malware-example.com'
)
$script:WatchlistTlds = @(
    'beer'
    # add more abuse-prone TLDs here, one per line (no dot), e.g. 'lat'
)

function Test-SuspiciousUrl {
    # Heuristic triage of a single URL. Returns @{Severity;Reason} for a hit, else $null.
    # Tuned to surface payload downloads, raw-IP/C2/exfil infra, obfuscation and abuse TLDs -
    # leads to verify, not verdicts.
    param([string]$Url)
    $lower = $Url.ToLower()
    $urlHost = Get-UrlHost $Url

    # Community malicious-URL feed (abuse.ch URLhaus, from communitysavedMALURLS.txt) - highest
    # confidence, so it's checked first. Exact URL match beats a host match, but either is HIGH.
    if ($script:MalUrlSet -and $script:MalUrlSet.Count -gt 0) {
        if ($script:MalUrlSet.Contains($lower.TrimEnd('/'))) {
            return @{ Severity = 'HIGH'; Reason = 'listed on the community malicious-URL feed (URLhaus)' }
        }
        if ($urlHost -and $script:MalUrlHostSet -and $script:MalUrlHostSet.Contains($urlHost)) {
            return @{ Severity = 'HIGH'; Reason = 'host listed on the community malicious-URL feed (URLhaus)' }
        }
    }

    # Curated watchlist (hand-maintained above) - exact host or a subdomain of a watched domain.
    if ($urlHost -and $script:WatchlistHosts) {
        foreach ($w in $script:WatchlistHosts) {
            $wl = $w.ToLower().Trim()
            if ($wl -and ($urlHost -eq $wl -or $urlHost.EndsWith('.' + $wl))) {
                return @{ Severity = 'HIGH'; Reason = "on the curated malicious-domain watchlist ($wl)" }
            }
        }
    }

    if ($lower -match '\.(exe|scr|hta|ps1|bat|cmd|vbs|jse?|wsf|jar|msi|dll|lnk|iso|img|apk|ace|7z)(\?|#|$)') {
        return @{ Severity = 'HIGH'; Reason = 'direct executable/script download' }
    }
    if ($urlHost -match '^\d{1,3}(\.\d{1,3}){3}$') {
        # Only flag PUBLIC raw-IP hosts. Private / internal ranges (RFC1918, loopback,
        # link-local, CGNAT) are almost always benign LAN devices - e.g. a firewall/appliance
        # admin page at 10.30.4.207 - so we don't alert on them.
        $o = $urlHost.Split('.') | ForEach-Object { [int]$_ }
        $isInternal =
            ($o[0] -eq 10) -or
            ($o[0] -eq 127) -or
            ($o[0] -eq 169 -and $o[1] -eq 254) -or
            ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) -or
            ($o[0] -eq 192 -and $o[1] -eq 168) -or
            ($o[0] -eq 100 -and $o[1] -ge 64 -and $o[1] -le 127)
        if (-not $isInternal) {
            return @{ Severity = 'HIGH'; Reason = 'connection to a raw public IP address' }
        }
    }
    # Lookalike / typo-squat domain (pdf-fast.com, adobe-reader-download.com, zoom-install...).
    # Conservative - only fires on brand+lure hyphenated hosts, so it is HIGH-confidence here.
    $look = Test-LookalikeDomain $urlHost
    if ($look) {
        return @{ Severity = 'HIGH'; Reason = $look }
    }
    if ($lower -match '(?i)(cdn\.discordapp\.com|discord(app)?\.com/api/webhooks|pastebin\.com/raw|paste\.ee|controlc\.com|transfer\.sh|anonfiles\.com|gofile\.io|mega\.(nz|io)|mediafire\.com|file\.io|0x0\.st|tmpfiles\.|temp\.sh|ngrok\.(io|app|dev)|serveo\.net|trycloudflare\.com|\.workers\.dev|\.r2\.dev|telegram\.org|t\.me/)') {
        return @{ Severity = 'HIGH'; Reason = 'known file-drop / C2 / exfil infrastructure' }
    }
    if ($urlHost -match 'raw\.githubusercontent\.com$' -or $urlHost -match 'gist\.githubusercontent\.com$') {
        return @{ Severity = 'MED'; Reason = 'raw GitHub content (common payload host)' }
    }
    if ($urlHost -match '^(bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd|cutt\.ly|rebrand\.ly|ow\.ly|rb\.gy|shorturl\.at|tiny\.cc|bit\.do|s\.id)$') {
        return @{ Severity = 'MED'; Reason = 'URL shortener (obscures destination)' }
    }
    if ($urlHost -match '\.(tk|top|xyz|gq|ml|cf|work|click|country|kim|men|loan|download|zip|mov|rest|cfd|sbs|lol|quest)$') {
        return @{ Severity = 'MED'; Reason = 'high-abuse TLD' }
    }
    if ($urlHost -and $script:WatchlistTlds) {
        foreach ($t in $script:WatchlistTlds) {
            $tl = $t.ToLower().Trim().TrimStart('.')
            if ($tl -and $urlHost.EndsWith('.' + $tl)) {
                return @{ Severity = 'MED'; Reason = "watchlisted high-abuse TLD (.$tl)" }
            }
        }
    }
    if ($urlHost -match '(^|\.)xn--') {
        return @{ Severity = 'MED'; Reason = 'punycode host (possible homoglyph/spoof)' }
    }
    if ($lower -match '(anydesk|teamviewer|atera|splashtop|screenconnect|connectwise|logmein|gotomypc|remoteutilities|ammyy|netsupport|meshcentral|rustdesk)') {
        return @{ Severity = 'INFO'; Reason = 'remote-access tool reference (confirm authorized)' }
    }
    return $null
}

Save-Output "10_browser_history.txt" {
    Write-Section "BROWSER HISTORY - URL EXTRACTION & ANALYSIS (per user)"
    "Dependency-free: URLs are read directly from each browser's history database (Chrome/Edge"
    "'History', Firefox 'places.sqlite', plus the -wal sidecar) - no SQLite engine, so per-visit"
    "timestamps/counts are not decoded; instead each profile's DB last-write time is shown in UTC"
    "as coarse timing context. Individual URLs are NOT added to the post-run FINDINGS list /"
    "00_SUMMARY (too noisy) - a few HIGH/MED are echoed live during the scan for awareness, and"
    "EVERY flagged URL of every severity is written in full to the per-user files. A single"
    "summary finding points you there. The full URL list per profile is written to:"
    "    10_browser_history\<user>\<browser>_<profile>.txt"
    if ($script:MalUrlCount -gt 0) {
        "Community malicious-URL feed active: $($script:MalUrlCount) URL(s) from communitysavedMALURLS.txt"
        "(abuse.ch URLhaus) - any visited URL or host on the feed is flagged HIGH."
    }
    if ($script:SquatDomainCount -gt 0) {
        "Squat-domain watchlist active: $($script:SquatDomainCount) domain(s) from squat_domains.txt"
        "(openSquat) - any host matching a watchlisted look-alike is flagged HIGH; see 10_squat_watchlist.txt."
    }
    ""

    $browsers = @(
        @{ Name = 'Chrome';  Glob = 'C:\Users\*\AppData\Local\Google\Chrome\User Data\*\History' }
        @{ Name = 'Edge';    Glob = 'C:\Users\*\AppData\Local\Microsoft\Edge\User Data\*\History' }
        @{ Name = 'Firefox'; Glob = 'C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\places.sqlite' }
    )

    $detailRoot = Join-Path $OutputPath '10_browser_history'
    $grandTotalUrls = 0
    $grandFlagged = 0
    $usersSeen = @{}
    # These caps limit ONLY how many URLs are ECHOED live during the scan (for awareness). NO
    # browser URL is added to the post-run FINDINGS list / 00_SUMMARY (they're -NoRecord). And
    # the caps never limit the output files: every per-user detail file gets ALL flagged + ALL
    # unique URLs (written below from $flagged / $urlList, which ignore these counters).
    $highEchoed = 0; $highCap = 5   # HIGH URLs echoed live during the scan (not recorded)
    $medEchoed  = 0; $medCap  = 3   # MED URLs echoed live during the scan (not recorded)
    $summaryRows = New-Object System.Collections.Generic.List[object]

    foreach ($b in $browsers) {
        $dbs = Get-ChildItem $b.Glob -ErrorAction SilentlyContinue -Force
        foreach ($db in $dbs) {
            $user = if ($db.FullName -match '(?i)\\Users\\([^\\]+)\\') { $matches[1] } else { 'unknown' }
            $profileName = Split-Path (Split-Path $db.FullName -Parent) -Leaf

            $dbModUtc = $db.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm') + 'Z'
            $urls = Get-UrlsFromHistoryFile -Path $db.FullName
            if ($null -eq $urls) {
                $summaryRows.Add([PSCustomObject]@{ User = $user; Browser = $b.Name; Profile = $profileName; 'ModifiedUTC' = $dbModUtc; URLs = 'LOCKED/ERR'; Flagged = '-' })
                continue
            }
            $usersSeen[$user] = $true
            $urlList = @($urls) | Sort-Object
            $grandTotalUrls += $urlList.Count

            $flagged = New-Object System.Collections.Generic.List[object]
            foreach ($u in $urlList) {
                $uHost = Get-UrlHost $u
                # Is this host on the squat watchlist? Resolved up-front so a squat hit can OWN the
                # alert for this URL: the squat reason (impersonates one of our brands) is more
                # specific than any generic heuristic, so we do NOT also emit a heuristic alert for
                # the same URL - that is the "no duplicate hardcoded-vs-dependency alert" guarantee.
                $sqMatch = if ($script:SquatDomainCount -gt 0) { Test-SquatHost $uHost } else { $null }

                $verdict = Test-SuspiciousUrl $u
                if ($verdict) {
                    # Always list the heuristic/feed verdict in the per-user detail file (raw data).
                    $flagged.Add([PSCustomObject]@{ Severity = $verdict.Severity; Reason = $verdict.Reason; URL = $u })
                    # But only feed the correlation + live echo when squat is NOT also claiming this
                    # URL (else the host double-alerts). Add-BrowserFlag further dedupes identical
                    # (user, host, reason). Echoes stay -NoRecord (kept out of the FINDINGS list).
                    if (-not $sqMatch) {
                        Add-BrowserFlag $user $b.Name $uHost $verdict.Severity $verdict.Reason $u
                        $msg = (Ex "Browser URL [$user/$($b.Name)] ^09 $($verdict.Reason): $u")
                        switch ($verdict.Severity) {
                            'HIGH' { if ($highEchoed -lt $highCap) { Add-Finding 'HIGH' '10' $msg '10_browser_history.txt' -NoRecord -HighlightUrl $u; $highEchoed++ } }
                            'MED'  { if ($medEchoed  -lt $medCap)  { Add-Finding 'MED'  '10' $msg '10_browser_history.txt' -NoRecord -HighlightUrl $u; $medEchoed++ } }
                            default { }   # INFO: written to the per-user detail file only
                        }
                    }
                }

                # Squat hit: the one, most-specific alert for this host. Deduped per (user, host);
                # feeds 10_squat_watchlist.txt and 00_BROWSER_ALERTS.txt.
                if ($sqMatch -and $script:SquatSeen.Add("$user|$uHost")) {
                    $reason = "matches openSquat squat-domain watchlist ($sqMatch)"
                    $script:SquatMatches.Add([PSCustomObject]@{ User=$user; Browser=$b.Name; Url=$u; Host=$uHost; Matched=$sqMatch; Source='browser-history' })
                    Add-Finding 'HIGH' '10' (Ex "Browser URL [$user/$($b.Name)] ^09 $($reason): $u") '10_squat_watchlist.txt' -HighlightUrl $u
                    Add-BrowserFlag $user $b.Name $uHost 'HIGH' $reason $u
                }
            }
            $grandFlagged += $flagged.Count

            # Build the per-user detail content.
            $lines = New-Object System.Collections.Generic.List[string]
            $lines.Add((Write-Section "$($b.Name) HISTORY - user '$user' - profile '$profileName'"))
            $lines.Add("Source DB   : $($db.FullName)")
            $lines.Add("DB modified : $($db.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC   ($($db.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')) local)")
            $lines.Add("Unique URLs : $($urlList.Count)    Flagged: $($flagged.Count)")
            $lines.Add('')
            $lines.Add((Write-Section "FLAGGED URLS (heuristic - verify before acting)"))
            if ($flagged.Count) {
                $firstFlag = $true
                foreach ($f in ($flagged | Sort-Object Severity, URL)) {
                    if (-not $firstFlag) { $lines.Add('') }   # blank line between each flagged entry
                    $lines.Add(("[{0,-4}] {1}" -f $f.Severity, $f.Reason))
                    $lines.Add(("        {0}" -f $f.URL))
                    $firstFlag = $false
                }
            } else {
                $lines.Add("(none flagged by heuristics)")
            }
            $lines.Add('')
            $lines.Add((Write-Section "ALL UNIQUE URLS ($($urlList.Count))"))
            foreach ($u in $urlList) { $lines.Add($u) }

            # Decide whether this detail file is worth writing (mirror the Save-Output policy for
            # the directly-written detail files). No file when: a find filter is active and this
            # profile has no matching URL (so no "(no matches...)" file), or - with no filter -
            # the profile yielded no URLs at all. A profile WITH history but no flags is still
            # written (informational, like the scheduled-tasks dump).
            $outArr = $lines.ToArray()
            $writeDetail = $true
            if ($script:FindFilter) {
                $outArr = Select-FilteredOutput -Lines $outArr -Term $script:FindFilter
                if ($script:LastFilterMatchCount -le 0) { $writeDetail = $false }
            } elseif ($urlList.Count -eq 0) {
                $writeDetail = $false
            }
            if ($writeDetail) {
                $userDir = Join-Path $detailRoot $user
                $null = New-Item -ItemType Directory -Path $userDir -Force -ErrorAction SilentlyContinue
                $safeProfile = ($profileName -replace '[^\w.\-]', '_')
                $detailFile = Join-Path $userDir ("{0}_{1}.txt" -f $b.Name, $safeProfile)
                $outArr | Out-File -FilePath $detailFile -Encoding UTF8 -Force
            }

            $summaryRows.Add([PSCustomObject]@{ User = $user; Browser = $b.Name; Profile = $profileName; 'ModifiedUTC' = $dbModUtc; URLs = $urlList.Count; Flagged = $flagged.Count })
        }
    }

    Write-Section "SUMMARY (per user / browser / profile)"
    if ($summaryRows.Count) {
        $summaryRows | Sort-Object User, Browser, Profile | Format-Table -AutoSize
    } else {
        "No browser history databases found for any user on this host."
        "(Chrome / Edge / Firefox not installed, or no user profiles present.)"
    }
    ""
    "Users with history : $($usersSeen.Keys.Count)"
    "Total unique URLs  : $grandTotalUrls"
    "Total flagged URLs : $grandFlagged"
    "(Individual URLs are intentionally NOT in the FINDINGS list - see the per-user detail files.)"
    if ($grandFlagged -gt 0) {
        # The ONE browser entry that goes in the findings list: an aggregate pointer, not a URL.
        Add-Finding 'INFO' '10' "Browser history: $grandFlagged potentially-suspicious URL(s) across $($usersSeen.Keys.Count) user(s) - review 10_browser_history\<user>\" '10_browser_history.txt'
    }
}

Save-Output "10_squat_watchlist.txt" {
    Write-Section "SQUAT-DOMAIN WATCHLIST (openSquat) - MATCHES"
    "Cross-references browser-history hosts and download-origin hosts (module 03 BITS + module 07"
    "Zone.Identifier) against the openSquat squat-domain watchlist (squat_domains.txt). A match means"
    "a visited or downloaded host is a look-alike / typosquat of one of your brand terms - a likely"
    "phishing or drive-by domain. Matching is host-based: an exact host, or any subdomain of a"
    "watchlist entry. Browser-history hits are collected during 10_browser_history; download origins"
    "are folded in here. Every match is a HIGH finding and also appears in 00_BROWSER_ALERTS.txt."
    ""
    if (-not $script:SquatDomainSet -or $script:SquatDomainCount -le 0) {
        "Watchlist not loaded: squat_domains.txt was not found next to secgurd.ps1 (or was empty)."
        "Generate it with the 'Refresh squat-domain watchlist' GitHub Action (it runs openSquat over"
        "keywords.txt), or pass -SquatDomains <file>. Nothing to cross-reference."
        return
    }
    "Watchlist domains loaded : $($script:SquatDomainCount)"
    "Source                   : $($script:SquatDomainFile)"
    ""

    # Fold in download-origin hosts. Deduped per (user, host) via the same $script:SquatSeen set the
    # browser loop used, so a host seen in both places is reported once.
    foreach ($ds in $script:DownloadSources) {
        foreach ($cand in @($ds.HostUrl, $ds.ReferrerUrl)) {
            if (-not $cand) { continue }
            $dh = Get-UrlHost $cand
            $dm = Test-SquatHost $dh
            if (-not $dm) { continue }
            $du = if ($ds.User) { $ds.User } else { 'unknown' }
            if (-not $script:SquatSeen.Add("$du|$dh")) { continue }
            $reason = "matches openSquat squat-domain watchlist ($dm)"
            $script:SquatMatches.Add([PSCustomObject]@{ User=$du; Browser="download-origin ($($ds.Source))"; Url=$cand; Host=$dh; Matched=$dm; Source='download-origin' })
            Add-Finding 'HIGH' '10' (Ex "Download origin [$du] ^09 $($reason): $cand") '10_squat_watchlist.txt'
            Add-BrowserFlag $du 'download-origin' $dh 'HIGH' $reason $cand
        }
    }

    if ($script:SquatMatches.Count -eq 0) {
        "No browser-history or download-origin host matched the watchlist."
        return
    }

    Write-Section "MATCHES ($($script:SquatMatches.Count))"
    foreach ($sm in ($script:SquatMatches | Sort-Object Matched, User, Host)) {
        "[$($sm.Matched)]  user=$($sm.User)  via=$($sm.Browser)"
        "        host : $($sm.Host)"
        "        url  : $($sm.Url)"
        ""
    }
}

Save-Output "10_browser_extensions.txt" {
    Write-Section "BROWSER EXTENSIONS (Chromium: Chrome/Edge/Brave, per user/profile)"
    "Malicious or sideloaded extensions are a real cred-theft / session-hijack / persistence"
    "vector. We enumerate installed Chromium extensions from each profile's Extensions folder and"
    "read each manifest (name, version, permissions, update_url). Heuristics flag broad host"
    "access combined with sensitive APIs, and a missing update_url (often sideloaded/unpacked) -"
    "leads to verify, not verdicts. (Firefox add-ons use a different format and aren't covered here.)"
    ""
    $extRoots = @(
        @{ Browser='Chrome'; Glob='C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Extensions' }
        @{ Browser='Edge';   Glob='C:\Users\*\AppData\Local\Microsoft\Edge\User Data\*\Extensions' }
        @{ Browser='Brave';  Glob='C:\Users\*\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Extensions' }
    )
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($er in $extRoots) {
        foreach ($extDir in (Get-ChildItem $er.Glob -Directory -ErrorAction SilentlyContinue -Force)) {
            $user = if ($extDir.FullName -match '(?i)\\Users\\([^\\]+)\\') { $matches[1] } else { 'unknown' }
            $profileName = Split-Path (Split-Path $extDir.FullName -Parent) -Leaf
            foreach ($idDir in (Get-ChildItem $extDir.FullName -Directory -ErrorAction SilentlyContinue)) {
                $extId = $idDir.Name
                $verDir = Get-ChildItem $idDir.FullName -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
                if (-not $verDir) { continue }
                $manifestPath = Join-Path $verDir.FullName 'manifest.json'
                if (-not (Test-Path $manifestPath)) { continue }
                $name=''; $version=''; $perms=@(); $hostPerms=@(); $updateUrl=''; $mf=$null
                try {
                    $mf = Get-Content $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json
                    $name = $mf.name; $version = $mf.version; $updateUrl = $mf.update_url
                    if ($mf.permissions)      { $perms = @($mf.permissions) }
                    if ($mf.host_permissions) { $hostPerms = @($mf.host_permissions) }
                } catch {}
                # resolve __MSG_name__ via _locales
                if ($name -match '^__MSG_(.+)__$' -and $mf) {
                    $key = $matches[1]
                    $loc = $mf.default_locale; if (-not $loc) { $loc = 'en' }
                    $msgPath = Join-Path $verDir.FullName ("_locales\{0}\messages.json" -f $loc)
                    if (-not (Test-Path $msgPath)) { $msgPath = Join-Path $verDir.FullName '_locales\en\messages.json' }
                    if (Test-Path $msgPath) {
                        try { $msgs = Get-Content $msgPath -Raw | ConvertFrom-Json; if ($msgs.$key.message) { $name = $msgs.$key.message } } catch {}
                    }
                }
                $allPerms = @(($perms + $hostPerms) | Where-Object { $_ -is [string] -and $_ })
                $broad = @($allPerms | Where-Object { $_ -match '^(<all_urls>|https?://\*/?\*?|\*://\*/\*)$' })
                $risky = @($allPerms | Where-Object { $_ -match '(?i)^(tabs|webRequest|webRequestBlocking|cookies|debugger|proxy|nativeMessaging)$' })

                $rows.Add([PSCustomObject]@{
                    User=$user; Browser=$er.Browser; Profile=$profileName
                    Name=$name; Version=$version; Id=$extId
                    UpdateUrl=$updateUrl; Permissions=($allPerms -join ', ')
                })

                if ($broad.Count -and @($risky | Where-Object { $_ -match '(?i)webRequest|cookies|debugger|nativeMessaging' }).Count) {
                    Add-Finding 'MED' '10' (Ex "Browser extension '$name' [$($er.Browser)/$user] has broad host access + sensitive APIs ($($risky -join ', ')) ^09 review") '10_browser_extensions.txt'
                }
                if (-not $updateUrl) {
                    Add-Finding 'INFO' '10' "Browser extension '$name' [$($er.Browser)/$user] has no update_url (possibly sideloaded/unpacked): $extId" '10_browser_extensions.txt'
                }
            }
        }
    }
    if ($rows.Count) {
        $rows | Sort-Object User, Browser, Profile, Name | Format-Table -AutoSize -Wrap
        ""
        "Total extensions: $($rows.Count)"
    } else {
        "(no Chromium browser extensions found, or no profiles present)"
    }
}

Save-Output "10_credential_files.txt" {
    Write-Section "CREDENTIAL/CONFIG FILES OF INTEREST"
    $targets = @(
        'C:\Users\*\.aws\credentials',
        'C:\Users\*\.ssh\*',
        'C:\Users\*\AppData\Roaming\FileZilla\recentservers.xml',
        'C:\Users\*\AppData\Roaming\FileZilla\sitemanager.xml',
        'C:\Users\*\AppData\Local\Microsoft\Credentials\*',
        'C:\Users\*\AppData\Roaming\Microsoft\Credentials\*',
        'C:\Windows\Panther\Unattend.xml',
        'C:\Windows\Panther\Unattended.xml',
        'C:\Windows\System32\sysprep\Unattend.xml',
        'C:\inetpub\wwwroot\web.config',
        'C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    )
    foreach ($t in $targets) {
        $found = Get-ChildItem $t -ErrorAction SilentlyContinue -Force
        if ($found) {
            "`n[FOUND] $t"
            $found | Select-Object FullName, LastWriteTime, Length | Format-Table -AutoSize
        }
    }
}

# ---------------------------------------------

#  11. LOLBINS / LIVING OFF THE LAND

# ---------------------------------------------

Save-Output "11_lolbin_usage.txt" {
    Write-Section "LOLBIN PROCESS EVENTS (Event 4688, last 500)"
    $lolbins = @('certutil','mshta','wscript','cscript','regsvr32','rundll32',
                  'msiexec','bitsadmin','wmic','msbuild','installutil',
                  'regasm','regsvcs','cmstp','xwizard','appsync','syncappvpublishingserver',
                  'mavinject','odbcconf','pcalua','forfiles','scriptrunner','diskshadow',
                  'esentutl','expand','extrac32','findstr','replace','makecab',
                  'ie4uinit','infdefaultinstall','microsoft.workflow.compiler')

    $lolHits = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688 } -MaxEvents 500 -ErrorAction SilentlyContinue |
        ForEach-Object {
            $msg = $_.Message
            $exe = if ($msg -match 'New Process Name:\s+(.+)') { $matches[1].Trim() } else { '' }
            $cmd = if ($msg -match 'Process Command Line:\s+(.+)') { $matches[1].Trim() } else { '' }
            $exe_lower = $exe.ToLower()
            # Match leaf filename only   '\wmic.exe' won't match 'wmic_helper.exe' or paths containing 'wmic'.

            $leaf = Split-Path -Leaf $exe_lower
            foreach ($bin in $lolbins) {
                if ($leaf -eq "$bin.exe" -or $leaf -eq $bin) {
                    [PSCustomObject]@{
                        Time    = $_.TimeCreated
                        Binary  = $bin
                        Process = $exe
                        CmdLine = $cmd
                    }
                    break
                }
            }
        }
    if ($lolHits) {
        $distinct = ($lolHits.Binary | Sort-Object -Unique) -join ', '
        Add-Finding 'MED' '11' "$($lolHits.Count) LOLBin execution(s) in 4688 logs: $distinct" '11_lolbin_usage.txt'
    }
    $lolHits | Format-Table -AutoSize
}

# ---------------------------------------------

#  12. AMCACHE & SHIMCACHE (timeline)

# ---------------------------------------------

Save-Output "12_amcache_shimcache.txt" {
    Write-Section "AMCACHE.HVE LOCATION"
    $amcache = "$env:SystemRoot\AppCompat\Programs\Amcache.hve"
    if (Test-Path $amcache) {
        $f = Get-Item $amcache
        "AmCache found: $($f.FullName)"
        "  Size: $($f.Length) bytes"
        "  LastModified: $($f.LastWriteTime)"
        "`n  NOTE: Parse offline with tools like AmcacheParser (EricZimmerman) for full detail."
    } else { "  AmCache not found at $amcache" }

    Write-Section "APPCOMPAT CACHE (ShimCache) - Registry"
    $shimKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
    if (Test-Path $shimKey) {
        "ShimCache registry key found."
        "  NOTE: Parse the binary blob offline with AppCompatCacheParser (EricZimmerman)."
        "  Key: $shimKey"
    } else { "  ShimCache key not found." }
}

# ---------------------------------------------

#  13. PREFETCH

# ---------------------------------------------

Save-Output "13_prefetch.txt" {
    Write-Section "PREFETCH FILES (execution evidence)"
    $prefetchDir = "$env:SystemRoot\Prefetch"
    if (Test-Path $prefetchDir) {
        Get-ChildItem $prefetchDir -Filter '*.pf' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object Name, LastWriteTime, Length |
            Format-Table -AutoSize
    } else {
        "Prefetch directory not found (may be disabled or Server OS)"
    }
}

# ---------------------------------------------

#  14. NAMED PIPES & HANDLES (advanced)

# ---------------------------------------------

Save-Output "14_named_pipes.txt" {
    Write-Section "NAMED PIPES (suspicious names worth investigating)"
    try {
        Get-ChildItem -Path '\\.\pipe\' -ErrorAction Stop |
            Sort-Object Name |
            Select-Object Name |
            Format-Table -AutoSize
    } catch {
        # Fallback for older systems

        try {
            $pipes = [System.IO.Directory]::GetFiles('\\.\pipe\')
            $pipes | Sort-Object | ForEach-Object { Split-Path -Leaf $_ }
        } catch {
            "Unable to enumerate named pipes: $_"
        }
    }
}

# ---------------------------------------------

#  WRITE INDEX + SUMMARY + FINDINGS

# ---------------------------------------------

$runEnd  = Get-Date
$elapsed = $runEnd - $script:RunStart
$elapsedStr = '{0:mm}m {0:ss}s' -f $elapsed
$isAdminNow = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$selectedIds = ($script:SelectedModules.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object { $_.Key } | Sort-Object) -join ', '

# 00_INDEX.txt   human-readable map of every file in the folder

$indexLines = @()
$indexLines += (Ex "secgurd $($script:secgurdVersion) ^09 Collection Index")
$indexLines += ("=" * 60)
$indexLines += "Host        : $env:COMPUTERNAME"
$indexLines += "User        : $env:USERDOMAIN\$env:USERNAME"
$indexLines += "Admin       : $isAdminNow"
$indexLines += "Started     : $($script:RunStart.ToString('yyyy-MM-dd HH:mm:ss'))"
$indexLines += "Finished    : $($runEnd.ToString('yyyy-MM-dd HH:mm:ss'))"
$indexLines += "Duration    : $elapsedStr"
$indexLines += "Modules run : $selectedIds"
$indexLines += "Lookback    : $($script:DaysBack) days"
if ($script:FindFilter) { $indexLines += "Find filter : '$($script:FindFilter)' (output scoped to lines containing this)" }
$indexLines += "Collected   : $($script:CollectedCount) files"
$indexLines += "Empty (skip): $($script:EmptySkipped) collector(s) had no data - no file written"
$indexLines += "Errors      : $($script:ErrorCount)"
$indexLines += ""
$indexLines += "FILES IN THIS FOLDER"
$indexLines += ("-" * 60)
# Recurse so per-user subfolders (e.g. 10_browser_history\<user>\) are listed too.
Get-ChildItem $OutputPath -Filter '*.txt' -Recurse | Sort-Object FullName | ForEach-Object {
    $rel = $_.FullName.Substring($OutputPath.Length).TrimStart('\', '/')
    $indexLines += ("  {0,-52} {1,8:N0} bytes" -f $rel, $_.Length)
}
# Collector errors are logged here (not as per-file ERROR artifacts) so nothing is lost.
if ($script:ErrorDetails.Count -gt 0) {
    $indexLines += ""
    $indexLines += "COLLECTOR ERRORS (no file written for these)"
    $indexLines += ("-" * 60)
    $script:ErrorDetails | ForEach-Object { $indexLines += "  $_" }
}
$indexLines | Out-File (Join-Path $OutputPath '00_INDEX.txt') -Encoding UTF8 -Force

# 00_SUMMARY.txt   findings + metadata, the first file an analyst should read

$summaryLines = @()
$summaryLines += (Ex "secgurd $($script:secgurdVersion) ^09 Triage Summary")
$summaryLines += ("=" * 60)
$summaryLines += "Host     : $env:COMPUTERNAME    User: $env:USERDOMAIN\$env:USERNAME"
$summaryLines += "When     : $($script:RunStart.ToString('yyyy-MM-dd HH:mm:ss'))   Duration: $elapsedStr"
$summaryLines += "Admin    : $isAdminNow"
$summaryLines += "Collected: $($script:CollectedCount) files   Errors: $($script:ErrorCount)"
if ($script:FindFilter) { $summaryLines += "Filter   : output scoped to '$($script:FindFilter)' (findings below limited to it)" }
$summaryLines += ""
$summaryLines += (Ex "FINDINGS (auto-flagged ^09 verify before acting)")
$summaryLines += ("-" * 60)
if ($script:Findings.Count -eq 0) {
    $summaryLines += "  No high-signal indicators auto-flagged."
    $summaryLines += (Ex "  (Absence of flags is NOT proof of a clean host ^09 review the raw files.)")
} else {
    $script:Findings | Sort-Object | ForEach-Object { $summaryLines += "  $_" }
}
$summaryLines += ""

# When a find filter is active, show at a glance which artifacts actually contained matches
# (so the analyst isn't hunting through dozens of "(no matches...)" files).
if ($script:FindFilter) {
    $summaryLines += (Ex "FILES WITH MATCHES (find: '$($script:FindFilter)')")
    $summaryLines += ("-" * 60)
    $hitFiles = $script:FindFileCounts.GetEnumerator() | Where-Object { $_.Value -gt 0 } | Sort-Object { $_.Value } -Descending
    if ($hitFiles) {
        foreach ($e in $hitFiles) {
            $word = if ($e.Value -eq 1) { 'instance' } else { 'instances' }
            $summaryLines += ("  {0,-42} {1,5} {2}" -f $e.Name, $e.Value, $word)
        }
        $emptyCount = @($script:FindFileCounts.GetEnumerator() | Where-Object { $_.Value -eq 0 }).Count
        $summaryLines += ""
        $summaryLines += ("  {0} file(s) matched; {1} collected file(s) had no matches." -f @($hitFiles).Count, $emptyCount)
    } else {
        $summaryLines += "  No artifact contained '$($script:FindFilter)'."
    }
    $summaryLines += ""
}

$summaryLines += "Generated by secgurd. Review raw artifact files for full detail."
$summaryLines | Out-File (Join-Path $OutputPath '00_SUMMARY.txt') -Encoding UTF8 -Force

# ---------------------------------------------
#  00_TIMELINE.txt   chronological merge of timestamped events
# ---------------------------------------------

Write-Host (Ex "  *  Building timeline...") -ForegroundColor Cyan
$timeline = New-Object System.Collections.Generic.List[object]
function Add-TL { param($Time, $Source, $Detail)
    # Honour the find filter so a scoped run's timeline only shows matching events.
    if ($script:FindFilter -and "$Source $Detail".IndexOf($script:FindFilter, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { return }
    if ($Time -is [string]) { $t = $null; [void][datetime]::TryParse($Time, [ref]$t) } else { $t = $Time }
    if ($t) { $timeline.Add([PSCustomObject]@{ Time=$t; Source=$Source; Detail=$Detail }) }
}
try {
    # Logons (4624) - last 14 days
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=(Get-Date).AddDays(-$script:DaysBack)} -MaxEvents 200 -ErrorAction SilentlyContinue | ForEach-Object {
        $x=[xml]$_.ToXml(); $u=($x.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
        $lt=($x.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'}).'#text'
        Add-TL $_.TimeCreated 'Logon' "4624 user=$u type=$lt"
    }
} catch {}
try {
    # Log clears
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 20 -ErrorAction SilentlyContinue | ForEach-Object { Add-TL $_.TimeCreated 'LogClear' '1102 Security log cleared' }
} catch {}
try {
    # New services (7045)
    Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=(Get-Date).AddDays(-$script:DaysBack)} -MaxEvents 100 -ErrorAction SilentlyContinue | ForEach-Object {
        $x=[xml]$_.ToXml(); $n=($x.Event.EventData.Data | Where-Object {$_.Name -eq 'ServiceName'}).'#text'
        Add-TL $_.TimeCreated 'NewService' "7045 service=$n"
    }
} catch {}
try {
    # Scheduled task creation/update (TaskScheduler 106/140)
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational';Id=106,140;StartTime=(Get-Date).AddDays(-$script:DaysBack)} -MaxEvents 100 -ErrorAction SilentlyContinue | ForEach-Object {
        Add-TL $_.TimeCreated 'Task' "$($_.Id) $($_.Message -replace '\s+',' ')".Substring(0,[Math]::Min(90,"$($_.Id) $($_.Message -replace '\s+',' ')".Length))
    }
} catch {}
try {
    # Recently modified files in System32 (last 7 days)
    Get-ChildItem "$env:SystemRoot\System32" -Filter *.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-$script:DaysBack) } |
        ForEach-Object { Add-TL $_.LastWriteTime 'FileMod' "System32\$($_.Name)" }
} catch {}

$tlLines = @()
$tlLines += (Ex "secgurd $($script:secgurdVersion) ^09 Event Timeline (most recent first)")
$tlLines += ("=" * 70)
$tlLines += "Merged from: logons (4624), log clears (1102), new services (7045),"
$tlLines += "             scheduled tasks (106/140), System32 exe modifications (within $($script:DaysBack)d)."
$tlLines += ("-" * 70)
if ($timeline.Count -eq 0) {
    $tlLines += "  (no timestamped events gathered - may require admin / log access)"
} else {
    $timeline | Sort-Object Time -Descending | ForEach-Object {
        $tlLines += ("{0:yyyy-MM-dd HH:mm:ss}  {1,-11} {2}" -f $_.Time, $_.Source, $_.Detail)
    }
}
$tlLines | Out-File (Join-Path $OutputPath '00_TIMELINE.txt') -Encoding UTF8 -Force

# ---------------------------------------------
#  00_HASHES.txt   SHA-256 of every artifact (evidence integrity)
# ---------------------------------------------

Write-Host (Ex "  *  Hashing artifacts (SHA-256)...") -ForegroundColor Cyan
$hashLines = @()
$hashLines += (Ex "secgurd $($script:secgurdVersion) ^09 SHA-256 Manifest")
$hashLines += ("=" * 78)
$hashLines += "Generated : $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))   Host: $env:COMPUTERNAME"
$hashLines += "Purpose   : evidence integrity - verify files were not altered after collection."
$hashLines += ("-" * 78)
# Recurse so per-user subfolder artifacts (e.g. 10_browser_history\<user>\) are hashed too.
Get-ChildItem $OutputPath -File -Recurse | Where-Object { $_.Name -ne '00_HASHES.txt' } | Sort-Object FullName | ForEach-Object {
    $rel = $_.FullName.Substring($OutputPath.Length).TrimStart('\', '/')
    try {
        $h = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
        $hashLines += ("{0}  {1}" -f $h, $rel)
    } catch {
        $hashLines += ("{0,-64}  {1}" -f 'ERROR-HASHING', $rel)
    }
}
$hashLines += ("-" * 78)
$hashLines += "Verify later with:  Get-FileHash <file> -Algorithm SHA256"
$hashLines | Out-File (Join-Path $OutputPath '00_HASHES.txt') -Encoding UTF8 -Force

# ---------------------------------------------
#  IOC HASH MATCHING   community list + manual list, kept separate
# ---------------------------------------------

# Resolve the MANUAL list from the -IOCHashes CLI param if the menu didn't already load one.
if (-not $script:IOCHashSet -and $IOCHashes) {
    if (Test-Path $IOCHashes) {
        $script:IOCHashSet = Import-IOCHashes $IOCHashes
        $script:IOCHashFile = $IOCHashes
        $script:IOCHashCount = $script:IOCHashSet.Count
    } else {
        Write-Host "  [!] -IOCHashes file not found: $IOCHashes" -ForegroundColor Yellow
    }
}

$haveCommunity = ($script:CommunityHashSet -and $script:CommunityHashCount -gt 0)
$haveManual    = ($script:IOCHashSet -and $script:IOCHashCount -gt 0)

if ($haveCommunity -or $haveManual) {
    # Friendly description of what we're matching against.
    $srcDesc = @()
    if ($haveCommunity) { $srcDesc += "community ($($script:CommunityHashCount))" }
    if ($haveManual)    { $srcDesc += "ones you added ($($script:IOCHashCount))" }
    Write-Host (Ex "  *  Matching on-disk binaries against $($srcDesc -join ' + ') hashes...") -ForegroundColor Cyan

    # Candidate set: real executables/DLLs in high-signal locations + running process images.
    $scanRoots = @(
        "$env:TEMP", "$env:SystemRoot\Temp",
        "$env:PUBLIC", "$env:ProgramData",
        "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:USERPROFILE\AppData\Local\Temp",
        "$env:USERPROFILE\AppData\Roaming", "$env:USERPROFILE\AppData\Local",
        "$env:SystemDrive\`$Recycle.Bin"
    ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

    $exts = '.exe','.dll','.scr','.ps1','.bat','.cmd','.vbs','.js','.hta','.com','.sys'
    $candidates = New-Object System.Collections.Generic.List[string]
    foreach ($root in $scanRoots) {
        try {
            Get-ChildItem $root -Recurse -File -ErrorAction SilentlyContinue -Force |
                Where-Object { $exts -contains $_.Extension.ToLower() -and $_.Length -lt 100MB } |
                ForEach-Object { $candidates.Add($_.FullName) }
        } catch {}
    }
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.Path) { $candidates.Add($_.Path) }
    }

    # Determine which algorithms are needed across BOTH lists (only hash what we must).
    $allKeys = @()
    if ($haveCommunity) { $allKeys += $script:CommunityHashSet.Keys }
    if ($haveManual)    { $allKeys += $script:IOCHashSet.Keys }
    $algos = @()
    $lengths = $allKeys | ForEach-Object { $_.Length } | Sort-Object -Unique
    if ($lengths -contains 32) { $algos += 'MD5' }
    if ($lengths -contains 40) { $algos += 'SHA1' }
    if ($lengths -contains 64) { $algos += 'SHA256' }
    if ($algos.Count -eq 0) { $algos = @('SHA256') }

    # Prepare separate result buffers per source.
    $commMatches = @()
    $manMatches  = @()
    $seen = @{}
    $scanned = 0

    foreach ($path in $candidates) {
        if ($seen.ContainsKey($path)) { continue }
        $seen[$path] = $true
        $scanned++
        foreach ($algo in $algos) {
            $fh = $null
            try { $fh = (Get-FileHash $path -Algorithm $algo -ErrorAction Stop).Hash.ToUpper() } catch { continue }
            $hitComm = $haveCommunity -and $script:CommunityHashSet.ContainsKey($fh)
            $hitMan  = $haveManual    -and $script:IOCHashSet.ContainsKey($fh)
            if ($hitComm) {
                $label = $script:CommunityHashSet[$fh]
                $commMatches += [PSCustomObject]@{ Path=$path; Hash=$fh; Algo=$algo; Label=$label }
                Add-Finding 'HIGH' '09' (Ex "IOC match [community] ($algo): $path$(if($label){" ($label)"})") '00_IOC_MATCHES_community.txt'
            }
            if ($hitMan) {
                $label = $script:IOCHashSet[$fh]
                $manMatches += [PSCustomObject]@{ Path=$path; Hash=$fh; Algo=$algo; Label=$label }
                Add-Finding 'HIGH' '09' (Ex "IOC match [you added] ($algo): $path$(if($label){" ($label)"})") '00_IOC_MATCHES_manual.txt'
            }
            if ($hitComm -or $hitMan) { break }  # this file already flagged; next file
        }
    }

    # Write a separate match file per source so you can always tell community vs. yours.
    function Write-IOCMatchFile {
        param($Title, $SourceFile, $Count, $Matches, $OutName)
        $L = @()
        $L += (Ex "secgurd $($script:secgurdVersion) ^09 IOC Hash Matches - $Title")
        $L += ("=" * 78)
        $L += "Source list : $SourceFile  ($Count hashes)"
        $L += "Algorithms  : $($algos -join ', ')"
        $L += "Scanned     : Temp, AppData, Public, ProgramData, Downloads, Desktop, running procs"
        $L += ("-" * 78)
        if ($Matches.Count -eq 0) {
            $L += "(no on-disk binaries matched this list)"
        } else {
            foreach ($m in $Matches) {
                $L += ("MATCH  {0}" -f $m.Path)
                $L += ("       {0} ({1}){2}" -f $m.Hash, $m.Algo, $(if ($m.Label) { "  [$($m.Label)]" } else { '' }))
            }
        }
        $L += ("-" * 78)
        $L += "Files scanned: $scanned   Matches: $($Matches.Count)"
        $L | Out-File (Join-Path $OutputPath $OutName) -Encoding UTF8 -Force
    }

    if ($haveCommunity) {
        Write-IOCMatchFile 'community list' $script:CommunityHashFile $script:CommunityHashCount $commMatches '00_IOC_MATCHES_community.txt'
    }
    if ($haveManual) {
        Write-IOCMatchFile 'ones you added' $script:IOCHashFile $script:IOCHashCount $manMatches '00_IOC_MATCHES_manual.txt'
    }

    $totalMatches = $commMatches.Count + $manMatches.Count
    if ($totalMatches -gt 0) {
        $parts = @()
        if ($commMatches.Count) { $parts += "$($commMatches.Count) community" }
        if ($manMatches.Count)  { $parts += "$($manMatches.Count) you-added" }
        Write-Alert (Ex "  ! IOC MATCH(es): $($parts -join ', ') - see 00_IOC_MATCHES_*.txt")
    } else {
        Write-Host (Ex "  [^14] No IOC matches ($scanned files scanned)") -ForegroundColor Green
    }
}

# ---------------------------------------------
#  BROWSER ALERT CORRELATION  (cross-reference flagged URLs with host artifacts)
# ---------------------------------------------

# Takes everything module 10 flagged ($script:BrowserFlagged) and cross-references each flagged
# host against what actually landed on disk - downloaded/temp files, IOC hash matches, and other
# findings. The payoff is the PDFast-style case: a flagged download URL (pdf-fast.com/PDFast.exe)
# whose leaf filename (PDFast.exe) ALSO shows up in Downloads or an IOC match = corroborated on
# host -> bumped to HIGH; other URLs on the same domain ride along at MED. Output is grouped,
# de-duplicated and readable: 00_BROWSER_ALERTS.txt, plus an inline finding if anything corroborates.
if (($script:BrowserFlagged -and $script:BrowserFlagged.Count -gt 0) -or ($script:DownloadSources -and $script:DownloadSources.Count -gt 0)) {
    Write-Host (Ex "  *  Correlating browser URLs with host artifacts...") -ForegroundColor Cyan

    # 1) Harvest candidate filenames present ON THIS HOST from already-written artifacts +
    #    findings. We keep them lowercased and as leaf names for matching against URL filenames.
    $hostFiles = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
    $addLeaf = {
        param($name)
        if (-not $name) { return }
        $n = ([string]$name).Trim()
        if ($n -match '([^\\/]+\.(exe|dll|scr|ps1|bat|cmd|vbs|js|hta|msi|com|lnk|iso|img|7z|zip))\b') {
            [void]$hostFiles.Add($matches[1].ToLower())
        }
    }
    # from 07 downloads/desktop + temp executables + recycle bin artifact text
    foreach ($af in @('07_downloads_desktop.txt','07_temp_executables.txt','07_recycle_bin.txt')) {
        $p = Join-Path $OutputPath $af
        if (Test-Path $p) {
            foreach ($ln in (Get-Content $p -ErrorAction SilentlyContinue)) { & $addLeaf $ln }
        }
    }
    # from IOC match files (MATCH lines carry the full on-disk path)
    foreach ($af in @('00_IOC_MATCHES_community.txt','00_IOC_MATCHES_manual.txt')) {
        $p = Join-Path $OutputPath $af
        if (Test-Path $p) {
            foreach ($ln in (Get-Content $p -ErrorAction SilentlyContinue)) {
                if ($ln -match '^\s*MATCH\s+(.+)$') { & $addLeaf $matches[1] }
            }
        }
    }
    # from the in-memory findings (catches scheduled-task / service / RMM drops naming a file)
    foreach ($fdg in $script:Findings) { & $addLeaf $fdg }

    # 1b) Fold in download origins from Zone.Identifier (module 07). These run through the SAME
    #     URL heuristic here (safe - all functions are defined by now). We only surface an origin
    #     when its URL is itself suspicious OR its host was already flagged from the browser side,
    #     so benign downloads don't flood the alerts. Because the file is on disk by definition,
    #     a matching filename corroborates it to HIGH in the scoring pass below. The full,
    #     unfiltered origin list always lives in 07_download_origins.txt.
    foreach ($ds in $script:DownloadSources) {
        $srcUrl = if ($ds.HostUrl) { $ds.HostUrl } else { $ds.ReferrerUrl }
        if (-not $srcUrl) { continue }
        $dsHost = Get-UrlHost $srcUrl
        $v = Test-SuspiciousUrl $srcUrl
        $sameAsBrowser = $false
        if ($dsHost) { foreach ($bf in $script:BrowserFlagged) { if ($bf.Host -eq $dsHost) { $sameAsBrowser = $true; break } } }
        if ($v -or $sameAsBrowser) {
            $sev = if ($v) { $v.Severity } else { 'MED' }
            $rsn = "download origin ($($ds.Source)) of $($ds.FileLeaf)$(if ($v) { " - $($v.Reason)" })"
            Add-BrowserFlag $ds.User 'download-origin' $dsHost $sev $rsn $srcUrl
            # ensure the downloaded file's own name is in the host-file set for corroboration
            & $addLeaf $ds.FileLeaf
        }
    }

    # 2) Which flagged URLs look like an actual payload fetch (so a host hit is corroboration,
    #    not just coincidence)? Reason text from Test-SuspiciousUrl tells us.
    $payloadHosts = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($bf in $script:BrowserFlagged) {
        if ($bf.Reason -match '(?i)executable/script download|fake-installer|lookalike|download origin') {
            if ($bf.Host) { [void]$payloadHosts.Add($bf.Host) }
        }
    }

    # 3) Walk every flagged URL; decide an EFFECTIVE severity:
    #      - HIGH  if the URL's own leaf filename is present on the host  (corroborated)
    #      - else  bump same-host URLs to at least MED when that host served a payload
    #      - else  keep the original severity
    $sevRank = @{ 'HIGH' = 3; 'MED' = 2; 'INFO' = 1 }
    $alertRows = New-Object System.Collections.Generic.List[object]
    $highCount = 0
    foreach ($bf in $script:BrowserFlagged) {
        $eff = $bf.Severity
        $note = ''
        # leaf filename from the URL itself
        $urlLeaf = ''
        if ($bf.Url -match '/([^/?#]+\.(exe|dll|scr|ps1|bat|cmd|vbs|js|hta|msi|com|lnk|iso|img|7z|zip))(\?|#|$)') {
            $urlLeaf = $matches[1].ToLower()
        }
        if ($urlLeaf -and $hostFiles.Contains($urlLeaf)) {
            $eff = 'HIGH'
            $note = "corroborated on host: $urlLeaf present in downloads/temp/IOC"
        } elseif ($bf.Host -and $payloadHosts.Contains($bf.Host) -and $sevRank[$eff] -lt $sevRank['MED']) {
            $eff = 'MED'
            $note = "same host served a payload URL"
        }
        if ($eff -eq 'HIGH') { $highCount++ }
        $alertRows.Add([PSCustomObject]@{
            EffSeverity = $eff
            User        = $bf.User
            Host        = $bf.Host
            Reason      = $bf.Reason
            Note        = $note
            Url         = $bf.Url
        })
    }

    # 4) Write a grouped, readable alert file: by user, then host, severity-ordered.
    $abLines = New-Object System.Collections.Generic.List[string]
    $abLines.Add((Ex "secgurd $($script:secgurdVersion) ^09 Browser Alert Correlation"))
    $abLines.Add(("=" * 72))
    $abLines.Add("Cross-references browser-flagged URLs with files seen on this host")
    $abLines.Add("(Downloads/Desktop, Temp, IOC matches, and other findings).")
    $abLines.Add("EffSeverity HIGH = the URL's filename was actually found on the host, OR a")
    $abLines.Add("lookalike/payload host; verify before acting - these are leads, not verdicts.")
    $abLines.Add(("-" * 72))
    $abLines.Add("Flagged URLs correlated : $($alertRows.Count)")
    $abLines.Add("Corroborated on host    : $highCount")
    $abLines.Add("Host filenames harvested: $($hostFiles.Count)")
    $abLines.Add("Download origins (Zone.Id): $($script:DownloadSources.Count) total (see 07_download_origins.txt)")
    $abLines.Add('')

    foreach ($userGrp in ($alertRows | Group-Object User | Sort-Object Name)) {
        $abLines.Add((Write-Section "USER: $($userGrp.Name)"))
        foreach ($hostGrp in ($userGrp.Group | Group-Object Host | Sort-Object Name)) {
            $abLines.Add("  host: $($hostGrp.Name)")
            $ordered = $hostGrp.Group | Sort-Object @{E={$sevRank[$_.EffSeverity]};Descending=$true}, Url
            foreach ($row in $ordered) {
                $abLines.Add(("    [{0,-4}] {1}" -f $row.EffSeverity, $row.Reason))
                if ($row.Note) { $abLines.Add("           ^ $($row.Note)") }
                $abLines.Add("           $($row.Url)")
            }
            $abLines.Add('')
        }
    }

    $abArr = $abLines.ToArray()
    if ($script:FindFilter) { $abArr = Select-FilteredOutput -Lines $abArr -Term $script:FindFilter }
    $abArr | Out-File (Join-Path $OutputPath '00_BROWSER_ALERTS.txt') -Encoding UTF8 -Force

    if ($highCount -gt 0) {
        Add-Finding 'HIGH' '10' "Browser correlation: $highCount flagged URL(s) corroborated by files on this host - see 00_BROWSER_ALERTS.txt" '00_BROWSER_ALERTS.txt'
        Write-Alert (Ex "  ! $highCount browser URL(s) corroborated on host - see 00_BROWSER_ALERTS.txt")
    } else {
        Write-Host (Ex "  [^14] Browser alerts written ($($alertRows.Count) flagged URL(s), none corroborated on host)") -ForegroundColor Green
    }
}

# ---------------------------------------------

#  BUNDLE INTO ZIP

# ---------------------------------------------

Write-Host ""
Write-Host (Ex " ^12^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^11") -ForegroundColor DarkGray
Write-Host ""

# Findings recap on screen

if ($script:Findings.Count -gt 0) {
    Write-Alert (Ex "  ^24 FINDINGS ($($script:Findings.Count))")
    foreach ($f in ($script:Findings | Sort-Object)) {
        if ($f -like '`[HIGH`]*') {
            Write-Alert "    $f"
        } else {
            $c = if ($f -like '`[MED`]*') { 'Yellow' } else { 'DarkGray' }
            Write-Host "    $f" -ForegroundColor $c
        }
    }
    Write-Host ""
} else {
    Write-Host (Ex "  ^24 No high-signal indicators auto-flagged (review raw files anyway).") -ForegroundColor DarkGray
    Write-Host ""
}

Write-Host (Ex "  ^27  Compressing the hoard...") -ForegroundColor Cyan
$zipPath = "$OutputPath.zip"
$zipOk = $false
try {
    Compress-Archive -Path $OutputPath -DestinationPath $zipPath -Force -ErrorAction Stop
    $zipOk = $true
} catch {
    Write-Host "  [!] Could not create zip: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host (Ex "      Raw folder is intact ^09 collect it manually.") -ForegroundColor DarkGray
}

Write-Host ""
Write-Host (Ex "  ^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00") -ForegroundColor DarkGray
Write-Host "  Collected : " -ForegroundColor DarkGray -NoNewline
Write-Host "$($script:CollectedCount) files" -ForegroundColor Green -NoNewline
if ($script:ErrorCount -gt 0) {
    Write-Host (Ex "   ^10   ") -ForegroundColor DarkGray -NoNewline
    Write-Host "$($script:ErrorCount) errors" -ForegroundColor Yellow -NoNewline
}
Write-Host (Ex "   ^10   ") -ForegroundColor DarkGray -NoNewline
Write-Host "$elapsedStr" -ForegroundColor White
Write-Host ""
if ($zipOk) {
    Write-Host (Ex "  [^14] Archive : ") -ForegroundColor Green -NoNewline
    Write-Host $zipPath -ForegroundColor White
}
Write-Host (Ex "  [^14] Raw     : ") -ForegroundColor Green -NoNewline
Write-Host $OutputPath -ForegroundColor White
Write-Host (Ex "  [^14] Start   : ") -ForegroundColor Green -NoNewline
Write-Host (Ex "00_SUMMARY.txt (findings) ^10 00_INDEX.txt (file map)") -ForegroundColor White
Write-Host ""

# Retrieval hint for remote sessions

Write-Host "  To pull results back over a PSRemoting session:" -ForegroundColor DarkGray
if ($zipOk) {
    Write-Host "    Copy-Item -FromSession `$s '$zipPath' -Destination .\" -ForegroundColor DarkGray
} else {
    Write-Host "    Copy-Item -FromSession `$s '$OutputPath' -Destination .\ -Recurse" -ForegroundColor DarkGray
}
Write-Host ""

Write-Flair (Ex "  ^13 The dragon falls. Triage complete. ^13") '1;91' 'Red'
Write-Host ""
Write-Host (Ex " ^11^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^12") -ForegroundColor DarkGray
Write-Host ""

# Optionally open the output folder when done (interactive desktop only; the 'o' menu toggle).

if ([Environment]::UserInteractive -and $script:OpenFolderWhenDone) {
    try { Invoke-Item $OutputPath } catch {}
}

# Return paths for caller use

[PSCustomObject]@{
    OutputFolder   = $OutputPath
    ZipArchive     = if ($zipOk) { $zipPath } else { $null }
    FilesCollected = $script:CollectedCount
    Errors         = $script:ErrorCount
    Findings       = $script:Findings
    Duration       = $elapsedStr
}
