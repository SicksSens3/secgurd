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
.PARAMETER IOCHashes
    Path to a file of known-bad SHA-256 hashes (one per line, optional ",label"). secgurd
    hashes on-disk binaries in high-signal locations (Temp, AppData, Public, Downloads, and
    running processes) and flags any that match. Fully offline - no API key or internet.
.PARAMETER DaysBack
    Lookback window in days for all time-bounded collectors (event logs, recently-modified
    files, the timeline, and new-account / modified-binary findings). Default 30. Use a
    larger value (e.g. 90) for suspected long-dwell compromises, smaller for fresh incidents.
.PARAMETER Help
    Show usage and exit.
.EXAMPLE
    .\secgurd.ps1
    Launches the interactive module menu.
.EXAMPLE
    iex (irm https://raw.githubusercontent.com/<you>/secgurd/main/secgurd.ps1)
    Pull from GitHub and run on a remoted machine.
.EXAMPLE
    .\secgurd.ps1 -Auto -OutputPath C:\Cases\IR-0042
    Run everything, no menu, custom output path.
.EXAMPLE
    .\secgurd.ps1 -Modules 03,04,06,11
    Run only persistence, PowerShell, processes, and LOLBins.
.EXAMPLE
    .\secgurd.ps1 -Auto -HtmlReport
    Run everything and also produce a single-file report.html for browser review.
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
    [switch]$HtmlReport,
    [string]$IOCHashes,
    [int]$DaysBack = 30,
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

$script:secgurdVersion = 'v1.1'

# ---------------------------------------------

#  SETUP

# ---------------------------------------------

$ErrorActionPreference = 'SilentlyContinue'
$script:RunStart = Get-Date
$script:Findings = [System.Collections.Generic.List[string]]::new()
$script:CollectedCount = 0
$script:ErrorCount = 0
$script:SkippedCount = 0
$script:ProceedWithRun = $false
$script:OpenFolderWhenDone = [bool]$OpenWhenDone
$script:RunLineActive = $false
$script:WithOwners = [bool]$WithOwners
$script:WithSignatures = [bool]$WithSignatures
$script:HtmlReport = [bool]$HtmlReport
$script:IOCHashFile = $null
$script:IOCHashSet = $null
$script:IOCHashCount = 0
$script:ShowIOCList = $false
# Lookback window (days) for all time-bounded collectors. Clamp to a sane 1..3650 range.
if ($DaysBack -lt 1) { $DaysBack = 1 }
if ($DaysBack -gt 3650) { $DaysBack = 3650 }
$script:DaysBack = $DaysBack

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

# ---------------------------------------------

#  secgurd BANNER

# ---------------------------------------------

function Show-secgurdBanner {
    # Color palette

    $gold   = 'Yellow'
    $hilt   = 'White'
    $pommel = 'Yellow'
    $tip    = 'Red'
    $rust   = 'DarkRed'
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
    Write-Host "    -HtmlReport           Also build a single-file report.html" -ForegroundColor Gray
    Write-Host "    -IOCHashes <file>     Match on-disk binaries against a SHA-256 IOC list" -ForegroundColor Gray
    Write-Host "    -DaysBack <N>         Lookback window for time-bounded collectors (default 30)" -ForegroundColor Gray
    Write-Host "    -Help                 Show this help" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  MENU COMMANDS" -ForegroundColor White
    Write-Host "    01-14                 Toggle a module on/off (space/comma-separate many)" -ForegroundColor Gray
    Write-Host "    a / n                 Select all / none" -ForegroundColor Gray
    Write-Host "    qa / net / ps         Apply a preset" -ForegroundColor Gray
    Write-Host "    o                     Toggle: open output folder when done" -ForegroundColor Gray
    Write-Host "    h                     Toggle: build + open HTML report" -ForegroundColor Gray
    Write-Host "    i                     Toggle: match hashes vs IOC list (prompts for file)" -ForegroundColor Gray
    Write-Host "    l                     Toggle: show the loaded IOC hash list in the menu" -ForegroundColor Gray
    Write-Host "    d                     Set lookback window in days (time-bounded collectors)" -ForegroundColor Gray
    Write-Host "    r                     Run selected modules" -ForegroundColor Gray
    Write-Host "    q                     Quit" -ForegroundColor Gray
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
    # Finds every secgurd output folder and zip under %TEMP% and deletes them,
    # gated behind a type-to-confirm prompt so it can't fire accidentally.
    if (-not $NoBanner) { Show-secgurdBanner }

    $pattern = Join-Path $env:TEMP 'secgurd_*'
    $items = Get-ChildItem $pattern -Force -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "  CLEANUP - remove secgurd output from this machine" -ForegroundColor Cyan
    Write-Host "  ----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Location: $env:TEMP" -ForegroundColor DarkGray
    Write-Host ""

    if (-not $items) {
        Write-Host "  Nothing to clean - no secgurd_* items found in TEMP." -ForegroundColor Green
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
            $kind = 'zip   '
        }
        $totalBytes += [int64]$size
        Write-Host ("   {0}  {1,-50} {2,8:N0} KB" -f $kind, $it.Name, ($size/1KB)) -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host ("  {0} item(s), {1:N1} MB total" -f $items.Count, ($totalBytes/1MB)) -ForegroundColor White
    Write-Host ""

    # Non-interactive safety: never auto-delete without a human confirming.
    if (-not [Environment]::UserInteractive -or $Host.Name -eq 'ServerRemoteHost') {
        Write-Host "  Refusing to delete in a non-interactive session." -ForegroundColor Yellow
        Write-Host "  Run interactively, or delete manually:" -ForegroundColor DarkGray
        Write-Host "    Remove-Item `"$pattern`" -Recurse -Force" -ForegroundColor DarkGray
        Write-Host ""
        return
    }

    # Two-step type-to-confirm
    Write-Flair "  This permanently deletes the items above. This cannot be undone." '1;91' 'Red'
    Write-Host ""
    Write-Host "  To confirm, type exactly:  " -ForegroundColor DarkGray -NoNewline
    Write-Host "DELETE" -ForegroundColor Yellow
    Write-Host "  (anything else cancels)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  > " -ForegroundColor DarkGray -NoNewline
    $confirm = Read-Host

    if ($confirm -cne 'DELETE') {
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
    [PSCustomObject]@{ Id='01'; Name='System info';          Desc='os, build, uptime, domain' }
    [PSCustomObject]@{ Id='02'; Name='Users & sessions';     Desc='accounts, logons, 4624/4625' }
    [PSCustomObject]@{ Id='03'; Name='Persistence';          Desc='run keys, tasks, services, wmi, ifeo' }
    [PSCustomObject]@{ Id='04'; Name='PowerShell artifacts'; Desc='history, transcripts, 4104' }
    [PSCustomObject]@{ Id='05'; Name='Network';              Desc='connections, dns, arp, fw' }
    [PSCustomObject]@{ Id='06'; Name='Processes';            Desc='proctree, cmdlines, unsigned dlls' }
    [PSCustomObject]@{ Id='07'; Name='Filesystem';           Desc='temp exes, ads, recent files' }
    [PSCustomObject]@{ Id='08'; Name='Event logs';           Desc='account changes, log clearing' }
    [PSCustomObject]@{ Id='09'; Name='Software & defender';  Desc='installed apps, patches, av status' }
    [PSCustomObject]@{ Id='10'; Name='Browser & creds';      Desc='history paths, .ssh, .aws' }
    [PSCustomObject]@{ Id='11'; Name='LOLBins';              Desc='certutil, mshta, rundll32...' }
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

function Show-ModuleMenu {
    # If we're not running interactively (e.g. piped via iex over remote shell with no TTY),

    # fall through and run everything. Prevents Read-Host deadlock.

    if (-not [Environment]::UserInteractive -or $Host.Name -eq 'ServerRemoteHost') {
        Write-Host ""
        Write-Host (Ex "  ^16  Non-interactive session detected ^09 running all modules.") -ForegroundColor Yellow
        Write-Host ""
        # No menu available to choose from, so enable everything.
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
        Write-Host "] quit" -ForegroundColor DarkGray
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
        Write-Host ("{0,-30}" -f 'Open output folder when done') -ForegroundColor White -NoNewline
        Write-Host "(local/RDP only)" -ForegroundColor DarkGray

        $hrOn   = $script:HtmlReport
        $hrMark = if ($hrOn) { (Ex "[^14]") } else { '[ ]' }
        $hrClr  = if ($hrOn) { 'Green' } else { 'DarkGray' }
        Write-Host "   " -NoNewline
        Write-Host $hrMark -ForegroundColor $hrClr -NoNewline
        Write-Host "  " -NoNewline
        Write-Host ("{0,-4}" -f 'h') -ForegroundColor Yellow -NoNewline
        Write-Host ("{0,-30}" -f 'Build + open HTML report') -ForegroundColor White -NoNewline
        Write-Host "(report.html)" -ForegroundColor DarkGray

        $iocOn   = [bool]$script:IOCHashFile
        $iocMark = if ($iocOn) { (Ex "[^14]") } else { '[ ]' }
        $iocClr  = if ($iocOn) { 'Green' } else { 'DarkGray' }
        $iocNote = if ($iocOn) { "($($script:IOCHashCount) hashes loaded)" } else { '(prompts for hash list)' }
        Write-Host "   " -NoNewline
        Write-Host $iocMark -ForegroundColor $iocClr -NoNewline
        Write-Host "  " -NoNewline
        Write-Host ("{0,-4}" -f 'i') -ForegroundColor Yellow -NoNewline
        Write-Host ("{0,-30}" -f 'Match hashes against IOC list') -ForegroundColor White -NoNewline
        Write-Host $iocNote -ForegroundColor DarkGray

        # Only offer the list toggle once hashes are loaded
        if ($iocOn) {
            $lMark = if ($script:ShowIOCList) { (Ex "[^14]") } else { '[ ]' }
            $lClr  = if ($script:ShowIOCList) { 'Green' } else { 'DarkGray' }
            $lNote = if ($script:ShowIOCList) { '(showing below)' } else { '(hidden)' }
            Write-Host "   " -NoNewline
            Write-Host $lMark -ForegroundColor $lClr -NoNewline
            Write-Host "  " -NoNewline
            Write-Host ("{0,-4}" -f 'l') -ForegroundColor Yellow -NoNewline
            Write-Host ("{0,-30}" -f 'Show IOC hash list in menu') -ForegroundColor White -NoNewline
            Write-Host $lNote -ForegroundColor DarkGray
        }

        Write-Host "   " -NoNewline
        Write-Host (Ex "[^17]") -ForegroundColor DarkCyan -NoNewline
        Write-Host "  " -NoNewline
        Write-Host ("{0,-4}" -f 'd') -ForegroundColor Yellow -NoNewline
        Write-Host ("{0,-30}" -f 'Lookback window (days)') -ForegroundColor White -NoNewline
        Write-Host "(currently $($script:DaysBack)d)" -ForegroundColor DarkGray

        Write-Host ""
        Write-Host (Ex "     ^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00") -ForegroundColor DarkGray
        Write-Host ""

        # Inline IOC hash list (toggled with 'l')
        if ($script:ShowIOCList -and $script:IOCHashSet -and $script:IOCHashCount -gt 0) {
            Show-IOCList
        }

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

        if ($cmd -eq 'h') {
            $script:HtmlReport = -not $script:HtmlReport
            $state = if ($script:HtmlReport) { 'ON' } else { 'OFF' }
            $pendingMsg = "Build HTML report: $state"
            Clear-Host; Show-secgurdBannerCompact
            continue
        }

        if ($cmd -eq 'i') {
            $iocLoaded = ($script:IOCHashSet -and $script:IOCHashCount -gt 0)
            Write-Host ""
            Write-Host "  IOC hash matching" -ForegroundColor Cyan -NoNewline
            if ($iocLoaded) {
                Write-Host "  ($($script:IOCHashCount) hashes loaded)" -ForegroundColor Green
            } else {
                Write-Host "  (none loaded)" -ForegroundColor DarkGray
            }
            Write-Host "    [f] " -ForegroundColor Yellow -NoNewline
            Write-Host "load hashes from a file" -ForegroundColor White
            Write-Host "    [p] " -ForegroundColor Yellow -NoNewline
            Write-Host "paste hashes (comma, space, or newline separated)" -ForegroundColor White
            Write-Host "    [l] " -ForegroundColor Yellow -NoNewline
            Write-Host "list / show loaded hashes" -ForegroundColor White
            if ($iocLoaded) {
                Write-Host "    [x] " -ForegroundColor Yellow -NoNewline
                Write-Host "turn IOC matching off" -ForegroundColor White
            }
            Write-Host "  > " -ForegroundColor DarkGray -NoNewline
            $how = (Read-Host).Trim().ToLower()

            if ($how -eq 'x') {
                if ($iocLoaded) {
                    $script:IOCHashFile = $null; $script:IOCHashSet = $null; $script:IOCHashCount = 0; $script:ShowIOCList = $false
                    $pendingMsg = "IOC hash matching: OFF"
                } else {
                    $pendingMsg = "Nothing to turn off - no hashes loaded."
                }
                Clear-Host; Show-secgurdBannerCompact; continue
            }

            if ($how -eq 'l') {
                Clear-Host; Show-secgurdBannerCompact
                if ($iocLoaded) {
                    Show-IOCList
                } else {
                    Write-Host ""
                    Write-Host "  No hashes loaded." -ForegroundColor Yellow
                    Write-Host "  Use [f] to load from a file or [p] to paste some first." -ForegroundColor DarkGray
                    Write-Host ""
                }
                Write-Host "  Press Enter to return to the menu..." -ForegroundColor DarkGray
                Read-Host | Out-Null
                Clear-Host; Show-secgurdBannerCompact; continue
            }

            $loaded = @{}; $src = ''
            if ($how -eq 'f') {
                Write-Host "  Path to hash list file:" -ForegroundColor Cyan
                Write-Host "  > " -ForegroundColor DarkGray -NoNewline
                $iocPath = (Read-Host).Trim('"').Trim()
                if ($iocPath -and (Test-Path $iocPath)) {
                    $loaded = Import-IOCHashes $iocPath
                    $src = $iocPath
                } else {
                    $pendingMsg = "File not found - IOC matching not enabled."
                }
            } elseif ($how -eq 'p') {
                Write-Host "  Paste hashes, then press Enter (commas/spaces/newlines all OK):" -ForegroundColor Cyan
                Write-Host "  > " -ForegroundColor DarkGray -NoNewline
                $pasted = Read-Host
                $loaded = ConvertFrom-IOCText $pasted
                $src = '(pasted)'
            } else {
                $pendingMsg = "Cancelled - pick f, p, l, or x."
            }

            if ($loaded.Count -gt 0) {
                $script:IOCHashFile = $src
                $script:IOCHashSet = $loaded
                $script:IOCHashCount = $loaded.Count
                Clear-Host; Show-secgurdBannerCompact
                Show-IOCList
                Write-Host "  Press Enter to return to the menu..." -ForegroundColor DarkGray
                Read-Host | Out-Null
                $pendingMsg = "IOC hash matching: ON ($($loaded.Count) hashes)"
            } elseif (($how -eq 'f' -or $how -eq 'p') -and -not $pendingMsg) {
                $pendingMsg = "No valid SHA-256 hashes found (must be 64 hex chars each)."
            }
            Clear-Host; Show-secgurdBannerCompact
            continue
        }

        if ($cmd -eq 'l') {
            if (-not $script:IOCHashSet -or $script:IOCHashCount -eq 0) {
                $pendingMsg = "No IOC hashes loaded - press 'i' to add some first."
            } else {
                $script:ShowIOCList = -not $script:ShowIOCList
                $state = if ($script:ShowIOCList) { 'shown' } else { 'hidden' }
                $pendingMsg = "IOC list $state in menu"
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

function Write-Section {
    param([string]$Title)
    $line = "=" * 60
    "$line`n  $Title`n$line"
}

function Add-Finding {
    param([string]$Severity, [string]$Module, [string]$Message, [string]$Artifact = '')
    # Severity: HIGH / MED / INFO. Artifact (optional) is the exact .txt filename this
    # finding points at, so the HTML report can highlight just that file (not the whole module).
    # We encode it inside the stored string as {file:NAME} and strip it before display.
    $tag = if ($Artifact) { " {file:$Artifact}" } else { '' }
    $script:Findings.Add("[$Severity] ($Module) $Message$tag")
    $color = switch ($Severity) {
        'HIGH' { 'Red' }
        'MED'  { 'Yellow' }
        default { 'DarkGray' }
    }
    # If a transient "running..." line is on screen, move to a fresh line first
    # so the finding doesn't get tangled with it.
    if ($script:RunLineActive) {
        Write-Host ""
        $script:RunLineActive = $false
    }
    Write-Host (Ex "       ^26^00 ") -ForegroundColor DarkGray -NoNewline
    Write-Host $Message -ForegroundColor $color
}

function ConvertFrom-IOCText {
    # Parse free-form IOC text into a hashtable: UPPERCASE-hash -> label.
    # Accepts hashes separated by commas, spaces, newlines, semicolons, or pipes - so you
    # can paste 'hash, hash, hash' OR one-per-line OR any mix. A token of exactly 64 hex
    # chars is a hash; if the NEXT token isn't itself a hash, it's treated as that hash's label.
    param([string]$Text)
    $set = @{}
    if (-not $Text) { return $set }
    # strip comment lines first
    $clean = ($Text -split "`r?`n" | Where-Object { -not $_.TrimStart().StartsWith('#') }) -join "`n"
    # tokenize on commas / whitespace / semicolons / pipes
    $tokens = $clean -split '[,;\s|]+' | Where-Object { $_ -ne '' }
    for ($i = 0; $i -lt $tokens.Count; $i++) {
        $t = $tokens[$i].Trim().ToUpper()
        if ($t -match '^[0-9A-F]{64}$') {
            # peek at the next token; if it's NOT a hash, use it as this hash's label
            $label = ''
            if ($i + 1 -lt $tokens.Count -and $tokens[$i+1] -notmatch '^[0-9A-Fa-f]{64}$') {
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

function Show-IOCList {
    # Print the currently-loaded IOC hashes with a green check, the source, and a count.
    if (-not $script:IOCHashSet -or $script:IOCHashCount -eq 0) {
        Write-Host ""
        Write-Host "  No IOC hashes loaded." -ForegroundColor DarkGray
        Write-Host ""
        return
    }
    Write-Host ""
    Write-Host "  " -NoNewline
    Write-Host (Ex "[^14] ") -ForegroundColor Green -NoNewline
    Write-Host "IOC hash matching ENABLED" -ForegroundColor White -NoNewline
    Write-Host "   source: $($script:IOCHashFile)" -ForegroundColor DarkGray
    Write-Host "  $('-' * 64)" -ForegroundColor DarkGray
    $n = 0
    foreach ($h in ($script:IOCHashSet.Keys | Sort-Object)) {
        $n++
        $label = $script:IOCHashSet[$h]
        # show first 16 + last 8 of the hash so the list stays readable
        $short = $h.Substring(0,16) + '...' + $h.Substring($h.Length-8)
        Write-Host ("   {0,3}. " -f $n) -ForegroundColor DarkGray -NoNewline
        Write-Host $short -ForegroundColor Gray -NoNewline
        if ($label) { Write-Host "  [$label]" -ForegroundColor DarkCyan } else { Write-Host "" }
        if ($n -ge 50) {
            Write-Host ("        ... and $($script:IOCHashCount - 50) more") -ForegroundColor DarkGray
            break
        }
    }
    Write-Host "  $('-' * 64)" -ForegroundColor DarkGray
    Write-Host "  $($script:IOCHashCount) hash(es) loaded - will be matched against on-disk binaries at run time." -ForegroundColor DarkGray
    Write-Host ""
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

    try {
        $result = & $Block
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
        Write-Host "$secs        " -ForegroundColor DarkGray
        $script:RunLineActive = $false
        $script:CollectedCount++
    } catch {
        $sw.Stop()
        "ERROR: $_" | Out-File -FilePath $file -Encoding UTF8 -Force
        if ($script:RunLineActive) { Write-Host "`r" -NoNewline }
        Write-Host "  $progress " -ForegroundColor DarkGray -NoNewline
        Write-Host "[!] " -ForegroundColor Yellow -NoNewline
        Write-Host "$FileName (error)            " -ForegroundColor DarkGray
        $script:RunLineActive = $false
        $script:ErrorCount++
    }
}

# Pre-count selected artifacts so the [n/total] progress is accurate.

# We do this by counting Save-Output lines for selected modules in this very script.

$script:TotalArtifacts = (
    $script:SelectedModules.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object {
        $mid = $_.Key
        switch ($mid) {
            '01' {2} '02' {3} '03' {7} '04' {4} '05' {5} '06' {3} '07' {4}
            '08' {3} '09' {2} '10' {2} '11' {1} '12' {1} '13' {1} '14' {1}
        }
    } | Measure-Object -Sum
).Sum
if (-not $script:TotalArtifacts) { $script:TotalArtifacts = 1 }

Write-Host ""
Write-Host (Ex "     ^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00  running triage  ^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00^00") -ForegroundColor DarkGray
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

    # Flag users created in the last 14 days (PasswordLastSet is a decent proxy for creation)

    $recentUsers = $localUsers | Where-Object {
        $_.PasswordLastSet -and $_.PasswordLastSet -gt (Get-Date).AddDays(-$script:DaysBack)
    }
    foreach ($u in $recentUsers) {
        Add-Finding 'MED' '02' (Ex "Local user '$($u.Name)' password set <14d ago ($($u.PasswordLastSet.ToString('yyyy-MM-dd'))) ^09 possible new account") '02_local_users.txt'
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
    Select-Object TimeCreated, Id,
        @{N='User';E={$_.Properties[5].Value}},
        @{N='LogonType';E={$_.Properties[8].Value}},
        @{N='SourceIP';E={$_.Properties[18].Value}},
        Message |
    Format-Table -AutoSize
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

Save-Output "03_scheduled_tasks.txt" {
    Write-Section "SCHEDULED TASKS (non-Microsoft)"
    Get-ScheduledTask |
        Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
        Select-Object TaskName, TaskPath, State,
            @{N='Actions';E={($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '}},
            @{N='Triggers';E={($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join '; '}} |
        Format-Table -AutoSize

    Write-Section "ALL SCHEDULED TASKS (full detail)"
    Get-ScheduledTask | ForEach-Object {
        $info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            Name       = $_.TaskName
            Path       = $_.TaskPath
            State      = $_.State
            LastRun    = $info.LastRunTime
            NextRun    = $info.NextRunTime
            LastResult = $info.LastTaskResult
            Actions    = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
            Author     = $_.Principal.UserId
        }
    } | Format-Table -AutoSize
}

Save-Output "03_services.txt" {
    Write-Section "ALL SERVICES"
    Get-Service | Select-Object Name, DisplayName, Status, StartType |
        Sort-Object Status, Name | Format-Table -AutoSize

    Write-Section "RUNNING SERVICES WITH BINARY PATH"
    Get-WmiObject Win32_Service |
        Where-Object { $_.State -eq 'Running' } |
        Select-Object Name, DisplayName, StartMode, State, PathName, StartName |
        Format-Table -AutoSize

    Write-Section "RECENTLY MODIFIED SERVICE BINARIES (last 30 days)"
    Get-WmiObject Win32_Service | ForEach-Object {
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
                $sigStatus = 'NotChecked'
                $signer = ''
                if ($script:WithSignatures) {
                    $sig = (Get-AuthenticodeSignature $path -ErrorAction SilentlyContinue)
                    $sigStatus = $sig.Status
                    $signer = $sig.SignerCertificate.Subject
                    if ($sig.Status -ne 'Valid') {
                        Add-Finding 'HIGH' '03' (Ex "Unsigned service binary modified <30d: $($_.Name) ^17 $path") '03_services.txt'
                    } else {
                        Add-Finding 'MED' '03' (Ex "Service binary modified <30d: $($_.Name) ^17 $path") '03_services.txt'
                    }
                } else {
                    Add-Finding 'MED' '03' (Ex "Service binary modified <30d: $($_.Name) ^17 $path") '03_services.txt'
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

Save-Output "03_wmi_persistence.txt" {
    Write-Section "WMI EVENT SUBSCRIPTIONS"

    Write-Section "  EventFilters"
    Get-WMIObject -Namespace root\subscription -Class __EventFilter |
        Select-Object Name, Query, QueryLanguage | Format-List

    Write-Section "  EventConsumers"
    $consumers = Get-WMIObject -Namespace root\subscription -Class __EventConsumer
    $consumers | Select-Object * | Format-List

    Write-Section "  FilterToConsumerBindings"
    $bindings = Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding
    $bindings | Select-Object * | Format-List

    if ($bindings) {
        Add-Finding 'HIGH' '03' (Ex "$($bindings.Count) WMI event consumer binding(s) present ^09 classic fileless persistence, review carefully") '03_wmi_persistence.txt'
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
    $accTargets = 'sethc.exe','utilman.exe','osk.exe','magnify.exe','narrator.exe','displayswitch.exe','atbroker.exe'
    foreach ($a in $accTargets) {
        $p = Join-Path $env:SystemRoot "System32\$a"
        if (Test-Path $p) {
            $f = Get-Item $p -ErrorAction SilentlyContinue
            $ver = (Get-Item $p).VersionInfo.OriginalFilename
            $suspect = ($ver -and $ver -notlike "*$a*")
            [PSCustomObject]@{
                Binary           = $a
                LastModified     = $f.LastWriteTime
                OriginalFilename = $ver
                Suspect          = $suspect
            }
            if ($suspect) {
                Add-Finding 'HIGH' '03' (Ex "Accessibility binary may be replaced: $a (OriginalFilename=$ver)") '03_advanced_persistence.txt'
            }
            # also flag an IFEO debugger specifically on an accessibility binary
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

# ---------------------------------------------

#  4. POWERSHELL ARTIFACTS

# ---------------------------------------------

Save-Output "04_ps_history.txt" {
    Write-Section "POWERSHELL HISTORY (ALL USERS)"
    $histPaths = Get-ChildItem 'C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt' -Force -ErrorAction SilentlyContinue
    foreach ($h in $histPaths) {
        "`n`n===== $($h.FullName) ====="
        Get-Content $h.FullName
    }
    if (-not $histPaths) { "  (no PSReadLine history files found)" }
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
    Get-WmiObject Win32_Process | ForEach-Object { $cmdLineByPid[[int]$_.ProcessId] = $_.CommandLine }

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
    Write-Section "RECENTLY MODIFIED FILES IN SYSTEM32 (last 7 days)"
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
        $data = Get-ItemProperty $shimKey
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
$indexLines += "Collected   : $($script:CollectedCount) files"
$indexLines += "Errors      : $($script:ErrorCount)"
$indexLines += ""
$indexLines += "FILES IN THIS FOLDER"
$indexLines += ("-" * 60)
Get-ChildItem $OutputPath -Filter '*.txt' | Sort-Object Name | ForEach-Object {
    $indexLines += ("  {0,-42} {1,8:N0} bytes" -f $_.Name, $_.Length)
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
$summaryLines += "Generated by secgurd. Review raw artifact files for full detail."
$summaryLines | Out-File (Join-Path $OutputPath '00_SUMMARY.txt') -Encoding UTF8 -Force

# ---------------------------------------------
#  00_TIMELINE.txt   chronological merge of timestamped events
# ---------------------------------------------

Write-Host (Ex "  *  Building timeline...") -ForegroundColor Cyan
$timeline = New-Object System.Collections.Generic.List[object]
function Add-TL { param($Time, $Source, $Detail)
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
$tlLines += "             scheduled tasks (106/140), System32 exe modifications (<7d)."
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
#  OPTIONAL: SINGLE-FILE HTML REPORT
# ---------------------------------------------

if ($script:HtmlReport) {
    Write-Host (Ex "  ^27  Building HTML report...") -ForegroundColor Cyan

    # HTML-escape helper
    function ConvertTo-HtmlText {
        param([string]$s)
        if ($null -eq $s) { return '' }
        $s = $s -replace '&','&amp;'
        $s = $s -replace '<','&lt;'
        $s = $s -replace '>','&gt;'
        return $s
    }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine("<title>secgurd report - $env:COMPUTERNAME</title>")
    [void]$sb.AppendLine('<style>')
    [void]$sb.AppendLine(@'
:root{--bg:#0e1116;--panel:#161b22;--ink:#c9d1d9;--muted:#8b949e;--line:#30363d;--gold:#d8b24a;--hi:#f85149;--med:#d29922;--info:#8b949e;--accent:#58a6ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
header{padding:24px 28px;border-bottom:1px solid var(--line);background:linear-gradient(180deg,#11161d,#0e1116)}
h1{margin:0;font-size:22px;letter-spacing:.08em;color:var(--gold)}
.logo{margin:0;font:11px/1.18 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre;overflow-x:auto}
.logo .gold{color:#e7c44d}
.logo .hilt{color:#f0f0f0}
.logo .tip{color:#e1372d}
.logo .dim{color:#3a4350}
.ver{color:var(--muted);font-size:12px;letter-spacing:.12em;text-transform:uppercase;margin-top:2px}
.tag{color:var(--hi);font-weight:600;font-size:13px;margin-top:4px}
.meta{display:flex;flex-wrap:wrap;gap:18px;margin-top:14px;font-size:13px;color:var(--muted)}
.meta b{color:var(--ink);font-weight:600}
.wrap{max-width:1100px;margin:0 auto;padding:24px 28px}
h2{font-size:15px;letter-spacing:.05em;color:var(--accent);border-bottom:1px solid var(--line);padding-bottom:6px;margin:32px 0 14px}
.findings{display:grid;gap:8px}
.f{padding:10px 12px;border-radius:8px;border-left:4px solid var(--line);background:var(--panel);display:block;color:inherit;text-decoration:none}
.f.HIGH{border-left-color:var(--hi)}.f.MED{border-left-color:var(--med)}.f.INFO{border-left-color:var(--info)}
a.f{cursor:pointer;transition:background .12s,transform .12s}
a.f:hover{background:#1c232c;transform:translateX(2px)}
a.f .go{float:right;font-size:11px;color:var(--muted);opacity:0;transition:opacity .12s}
a.f:hover .go{opacity:1}
/* artifact highlight when jumped-to from a finding */
details.hl-HIGH{border-color:var(--hi);box-shadow:0 0 0 1px var(--hi),0 0 16px rgba(248,81,73,.25)}
details.hl-MED{border-color:var(--med);box-shadow:0 0 0 1px var(--med),0 0 16px rgba(210,153,34,.25)}
details.hl-INFO{border-color:var(--info);box-shadow:0 0 0 1px var(--info),0 0 16px rgba(139,148,158,.25)}
.modhdr.hl-HIGH{color:var(--hi)}.modhdr.hl-MED{color:var(--med)}.modhdr.hl-INFO{color:var(--gold)}
.sev{display:inline-block;font-size:11px;font-weight:700;padding:1px 7px;border-radius:4px;margin-right:8px;vertical-align:1px}
.sev.HIGH{background:rgba(248,81,73,.18);color:#ff7b72}.sev.MED{background:rgba(210,153,34,.18);color:#e3b341}.sev.INFO{background:rgba(139,148,158,.18);color:#adbac7}
.none{color:var(--muted);font-style:italic}
details{background:var(--panel);border:1px solid var(--line);border-radius:8px;margin:8px 0;overflow:hidden}
summary{cursor:pointer;padding:10px 14px;font-weight:600;list-style:none;display:flex;justify-content:space-between;align-items:center}
summary::-webkit-details-marker{display:none}
summary:hover{background:#1c232c}
summary .sz{color:var(--muted);font-weight:400;font-size:12px}
details.empty summary{color:var(--muted)}
.badge{display:inline-block;font-size:10px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:var(--muted);background:rgba(139,148,158,.14);border:1px solid var(--line);border-radius:10px;padding:1px 8px;margin-left:8px;vertical-align:1px}
.badge.err{color:#b08a86;background:rgba(176,138,134,.10);border-color:rgba(176,138,134,.30)}
.nodata{padding:14px 16px;border-top:1px solid var(--line);color:var(--muted);font-style:italic;font-size:13px}
details.errored summary{color:#b6938f}
.errbox{padding:14px 16px;border-top:1px solid rgba(176,138,134,.25);color:#a98e8a;font-size:13px;background:rgba(176,138,134,.05)}
.errbox b{color:#c79a95}
pre{margin:0;padding:14px 16px;border-top:1px solid var(--line);background:#0b0f14;color:#c9d1d9;font:12.5px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre-wrap;word-break:break-word;max-height:520px;overflow:auto}
.modhdr{margin-top:26px;color:var(--gold);font-size:13px;letter-spacing:.1em;text-transform:uppercase}
footer{color:var(--muted);font-size:12px;text-align:center;padding:24px;border-top:1px solid var(--line);margin-top:30px}
.filter{margin:10px 0 4px;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.filter button{background:var(--panel);color:var(--ink);border:1px solid var(--line);border-radius:6px;padding:5px 10px;cursor:pointer;font-size:12px}
.filter button:hover{border-color:var(--accent)}
.filter .clearbtn{margin-left:auto;color:var(--muted)}
.filter .clearbtn:hover{border-color:var(--muted);color:var(--ink)}
'@)
    [void]$sb.AppendLine('</style></head><body>')

    # Header
    $hHost = ConvertTo-HtmlText $env:COMPUTERNAME
    $hUser = ConvertTo-HtmlText "$env:USERDOMAIN\$env:USERNAME"
    [void]$sb.AppendLine('<header>')
    [void]$sb.AppendLine('<pre class="logo">')
    [void]$sb.AppendLine((Ex '<span class="dim"> ^11^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^12</span>'))
    [void]$sb.AppendLine((Ex '<span class="hilt">      ^07^03^06 </span><span class="gold">^02^02^02^02^02^02^02^06^02^02^02^02^02^02^02^06 ^02^02^02^02^02^02^06 ^02^02^02^02^02^02^06 ^02^02^06   ^02^02^06^02^02^02^02^02^02^06 ^02^02^02^02^02^02^06</span>'))
    [void]$sb.AppendLine((Ex '<span class="hilt">      ^04 ^15^03</span><span class="gold">^02^02^07^03^03^03^03^05^02^02^07^03^03^03^03^05^02^02^07^03^03^03^03^05^02^02^07^03^03^03^03^05 ^02^02^04   ^02^02^04^02^02^07^03^03^02^02^06^02^02^07^03^03^02^02^06</span><span class="tip">^03^03^03^03^03^03^18</span>'))
    [void]$sb.AppendLine((Ex '<span class="hilt">(</span><span class="gold">o</span><span class="hilt">)^03^03^03^19 ^04 </span><span class="gold">^02^02^02^02^02^02^02^06^02^02^02^02^02^06  ^02^02^04     ^02^02^04  ^02^02^02^06^02^02^04   ^02^02^04^02^02^02^02^02^02^07^05^02^02^04  ^02^02^04</span><span class="tip">^03^03^03^03^03^03^03^20</span>'))
    [void]$sb.AppendLine((Ex '<span class="hilt">      ^04 ^15^03</span><span class="gold">^08^03^03^03^03^02^02^04^02^02^07^03^03^05  ^02^02^04     ^02^02^04   ^02^02^04^02^02^04   ^02^02^04^02^02^07^03^03^02^02^06^02^02^04  ^02^02^04</span><span class="tip">^03^03^03^03^03^03^21</span>'))
    [void]$sb.AppendLine((Ex '<span class="hilt">      ^08^03^05 </span><span class="gold">^02^02^02^02^02^02^02^04^02^02^02^02^02^02^02^06^08^02^02^02^02^02^02^06^08^02^02^02^02^02^02^07^05^08^02^02^02^02^02^02^07^05^02^02^04  ^02^02^04^02^02^02^02^02^02^07^05</span>'))
    [void]$sb.AppendLine((Ex '<span class="gold">          ^08^03^03^03^03^03^03^05^08^03^03^03^03^03^03^05 ^08^03^03^03^03^03^05 ^08^03^03^03^03^03^05  ^08^03^03^03^03^03^05 ^08^03^05  ^08^03^05^08^03^03^03^03^03^05</span>'))
    [void]$sb.AppendLine((Ex '<span class="dim">                    ^22  F O R E N S I C   T R I A G E  ^22</span>'))
    [void]$sb.AppendLine((Ex '<span class="dim"> ^12^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^01^11</span>'))
    [void]$sb.AppendLine('</pre>')
    [void]$sb.AppendLine((Ex '<div class="tag">^13 Slayer of threats. Keeper of truth. ^13</div>'))
    [void]$sb.AppendLine("<div class=`"ver`">$($script:secgurdVersion) &middot; Forensic Triage</div>")
    [void]$sb.AppendLine('<div class="meta">')
    [void]$sb.AppendLine("<span><b>Host:</b> $hHost</span>")
    [void]$sb.AppendLine("<span><b>User:</b> $hUser</span>")
    [void]$sb.AppendLine("<span><b>Admin:</b> $isAdminNow</span>")
    [void]$sb.AppendLine("<span><b>Started:</b> $($script:RunStart.ToString('yyyy-MM-dd HH:mm:ss'))</span>")
    [void]$sb.AppendLine("<span><b>Duration:</b> $elapsedStr</span>")
    [void]$sb.AppendLine("<span><b>Lookback:</b> $($script:DaysBack)d</span>")
    [void]$sb.AppendLine("<span><b>Collected:</b> $($script:CollectedCount) files</span>")
    [void]$sb.AppendLine("<span><b>Errors:</b> $($script:ErrorCount)</span>")
    [void]$sb.AppendLine('</div></header>')

    [void]$sb.AppendLine('<div class="wrap">')

    # Findings section
    [void]$sb.AppendLine("<h2>Findings ($($script:Findings.Count))</h2>")
    if ($script:Findings.Count -eq 0) {
        [void]$sb.AppendLine('<p class="none">No high-signal indicators auto-flagged. Absence of flags is not proof of a clean host - review the raw artifacts below.</p>')
    } else {
        [void]$sb.AppendLine('<div class="filter"><button onclick="ff(0)">All</button><button onclick="ff(1)">HIGH</button><button onclick="ff(2)">MED</button><button onclick="ff(3)">INFO</button><button class="clearbtn" onclick="clearHl()">Clear highlight</button></div>')
        [void]$sb.AppendLine('<div class="findings" id="findings">')
        foreach ($f in ($script:Findings | Sort-Object)) {
            $sev = 'INFO'
            if ($f -like '`[HIGH`]*') { $sev = 'HIGH' }
            elseif ($f -like '`[MED`]*') { $sev = 'MED' }
            # module number is stored as "(NN)" right after the severity prefix
            $fmod = ''
            if ($f -match '^\[(?:HIGH|MED|INFO)\]\s*\((\d{2})\)') { $fmod = $matches[1] }
            # optional precise target file encoded as {file:NAME}
            $ffile = ''
            if ($f -match '\{file:([^}]+)\}') { $ffile = $matches[1] }
            # strip the "[SEV] " prefix AND the {file:...} tag before display
            $msg = $f -replace '^\[(HIGH|MED|INFO)\]\s*',''
            $msg = $msg -replace '\s*\{file:[^}]+\}\s*$',''
            $msg = ConvertTo-HtmlText $msg
            if ($fmod -or $ffile) {
                # data-file (exact artifact) takes priority; data-mod is the fallback target
                $anchor = if ($ffile) { "#art-$([System.IO.Path]::GetFileNameWithoutExtension($ffile))" } else { "#mod-$fmod" }
                [void]$sb.AppendLine("<a class=`"f $sev`" href=`"$anchor`" data-mod=`"$fmod`" data-file=`"$ffile`" data-sev=`"$sev`" onclick=`"jump(this);return false;`"><span class=`"sev $sev`">$sev</span>$msg<span class=`"go`">view &darr;</span></a>")
            } else {
                [void]$sb.AppendLine("<div class=`"f $sev`"><span class=`"sev $sev`">$sev</span>$msg</div>")
            }
        }
        [void]$sb.AppendLine('</div>')
    }

    # Artifacts: each txt file as a collapsible section, grouped by module number
    [void]$sb.AppendLine('<h2>Artifacts</h2>')
    $files = Get-ChildItem $OutputPath -Filter '*.txt' | Sort-Object Name
    $lastMod = ''
    foreach ($file in $files) {
        if ($file.Name -like '00_*') { continue }  # index/summary shown elsewhere
        $modNum = if ($file.Name -match '^(\d{2})_') { $matches[1] } else { '' }
        $modName = ($script:ModuleCatalogue | Where-Object { $_.Id -eq $modNum }).Name
        if ($modNum -and $modNum -ne $lastMod) {
            [void]$sb.AppendLine("<div class=`"modhdr`" id=`"mod-$modNum`">$modNum &middot; $(ConvertTo-HtmlText $modName)</div>")
            $lastMod = $modNum
        }
        $rawContent = ''
        try { $rawContent = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue } catch {}
        if ($null -eq $rawContent) { $rawContent = '' }

        # Decide if this artifact actually has data. A Write-Section block is exactly:
        #   ===...   /   <Title>   /   ===...
        # so a "title" line is any non-divider line that sits directly next to a === rule.
        # We strip dividers, those title lines, and common "(none found)" placeholders; if
        # nothing meaningful remains, the artifact is empty even though it has a banner.
        $allLines = $rawContent -split "`r?`n"
        $isDivider = { param($s) $s.Trim() -match '^[=\-]{3,}$' }
        $hasData = $false
        for ($li = 0; $li -lt $allLines.Count; $li++) {
            $t = $allLines[$li].Trim()
            if ($t -eq '') { continue }
            if (& $isDivider $t) { continue }
            # placeholder lines like "(none found)" / "(not found)" / "(disabled)"
            if ($t -match '^\(.*(none|not found|no .*found|disabled|unavailable|empty).*\)$') { continue }
            # section title? adjacent (prev or next non-blank line) is a === divider
            $prev = ''; for ($p = $li-1; $p -ge 0; $p--) { if ($allLines[$p].Trim() -ne '') { $prev = $allLines[$p].Trim(); break } }
            $next = ''; for ($n = $li+1; $n -lt $allLines.Count; $n++) { if ($allLines[$n].Trim() -ne '') { $next = $allLines[$n].Trim(); break } }
            if ((& $isDivider $prev) -and (& $isDivider $next)) { continue }   # it's a section title (=== / title / ===)
            # anything left is real data
            $hasData = $true
            break
        }

        $kb = '{0:N0} KB' -f ($file.Length/1KB)
        $nameHtml = ConvertTo-HtmlText $file.Name
        $artId = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)

        # An errored collector writes "ERROR: ..." into its file (see Save-Output catch block).
        $isError = $rawContent -match '(?m)^\s*ERROR:\s'

        if ($isError) {
            # Pull the error message text for the banner.
            $errMsg = ''
            if ($rawContent -match '(?m)^\s*ERROR:\s*(.+)$') { $errMsg = $matches[1].Trim() }
            $errHtml = ConvertTo-HtmlText $errMsg
            [void]$sb.AppendLine("<details class=`"errored`" id=`"art-$artId`" data-mod=`"$modNum`" data-file=`"$($file.Name)`"><summary><span>$nameHtml <span class=`"badge err`">error</span></span><span class=`"sz`">$kb</span></summary><div class=`"errbox`"><b>This collector failed to run.</b><br>$errHtml</div></details>")
        }
        elseif (-not $hasData) {
            # Empty / no findings in this artifact: badge on the summary + a friendly banner inside.
            [void]$sb.AppendLine("<details class=`"empty`" id=`"art-$artId`" data-mod=`"$modNum`" data-file=`"$($file.Name)`"><summary><span>$nameHtml <span class=`"badge`">no data</span></span><span class=`"sz`">$kb</span></summary><div class=`"nodata`">Nothing collected for this artifact &mdash; nothing was present on this host, or it was not accessible.</div></details>")
        } else {
            $content = ConvertTo-HtmlText $rawContent
            [void]$sb.AppendLine("<details id=`"art-$artId`" data-mod=`"$modNum`" data-file=`"$($file.Name)`"><summary><span>$nameHtml</span><span class=`"sz`">$kb</span></summary><pre>$content</pre></details>")
        }
    }

    [void]$sb.AppendLine('</div>')  # /wrap
    [void]$sb.AppendLine("<footer>Generated by secgurd $($script:secgurdVersion) on $($runEnd.ToString('yyyy-MM-dd HH:mm:ss')). Single-file report - safe to copy off-host.</footer>")

    # tiny JS for findings filter (self-contained, no external deps)
    [void]$sb.AppendLine('<script>')
    [void]$sb.AppendLine('function ff(n){var m=["","HIGH","MED","INFO"][n];var L=document.querySelectorAll("#findings .f");for(var i=0;i<L.length;i++){L[i].style.display=(!m||L[i].classList.contains(m))?"":"none"}}')
    [void]$sb.AppendLine('function clearHl(){var sevs=["HIGH","MED","INFO"];for(var s=0;s<sevs.length;s++){var rm=document.querySelectorAll(".hl-"+sevs[s]);for(var j=0;j<rm.length;j++){rm[j].classList.remove("hl-"+sevs[s])}}}')
    [void]$sb.AppendLine('function jump(el){clearHl();var sev=el.getAttribute("data-sev")||"INFO";var file=el.getAttribute("data-file")||"";var mod=el.getAttribute("data-mod")||"";var target=null;var ds=document.getElementsByTagName("details");for(var k=0;k<ds.length;k++){var d=ds[k];var match=file?(d.getAttribute("data-file")===file):(d.getAttribute("data-mod")===mod);if(match){d.classList.add("hl-"+sev);d.open=true;if(!target)target=d}}if(!file&&mod){var hdr=document.getElementById("mod-"+mod);if(hdr){hdr.classList.add("hl-"+sev);if(!target)target=hdr}}if(target){target.scrollIntoView({behavior:"smooth",block:"start"})}}')
    [void]$sb.AppendLine('</script>')
    [void]$sb.AppendLine('</body></html>')

    try {
        $sb.ToString() | Out-File (Join-Path $OutputPath 'report.html') -Encoding UTF8 -Force
        Write-Host (Ex "  ^14 report.html built") -ForegroundColor Green
    } catch {
        Write-Host "  [!] Could not write report.html: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

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
Get-ChildItem $OutputPath -File | Where-Object { $_.Name -ne '00_HASHES.txt' } | Sort-Object Name | ForEach-Object {
    try {
        $h = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
        $hashLines += ("{0}  {1}" -f $h, $_.Name)
    } catch {
        $hashLines += ("{0,-64}  {1}" -f 'ERROR-HASHING', $_.Name)
    }
}
$hashLines += ("-" * 78)
$hashLines += "Verify later with:  Get-FileHash <file> -Algorithm SHA256"
$hashLines | Out-File (Join-Path $OutputPath '00_HASHES.txt') -Encoding UTF8 -Force

# ---------------------------------------------
#  00_IOC_MATCHES.txt   match on-disk binaries against a known-bad SHA-256 list
# ---------------------------------------------

# Resolve the IOC list: interactive toggle wins; else the -IOCHashes CLI param.
if (-not $script:IOCHashSet -and $IOCHashes) {
    if (Test-Path $IOCHashes) {
        $script:IOCHashSet = Import-IOCHashes $IOCHashes
        $script:IOCHashFile = $IOCHashes
        $script:IOCHashCount = $script:IOCHashSet.Count
    } else {
        Write-Host "  [!] -IOCHashes file not found: $IOCHashes" -ForegroundColor Yellow
    }
}

if ($script:IOCHashSet -and $script:IOCHashCount -gt 0) {
    Write-Host (Ex "  *  Matching on-disk binaries against $($script:IOCHashCount) IOC hashes...") -ForegroundColor Cyan

    # Build the candidate set: real executables/DLLs from the high-signal locations a triage
    # would care about. We hash these (not secgurd's own output) and compare to the IOC list.
    $scanRoots = @(
        "$env:TEMP", "$env:SystemRoot\Temp",
        "$env:PUBLIC", "$env:ProgramData",
        "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:USERPROFILE\AppData\Local\Temp",
        "$env:USERPROFILE\AppData\Roaming", "$env:USERPROFILE\AppData\Local"
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
    # also include currently-running process images (catches things outside the scan roots)
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.Path) { $candidates.Add($_.Path) }
    }

    $seen = @{}
    $matchLines = @()
    $matchLines += (Ex "secgurd $($script:secgurdVersion) ^09 IOC Hash Matches")
    $matchLines += ("=" * 78)
    $matchLines += "IOC list  : $($script:IOCHashFile)  ($($script:IOCHashCount) hashes)"
    $matchLines += "Scanned   : Temp, AppData, Public, ProgramData, Downloads, Desktop, running procs"
    $matchLines += ("-" * 78)

    $matchCount = 0; $scanned = 0
    foreach ($path in $candidates) {
        if ($seen.ContainsKey($path)) { continue }
        $seen[$path] = $true
        $scanned++
        try {
            $fh = (Get-FileHash $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpper()
            if ($script:IOCHashSet.ContainsKey($fh)) {
                $matchCount++
                $label = $script:IOCHashSet[$fh]
                $matchLines += ("MATCH  {0}" -f $path)
                $matchLines += ("       {0}{1}" -f $fh, $(if ($label) { "  [$label]" } else { '' }))
                Add-Finding 'HIGH' '09' (Ex "IOC hash match: $path$(if($label){" ($label)"})") '00_IOC_MATCHES.txt'
            }
        } catch {}
    }
    $matchLines += ("-" * 78)
    $matchLines += "Files scanned: $scanned   Matches: $matchCount"
    if ($matchCount -eq 0) { $matchLines += "(no on-disk binaries matched the IOC list)" }
    $matchLines | Out-File (Join-Path $OutputPath '00_IOC_MATCHES.txt') -Encoding UTF8 -Force

    if ($matchCount -gt 0) {
        Write-Host (Ex "  ! $matchCount IOC MATCH(es) found - see 00_IOC_MATCHES.txt") -ForegroundColor Red
    } else {
        Write-Host (Ex "  [^14] No IOC matches ($scanned files scanned)") -ForegroundColor Green
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
    Write-Host (Ex "  ^24 FINDINGS ($($script:Findings.Count))") -ForegroundColor Red
    foreach ($f in ($script:Findings | Sort-Object)) {
        $c = if ($f -like '`[HIGH`]*') { 'Red' } elseif ($f -like '`[MED`]*') { 'Yellow' } else { 'DarkGray' }
        Write-Host "    $f" -ForegroundColor $c
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
if ($script:HtmlReport -and (Test-Path (Join-Path $OutputPath 'report.html'))) {
    Write-Host (Ex "  [^14] Report  : ") -ForegroundColor Green -NoNewline
    Write-Host (Join-Path $OutputPath 'report.html') -ForegroundColor White
}
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

# Optionally open the output folder (interactive desktop only)

# Open results when done (interactive desktop only).
#  - HTML report toggle (h) opens report.html on its own.
#  - Open-folder toggle (o) opens the output folder.
# These are independent; if both are on, the report opens and the folder opens.

if ([Environment]::UserInteractive) {
    $reportPath = Join-Path $OutputPath 'report.html'
    if ($script:HtmlReport -and (Test-Path $reportPath)) {
        try { Invoke-Item $reportPath } catch {}
    }
    if ($script:OpenFolderWhenDone) {
        try { Invoke-Item $OutputPath } catch {}
    }
}

# Return paths for caller use

[PSCustomObject]@{
    OutputFolder   = $OutputPath
    ZipArchive     = if ($zipOk) { $zipPath } else { $null }
    HtmlReport     = if ($script:HtmlReport -and (Test-Path (Join-Path $OutputPath 'report.html'))) { Join-Path $OutputPath 'report.html' } else { $null }
    FilesCollected = $script:CollectedCount
    Errors         = $script:ErrorCount
    Findings       = $script:Findings
    Duration       = $elapsedStr
}
