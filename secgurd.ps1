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
        '14' = [char]0x2713
        '15' = [char]0x2560
        '16' = [char]0x26A0
        '17' = [char]0x2192
        '18' = [char]0x2572
        '19' = [char]0x2563
        '20' = [char]0x25B6
        '21' = [char]0x2571
        '22' = [char]0x16CA
        '23' = [char]0x2717
        '24' = [char]0x2691
        '25' = [char]0x26A1
        '26' = [char]0x2514
        '27' = [char]0x2692
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

# Force UTF-8 output so box-drawing chars render correctly

try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
try { $OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

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
    Write-Host "    -Help                 Show this help" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  MENU COMMANDS" -ForegroundColor White
    Write-Host "    01-14                 Toggle a module on/off (space/comma-separate many)" -ForegroundColor Gray
    Write-Host "    a / n                 Select all / none" -ForegroundColor Gray
    Write-Host "    qa / net / ps         Apply a preset" -ForegroundColor Gray
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

if (-not $NoBanner) { Show-secgurdBanner }

$script:ModuleCatalogue = @(
    [PSCustomObject]@{ Id='01'; Name='System info';          Desc='os, build, uptime, domain' }
    [PSCustomObject]@{ Id='02'; Name='Users & sessions';     Desc='accounts, logons, 4624/4625' }
    [PSCustomObject]@{ Id='03'; Name='Persistence';          Desc='run keys, tasks, services, wmi' }
    [PSCustomObject]@{ Id='04'; Name='PowerShell artifacts'; Desc='history, transcripts, 4104' }
    [PSCustomObject]@{ Id='05'; Name='Network';              Desc='connections, dns, arp, fw' }
    [PSCustomObject]@{ Id='06'; Name='Processes';            Desc='proctree, cmdlines, unsigned dlls' }
    [PSCustomObject]@{ Id='07'; Name='Filesystem';           Desc='temp exes, ads, recent files' }
    [PSCustomObject]@{ Id='08'; Name='Event logs';           Desc='account changes, log clearing' }
    [PSCustomObject]@{ Id='09'; Name='Software & patches';   Desc='installed apps, hotfixes' }
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
foreach ($m in $script:ModuleCatalogue) { $script:SelectedModules[$m.Id] = $true }

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

        if ($cmd -eq '?' -or $cmd -eq 'h' -or $cmd -eq 'help') {
            Clear-Host
            Show-secgurdBannerCompact
            Show-Help
            Write-Host "   Press Enter to return to the menu..." -ForegroundColor DarkGray
            Read-Host | Out-Null
            Clear-Host
            Show-secgurdBannerCompact
            continue
        }

        if ($cmd -eq 'r' -or $cmd -eq 'run') {
            if ($count -eq 0) {
                $pendingMsg = (Ex "^16  No modules selected ^09 pick at least one, or 'a' for all.")
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
elseif (-not $Auto) {
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
    param([string]$Severity, [string]$Module, [string]$Message)
    # Severity: HIGH / MED / INFO

    $script:Findings.Add("[$Severity] ($Module) $Message")
    $color = switch ($Severity) {
        'HIGH' { 'Red' }
        'MED'  { 'Yellow' }
        default { 'DarkGray' }
    }
    Write-Host (Ex "       ^26^00 ") -ForegroundColor DarkGray -NoNewline
    Write-Host $Message -ForegroundColor $color
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
    try {
        $result = & $Block
        $result | Out-File -FilePath $file -Encoding UTF8 -Force
        $sw.Stop()
        $secs = ('{0,5:N1}s' -f ($sw.ElapsedMilliseconds / 1000))
        Write-Host "  $progress " -ForegroundColor DarkGray -NoNewline
        Write-Host (Ex "[^14] ") -ForegroundColor Green -NoNewline
        Write-Host ("{0,-42}" -f $FileName) -ForegroundColor Gray -NoNewline
        Write-Host $secs -ForegroundColor DarkGray
        $script:CollectedCount++
    } catch {
        $sw.Stop()
        "ERROR: $_" | Out-File -FilePath $file -Encoding UTF8 -Force
        Write-Host "  $progress " -ForegroundColor DarkGray -NoNewline
        Write-Host "[!] " -ForegroundColor Yellow -NoNewline
        Write-Host "$FileName (error)" -ForegroundColor DarkGray
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
        $_.PasswordLastSet -and $_.PasswordLastSet -gt (Get-Date).AddDays(-14)
    }
    foreach ($u in $recentUsers) {
        Add-Finding 'MED' '02' (Ex "Local user '$($u.Name)' password set <14d ago ($($u.PasswordLastSet.ToString('yyyy-MM-dd'))) ^09 possible new account")
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
                    Add-Finding 'MED' '02' "Local account in Administrators group: $($mem.Name)"
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
            if ($f -and $f.LastWriteTime -gt (Get-Date).AddDays(-30)) {
                $sig = (Get-AuthenticodeSignature $path -ErrorAction SilentlyContinue)
                $signer = $sig.SignerCertificate.Subject
                if ($sig.Status -ne 'Valid') {
                    Add-Finding 'HIGH' '03' (Ex "Unsigned service binary modified <30d: $($_.Name) ^17 $path")
                } else {
                    Add-Finding 'MED' '03' (Ex "Service binary modified <30d: $($_.Name) ^17 $path")
                }
                [PSCustomObject]@{
                    Service      = $_.Name
                    Path         = $path
                    LastModified = $f.LastWriteTime
                    SigStatus    = $sig.Status
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
        Add-Finding 'HIGH' '03' (Ex "$($bindings.Count) WMI event consumer binding(s) present ^09 classic fileless persistence, review carefully")
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
    Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-PowerShell/Operational'
        Id      = 4104
    } -MaxEvents 500 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Message}} |
        Format-List

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

    Write-Section "INBOUND ALLOW RULES (non-built-in)"
    Get-NetFirewallRule -Direction Inbound -Action Allow |
        Where-Object { $_.Profile -ne 'Any' -or $_.Enabled -eq 'True' } |
        Select-Object DisplayName, Enabled, Profile, Direction, Action,
            @{N='Program';E={($_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program}},
            @{N='LocalPorts';E={($_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue).LocalPort}} |
        Where-Object { $_.Program -ne 'Any' -and $_.Program -ne $null } |
        Format-Table -AutoSize
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
    # Build dict once for fast lookups (fixes per-proc WMI query perf + parent-lookup bug)

    $procs = Get-WmiObject Win32_Process
    $byPid = @{}
    foreach ($p in $procs) { $byPid[[int]$p.ProcessId] = $p }

    $procs | ForEach-Object {
        $proc = $_
        $parent = $byPid[[int]$proc.ParentProcessId]
        $owner = ""
        try {
            $o = $proc.GetOwner()
            if ($o.ReturnValue -eq 0) { $owner = "$($o.Domain)\$($o.User)" }
        } catch {}
        [PSCustomObject]@{
            PID         = $proc.ProcessId
            PPID        = $proc.ParentProcessId
            Name        = $proc.Name
            ParentName  = if ($parent) { $parent.Name } else { '<none>' }
            CommandLine = $proc.CommandLine
            Owner       = $owner
        }
    } | Sort-Object PPID, PID | Format-Table -AutoSize
}

Save-Output "06_loaded_dlls.txt" {
    Write-Section "LOADED DLLs PER PROCESS (unsigned)"
    Get-Process | ForEach-Object {
        $proc = $_
        try {
            $proc.Modules | ForEach-Object {
                $sig = Get-AuthenticodeSignature $_.FileName -ErrorAction SilentlyContinue
                if ($sig.Status -ne 'Valid') {
                    [PSCustomObject]@{
                        PID       = $proc.Id
                        Process   = $proc.Name
                        Module    = $_.ModuleName
                        Path      = $_.FileName
                        SigStatus = $sig.Status
                    }
                }
            }
        } catch {}
    } | Format-Table -AutoSize
}

# ---------------------------------------------

#  7. FILE SYSTEM ARTIFACTS

# ---------------------------------------------

Save-Output "07_recently_modified_system32.txt" {
    Write-Section "RECENTLY MODIFIED FILES IN SYSTEM32 (last 7 days)"
    Get-ChildItem "$env:SystemRoot\System32" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
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
                    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) } |
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
        Write-Section "Event $id - $($eventIds[$id]) (last 50)"
        $logName = if ($id -ge 7000) { 'System' } else { 'Security' }
        Get-WinEvent -FilterHashtable @{ LogName = $logName; Id = $id } -MaxEvents 50 -ErrorAction SilentlyContinue |
            Select-Object TimeCreated, Id, Message | Format-List
    }
}

Save-Output "08_cleared_logs.txt" {
    Write-Section "EVENT LOG CLEAR HISTORY"
    $sec1102 = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=1102]]" -MaxEvents 100 -ErrorAction SilentlyContinue
    $sys104  = Get-WinEvent -LogName System -FilterXPath "*[System[EventID=104]]" -MaxEvents 100 -ErrorAction SilentlyContinue
    if ($sec1102) {
        Add-Finding 'HIGH' '08' (Ex "Security log was CLEARED ($($sec1102.Count) event(s) 1102) ^09 possible anti-forensics")
    }
    if ($sys104) {
        Add-Finding 'MED' '08' "A System/application log was cleared ($($sys104.Count) event(s) 104)"
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
        Add-Finding 'MED' '11' "$($lolHits.Count) LOLBin execution(s) in 4688 logs: $distinct"
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

if ($OpenWhenDone -and [Environment]::UserInteractive) {
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
