# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Replay the SMB2 model corpus against the Windows SMB server of this machine.

.DESCRIPTION
The Windows counterpart of harness/samba/run_samba_mbt.sh, and it drives the
same replayer (harness/samba/smb2_replay.py) -- a raw SMB2 client, not the
Windows redirector, so every request is exactly the one the model describes.

The server is the in-box one (LanmanServer), which is always there and always
owns 445; there is nothing to start.  What this script does is make it the
server the cell configs describe (harness/windows/configs/_windows.json):

  * a share over a fresh NTFS directory, with a local account of its own that
    holds full control of it.  The model has no identity axis, so one account
    with every right is the whole of it;
  * EnableOplocks and EnableLeasing off, so no caching grant can change the
    timing of a conflicting open -- the profile the corpus was generated for.

Then it replays each cell's trace directory in turn, the share emptied between
traces by the replayer itself (it runs on the same machine and owns the path).

It needs an elevated shell: creating an account, a share and changing the
server configuration are all administrative.  It CHANGES THIS MACHINE'S SMB
SERVER CONFIGURATION and does not put it back, so run it on a disposable
machine -- a CI runner -- and nowhere else.

.PARAMETER CorpusRoot
The corpus root: the directory holding windows/smb2/<cell>/*.itf.json.

.PARAMETER Cells
The cells to replay (default: every directory under windows/smb2).

.PARAMETER Survey
Report every diverging step of a trace instead of stopping at the first.

.PARAMETER LogDir
Where each cell's replay output is kept (default: none kept).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $CorpusRoot,
    [string[]] $Cells,
    [switch] $Survey,
    [string] $LogDir
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$replay = Join-Path $here '..\samba\smb2_replay.py'

$cellRoot = Join-Path $CorpusRoot 'windows\smb2'
if (-not (Test-Path $cellRoot)) { throw "no Windows cells under $cellRoot" }
if (-not $Cells) {
    # The strict twins are the same batches with every deviation off; they
    # report, they do not gate, and are replayed only when named.
    $Cells = Get-ChildItem $cellRoot -Directory |
        Where-Object Name -notlike '*-strict' | ForEach-Object Name | Sort-Object
}

$user = 'specsmbt'
$share = 'specsmbt'
# Local to this machine and this run.  Mixed classes, because the default
# password policy demands them.
$password = 'Mbt!' + [Guid]::NewGuid().ToString('N').Substring(0, 20) + 'aZ9'
$base = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }
$sharePath = Join-Path $base ('specs_smb_share_' + $PID)

$os = Get-CimInstance Win32_OperatingSystem
"=== $($os.Caption) $($os.Version) build $($os.BuildNumber) $($os.OSArchitecture) ==="

# --- the account -----------------------------------------------------------
if (Get-LocalUser -Name $user -ErrorAction SilentlyContinue) { Remove-LocalUser -Name $user }
New-LocalUser -Name $user -Password (ConvertTo-SecureString $password -AsPlainText -Force) `
    -PasswordNeverExpires -AccountNeverExpires -UserMayNotChangePassword | Out-Null

# --- the directory ---------------------------------------------------------
New-Item -ItemType Directory -Force $sharePath | Out-Null
# Full control, inherited by everything created under it, for the account the
# replayer authenticates as and for this (elevated) process, which empties the
# directory between traces.
& icacls $sharePath /inheritance:r /grant "${user}:(OI)(CI)F" /grant '*S-1-5-32-544:(OI)(CI)F' /grant '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "icacls failed on $sharePath" }
# Anything else that opens files here behind the server's back is a sharing
# violation the model cannot predict.  Best effort: neither is present on
# every image.
try { Add-MpPreference -ExclusionPath $sharePath -ErrorAction Stop } catch { "note: no Defender exclusion ($($_.Exception.Message))" }
& attrib +I $sharePath 2>$null    # not content indexed

# --- the server ------------------------------------------------------------
Set-SmbServerConfiguration -EnableOplocks $false -EnableLeasing $false -Force -Confirm:$false
if (Get-SmbShare -Name $share -ErrorAction SilentlyContinue) { Remove-SmbShare -Name $share -Force -Confirm:$false }
New-SmbShare -Name $share -Path $sharePath -FullAccess $user, '*S-1-5-32-544' `
    -CachingMode None -FolderEnumerationMode Unrestricted | Out-Null
# The caching switches are read when the server starts.
Restart-Service LanmanServer -Force
$deadline = (Get-Date).AddSeconds(60)
while (-not (Get-SmbShare -Name $share -ErrorAction SilentlyContinue)) {
    if ((Get-Date) -gt $deadline) { throw 'the share did not come back after restarting LanmanServer' }
    Start-Sleep -Milliseconds 500
}

'--- server configuration ---'
Get-SmbServerConfiguration | Format-List EnableOplocks, EnableLeasing, EnableSMB2Protocol,
    RequireSecuritySignature, EnableSecuritySignature, EncryptData, RejectUnencryptedAccess,
    EnableAuthenticateUserSharing | Out-String -Width 200
Get-SmbShare -Name $share | Format-List Name, Path, CachingMode, EncryptData, ContinuouslyAvailable | Out-String -Width 200
"filesystem: $((Get-Volume -FilePath $sharePath).FileSystemType)"

# --- the replay ------------------------------------------------------------
if ($LogDir) { New-Item -ItemType Directory -Force $LogDir | Out-Null }
# The replayer finds windows_deviations.py through the module search path.
$env:PYTHONPATH = $here
$env:PYTHONUNBUFFERED = '1'
$env:PYTHONIOENCODING = 'utf-8'

$results = [ordered]@{}
try {
    foreach ($cell in $Cells) {
        $dir = Join-Path $cellRoot $cell
        "`n=== cell $cell ($((Get-ChildItem $dir -Filter *.itf.json).Count) traces) ==="
        $cmd = @($replay, '--server', '127.0.0.1', '--port', '445',
                 '--share', $share, '--share-path', $sharePath,
                 '--user', $user, '--password', $password,
                 '--server-kind', 'windows', '--trace-dir', $dir)
        if ($Survey) { $cmd += '--keep-going' }
        # 2>&1 through cmd, so python's stderr is text here and not a stream
        # of PowerShell error records that would stop the script.
        $ErrorActionPreference = 'Continue'
        if ($LogDir) {
            & python @cmd 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath (Join-Path $LogDir "$cell.log")
        } else {
            & python @cmd 2>&1 | ForEach-Object { "$_" }
        }
        $rc = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
        $results[$cell] = switch ($rc) {
            0 { 'ok' } 1 { 'DIVERGED' } 77 { 'skipped' } default { "HARNESS ERROR ($rc)" }
        }
    }
} finally {
    Remove-SmbShare -Name $share -Force -Confirm:$false -ErrorAction SilentlyContinue
    Remove-LocalUser -Name $user -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $sharePath -ErrorAction SilentlyContinue
}

"`n=== summary ==="
$results.GetEnumerator() | ForEach-Object { '{0,-12} {1}' -f $_.Key, $_.Value }
if ($results.Values | Where-Object { $_ -ne 'ok' -and $_ -ne 'skipped' }) { exit 1 }
if (-not ($results.Values | Where-Object { $_ -eq 'ok' })) { exit 77 }
exit 0
