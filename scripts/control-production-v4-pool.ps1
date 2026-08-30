[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Status', 'Stop', 'Restart', 'InstallAutostart', 'RemoveAutostart')]
    [string]$Action,
    [string]$DataDirectory = (Join-Path $PSScriptRoot 'pool-data'),
    [ValidateRange(1, 600)][int]$StopTimeoutSeconds = 180
)

$ErrorActionPreference = 'Stop'
$DataDirectory = [IO.Path]::GetFullPath($DataDirectory)
$controlDirectory = Join-Path $DataDirectory 'pool-control'
$stateFile = Join-Path $controlDirectory 'pool-state.json'
$settingsFile = Join-Path $controlDirectory 'pool-settings.json'
$shutdownRequestFile = Join-Path $controlDirectory 'shutdown.request'
$startScript = Join-Path $PSScriptRoot 'START-POOL.ps1'
$autostartName = 'CommonFoundry-ProductionV4-Pool.cmd'
$autostartFile = Join-Path ([Environment]::GetFolderPath('Startup')) $autostartName
$shutdownBytes = [Text.Encoding]::ASCII.GetBytes("CMFD_POOL_SHUTDOWN_V1`n")

function Read-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    $item = Get-Item -LiteralPath $Path
    if ($item.Length -gt 65536) {
        throw "Control file is unexpectedly large: $Path"
    }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Get-RunningPool {
    $state = Read-JsonFile -Path $stateFile
    if ($null -eq $state) {
        return $null
    }
    if ($state.schema -ne 'CommonFoundry/ProductionV4/PoolProcess/v1') {
        throw "Pool process state has an unsupported schema: $stateFile"
    }
    try {
        $process = Get-Process -Id ([int]$state.pid) -ErrorAction Stop
        if ($process.StartTime.ToUniversalTime().Ticks -eq [int64]$state.process_start_utc_ticks) {
            return [pscustomobject]@{ State = $state; Process = $process }
        }
    } catch {
        return $null
    }
    return $null
}

function Remove-StaleControlFiles {
    Remove-Item -LiteralPath $stateFile, $shutdownRequestFile -Force -ErrorAction SilentlyContinue
}

function Show-PoolStatus {
    $running = Get-RunningPool
    if ($null -eq $running) {
        Remove-StaleControlFiles
        Write-Host 'Pool status: stopped'
        return 3
    }
    $dashboard = 'unreachable'
    try {
        $response = Invoke-WebRequest -Uri ([string]$running.State.dashboard_url) -UseBasicParsing -TimeoutSec 2
        if ($response.StatusCode -eq 200) {
            $dashboard = 'healthy'
        }
    } catch {
        $dashboard = 'starting or unreachable'
    }
    Write-Host "Pool status: running"
    Write-Host "Process ID: $($running.State.pid)"
    Write-Host "Dashboard: $($running.State.dashboard_url) ($dashboard)"
    Write-Host "Log: $($running.State.log_file)"
    return 0
}

function Stop-Pool {
    $running = Get-RunningPool
    if ($null -eq $running) {
        Remove-StaleControlFiles
        Write-Host 'Pool is already stopped.'
        return
    }
    New-Item -ItemType Directory -Force $controlDirectory | Out-Null
    if (Test-Path -LiteralPath $shutdownRequestFile) {
        $existing = [IO.File]::ReadAllBytes($shutdownRequestFile)
        if (-not [Linq.Enumerable]::SequenceEqual([byte[]]$existing, [byte[]]$shutdownBytes)) {
            throw "Refusing malformed shutdown request: $shutdownRequestFile"
        }
    } else {
        $stream = [IO.File]::Open($shutdownRequestFile, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        try {
            $stream.Write($shutdownBytes, 0, $shutdownBytes.Length)
            $stream.Flush($true)
        } finally {
            $stream.Dispose()
        }
    }
    Write-Host "Graceful shutdown requested for process $($running.State.pid)."
    $deadline = [DateTime]::UtcNow.AddSeconds($StopTimeoutSeconds)
    do {
        Start-Sleep -Milliseconds 250
        if ($running.Process.HasExited) {
            Remove-StaleControlFiles
            Write-Host 'Pool stopped cleanly.'
            return
        }
        $running.Process.Refresh()
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Pool did not stop within $StopTimeoutSeconds seconds. It was not force-killed; inspect $($running.State.log_file)."
}

function ConvertTo-CmdLiteral {
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value.Contains("`r") -or $Value.Contains("`n") -or $Value.Contains('"')) {
        throw 'Autostart paths cannot contain quotes or line breaks.'
    }
    return $Value.Replace('%', '%%')
}

switch ($Action) {
    'Status' {
        exit (Show-PoolStatus)
    }
    'Stop' {
        Stop-Pool
    }
    'Restart' {
        Stop-Pool
        if (-not (Test-Path -LiteralPath $settingsFile -PathType Leaf)) {
            throw 'Saved pool settings are unavailable. Run START-POOL.bat once first.'
        }
        & $startScript -DataDirectory $DataDirectory
        exit $LASTEXITCODE
    }
    'InstallAutostart' {
        if (-not (Test-Path -LiteralPath $settingsFile -PathType Leaf)) {
            throw 'Saved pool settings are unavailable. Run START-POOL.bat once first.'
        }
        $startBatch = ConvertTo-CmdLiteral (Join-Path $PSScriptRoot 'START-POOL.bat')
        $savedData = ConvertTo-CmdLiteral $DataDirectory
        $content = "@echo off`r`ncall `"$startBatch`" -DataDirectory `"$savedData`"`r`n"
        [IO.File]::WriteAllText($autostartFile, $content, [Text.Encoding]::ASCII)
        Write-Host "Pool autostart installed for the current Windows user: $autostartFile"
        Write-Host 'The pool will open visibly after this user signs in.'
    }
    'RemoveAutostart' {
        Remove-Item -LiteralPath $autostartFile -Force -ErrorAction SilentlyContinue
        Write-Host 'Pool autostart removed for the current Windows user.'
    }
}
