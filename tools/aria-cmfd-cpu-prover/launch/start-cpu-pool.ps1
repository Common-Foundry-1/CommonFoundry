#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Model,
    [Parameter(Mandatory)][string]$FixedRecord,
    [Parameter(Mandatory)][string]$Scratch,
    [Parameter(Mandatory)][string[]]$PoolArguments
)
$ErrorActionPreference = 'Stop'
$runtime = Split-Path -Parent $PSScriptRoot
$node = Join-Path $runtime 'cmfd-node.exe'
$prover = Join-Path $PSScriptRoot 'aria-cmfd-cpu-prover.exe'
$modelPath = (Resolve-Path -LiteralPath $Model).Path
$recordPath = (Resolve-Path -LiteralPath $FixedRecord).Path
$scratchPath = [IO.Path]::GetFullPath($Scratch)
if (!(Test-Path -LiteralPath $node -PathType Leaf) -or !(Test-Path -LiteralPath $prover -PathType Leaf)) {
    throw 'Install the candidate node and CPU prover together in the verified mainnet runtime.'
}
if (!('CommonFoundryResidentModel' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'CommonFoundryResidentModel.cs') -CompilerOptions /unsafe
}
$pin = [CommonFoundryResidentModel]::new($modelPath)
try {
    if (!$pin.Locked) { throw "Could not lock the model in RAM: $($pin.LockError)" }
    $process = [Diagnostics.ProcessStartInfo]::new()
    $process.FileName = $node
    $process.UseShellExecute = $false
    $process.Environment['ARIA_POOL_CPU_ONLY']='1'
    $process.Environment['CMFD_CPU_POOL_PROFILE']='9950x3d'
    $process.Environment['ARIA_POOL_CPU_SHARES']='1x14'
    $process.Environment['ARIA_POOL_CPU_PROVER']=$prover
    $process.Environment['ARIA_POOL_CPU_PROVER_SCRATCH']=$scratchPath
    foreach($arg in (@('--production-v4-bank',$modelPath,'--production-v4-fixed-record',$recordPath,'pool-serve') + $PoolArguments)) {
        $process.ArgumentList.Add($arg)
    }
    $child = [Diagnostics.Process]::Start($process)
    try { $child.WaitForExit(); $status=$child.ExitCode } finally { $child.Dispose() }
    if ($status -ne 0) { throw "The pool exited with code $status." }
} finally { $pin.Dispose() }