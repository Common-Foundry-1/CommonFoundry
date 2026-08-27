@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Common Foundry Multi-GPU Miner

rem ================================================================
rem EDIT ONLY THIS SECTION
rem ================================================================
rem These defaults work with a wallet on this PC or the community bootstrap.
set "LOCAL_PEER=127.0.0.1:18444"
set "BOOTSTRAP_PEER=107.214.187.2:18444"
rem Use auto for NVIDIA, or opencl for Intel Arc.
set "GPU_BACKEND=auto"
set "GPU_INDEXES="
rem PAYOUT_ADDRESS is your wallet's 64-character receive address.
set "PAYOUT_ADDRESS="
set "BATCH_SIZE=8192"
rem 0 automatically divides host CPU threads across the selected GPUs (maximum 16 each).
set "WORKERS_PER_GPU=0"
set "STATS_SECONDS=5"
set "PRODUCTION_V3_MAX_ROWS=131072"
rem ================================================================
rem GPU_INDEXES examples:
rem   blank   = use every GPU exposed by the selected backend
rem   0       = use GPU 0 only
rem   0,1,2,3 = use GPUs 0 through 3
rem Run LIST-GPUS.bat to see the indexes on this rig.
rem PAYOUT_ADDRESS is required because the connected node creates the block.
rem ================================================================

if not exist "%~dp0cmfd-miner.exe" (
  echo ERROR: cmfd-miner.exe is missing from this folder.
  pause
  exit /b 1
)

if not defined PAYOUT_ADDRESS (
  echo ERROR: Set PAYOUT_ADDRESS to the 64-character receive address shown by your wallet.
  echo Right-click START-MINER.bat, choose Edit, and fill in PAYOUT_ADDRESS near the top.
  pause
  exit /b 1
)

set "PRODUCTION_V3_READY="
if exist "%~dp0production-v3\MODEL-V2.bank" if exist "%~dp0production-v3\MODEL-V2.manifest.json" if exist "%~dp0production-v3\DORY-V3-MODEL-RECORD-V2.json" (
  if "%LOCAL_PEER%"=="127.0.0.1:18444" set "LOCAL_PEER=127.0.0.1:21444"
  if "%BOOTSTRAP_PEER%"=="107.214.187.2:18444" set "BOOTSTRAP_PEER=107.214.187.2:21444"
  rem ProductionV3 accepts --batch-size 1-64 (per-worker nonce stride; proof
  rem time dominates). Correct the reference-profile default automatically.
  if "%BATCH_SIZE%"=="8192" set "BATCH_SIZE=64"
  if not exist "%~dp0production-v3\scratch" mkdir "%~dp0production-v3\scratch"
  rem ProductionV3 refuses to load model artifacts from a directory other
  rem accounts can reach, and extracting a ZIP leaves inherited permissions in
  rem place. SYSTEM and Administrators are named by well-known SID so this also
  rem works on non-English Windows.
  icacls "%~dp0production-v3" /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" >nul 2>&1
  if errorlevel 1 echo WARNING: could not make production-v3 private; the miner may refuse to start.
  set "PRODUCTION_V3_READY=1"
)

set "PEER_ARGS="
if defined LOCAL_PEER set "PEER_ARGS=--peer %LOCAL_PEER%"
if defined BOOTSTRAP_PEER set "PEER_ARGS=!PEER_ARGS! --peer %BOOTSTRAP_PEER% --allow-public-peers"

set "DEVICE_ARGS="
if defined GPU_INDEXES (
  set "GPU_LIST=!GPU_INDEXES:,= !"
  for %%G in (!GPU_LIST!) do set "DEVICE_ARGS=!DEVICE_ARGS! --device %%G"
)

set "CMFD_GPU_BACKEND=%GPU_BACKEND%"

echo Starting Common Foundry miner...
echo GPU backend: %GPU_BACKEND%
echo Local wallet peer: %LOCAL_PEER%
echo Bootstrap fallback: %BOOTSTRAP_PEER%
if defined GPU_INDEXES (
  echo GPUs: %GPU_INDEXES%
) else (
  echo GPUs: all supported devices
)
echo.

if defined PRODUCTION_V3_READY (
  "%~dp0cmfd-miner.exe" mine ^
    !PEER_ARGS! ^
    !DEVICE_ARGS! ^
    --miner %PAYOUT_ADDRESS% ^
    --batch-size %BATCH_SIZE% ^
    --workers-per-gpu %WORKERS_PER_GPU% ^
    --stats-seconds %STATS_SECONDS% ^
    --production-v3-bank "%~dp0production-v3\MODEL-V2.bank" ^
    --production-v3-manifest "%~dp0production-v3\MODEL-V2.manifest.json" ^
    --production-v3-record-v2 "%~dp0production-v3\DORY-V3-MODEL-RECORD-V2.json" ^
    --production-v3-scratch "%~dp0production-v3\scratch" ^
    --production-v3-max-rows %PRODUCTION_V3_MAX_ROWS%
) else (
  "%~dp0cmfd-miner.exe" mine ^
    !PEER_ARGS! ^
    !DEVICE_ARGS! ^
    --miner %PAYOUT_ADDRESS% ^
    --batch-size %BATCH_SIZE% ^
    --workers-per-gpu %WORKERS_PER_GPU% ^
    --stats-seconds %STATS_SECONDS%
)

echo.
echo Miner stopped with exit code %ERRORLEVEL%.
pause
