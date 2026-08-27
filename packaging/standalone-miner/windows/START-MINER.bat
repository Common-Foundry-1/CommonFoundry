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

rem ================================================================
rem ProductionV3 model bank bootstrap
rem The 6.4 GB model bank cannot ship as one download (GitHub caps release
rem assets at 2 GiB), so on first run this launcher downloads its four
rem published parts, verifies every SHA-256, assembles MODEL-V2.bank, and
rem deletes the parts. Later runs skip all of this. Needs ~13 GB free during
rem the first run and an internet connection; nothing else to do.
rem ================================================================
set "BANK_BASE_URL=https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/download/v0.1.0-devnet.15"
set "BANK_SHA=5f9b213c3bda51b74e4ebabb26607b67385d613aa8d99af915a48ab063e17d4e"
set "BANK_BYTES=6442975416"
set "PART_SHA_01=3af0fd15bf0377bab42f2c59d8337f4f82e87e32c5f8c4f27ebfc21681450254"
set "PART_SHA_02=9d4f2547dc632c1c5f74ace84d26ca2ce38be50bea01ed93542fc5ab56aed6cf"
set "PART_SHA_03=a1bf1ac3230a54006039b3ce2add912e4c6f94065afad322bbaebee15b089602"
set "PART_SHA_04=5af1c6de16f5d48032aa9b37a5d48abd5d6c6e22b24935476faddb9af2cf7069"

if exist "%~dp0production-v3\MODEL-V2.bank" goto bank_ready
echo First run: fetching the 6.4 GB ProductionV3 model bank (four verified parts)...
for %%P in (01 02 03 04) do call :fetch_part %%P || exit /b 1
echo Assembling MODEL-V2.bank...
copy /b "%~dp0production-v3\RCNET1-MODEL-V2.bank.part01" ^
      + "%~dp0production-v3\RCNET1-MODEL-V2.bank.part02" ^
      + "%~dp0production-v3\RCNET1-MODEL-V2.bank.part03" ^
      + "%~dp0production-v3\RCNET1-MODEL-V2.bank.part04" "%~dp0production-v3\MODEL-V2.bank.tmp" >nul
if errorlevel 1 (
  echo ERROR: assembling the model bank failed.
  pause
  exit /b 1
)
for %%F in ("%~dp0production-v3\MODEL-V2.bank.tmp") do set "BANK_ACTUAL_BYTES=%%~zF"
if not "!BANK_ACTUAL_BYTES!"=="%BANK_BYTES%" (
  echo ERROR: assembled bank size mismatch: expected %BANK_BYTES%, got !BANK_ACTUAL_BYTES!.
  del "%~dp0production-v3\MODEL-V2.bank.tmp"
  pause
  exit /b 1
)
echo Verifying the assembled bank's SHA-256 (a few minutes)...
call :hash_matches "%~dp0production-v3\MODEL-V2.bank.tmp" "%BANK_SHA%" || (
  echo ERROR: assembled bank failed SHA-256 verification. Delete the .part
  echo files in production-v3 and run this launcher again to re-download.
  del "%~dp0production-v3\MODEL-V2.bank.tmp"
  pause
  exit /b 1
)
move /y "%~dp0production-v3\MODEL-V2.bank.tmp" "%~dp0production-v3\MODEL-V2.bank" >nul
del "%~dp0production-v3\RCNET1-MODEL-V2.bank.part01" "%~dp0production-v3\RCNET1-MODEL-V2.bank.part02" "%~dp0production-v3\RCNET1-MODEL-V2.bank.part03" "%~dp0production-v3\RCNET1-MODEL-V2.bank.part04" 2>nul
echo Model bank ready and verified.
:bank_ready

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

goto :eof

:fetch_part
set "PART=%~1"
set "PART_FILE=%~dp0production-v3\RCNET1-MODEL-V2.bank.part%PART%"
call set "PART_EXPECTED=%%PART_SHA_%PART%%%"
if exist "%PART_FILE%" (
  echo Part %PART% already present; verifying...
  call :hash_matches "%PART_FILE%" "%PART_EXPECTED%" && exit /b 0
  echo Part %PART% failed verification; re-downloading.
  del "%PART_FILE%"
)
echo Downloading part %PART% of 04 (about 1.6 GB)...
curl.exe -L --fail --retry 3 --retry-delay 5 -o "%PART_FILE%.tmp" "%BANK_BASE_URL%/RCNET1-MODEL-V2.bank.part%PART%"
if errorlevel 1 (
  echo ERROR: downloading part %PART% failed. Check your connection and rerun.
  del "%PART_FILE%.tmp" 2>nul
  pause
  exit /b 1
)
move /y "%PART_FILE%.tmp" "%PART_FILE%" >nul
echo Verifying part %PART%...
call :hash_matches "%PART_FILE%" "%PART_EXPECTED%" && exit /b 0
echo ERROR: part %PART% failed SHA-256 verification after download.
del "%PART_FILE%"
pause
exit /b 1

:hash_matches
set "HM_ACTUAL="
for /f "skip=1 tokens=*" %%H in ('certutil -hashfile "%~1" SHA256') do (
  if not defined HM_ACTUAL set "HM_ACTUAL=%%H"
)
set "HM_ACTUAL=%HM_ACTUAL: =%"
for /f "delims=" %%L in ('powershell -NoProfile -Command "'%HM_ACTUAL%'.ToLowerInvariant()"') do set "HM_ACTUAL=%%L"
if /i "%HM_ACTUAL%"=="%~2" exit /b 0
exit /b 1
