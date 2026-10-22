@echo off
setlocal EnableExtensions

set "APP_NAME=Anubis"
set "DEFAULT_SOURCE=https://github.com/CorpLynx/Anubis/archive/refs/heads/main.zip"
if not defined LOCALAPPDATA set "LOCALAPPDATA=%USERPROFILE%\AppData\Local"
set "ANUBIS_HOME=%LOCALAPPDATA%\Anubis"
set "ANUBIS_VENV=%ANUBIS_HOME%\venv"
set "ANUBIS_BIN=%ANUBIS_HOME%\bin"
set "SCRIPT_DIR=%~dp0"

if not defined ANUBIS_SOURCE_URL (
    if exist "%SCRIPT_DIR%pyproject.toml" (
        set "PACKAGE_SOURCE=%SCRIPT_DIR%"
    ) else (
        set "PACKAGE_SOURCE=%DEFAULT_SOURCE%"
    )
) else (
    set "PACKAGE_SOURCE=%ANUBIS_SOURCE_URL%"
)

where py >nul 2>nul
if not errorlevel 1 (
    set "PY_LAUNCHER=py -3"
) else (
    set "PY_LAUNCHER=python"
)

%PY_LAUNCHER% -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul
if errorlevel 1 (
    echo %APP_NAME% requires Python 3.10 or newer. Install Python or set up the Python launcher.
    exit /b 1
)

if not exist "%ANUBIS_HOME%" mkdir "%ANUBIS_HOME%"
if not exist "%ANUBIS_BIN%" mkdir "%ANUBIS_BIN%"
%PY_LAUNCHER% -m venv "%ANUBIS_VENV%"
if errorlevel 1 (
    echo Failed to create the isolated Anubis environment.
    exit /b 1
)

"%ANUBIS_VENV%\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 exit /b 1
"%ANUBIS_VENV%\Scripts\python.exe" -m pip install --upgrade --force-reinstall "%PACKAGE_SOURCE%"
if errorlevel 1 exit /b 1

powershell -NoProfile -Command "$bin=$env:ANUBIS_BIN; $q=[char]34; $pct=[char]37; $arg=$pct+'*'; $rel=$pct+'~dp0..\venv\Scripts\'; $a='@echo off'+[Environment]::NewLine+$q+$rel+'anubis.exe'+$q+' '+$arg+[Environment]::NewLine; $l='@echo off'+[Environment]::NewLine+$q+$rel+'localguard.exe'+$q+' '+$arg+[Environment]::NewLine; [IO.File]::WriteAllText((Join-Path $bin 'anubis.cmd'),$a,[Text.Encoding]::ASCII); [IO.File]::WriteAllText((Join-Path $bin 'localguard.cmd'),$l,[Text.Encoding]::ASCII); $p=[Environment]::GetEnvironmentVariable('Path','User'); $parts=@($p -split ';' | Where-Object { $_ }); if (-not ($parts | Where-Object { $_.TrimEnd('\') -ieq $bin.TrimEnd('\') })) { [Environment]::SetEnvironmentVariable('Path', (($parts + $bin) -join ';'), 'User') }"
if errorlevel 1 (
    echo Installed Anubis, but could not update your user PATH.
    echo Add this directory to PATH manually: %ANUBIS_BIN%
    exit /b 1
)

echo Anubis installed in %ANUBIS_VENV%.
echo Open a new terminal, then run: anubis --help
exit /b 0
