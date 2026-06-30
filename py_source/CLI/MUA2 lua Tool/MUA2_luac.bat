@echo off
REM chcp 65001 >nul

REM -----------------------------------------------------------------------------

REM Settings:

REM FbxToIgz; unluac; luac
set operation=luac
set inext=.xml, .txt
set delInputFiles=false
set recursive=true

set texturepath=materials/actors

REM -----------------------------------------------------------------------------

REM these are automatic settings, don't edit them:
set "erl=%~dp0error.log"
call :start%operation% 2>nul

if not "%~1"=="" goto Args
set "f=%~dp0"
set "fullpath=%f:~0,-1%"
call :isfolder
goto End

:Args
if ""=="%args%" call :convCCL args
for %%p in (%args%) do (
 set fullpath=%%~p
 2>nul pushd "%%~p" && call :isfolder || call :isfiles
)
goto End

:isfolder
cd /d "%fullpath:"=%"
call :rec%recursive%
if "%inext%"==".n/a" goto %operation%
for /f "delims=" %%i in ('dir %inext:.=*.% 2^>nul ') do (
 set "fullpath=%dp%%%~i"
 call :isfiles
)
EXIT /b
:rectrue
set dircmd=/b /a-d /s
set dp=
EXIT /b
:recfalse
set dircmd=/b /a-d
set "dp=%fullpath%\"
EXIT /b

:isfiles
set "fullpath=%fullpath:"=%"
if /i "%fullpath%"=="%outfile%" EXIT /b
call :filesetup
if not "%inext%"==".*" echo %xtnsonly%|findstr /eil "%inext:,=%" >nul || EXIT /b
call :%operation%
if %errorlevel% GTR 0 goto Errors
if %delInputFiles%==true del "%fullpath%"
set any=true
EXIT /b

:convCCL
set "i=%cmdcmdline:"=""%"
set "i=%i:*"" =%"
set "i=%i:~0,-2%"
if ""=="%i%" EXIT /b
:fixQ
if ""=="%i%" call set "i=%%%1%%"
set "i=%i:^=^^%"
set "i=%i:&=^&%"
set "i=%i: =^ ^ %"
set i=%i:""="%
set "i=%i:"=""Q%"
set "i=%i:  ="S"S%"
set "i=%i:^ ^ = %"
set "i=%i:""="%"
set "i=%i:"Q=%"
set %1="%i:"S"S=" "%"
set i=
EXIT /b

:filesetup
for %%i in ("%fullpath%") do (
 set pathonly=%%~dpi
 set pathname=%%~dpni
 set nameonly=%%~ni
 set namextns=%%~nxi
 set xtnsonly=%%~xi
 set filesize=%%~zi
)
EXIT /b

:startFbxToIgz
REM .dds and .tga are confirmed to work (DDS10?)
set inext=.dds, .tga, .png, .fbx
call :checkTools actorIGZMaker || goto FbxToIgzMissing
call :checkTools image2igz || goto FbxToIgzMissing
EXIT /b 0
:FbxToIgzMissing
echo actorIGZMaker.exe or image2igz.exe not found.
goto Errors
:startunluac
set inext=.lua
if exist "%~dp0unluac.jar" EXIT /b 0
echo unluac.jar not found. Please add it from https://sourceforge.net/projects/unluac/files/latest/download .
goto Errors
:startluac
mkdir "%~dp0compiled\"
set inext=.lua
call :checkTools luac5.1 && EXIT /b
echo luac5.1.exe not found. Please add it from https://sourceforge.net/projects/luabinaries/files/5.1.5/Tools Executables/lua-5.1.5_Win64_bin.zip/download .
goto Errors

:FbxToIgz
if /i "%xtnsonly%"==".fbx" goto actorIGZMaker
mkdir "%pathonly%materials\actors"
%image2igz% "%fullpath%" "%pathonly%materials\actors\%nameonly%.igz" materials\actors
EXIT /b
:actorIGZMaker
mkdir "%pathonly%actors"
%actorIGZMaker% "%fullpath%" "%pathonly%actors\%nameonly%.igz" materials\actors
EXIT /b

:unluac
REM only works properly, if saved paths start with a drive letter
set psc="$p = '%fullpath%'; $start = 20; $end = $start + (gc $p -Encoding byte -TotalCount $start)[12]; [Text.Encoding]::UTF8.GetString((gc $p -Encoding byte -TotalCount $end)[($start + 4)..$end])"
for /f "delims=" %%p in ('PowerShell %psc%') do set "op=%pathonly%\%%~p"
for %%o in ("%op%") do mkdir "%%~dpo"
java -jar unluac.jar "%fullpath%" > "%op%"
EXIT /b

:luac
REM saves %fullpath% to the compiled lua (probably unimportant for MUA2)
%luac5.1% -o "%~dp0compiled\%namextns%" "%fullpath%"
EXIT /b


:checkTools program
REM if "%IG_ROOT%"=="" cd /d "%~dp0" & if not exist "%~dp0libIGCore.dll" echo The IG_ROOT variable is not defined. Please check your Alchemy 5 installation. & goto Errors
if exist "%~dp0%1.exe" set %1="%~dp0%1.exe"
if not defined %1 for /f "delims=" %%a in ('where %1.exe 2^>nul') do set %1=%1
REM if not defined %1 if exist "%IG_ROOT%\bin\%1.exe" set %1="%IG_ROOT%\bin\%1.exe"
if defined %1 EXIT /b 0
EXIT /b 1


:End
CLS
for %%e in ("%erl%") do if %%~ze GTR 0 goto Errors
del "%erl%"
goto cleanup
:Errors
echo.
echo There was an error in the process. Check the error description.
if exist "%erl%" (
 echo.
 type "%erl%"
)
pause
:cleanup
EXIT