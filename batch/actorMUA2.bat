@echo off
REM chcp 65001 >nul

REM -----------------------------------------------------------------------------

REM Settings:

set operation=FbxToIgz
set inext=.xml, .txt
set delInputFiles=false
set recursive=false

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

:FbxToIgz
if /i "%xtnsonly%"==".fbx" goto actorIGZMaker
mkdir "%pathonly%materials\actors"
%image2igz% "%fullpath%" "%pathonly%materials\actors\%nameonly%.igz" materials\actors
if %errorlevel% GTR 0 goto Errors
EXIT /b
:actorIGZMaker
mkdir "%pathonly%actors"
%actorIGZMaker% "%fullpath%" "%pathonly%actors\%nameonly%.igz" materials\actors
if %errorlevel% GTR 0 goto Errors
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