@echo off
REM chcp 65001 >nul

REM -----------------------------------------------------------------------------

REM Settings:

REM What operation should be made? (QuickBMS =QBext; Compression type scanner =comtype_scan2; Noesis =Noesis; Enbaya compressed animations IGB =EnbExt; FSB audio =FSBext; ImageMagick =Magick; PVR texture tool =PVRext; NetEase NPK extractor =NPKEext; MSW sound extractor, eg. sound_high.npk =MSWsext; Ravioli Game Tools Extractor =RExtractor; =FFmpeg; use FFmpeg to split MUA music =SplitMUAwav4chan)
set operation=QBext
REM Delete input files? (yes =true; no =false; ask each time =ask)
set delIn=false
REM Ask before backing up existing files? (yes =true; no =false; always replace, not safe! =replace)
set askbackup=false
REM Include subfolders (recursive mode)? (yes =true; no =false)
set recursive=false
REM Define input format (extension with ".", eg.: =.ktx, all =.*)
set inext=.*

REM Quick BMS Settings:
REM Define input format and decryption script. (ask each time instead =ask)
set scrpt=marvel_ultimate_alliance.bms
REM -l     list the files without extracting them
REM -f W   filter the files to extract using the W wildcards separated by comma or
REM        semicolon, example -f "*.mp3,*.txt;*myname*"
REM        if the filter starts with ! it's considered an ignore/exclusion filter,
REM        it can be a text file containing multiple filters too, * and {} are same
REM        example: quickbms -f "*.mp3;!*.ogg" script.bms archive.dat output
REM        example: quickbms -f myfilters_list.txt script.bms archive.dat
REM        use {} instead of * to avoid issues on Windows, multiple -f are ok too
REM -F W   as above but works only with the files in the input folder (if used)
REM -o     overwrite the output files without confirmation if they already exist
REM -k     keep the current files if already exist without asking (skip all)
REM -K     automatically rename the output files if duplicates already exist
set QBopt=%QBopt%-K 
REM -r     experimental reimport option that should work with many archives:
REM          quickbms script.bms archive.pak output_folder
REM          modify the needed files in output_folder and maybe remove the others
REM          quickbms -w -r script.bms archive.pak output_folder
REM        you MUST read section 3 of quickbms.txt before using this feature,
REM        use -r -r to use the alternative and better REIMPORT2 mode
REM -u     check if there is a new version of QuickBMS available
set QBupd=false
REM -i     generate an ISO9660 file instead of extracting every file, the name of the ISO image will be the name of the input file or folder
rem QBopt=%QBopt%-i 
REM -z     exactly as above but it creates a ZIP file instead of an ISO image
REM Advanced options:
REM -d     automatically create an additional output folder with the name of the input folder and file processed, eg. models/mychar/mychar.arc/*,
REM        -d works also if input and output folders are the same (rename folder)
REM -D     like -d but without the folder with the filename, eg. models/mychar/*
REM -E     automatically reverse the endianess of any input file by simply reading each field and writing the reversed value, each Get produces a Put
REM -c     old quick list of basic BMS commands and some notes about this tool
REM -S CMD execute the command CMD on each file extracted, you must specify the #INPUT# placeholder which will be replaced by the name of the file, example: -S "lame.exe -b 192 -t --quiet #INPUT#"
REM -Y     automatically answer yes to any question
set QBopt=%QBopt%-Y 
REM -O F   redirect the output of all the extracted files to the output file F
REM -s SF  add a script file or command before the execution of the input script,
REM        useful if an archive uses a different endianess or encryption and so on
REM        SF can be a script or directly the bms instruction you want to execute
REM -.     don't terminate QuickBMS if there is an error while parsing multiple
REM        files (like wrong compression or small file), just continue with the
REM        other files in the folder; useful also in rare cases in reimport mode
REM Debug and experimental options:
REM -v     verbose debug script information, useful for verifying possible errors
REM -V     alternative verbose info, useful for programmers and formats debugging
REM -q     quiet, no *log information
REM -Q     very quiet, no information displayed except the Print command
REM -L F   dump the offset, size and name of the extracted files into the file F
REM -x     use the hexadecimal notation in myitoa (debug)
REM -0     no extraction of files, useful for testing a script without using space
REM -R     needed for programs that act as interface for QuickBMS and in batch
REM -a S   pass arguments to the input script that will take the names
REM        quickbms_arg1, quickbms_arg2, quickbms_arg3 and so on, note they are
REM        handled as arguments so pay attention to spaces and commas, eg:
REM          -a "arg1 \"arg 2\", arg3"
REM          -a arg1 -a "\"arg 2\"" -a arg3
REM        a full backup of the whole -a options is on the var quickbms_arg
REM -H     experimental HTML hex viewer output, use it only with very small files!
REM -X     experimental hex viewer output on the console (support Less-like keys)
REM -9     toggle XDBG_ALLOC_ACTIVE  (enabled)
REM -8     toggle XDBG_ALLOC_INDEX   (enabled)
REM -7     toggle XDBG_ALLOC_VERBOSE (disabled)
REM -6     toggle XDBG_HEAPVALIDATE  (disabled)
REM -3     execute an INT3 before each CallDll, compression and encryption
REM -I     toggle variable names case sensitivity (default insensitive)
REM -M F   experimental compare and merge feature that allows to compare the extracted files with those located in the folder F, currently this experimental option will create files of 0 bytes if they are not different, so it's not simple to identify what files were written
REM -Z     input file cleaner, in reimport mode replaces all archived files with zeroes, no matter if they exist or not in the folder, will be all zeroed
REM -P CP  set the codepage to use (default utf8), it can be a number or string
REM -T     do not delete the TEMPORARY_FILE at the end of the process
REM -N     decimal names for files without a name: 0.dat instead of 00000000.dat
REM -e     ignore the compression errors and dump the (wrong) output data anyway
REM -J     all the constant strings are considered Java/C escaped strings (cstring)
REM -B     debug option dumping all the non-parsed content of the open files, the data will be saved in the output folder as QUICKBMS_DEBUG_FILE*
REM -W P   experimental web API (P is the port) and pipe/mailslot IPC interface
REM -t N   experimental tree-view of the extracted/listed files where N is:
REM        0:text1, 1:text2, 2:text3, 3:json1, 4:json2, 5:web, 6:dos, 7:ls
REM -U [S] list of available compression algorithms, use S for searching names
REM -#     in reimport mode checks if the archived files and those to reimport are the same (hash), it's useful if you didn't remove the unmodified files
REM -j     force UTF16 output in some functions, for example with SLog
REM -b C   use C (char or hex) as filler in reimporting if the new file is smaller, by default it's used space in SLog and 0 for Log and CLog
REM Features and security activation options:
REM -w     enable the write mode required to write physical input files with Put*
REM -C     enable the usage of CallDll without asking permission
REM -n     enable the usage of network sockets
REM -p     enable the usage of processes
REM -A     enable the usage of audio device
REM -g     enable the usage of video graphic device
REM -m     enable the usage of Windows messages
REM -G     force the GUI mode on Windows, it's automatically enabled if you double-click on the QuickBMS executable

REM FFmpeg settings:
REM usage: ffmpeg [options] [[infile options] -i infile]... {[outfile options] outfile}...
REM    -h full -- all options
REM    -h type=name -- eg. -h decoder=xma2
REM -formats            show available formats
REM -muxers             show available muxers
REM -demuxers           show available demuxers
REM -decoders           show available decoders
REM -encoders           show available encoders
REM -devices            show available devices
REM -codecs             show available codecs
REM -bsfs               show available bit stream filters
REM -protocols          show available protocols
REM -filters            show available filters
REM -report             generate a report
REM -stats              print progress report during encoding
REM -y                  overwrite output files
REM -n                  never overwrite output files
REM -vol volume         change audio volume (256=normal)
REM -copy_unknown       Copy unknown stream types
REM -vsync              video sync method
REM -async              audio sync method
REM -xerror error       exit on error
REM -copytb mode        copy input stream time base when stream copying
REM -vstats_file file   dump video coding statistics to file
REM -qsv_device device  set QSV hardware device (DirectX adapter index, DRM path or X11 display name)
REM -hide_banner hide_banner  do not show program banner
REM Per-file main options:
REM -f fmt              force format
REM -c codec            codec name
REM -dcodec codec       force data codec ('copy' to copy stream)
REM -pre preset         preset name
REM -map_metadata outfile[,metadata]:infile[,metadata]  set metadata information of outfile from infile
REM -t duration         record or transcode "duration" seconds of audio/video
REM -to time_stop       record or transcode stop time
REM -ss time_off        set the start time offset
REM -sseof time_off     set the start time offset relative to EOF
REM -accurate_seek      enable/disable accurate seeking with -ss
REM -target type        specify target file type ("vcd", "svcd", "dvd", "dv" or "dv50" with optional prefixes "pal-", "ntsc-" or "film-")
REM -apad               audio pad
REM -frames number      set the number of frames to output
REM -map [-]input_file_id[:stream_specifier][,sync_file_id[:stream_specifier]]  set input stream mapping
REM -map_channel file.stream.channel[:syncfile.syncstream]  map an audio channel from one stream to another, eg. "-map_channel 0.0.0 -map_channel 0.0.1" to use the first two channels for use in stereo track.
set FFopt=%FFopt%
REM -q q                use fixed quality scale (VBR)
REM -stream_loop loop count  set number of times input stream shall be looped
REM -autorotate         automatically insert correct rotate filters
REM -autoscale          automatically insert a scale filter at the end of the filter graph
REM Video options:
REM -vframes number     set the number of video frames to output
REM -r rate             set frame rate (Hz value, fraction or abbreviation)
REM -fpsmax rate        set max frame rate (Hz value, fraction or abbreviation)
REM -s size             set frame size (WxH or abbreviation)
REM -aspect aspect      set aspect ratio (4:3, 16:9 or 1.3333, 1.7777)
REM -vn                 disable video
REM -vcodec codec       force video codec ('copy' to copy stream)
REM -pass n             select the pass number (1 to 3)
REM -vf filter_graph    set video filters
REM -ab bitrate         audio bitrate (please use -b:a)
REM -b bitrate          video bitrate (please use -b:v)
REM -dn                 disable data
REM -hwaccel hwaccel name  use HW accelerated decoding
REM -hwaccel_device devicename  select a device for HW acceleration
REM Audio options:
REM -aframes number     set the number of audio frames to output
REM -aq quality         set audio quality (codec-specific)
REM -ar rate            set audio sampling rate (in Hz)
REM -ac channels        set number of audio channels
REM -an                 disable audio
REM -acodec codec       force audio codec ('copy' to copy stream)
REM -vol volume         change audio volume (256=normal)
REM -af filter_graph    set audio filters
REM -sample_fmt format  set sample format
REM -channel_layout layout  set channel layout
REM -guess_layout_max   set the maximum number of channels to try to guess the channel layout
REM Subtitle options:
REM -sn                 disable subtitle
REM -scodec codec       force subtitle codec ('copy' to copy stream)
REM -fix_sub_duration   fix subtitles duration
REM -canvas_size size   set canvas size (WxH or abbreviation)

REM Noesis Settings:
REM Full settings @ https://www.reddit.com/r/ffxioffline/comments/653onc/noesis_advanced_export_optionscommands/
REM Pre-define output format (None, auto = exo=; prompt each =ask)
set exo=png
REM Second output? (No 2nd output = xo2=; eg. =tga)
set xo2=
REM Select plugin? (No plugin = xo2=; eg. =???) (use display names, not file names)
set pli=

REM Animation Extractor Settings:
REM Enbaya signature?
set signature=c4 99 09 10
rem MUA PC: ac 8b 0a 10
rem Animation Mixer temp (Alchemy 5): 88 2f 06 10  
rem XML2 PSP: c4 99 09 10
rem XML2 PC: 10 9c 07 10
rem Dokapon: b8 b4 07 10
REM Remove enbaya data after converting to RTRD? (yes =true; no =false)
set delEnbaya=true

REM Image Magick Options:
REM Tool to use: composite, conjure, convert, dcraw, ffmpeg, identify, IMDisplay, magick (default), mogrify, montage, stream, compare
set tl=magick
REM Parameters: not explained, there are way too many. Check https://imagemagick.org/script/command-line-tools.php
REM Green normal to blue normal: option=-channel R -fx A -channel B -fx "sqrt(1-((2*R-1)^2+(2*G-1)^2))/2+0.5" -alpha off -alpha on
REM Blue normal to green normal: option=xc:"#000000" -channel B -clut -channel A -fx R -channel R -fx B
REM Grayscale: option=-colorspace Gray
set option=xc:"#000000" -channel B -clut -channel A -fx R -channel R -fx B
REM Output format:
set format=png

REM PVR Texture Tool Options:
REM Same settings for all? (yes =true; no =false)
set all=false
REM -i [filepath],<additionalfiles...>                      Specify the input file(s).
REM -ics [colourspace]                                      Explicitly set the colourspace for all input files.
REM -o <filepath>                                           Set the output file destination.
REM (ask out=; formats: =dds)
set out=
REM -noout                                                  Suppress the output of a .pvr file.
REM (ask noout=; yes =true; no =false)
set noout=
REM -d <filepath>                                           Save a decompressed file alongside the output.
REM (ask dout=; formats: =png; =tga)
set dout=
REM -cube <faceorder>                                       Construct a cube map from available input files.
REM -equi2cube <filter>                                     Construct a cube map from a single equirectangular image.
REM -array                                                  Construct a texture array from available input files.
REM -pad [2|4|8]                                            Add padding to the meta data, to align texture data to a byte boundary.
REM -legacypvr                                              Save the output to the deprecated PVR v2 container
REM -r [width],[height]                                     Resize a texture to the given size.
REM -square <+|->                                           Forces the texture into a square.
REM -pot <+|->                                              Forces the texture into power of two dimensions.
REM -rfilter [nearest|linear|cubic]                         Specify the filter used when resizing the texture. Default: linear.
REM -rotate [z],<+|->                                       Rotate the texture around a given axis.
REM -flip [x|y],<"flag">                                    Flip the texture over a given axis.
REM -b <width>,<height>                                     Add a mirrored border to the texture.
REM -p                                                      Multiply the texture by its alpha value.
REM -l                                                      Discard any data in fully transparent areas.
REM -n [scale],<channelorder>                               Generate a normal map from the input texture.
REM -m <numberofmipmaps>                                    Generates MIP-Maps for the input texture.
REM -mfilter ['nearest'|'linear'|'cubic']                   Specify the filter used when generating MIP-Maps. Default: linear.
REM -c                                                      Saturates the tail of the MIP-Map chain with colours for debugging purposes.
REM -f [format],<variabletype>,<colourspace>                Specify the pixel format to encode to.
REM (ask fmt=; formats: =r8g8b8a8; =r16g16b16a16; =r8g8b8)
set fmt=
REM -q [quality]                                            Sets the encoding quality level used by the compressor.
REM -dither                                                 Dither the texture before transcoding to avoid banding artifacts.
REM -maxrange [max range]                                   Sets the maximum range (min 1.0) to use when encoding to RGBM and RGBD texture formats.
REM -j [jobs]                                               Sets the maximum number of threads to use for transcoding. Default: all cores.
REM -ibldiffuse [samples],[dimensions]                      Generate a mipmapped diffuse irradiance texture from a environment map.
REM -iblspecular [samples],[dimensions],<levels to discard> Generates a prefiltered specular irradiance texture from a environment map.
REM -irz                                                    Include a roughness of zero when generating the prefiltered specular environment map.
REM -shh                                                    Do not output messages of any kind.
REM -help <commandargument>                                 Print the help text for all options or a specified option.
REM -red [filename],<channelname>                           Sets the Red channel in the input texture to match the channel specified in a second image.
REM -green [filename],<channelname>                         Sets the Green channel in the input texture to match the channel specified in a second image.
REM -blue [filename],<channelname>                          Sets the Blue channel in the input texture to match the channel specified in a second image.
REM -alpha [filename],<channelname>                         Sets the Alpha channel in the input texture to match the channel specified in a second image.
REM -diff [filename],<mode>,<modifier>                      Calculates the difference between two textures, providing error metrics, and an optional visual representation.
REM -rcanvas [width],[height]                               Resizes a texture to the given size, without changing the image data.
REM -squarecanvas <+|->                                     Forces the texture into a square, without changing the image data.
REM -potcanvas <+|->                                        Forces the texture into power of two dimensions, without changing the image data.
REM -offsetcanvas [xoffset],[yoffset]                       Sets the offset when performing a canvas resize.
REM -centrecanvas                                           Sets the offset from center when performing a canvas resize.

REM -----------------------------------------------------------------------------

REM these are automatic settings, don't edit them:
if ""=="%temp%" set "temp=%~dp0"
set "tem=%temp%\%operation%.tmp"
call :start%operation%

if not "%~1"=="" goto Args
set "f=%~dp0"
set "fullpath=%f:~0,-1%"
call :isfolder
GOTO End

:Args
if ""=="%args%" call :convCCL args
for %%p in (%args%) do (
 set fullpath=%%~p
 2>nul pushd "%%~p" && call :isfolder || call :isfiles
)
GOTO End

:isfolder
cd /d "%fullpath:"=%"
call :rec%recursive%
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
call :filesetup
if not "%inext%"==".*" echo %xtnsonly%|findstr /eil "%inext:,=%" >nul || EXIT /b
call :%operation%
if %delIn%==true del "%fullpath%"
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
)
EXIT /b


:startSplitMUAwav4chan
set inext=.wav
:startFFmpeg
set tl=ffmpeg
goto tools
:startNoesis
set cmd= ?cmode
if defined pli set cmd= ?runtool "%pli%"
set inext=.*
set tl=Noesis
goto tools
:startcomtype_scan2
set inext=.*
set scrpt=comtype2_scan
set QBupd=false
:startQBext
set tl=quickbms
if "%inext%" == "ask" set inext=
if "%scrpt%" == "ask" set scrpt=
:IEask
if defined inext goto tools
set /p inext=Please enter extensions to filter input files. Press enter to process all: 
goto tools
set inext=& for %%i in (%inext%) do call :addVar inext .%%i
set inext=%inext:..=.%
set inext=%inext:.=, .%
set inext=%inext:~2%
goto tools
:startFSBext
set inext=.fsb, .pak
set tl=fsbext
goto tools
:startMagick
set inext=.png, .jpeg, .jpg, .tga, .dds, .bmp, .gif, .heic, .tiff, .dpx, .exr, .webp, .pdf, .svg
goto tools
:startPVRext
REM set inext=.ktx
set tl=PVRTexToolCLI
goto IEask
:startNPKEext
set inext=.npk
set tl=EXPKDec
goto tools
:startMSWsext
set inext=.npk
set scrpt=npkUnpackerExtFilter
set QBupd=false
set tl=quickbms
call :tools
:startRExtractor
set tl=RExtractorConsole
goto IEask
:startEnbExt
set inext=.igb
set tl=enbrip
:tools
call :checkTools %tl%
EXIT /b


:QBext
if "%QBupd%" == "true" %quickbms% -u & pause
for %%s in ("%scrpt%") do set "scrpt=%%~dpns.bms" & set sn=%%~ns.bms
if not exist "%scrpt%" for %%q in (%quickbms%) do set "scrpt=%%~dpq%sn%"
:checkScript
if not exist "%scrpt%" call :QBas & goto checkScript
:QBe
%quickbms% %QBopt%"%scrpt%" "%fullpath%" "%pathname%" || goto Errors
EXIT /b
:QBas
set /p "scrpt=Please enter or paste the path, name and extension of the decryption script: "
set "scrpt=%scrpt:"=%"
EXIT /b
:QBextPost
echo %QBopt% | find "-l" >nul && pause
EXIT /b
:comtype_scan2
if not exist "%scrpt%" goto Errors
echo If an algorithm doesn't return immediately press CTRL+C
echo and answer 'n' [no] when asked to "terminate batch job"
for /l %%i in (1,1,1000) do set QBopt=-a "%%i" & call :QBe
EXIT /b

:SplitMUAwav4chan
set FFopt=-map_channel 0.0.0 -map_channel 0.0.1 "%pathname%a.wav" -map_channel 0.0.2 -map_channel 0.0.3 "%pathname%x.wav"
:FFmpeg
%ffmpeg% -i "%fullpath%" %FFopt%
EXIT /b

:Noesis
if /i "%exo%"=="ask" call :
if defined exo set e=.exo
%Noesis% %cmd% "%fullpath%" "%pathname%%e%"
if defined xo2 %Noesis% %cmd% "%fullpath%" "%pathname%.%xo2%"
EXIT /b

:EnbExt
if "%signature%"=="" set /p signature=Paste the hex signature for Enbaya animation data here: 
set sig=0x%signature: =,0x%
call :BINsplitPS BsPe
for %%e in ("%pathname%\*.enbaya") do set "enbpath=%%~fe" & call :enbrip
EXIT /b

:enbrip
for %%i in ("%enbpath%") do set en=%%~ni
echo "%en%">>"%pathname%-info.txt"
%enbrip% "%enbpath%" 1.0 | find /i "duration">>"%pathname%-info.txt"
if %delEnbaya%==true del "%enbpath%"
EXIT /b


:FSBext
if /i %xtnsonly%==.pak goto PAKe
:FSBe
call :askDel FSB
set MC=
for /f "tokens=5" %%t in ('%fsbext% -l "%fullpath%" ^| find " mpeg "') do if "%%t"=="4" set MC=-M 
%fsbext% -A %MC%"%fullpath%"
if %delIn%==true del "%fullpath%"
EXIT /b

:fs
cd "%pathname%"
call :FSBe
del "%fullpath%"
EXIT /b
:PAKe
call :BINsplitPS PAKePS
for %%f in ("%pathname%\*.fsb") do set delIn=true& set "fullpath=%%~f" & call :fs & set delIn=%delIn%
EXIT /b
rem or use VGMToolbox to split ("Advanced Cutter" and "FSB Cutter" preset)
rem old powershell code, using slow Format-Hex - doesn't extract last file:
$f='D:\Programme\_portable\Tools\marvel,games\fmod.tools\Extract\pc_psylocke_bank_vp.pak'
$s='FSB'
$fb=[System.IO.File]::ReadAllBytes($f)
$fh=Format-Hex -Path $f
$fh | Select-String -Pattern $s -CaseSensitive | ForEach-Object -Process {
  $a = $h
  $h = ($_ -split '\s+')[0]
  $h = '0x' + $h
  $b = $h-1
  $o = $f.Substring(0, $f.LastIndexOf('.')) + '_' + $b + '.fsb'
  if($a){
    $c = $fb[$a..$b]
    [System.IO.File]::WriteAllBytes($o, $c)
  }
}
rem Never used the hex values for $s:
echo $sh = @()
echo $s.TocharArray() | ForEach-Object -Process {$sh += '{0:x}' -f [int][char]$_}

:Magick
call :checkExist %format%
call set "magick=%%%tl%%%"
%magick% "%fullpath%" %option% "%pathname%.%format%" || goto Errors
EXIT /b

:PVRext
if not %all%==true call :PVRoptions %xtnsonly:~1%
call :PVRsetup
call :askDel %xtnsonly:~1%
%PVRTexToolCLI% -i "%fullpath%" %nop%%o%%d%%f% || goto Errors
EXIT /b
:PVRsetup
set d=& set o=& set f=& set nop=
if defined dout set d=-d "%pathname%.%dout%" 
if defined out set o=-o "%pathname%.%out%" 
if defined fmt set f=-f %fmt% 
if "%noout%"=="true" set nop=-noout
EXIT /b
:PVRoptions
CLS
echo PowerVR TexTool for %1 Options
echo --------------------------------
echo Switch options by pressing the letter at the start of each line:
echo.
echo D Uncompressed output format: %dout%
echo O Compressed output format:   %out%
echo F Image Format (bit depth):   %fmt%
echo P Create a .pvr file:         %noout%
echo.
echo A Accept options and continue.
echo R Accept options for all remaining files and continue.
echo.
choice /c "DOFPRA"
set all=false
if errorlevel 6 EXIT /b
set all=true
if errorlevel 5 EXIT /b
if errorlevel 4 call :switch noout true false & goto PVRoptions
if errorlevel 3 call :optionSwitch fmt r8g8b8a8 r16g16b16a16 r8g8b8 & goto PVRoptions
if errorlevel 2 call :optionSwitch out dds & goto PVRoptions
if errorlevel 1 call :switch dout png tga & goto PVRoptions
EXIT /b

:NPKEext
%EXPKDec% "%fullpath%" || goto Errors
EXIT /b

:RExtractor
mkdir "%pathname%" 2>nul
%RExtractorConsole% "%fullpath%" "%pathname%" /as || goto Errors
EXIT /b
REM /s =   /subdir  Create subdirectory for each input file
REM /if =  /imageformat:<extension>  Convert image
REM /sf =  /soundformat:<extension>  Convert sound
REM /fsf = /fallbacksoundformat:<extension>  if conversion in /sf is not possible
REM /e =   /extract   Start extraction autom. and exit when finished (for GUI only)
REM /at =  /archivetype:<name>       Specify the archive type
REM /as =  /allowscanning            Allow scanning of unknown files
REM /rd =  /rootdir:<RootDirectory>[;<RootDirectory>;...]  Specify root directories
REM /? =   /help                     Show this help message

:MSWsext
set /p f=<"%fullpath%"
if /i "%f:~,4%" == "EXPK" call :checkTools EXPKDec & goto NPKEext
set "o=%pathname%"
set "pathname=%pathonly:~,-1%"
call :QBext
echo.
choice /m "Extract .bnk files"
if errorlevel 2 EXIT /b
for %%b in ("%o%\*.bnk") do %RExtractorConsole% "%%~fb" "%o%" /s /at:"Wwise Sound Bank" || goto Errors
:MSWsID
echo.
echo Sorting files . . .
mkdir "%o%\music" 2>nul
for %%m in ("%o%\*.wem") do call :MSWm %%~zm %%~nm
for /f "delims=" %%t in ('dir /b /s "%o%\*.txt"') do (
 set "txt=%%~ft"
 set /p ev=<"%%~ft"
 for /f "usebackq tokens=1-6 skip=1 delims=	" %%i in ("%%~ft") do (
  set ID=%%i
  set Nm=%%j
  set Fp=%%k
  set Op=%%l
  set Nt=%%m
  set Sz=%%n
  call :MSWprocID
)) & call :MSWmoveT
for /f "delims=" %%d in ('dir /ad /b /s "%o%\*"') do rd "%%~d"
choice /m "Remove .bnk files"
if not errorlevel 2 del "%o%\*.bnk"
EXIT /b
:MSWprocID
set "n=%Nm%"
REM Various types here, only In Memory Audio is needed but all other types may have this type attached. Currently only one State, which must not go anywhere.
set "ev=%ev:~,5%"
if /i "%ev%" == "State" set "tf=%o%" & EXIT /b
if /i "%ev%" == "Event" (
 if /i "%Nm:~,5%" == "Play_" set "n=%Nm:~5%"
 set "Nt=%Op%"
 set "Op=%Fp%"
) else if not defined Sz set "Sz=%Nt%" & set ev=
REM Hero id number from name is preferred, but inconsistent and must be checked for irregularities
set "c=%n%xxx"
for /f "delims=0123456789" %%n in ("%n:~,1%") do set "c=%c:*_=%"
for /f "delims=0123456789" %%n in ("%c:~,4%") do call :MSWsFp SFX\hero\
set "c=%c: =_%"
set charID=%c:~,4%
set costID=%c:~4,2%
REM most costumes are adjacent to the hero number, but some are wrong, with a "_" in between
if "%c:~4,1%" == "_" (
 if "%c:~7,1%" == "_" set costID=%c:~5,2%
 if "%c:~6,1%" == "_" set costID=%c:~5,2%
)
call :MSWnames %charID% %costID%
if not "%hf%" == "%o%\%charNm%\%s%" call :MSWdef
:MSWmoveID
for /f "delims=" %%s in ('dir /b /s "%o%\*.wem" ^| find "%ID%.wem"') do (
 if not exist "%hf%" mkdir "%hf%"
 move "%%~fs" "%hf%\%Nm%.wem" || echo   "%%~fs" not moved to "%Nm%.wem". >>"%~dp0temp.log"
)
EXIT /b
:MSWmoveT
mkdir "%tf%" 2>nul
move "%txt%" "%tf%\"
set hf=
EXIT /b
:MSWsFp
echo "%Fp%" | find /i "%1" >nul && call set "c=%%Fp:*%1=%%"
EXIT /b
:MSWdef
REM Some files are named wrong, but these can use the previous folder
echo {%ID%} | findstr "{608223499} {792105017} {684284486} {1069865956} {566123032} {754814267} {109281569} {409804267} {600466344}" >nul && EXIT /b
if not defined hf set "tf=%o%\%charNm%\%s%"
set "hf=%o%\%charNm%\%s%"
EXIT /b
REM Alternate codes:
REM - skips more, but doesn't account for Play_
if /i "%ID:~,9%" == "In Memory" ( set ev=
) else for /f "delims=0123456789" %%n in ("%ID%") do set "ev=%ID:~,5%"
REM - search for hero and hero_vo for num from path (not tested how good that would be in comparison to name)
echo "%Fp%" | findstr /i "\\hero_vo\\ SFX\\hero\\" && goto NPC
REM - alternatively search and strip directly. But all monster etc need a separate code
call :MSWsFp SFX\hero\
call :MSWsFp \hero_vo\


:BINsplitPS
mkdir "%pathname%" 2>nul
call :%1 > "%tem%.ps1"
CLS
echo Splitting "%nameonly%" . . .
Powershell -executionpolicy remotesigned -File "%tem%.ps1"
CLS
EXIT /b
:PAKePS
echo $s = 'FSB'
echo $sb = [byte[]]$s.TocharArray()
echo $x = '.fsb'
goto BsPm
:BsPe
echo $sb = %sig%
echo $x = '.enbaya'
rem    Header:
rem    $v = $c[0..75]
rem    Duration:
rem    $d = ([BitConverter]::ToSingle($c[12..15], 0) ^| %% { '{0:0.000000}' -f $_ })
rem    Tolerance:
rem    $e = ([BitConverter]::ToSingle($c[8..11], 0) ^| %% { '{0:0.000000}' -f $_ })
rem    Speed? (is 01 or 07, but others work too, higher on long animations):
rem    $v = $c[56]
rem    Motion? (values 00, 04):
rem    $m = $c[28]
rem    Motion? (values 0x1b02, 0x0b03):
rem    $m2 = $c[32] + $c[33]*256 + $c[34]*65536 + $c[35]*16777216
rem    Motion?:
rem    $m3 = $c[36] + $c[37]*256 + $c[38]*65536 + $c[39]*16777216
rem    Rotation?:
rem    $v = $c[64]
rem    Always 14 to 1e (more or less? usually 14):
rem    $z = $c[16]
rem    ? (3a-f, 4a)?:
rem    $z = $c[20]
rem    Rotation? (4, 8, 14):
rem    $v = $c[64]
rem    useAnimationTransBoolArray bitCount:
rem    $t = $c[4]
rem    $t = $c[72]
:BsPm
echo $n = "%pathname%\%nameonly%_"
echo $f = "%fullpath%"
echo function BinSplit {
echo   $c = $fb[$a..$b]
echo   $o = $n + $a + $x
echo   [System.IO.File]::WriteAllBytes($o, $c)
echo }
echo $fb = [System.IO.File]::ReadAllBytes($f)
echo For ($ix = 0; $ix -le $fb.Length - $sb.Length ; $ix++) {
echo   For ($i = 0; $i -lt $sb.Length -and $fb[$ix + $i] -eq $sb[$i]; $i++) {}
echo   If ($i -ge $sb.Length) {
echo     $b = $ix-1
echo     If($a){
echo       BinSplit
echo     }
echo     $a = $ix
echo   }
echo }
echo $a = $b+1
echo $b = $fb.Length
echo BinSplit
EXIT /b

:MSWnames
set s=
if /i "%n:~,2%" == "UI" set charNm=sfx\UI& EXIT /b
if /i "%c:~,6%" == "bobao0" set charNm=announcer& EXIT /b REM F.R.I.D.A.Y.
if /i "%c:~,6%" == "bobao1" set charNm=announcer\Nick Fury& EXIT /b
if /i "%c:~,6%" == "bobao2" set charNm=announcer\JJJ& EXIT /b
if /i "%c:~,6%" == "bobao3" set charNm=announcer\Cosmo& EXIT /b
if /i "%c:~,6%" == "bobao4" set charNm=announcer\Peni Parker& EXIT /b
if /i "%c:~,6%" == "bobao5" set charNm=announcer\Death& EXIT /b
if /i "%c:~,6%" == "bobao6" set charNm=announcer\Carina Walters& EXIT /b
if /i "%c:~,6%" == "bobao7" set charNm=announcer\Uatu& EXIT /b
if /i "%c:~,6%" == "bobao8" set charNm=announcer\Gwenpool& EXIT /b
if /i "%c:~,3%" == "sys" set charNm=announcer& EXIT /b
if /i "%n:~,9%" == "ani_scene" set charNm=announcer\tutorial& EXIT /b
echo "%Op%" | find "tutorial_lines_vo" >nul && set charNm=announcer\tutorial&& EXIT /b
REM newbie, tutorial
echo "%Op%" | find "common_sfx" >nul && set charNm=sfx\common&& EXIT /b
REM emoji, fanzhongli, equipment, kaichang, common
if /i "%n:~,7%" == "tunxing" set charNm=sfx\common& EXIT /b
if /i "%n:~,12%" == "ylwf_zhenjin" set charNm=sfx\common& EXIT /b
if /i "%n:~,8%" == "pc_spell" set charNm=sfx\summoner& EXIT /b
if /i "%n:~,9%" == "worldvive" set charNm=sfx& EXIT /b
if /i "%n:~,4%" == "amb_" set charNm=sfx\ambient& EXIT /b
if /i "%n:~,4%" == "set_" set charNm=sfx\ambient& EXIT /b
if /i "%n:~,4%" == "map_" set charNm=sfx\ambient& EXIT /b
if /i "%n:~,10%" == "battlepass" set charNm=sfx\battlepass& EXIT /b
echo "%Fp%" | find "sound\SFX\music" >nul && set charNm=music&& set hf=&& EXIT /b
echo "%Op%" | find "monster_buff" >nul && set charNm=monster\buff&& EXIT /b
echo "%Op%" | find "monster_boss_buff" >nul && set charNm=monster\boss_buff&& EXIT /b
if %c:~,1% GTR 7 if %c:~,1% LEQ 9 goto MSWn
set c=Unknown
if %1==1001 ( set c=Captain America
 if "%2"=="a_" set s=Planetary Defender
 if "%2"=="a2" set s=Peacetime Warrior
 if "%2"=="a3" set s=Captain Hydra)
if %1==1002 ( set c=Iron Man
 if "%2"=="a_" set s=Peacetime Celebrity
 if "%2"=="s_" set s=Planetary Armor
 if "%2"=="a3" set s=Tesseract Armor)
if %1==1003 ( set c=Spider-Man
 if "%2"=="s_" set s=Arcade
 if "%2"=="a2" set s=Street Spider
 if "%2"=="a3" set s=Black and Gold Suit MCU NWH
 if "%2"=="a4" set s=Spirit of the Web
 if "%2"=="e_" set s=Arcade Spider-Man - Cosmic Ace Edition)
if %1==1004 ( set c=Hawkeye
 if "%2"=="a_" set s=MCU Avengers Endgame
 if "%2"=="a2" set s=Frozen Archer
 if "%2"=="a3" set s=Pirate Archer)
if %1==1005 ( set c=Black Widow
 if "%2"=="a_" set s=Planetary Spy
 if "%2"=="a2" set s=MCU Black Widow
 if "%2"=="a3" set s=Red Musketeer)
if %1==1006 ( set c=Hulk
 if "%2"=="c_" set s=MCU Thor Ragnarok
 if "%2"=="s_" set s=Planetary Destroyer
 if "%2"=="a_" set s=Joe Fixit
 if "%2"=="a2" set s=Seaside Lifeguard
 if "%2"=="a3" set s=Mech Hulk)
if %1==1007 ( set c=Thor
 if "%2"=="a_" set s=Frost Giant
 if "%2"=="s_" set s=Hel-Sworn Thor
 if "%2"=="a3" set s=Viking Captain
 if "%2"=="a4" set s=MCU Thor Love and Thunder)
if %1==1008 ( set c=Falcon
 if "%2"=="a_" set s=Dragon Rider
 if "%2"=="a2" set s=MCU Falcon and Winter Soldier
 if "%2"=="b_" set s=Aviary Armor)
if %1==1009 ( set c=Captain Marvel
 if "%2"=="s_" set s=Planetary Ace
 if "%2"=="a_" set s=Planetary Ace
 if "%2"=="a1" set s=Planetary Ace)
if %1==1010 ( set c=Winter Soldier
 if "%2"=="b_" set s=1872 Winter Soldier
 if "%2"=="a2" set s=MCU Falcon and Winter Soldier)
if %1==1011 ( set c=Ant-Man
 if "%2"=="a_" set s=Arcade Futurist
 if "%2"=="b_" set s=MCU Avengers Endgame)
if %1==1012 set c=Wasp
if %1==1013 ( set c=Quicksilver
 if "%2"=="a_" set s=Quick Skater
 if "%2"=="a2" set s=Free Runner)
if %1==1014 ( set c=Scarlet Witch
 if "%2"=="a_" set s=Romantic Magic
 if "%2"=="a1" set s=Romantic Magic
 if "%2"=="a2" set s=Chaos Style
 if "%2"=="a3" set s=MCU Wanda Vision
 if "%2"=="a4" set s=Mech Witch
 if "%2"=="b_" set s=House of M
 if "%2"=="a6" set s=Chaos Coven)
if %1==1015 ( set c=Vision
 if "%2"=="a_" set s=Romantic Vow
 if "%2"=="a2" set s=MCU Wanda Vision)
if %1==1016 ( set c=Black Panther
 if "%2"=="a2" set s=Savanna King
 if "%2"=="a_" set s=Planetary Warrior)
if %1==1017 ( set c=Black Knight
 if "%2"=="a_" set s=Gallant Knight)
if %1==1018 ( set c=Cloak and Dagger
 if "%2"=="a2" set s=Enchanted Union
 if "%2"=="a3" set s=Yin and Yang)
if %1==1019 set c=Corvus Glaive
if %1==1020 set c=Proxima Midnight
if %1==1021 set c=Ebony Maw
if %1==1022 ( set c=Cull Obsidian
 if "%2"=="b_" set s=MCU Avengers Infinity War)
if %1==1023 ( set c=Loki
 if "%2"=="a_" set s=Lady Loki
 if "%2"=="a3" set s=MCU TVA Suit)
if %1==1024 ( set c=Heimdall
 if "%2"=="a_" set s=Jotun Guardian)
if %1==1025 ( set c=Lady Sif
 if "%2"=="a_" set s=Goddess of Asgard
 if "%2"=="a1" set s=Goddess of Asgard
 if "%2"=="a2" set s=Eastern General)
if %1==1026 ( set c=Executioner
 if "%2"=="b_" set s=Samurai Executioner
 if "%2"=="c_" set s=MCU Thor Ragnarok)
if %1==1027 set c=Cyclops
if %1==1028 ( set c=Beast
 if "%2"=="a_" set s=Zen)
if %1==1029 ( set c=Iceman
 if "%2"=="a_" set s=Free Skater
 if "%2"=="a4" set s=Icebreaker)
if %1==1030 ( set c=Angel
 if "%2"=="a_" set s=Archangel
 if "%2"=="a2" set s=Fallen Angel
 if "%2"=="a3" set s=Masked Prince)
if %1==1031 ( set c=Storm
 if "%2"=="a_" set s=Queen of Wakanda
 if "%2"=="a2" set s=Savanna Queen
 if "%2"=="s_" set s=Lightning Style)
if %1==1032 ( set c=Emma Frost
 echo "%Fp%" | find /i "SFX\hero\1032a\" >nul && set s=Diamond Style
 if "%2"=="a_" set s=Diamond Style
 if "%2"=="a2" set s=Masked Queen)
if %1==1033 ( set c=Wolverine
 if "%2"=="a_" set s=1872 Wolverine
 if "%2"=="a2" set s=Phoenix Nirvana)
if %1==1034 ( set c=Magneto
 if "%2"=="a_" set s=Galactic Gravity)
if %1==1035 ( set c=Colossus
 if "%2"=="a_" set s=Undisputed Champion)
if %1==1036 ( set c=Deadpool
 if "%2"=="a_" set s=Pirate
 if "%2"=="a2" set s=Chefpool)
if %1==1037 ( set c=Pixie
 if "%2"=="c_" set s=Uncanny X-Men
 if "%2"=="a_" set s=Secret Garden
 if "%2"=="a2" set s=Steam Fairy)
if %1==1038 ( set c=Star-Lord
 if "%2"=="a1" set s=Space Armor
 if "%2"=="a2" set s=Arcade
 if "%2"=="a3" set s=Sun-Lord
 if "%2"=="b_" set s=Grounded
 if "%2"=="s_" set s=Street Rocker)
if %1==1039 set c=Gamora
if %1==1040 ( set c=Groot
 if "%2"=="a_" set s=Arcade
 if "%2"=="a2" set s=Dark Groot
 if "%2"=="a3" set s=Frost Pine
 if "%2"=="a4" set s=Flora Colossus)
if %1==1041 ( set c=Rocket Raccoon
 if "%2"=="b_" set s=MCU Avengers Endgame
 if "%2"=="s_" set s=Arcade
 if "%2"=="e_" set s=Arcade - Cosmic Ace Edition)
if %1==1042 ( set c=Ronan
 if "%2"=="a_" set s=Ultimate
 if "%2"=="a2" set s=Samurai Hammer
 if "%2"=="b_" set s=The Arbiter)
if %1==1043 ( set c=Yondu
 if "%2"=="a_" set s=Arcade)
if %1==1044 ( set c=Mantis
 if "%2"=="a_" set s=Dark Mantis
 if "%2"=="a2" set s=Eastern Emerald
 if "%2"=="a3" set s=Elf Priest
 if "%2"=="a4" set s=Sweet Summer Lemonade)
if %1==1045 ( set c=Mister Fantastic
 if "%2"=="a_" set s=Time-Lost)
if %1==1046 ( set c=Invisible Woman
 if "%2"=="a_" set s=Malice
 if "%2"=="a3" set s=Vanishing Style)
if %1==1047 ( set c=Human Torch
 if "%2"=="a_" set s=Arcade Human Torch)
if %1==1048 ( set c=The Thing
 if "%2"=="a_" set s=Pirate)
if %1==1049 set c=Black Bolt
if %1==1050 set c=Medusa
if %1==1051 set c=Crystal and Lockjaw
if %1==1052 ( set c=Daredevil
 if "%2"=="a2" set s=Steam Devil
 if "%2"=="a_" set s=Eastern Devil)
if %1==1053 ( set c=Iron Fist
 if "%2"=="a_" set s=Eastern Dragon
 if "%2"=="a2" set s=Fist of the Undead)
if %1==1054 ( set c=Thanos
 if "%2"=="a_" set s=Mech Thanos
 if "%2"=="s_" set s=Titan of Light)
if %1==1055 ( set c=Hela
 if "%2"=="a_" set s=Goddess of Justice
 if "%2"=="a2" set s=Thorn Queen
 if "%2"=="a3" set s=Phantom Queen
 if "%2"=="a4" set s=Eastern Goddess)
if %1==1056 ( set c=Doctor Strange
 if "%2"=="a_" set s=Infernal Sorcerer
 if "%2"=="a2" set s=Eastern Mystic
 if "%2"=="a3" set s=MCU Doctor Strange 2)
if %1==1057 set c=Phoenix
if %1==1058 ( set c=Sandman
 if "%2"=="a_" set s=Beach Bully)
if %1==1059 ( set c=Venom
 if "%2"=="s_" set s=VEN#m Suit
 if "%2"=="a2" set s=Street Tagger)
if %1==1060 ( set c=Polaris
 if "%2"=="a_" set s=Magnetic Style
 if "%2"=="a2" set s=Icy Aurora)
if %1==1061 ( set c=Gambit
 if "%2"=="a_" set s=Shi'Ar Uniform
 if "%2"=="a2" set s=White Devil
 if "%2"=="a3" set s=Eastern Ace)
if %1==1062 ( set c=War Machine
 if "%2"=="a_" set s=Unk
 if "%2"=="a2" set s=Warbringer)
REM if "%2"=="b_" set s=Unk
if %1==1063 ( set c=Ghost
 if "%2"=="a_" set s=Samurai)
if %1==1064 ( set c=Green Goblin
 if "%2"=="c_" set s=Stealth Suit)
if %1==1065 ( set c=Jubilee
 if "%2"=="a_" set s=Firework Style)
if %1==1066 ( set c=Shang-Chi
 if "%2"=="a2" set s=MCU SCatLotTR)
if %1==1067 ( set c=Blade
 if "%2"=="a_" set s=Lord of Night
 if "%2"=="a3" set s=Timeless Hunter)
if %1==1068 set c=Mystique
if %1==1069 ( set c=Ancient One
 if "%2"=="s_" set s=Eastern Chivalry)
if %1==1070 ( set c=Adam Warlock
 if "%2"=="a_" set s=Elf Sorcerer)
if %1==1071 ( set c=Mysterio
 if "%2"=="a_" set s=Fatal Magic
 if "%2"=="a2" set s=Snow Illusion)
if %1==1072 ( set c=Psylocke
 if "%2"=="a2" set s=Hellfire Gown
 if "%2"=="b_" set s=Psionic Knight)
if %1==1073 ( set c=Magik
 if "%2"=="a_" set s=Samurai)
if %1==1074 set c=Drax the Destroyer
if %1==1075 set c=Namor
if %1==1076 set c=Electra
if %1==1077 set c=Juggernaut
if %1==1078 set c=Rogue
if %1==1079 set c=Doctor Octopus
if %1==1080 set c=Mister Negative
if %1==1081 set c=Quake
if %1==1082 ( set c=Ghost Rider
 if "%2"=="b_" set s=Cosmic Rider)
if %1==1083 set c=Moon Knight
if %1==1084 ( set c=Squirrel Girl
 if "%2"=="a_" set s=Fluffy Summer)
if %1==1085 set c=Howard the Duck
if %1==1086 ( set c=Taskmaster
 if "%2"=="b_" set s=MCU Black Widow)
REM MCU and Tactical Suit both don't have a cape and it didn't seem to work in-game
if %1==1087 set c=Wave
if %1==1088 set c=Bishop
if %1==1089 ( set c=Moonstar
 if "%2"=="a_" set s=Elf Hunter
 if "%2"=="b_" set s=Crescent Knight)
if %1==1090 ( set c=Professor X
 if "%2"=="a_" set s=Spirit of Intellect)
if %1==1091 set c=Seleene
if %1==1092 set c=Ikaris
if %1==1093 set c=Sersi
if %1==1094 ( set c=Thena
 if "%2"=="c_" set s=MCU Eternals)
if %1==1095 set c=Sprite aka Shadowcat
if %1==1096 set c=Gilgamesh
if %1==1097 ( set c=Luna Snow
 if "%2"=="s_" set s=Space Diva)
if %1==1098 set c=War Tiger
if %1==1099 set c=Shuri
if %1==1100 set c=Black Cat
if %1==1101 set c=Dazzler
if %1==1102 set c=Red Skull
if %1==1103 set c=Punisher
if %1==1104 set c=Silver Sable
if %1==1105 set c=Doctor Doom
if %1==1106 set c=Wenwu
if %1==1107 set c=Talisman
if %1==1108 set c=Snowbird
if %1==1109 set c=Doctor Voodoo
if %1==1110 set c=Clea
if %1==1111 set c=Shiklah
if %1==1114 set c=Mighty Thor
if %1==1118 set c=America Chavez
REM Brilliant Collection (both):
if %1==1121 set c=Hulkbuster
if %1==1122 set c=Ghost-Spider
set charNm=%1_%c%
EXIT /b
REM Event skins:
REM Winter Celebration: Hawkeye 1004a2, Quicksilver 1013a, Groot 1040a3, Polaris 1060a2, Gambit 1061a2, Mysterio 1071a2? (Star Membership)
REM Peace Era: Captain America 1001a2, Iron Man 1002a
REM Space War: Iron Man 1002s, Black Widow 1005a (Star Membership), Hulk 1006s (Brilliant Collection), Captain Marvel 1009a, Black Panther 1016a, Star-Lord 1038a1 (? Battle Pass)
REM Arcade: Spider-Man 1003s, Star-Lord 1038a2, Groot 1040a, Rocket Raccoon 1041s (+1041e Cosmic Ace), Yondu 1043a, Ant-Man 1011_a, Human Torch 1047a (Battle Pace)
REM Brilliant Collection: Hulk 1006s, Thor 1007s, Hulkbuster, Ghost-Spider
REM Avengers Mech Strike: Hulk 1006a3, Scarlet Witch 1014a4, Thanos 1054a, Falcon 1008b (S8), Groot 1040a4, Venom 1059s (Legndary) mb Arcade?
REM Street Sports: Quicksilver 1013a2, Iceman 1029a, Spider-Man 1003a2, Venom, Star-Lord 1038s (Brilliant Collection)
REM Date Night: Scarlet Witch 1014a, Vision 1015a, Cloak and Dagger 1018a2
REM Nightmare Dimension: Angel 1030a2
REM High Fashion: Storm 1031s, Emma Frost 1032a, Jubilee 1065a, Invisible Woman 1046a3, Polaris 1060a? (Star Membership)
REM Gothic Masquerade: Emma Frost 1032a2, Hela 1055a3, Angel 1030a3
REM Pool Party: Hulk 1006a2 (Battle Pass), Star-Lord 1038a3, Mantis 1044a3, Sandman 1058a (Battle Pass), Squirrel Girl 1084a (Battle Pass)
REM Lunar New Year 2022: Mantis 1044a2, Daredevil 1052a, Iron Fist 1053a, Gambit 1061a3
REM Chinese New Year 2022: Doctor Strange 1056a2
REM Chinese New Year 2021: Ancient One 1069s
REM Opposite Realm: Hela 1055a, Doctor Strange 1056a, War Machine 1062a2, Captain America 1001a3, Thor 1007s
REM Cosmic Ace: Spider-Man 1003e
REM Hellfire Gala: Psylocke 1072a2
REM Hyperspace Era: Luna Snow 1097s
REM Battle Pass:
REM Steampunk Unknown: Pixie 1037a2 (Battle Pass), Daredevil 1052a2 (Battle Pass), Mister Fantastic 1045a (Star Membership)
REM Elf Unknown: Mantis 1044a3, Adam Warlock 1070a, Moonstar 1089a, (Hela 1055a2?)
REM Unknown: Falcon 1008a, Scarlet Witch 1014a2, Lady Sif 1025a, Magneto 1034a, Deadpool 1036a2, Mantis 1044a, Mysterio 1071a (Battle Pass)

REM Samurai Spirit: Executioner 1026b, Magik 1073a (Battle Pass), Ghost 1063a (Star Membership), Ronan 1042a2 (Battle Pass)
REM Eastern Legend: Pixie 1037a (Battle Pass), Beast 1028a (Battle Pass), Cloak and Dagger 1018a3 (Battle Pass), Hela 1055a4
REM The Lost Sea: Hawkeye 1004a3 (Battle Pass), Black Widow 1005a3 (Battle Pass), Thor 1007a3, Deadpool 1036a (Legendary), The Thing 1048a (Star Membership)
REM Secret Agent: Iceman 1029a4
REM Dark Vengeance: Spider-Man 1003a4, Professor X 1090a?
REM Tesseract Fusion: Iron Man 1002a3
REM 3099: Blade 1067a3
REM Limited: Scarlet Witch 1014a6, Lady Sif 1025a2
:MSWn
REM confirmed common: 8001-4, 8201-7+11-16 (18+19 found but unconfirmed)
set s=common
REM confirmed special: 8100-2, 8210
if %c:~1,1%==1 set s=special
if %1==8210 set s=special
if %1==8100 set s=%1_Surtur
if %1==8101 set s=%1_Leviathan
if %1==8102 set s=8100_Surtur
set charNm=monster\%s%
set s=
EXIT /b
:MSWm
set m=
if %1==174760 set m=G104_bgm_hulk_starwar_v1
if %1==139614 set m=marvel_victory
if %1==1578550 set m=marvel_battlebrawl1
if %1==1343592 set m=Black Widow_Gamehall Music
if %1==1836894 set m=marvel_battle_s1_base
if %1==1301782 set m=Black Widow_Login Music
if %1==1448698 set m=m1_login_music
if %1==212267 set m=G104_storm_dance_feature_music_WIP2
if %1==128744 set m=G104_Galactus_mode
if %1==504842 set m=ambient
if %1==1259352 set m=marvel_battlebrawl
if %1==253775 set m=G104_thor_mirrored_world_v1c
if %1==220457 set m=G104_TX_CG
if %1==1447817 set m=marvel_battle_s3_melody
if %1==154416 set m=marvel_mvp
if %1==250223 set m=G104_bgm_spiderman_game_v2
if %1==1611549 set m=rolechoice_normal
if %1==161258 set m=G104_iron_man_v3
if %1==2350558 set m=gamehall
if %1==1323375 set m=G104_Shang Chi_Lobby
if %1==104701 set m=Marvel Super War_Winter Season_Intro
if %1==238290 set m=G104_TQ_feature_music_02
if %1==1398885 set m=LunarNY Lobby Mastered
if %1==1646054 set m=marvel_battle_s2_base
if %1==1602938 set m=marvel_battle_s3_base
if %1==1562757 set m=LunarNY Login Mastered
if %1==138793 set m=marvel_defeat
if %1==245679 set m=G104_QYBS_chinese_feature_music
if %1==206012 set m=Cutscene_Pirate
if %1==191467 set m=G104_bgm_Ancient One_v2
if %1==752020 set m=marvel_surtur_music
if %1==30991 set m=transition-ui
if %1==1460339 set m=Marvel Super War_Winter Season_Loop
if %1==49631 set m=transition
if %1==1751599 set m=marvel_battle_s1_melody
if %1==1686385 set m=rolechoice_bp
if %1==1495671 set m=marvel_battle_s2_melody
if %1==1570990 set m=Marvel Eternals Login v1a_Mstr2
if %1==571302 set m=marvel_scoreboard
if %1==761464 set m=Girlgroup_interface_music_V4
if %1==1651444 set m=Marvel Eternals Lobby v1a_Mstr1
if %1==1684793 set m=G104_Thor_Lobby
if %1==1195647 set m=Cyperpunk_gamehall_music
if %1==1600710 set m=G104_Anniversary_interface_music
if %1==1701804 set m=LunaSnow_Interface_music_0111
if %1==308653 set m=venom_mech_feature_music
if %1==163116 set m=rocket_raccoon_anniversary_feature_music
if %1==332127 set m=Star_Lord_Anniversary_feature_music
if %1==383600 set m=LunaSnow_feature
REM Music below is either removed or not yet added (or possibly I didn't find them)
if %1==210564 set m=unknown_dubstep_feature_music_1
if %1==244204 set m=unknown_dubstep_feature_music_2
if %1==243352 set m=unknown_dubstep_feature_music_3
if %1==218012 set m=unknown_dubstep_feature_music_4
if %1==239721 set m=unknown_dubstep_feature_music_5
if %1==214145 set m=unknown_dubstep_feature_music_6
if %1==212411 set m=unknown_dubstep_feature_music_7
if %1==213493 set m=unknown_dubstep_feature_music_8
if %1==223343 set m=unknown_dubstep_feature_music_9
if %1==49497 set m=unknown_dubstep_stinger_1
if %1==46903 set m=unknown_dubstep_stinger_2
if %1==1503601 set m=LunaSnow_music_shorter (login)
REM G104_Shang Chi_Login does not seem to exist anymore.
if "%m%"=="" EXIT /b
move "%o%\%2.wem" "%o%\music\%m%.wem"
EXIT /b

:optionSwitch
if not defined %1t set %1t=1
set x=0
for %%c in (%*) do set /a x+=1
set /a %1t+=1
call set t=%%%1t%%
for /f "tokens=%t%" %%s in ("%*") do set %1=%%s
if %x%==%t% set %1t=1
EXIT /b

:switch
call echo "%%%1%%" | find "%~2" && set "%1=%~3" || set "%1=%~2"
EXIT /b

:checkExist extension
set "%1=%pathname%.%1"
:numberedBKP var
if %askbackup%==replace EXIT /b 0
call set "NB=%%%1%%"
if not exist "%NB%" EXIT /b 0
set /a n+=1
if exist "%NB%.%n%.bak" goto numberedBKP
if %askbackup%==true (
 choice /m "'%NB%' exists already. Do you want to make a backup"
 if ERRORLEVEL 2 EXIT /b
)
%2copy "%NB%" "%NB%.%n%.bak" %3
set n=0
EXIT /b 0

:addVar var string
call set "%1=%%%1%%%2" & EXIT /b
:replaceVar var org.string replace.string
call set "%1=%%%1:%~2=%~3%%" & EXIT /b

:askDel
if not %delIn%==ask EXIT /b
choice /m "Do you want to delete the %1 files"
if errorlevel 2 (set delIn=false) else set delIn=true
EXIT /b

:checkTools program
if exist "%~dp0%1.exe" set %1="%~dp0%1.exe"
if not defined %1 for /f "delims=" %%a in ('where %1 2^>nul') do set %1=%1
if defined %1 EXIT /b 0
echo %1.exe not found.
goto Errors

:Errors
pause
:End
pause
call :%operation%Post
:cleanup
del "%tem%" "%tem%.ps1"
EXIT