
set arguments=--specpath dist --onefile --version-file=..\script.txt --icon=..\MUA2.ico script.pyw  --add-data "..\MUA2.ico;."
REM --additional-hooks-dir=.

REM ----------------- CustomTkInter GUI --------------------

for /f "tokens=1* delims=: " %%k in ('pip show customtkinter ^| findstr /bl "Location"') do set l=%%l
if not errorlevel 0 exit

pip install -r requirements.txt
if not errorlevel 0 exit

pyinstaller %arguments:script=GUI\MUA2_PAK_Editor% --noconfirm --windowed --add-data "%l:\=/%/customtkinter;customtkinter/"


REM ----------------- CLI Tools --------------------

pip install pyinstaller
if not errorlevel 0 exit

for %%s in (MUA2_PAK) do ((
    echo from CLI.%%s import main
    echo if __name__ == '__main__':
    echo     main^(^)
  ) > cli.py
  pyinstaller --specpath dist --onefile --version-file=..\CLI\%%s.txt --icon=..\MUA2.ico cli.py --name %%s
)