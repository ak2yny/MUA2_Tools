for %%s in (MUA2_PAK) do ((
    echo from CLI.%%s import main
    echo if __name__ == '__main__':
    echo     main^(^)
  ) > cli.py
  pyinstaller --specpath dist --onefile --version-file=..\CLI\%%s.txt --icon=..\MUA2.ico cli.py --name %%s
)