from argparse import ArgumentParser
from glob import glob
from pathlib import Path
from subprocess import run

def get_path_end_offset(data: bytes) -> tuple[bytes, int]:
    # The Lua 5.1 header is exactly 12 bytes long.
    if len(data) < 12: return 0 # WIP: throw exception?

    size_t = data[8] # 4 or 8 (uint32 or uint64)
    return 12 + size_t + int.from_bytes(data[12:12 + size_t],
        byteorder=('little' if data[6] else 'big')) # 0 = big, 1 = little

def unpack(file_path: Path):
    out_dir = file_path.with_suffix('')
    data = file_path.read_bytes()
    if data[:4] != b'\x1bLua':
        print(f'[-] Skipping {file_path}: No Lua signature found.')
        return
    out_dir.mkdir(parents=True, exist_ok=True)

    base_name = file_path.name

    # Extract exact source path block (size integer + string bytes)
    # Save this exact binary block so we can inject it later
    #WIP: This is a path that would be useful to use later on (instead of a flle)
    (out_dir / (base_name + '.pathblock')).write_bytes(data[12:get_path_end_offset(data)])

    print(f'[+] Decompiling {base_name}...')
    with (out_dir / base_name).open('w') as f:
        run(['java', '-jar', 'unluac.jar', file_path], stdout=f)

def repack(edited_file: Path):
    base_name = edited_file.name
    path_file = edited_file.with_name(base_name + '.pathblock')
    file_path = edited_file.with_stem(edited_file.stem + '.luac')

    print(f'[+] Compiling {base_name}...')
    run(['luac5.1.exe', '-o', file_path, edited_file])

    # Binary Splice: Inject the original size integer and string back into the bytecode
    #WIP: alternatively, the user should make sure he's using the same file name
    if path_file.exists():
        new_bytecode = file_path.read_bytes()
        # 12-byte header + Original Size & String + Rest of the compiled bytecode
        new_bytecode = new_bytecode[:12] + path_file.read_bytes() + new_bytecode[get_path_end_offset(new_bytecode):]
        file_path.write_bytes(new_bytecode)
    #print(f"[+] Successfully repacked {base_name} with 1:1 original hex structure!")

def main():
    parser = ArgumentParser()
    parser.add_argument('input', help='input file (supports glob)')
    parser.add_argument('-r', '--repack', action='store_true', help='repack the input file to compiled .lua (luac)')
    args = parser.parse_args()
    input_files = glob(args.input.replace('[', '[[]'), recursive=True)

    if not input_files:
        raise ValueError('No files found')

    if args.repack:
        for input_file in input_files:
            repack(Path(input_file))
    else:
        for input_file in input_files:
            unpack(Path(input_file))

if __name__ == '__main__':
    main()
