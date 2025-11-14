# WAV channel extractor
# by ak2yny


import glob
import wave
from argparse import ArgumentParser
from numpy import frombuffer, uint8, uint16, uint32
from pathlib import Path


SUPPORTED_DEPTHS = { 1: uint8, 2: uint16, 4: uint32 }

def extract_channels(input_file: Path, channels: tuple = None):
    with wave.open(str(input_file)) as wav:
        # Read data
        nch   = wav.getnchannels()
        depth = wav.getsampwidth()
        wav.setpos(0)
        data = wav.readframes(wav.getnframes())

    # (24-bit data not supported)
    typ = SUPPORTED_DEPTHS.get(depth)
    if not typ:
        raise ValueError(f'sample width {depth} not supported')
    if channels and (max(channels) > nch or min(channels) < 1):
        raise ValueError(f'Not all channels {channels} are in range 1 to {nch}'.)

    # Extract channel data
    data = frombuffer(data, dtype=typ)
    channels = (int(c) - 1 for c in channels) if channels else range(nch)
    for c in channels:
        # Save channel to a separate file
        print(f'Extracting channel {c+1} of {nch}, {depth*8}-bit depth')
        with wave.open(str(input_file.with_stem(f'{input_file.stem}_{c}')), 'wb') as outwav:
            outwav.setparams(wav.getparams())
            outwav.setnchannels(1)
            outwav.writeframes(data[c::nch].tobytes())

def main():
    parser = ArgumentParser()
    parser.add_argument('input', help='input file (supports glob)')
    parser.add_argument('channels', nargs='*', help='define which channel(s) to extract')
    args = parser.parse_args()
    input_files = glob.glob(args.input.replace('[', '[[]'), recursive=True)

    if not input_files:
        raise ValueError('No files found')

    found_any = False
    for input_file in input_files:
        input_file = Path(input_file)

        if input_file.suffix.casefold() == '.wav':
            extract_channels(input_file, args.channels)
            found_any = True

    if not found_any:
        raise ValueError('No files found')

if __name__ == '__main__':
    main()