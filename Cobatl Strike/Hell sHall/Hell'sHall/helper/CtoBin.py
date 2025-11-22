#!/usr/bin/env python3
import re
import argparse

def carray_to_bin(infile, outfile):
    with open(infile, "r") as f:
        text = f.read()

    # find all \x?? tokens
    bytes_list = re.findall(r"\\x([0-9a-fA-F]{2})", text)

    if not bytes_list:
        print(f"[!] No hex bytes found in {infile}")
        return

    with open(outfile, "wb") as out:
        out.write(bytes(int(x, 16) for x in bytes_list))

    print(f"[+] Extracted {len(bytes_list)} bytes from {infile} -> {outfile}")

def main():
    parser = argparse.ArgumentParser(
        description="Convert a C array file with hex values into a raw .bin payload"
    )
    parser.add_argument("input", help="Input .c/.h file containing unsigned char array")
    parser.add_argument("output", help="Output .bin file")

    args = parser.parse_args()
    carray_to_bin(args.input, args.output)

if __name__ == "__main__":
    main()
