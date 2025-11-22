import sys

def RSHasher(api_name: str) -> int:
    a = 87621
    b = 316469
    h = 0
    for c in api_name.encode("utf-8"):
        h = h * a + c
        a = a * b
    return h & 0xFFFFFFFF  # keep it 32-bit

def main():
    if len(sys.argv) < 2:
        print("Usage: python hasher.py <API_NAME1> <API_NAME2> ...")
        sys.exit(1)

    for api_name in sys.argv[1:]:
        hash_val = RSHasher(api_name)
        print(f"{api_name:<20} -> 0x{hash_val:08X}\n----------------------------------")

if __name__ == "__main__":
    main()
