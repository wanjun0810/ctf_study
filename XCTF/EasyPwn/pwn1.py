from pwn import *

sh = process("./pwn1")
# https://blog.csdn.net/seaaseesa/article/details/103089382

# char s[1024]; 
# read(0, s, 0x438uLL);  0x438 = 1080-1024 = 56

# snprintf(v2, 0x7D0uLL, v3, s);  0x7d0 = 2000
#  int snprintf(char *str, size_t size, const char *format, ...) 设将可变参数(...)按照 format 格式化成字符串，并将字符串复制到 str 中，size 为要写入的字符的最大数目