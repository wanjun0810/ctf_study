from pwn import *
from LibcSearcher import *

sh = process('./pwn3')
elf = ELF('./pwn3')
libc = ELF('./libc.so.6')