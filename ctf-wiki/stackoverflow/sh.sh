# gcc -m32 -g -c elfDemo.c -o elfDemo.o
# gcc -m32 -g elfDemo.c -o elfDemo.out
# gcc -m32 -g -static elfDemo.c -o elfDemo_static.out

gcc -m32 -fno-stack-protector  -no-pie stack_example.c -o stack_example
gcc -m32 -fno-stack-protector -z execstack -no-pie ret2shellcode.c -o ret2shellcode
gcc -fno-stack-protector -z execstack -no-pie ret2stackshell.c -g -o ret2stackshell