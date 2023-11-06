#include <stdio.h>

int main(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    char str[100];
    printf("%p", str);
    gets(str);
    return 0;
}