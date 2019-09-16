#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

int do_something(char *buf){
    int ret=0;
    switch(*(int *)buf){
        case 1:
            printf("case 1n");
            break;
        case 2:
            printf("case 2n");
            break;
        case 3:
            printf("case 3n");
            break;
        case 4:
            printf("case 4n");
            break;
        /*case 5:*/
            /*printf("case 5n");*/
            /*break;*/
    }
    return ret;
}
int main(int argc,char **argv){
    char *buf=malloc(0x100);
    *(int *)buf = 0x1;
    do_something(buf);


    return 0;
}