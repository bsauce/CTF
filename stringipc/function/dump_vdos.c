// 获取gettimeofday 字符串的偏移，便于爆破；dump vdso还是需要在程序中爆破VDSO地址，然后gdb中断下，$dump memory即可（VDSO地址是从ffffffff开头的）。
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/auxv.h> 

 #include <sys/mman.h>
int main(){
    int test;
    size_t result=0;
    unsigned long sysinfo_ehdr = getauxval(AT_SYSINFO_EHDR);
    result=memmem(sysinfo_ehdr,0x1000,"gettimeofday",12);
    printf("[+]VDSO : %p\n",sysinfo_ehdr);
    printf("[+]The offset of gettimeofday is : %x\n",result-sysinfo_ehdr);
    scanf("Wait! %d", test);  
    /* 
    gdb break point at 0x400A36
    and then dump memory
    why only dump 0x1000 ???
    */
    if (sysinfo_ehdr!=0){
        for (int i=0;i<0x2000;i+=1){
            printf("%02x ",*(unsigned char *)(sysinfo_ehdr+i));
        }
    }

}