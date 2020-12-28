#!/bin/bash

stty intr ^]
cd `dirname $0`
timeout --foreground 600 qemu-system-x86_64 \
    -m 128M \
    -nographic \
    -kernel bzImage \
    -append 'console=ttyS0 loglevel=3 pti=off oops=panic panic=1 nokaslr' \
    -monitor /dev/null \
    -initrd rootfs.cpio \
    -smp 2,cores=2,threads=1 \
    -s \
    -cpu qemu64,smep 2>/dev/null

