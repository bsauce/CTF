#! /bin/sh
qemu-system-x86_64 \
    -m 256M \
    -nographic -net user -net nic \
    -kernel bzImage \
    -append 'console=ttyS0 loglevel=3 oops=panic panic=1 kaslr' \
    -monitor /dev/null 2>/dev/null \
    -initrd initramfs.cpio \
    -smp cores=2,threads=2 \
    -cpu qemu64,smep,smap  \
    -s
