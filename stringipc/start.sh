qemu-system-x86_64 \
-m 256M \
-kernel ./linux-4.4.184/arch/x86/boot/bzImage \
-initrd  ./built.cpio \
-append "console=ttyS0 root=/dev/ram rdinit=/sbin/init quiet" \
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
-cpu qemu64,+smep,+smap \
-s \
-nographic 

