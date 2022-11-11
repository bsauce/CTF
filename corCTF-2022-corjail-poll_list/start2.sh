qemu-system-x86_64  \
-m 1G  \
-smp 4,cores=4,threads=4 \
-kernel ./bzImage    \
-append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0 nokaslr no_hash_pointers"     \
-drive file=./stretch.img,format=raw \
-net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
-net nic,model=e1000 \
-nographic  \
-pidfile vm.pid \
-s \
2>&1 | tee vm.log

