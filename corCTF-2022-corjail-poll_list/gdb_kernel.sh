gdb \
    -ex "add-auto-load-safe-path $(pwd)" \
    -ex "file ./linux-5.10.127/vmlinux" \
    -ex "target remote localhost:1234" \
    -ex "b *0xffffffff814cc72e" \
    -ex "c"
