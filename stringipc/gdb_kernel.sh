gdb \
    -ex "add-auto-load-safe-path $(pwd)" \
    -ex "file ./linux-4.4.184/vmlinux" \
    -ex 'target remote localhost:1234' \
    -ex 'continue' \

