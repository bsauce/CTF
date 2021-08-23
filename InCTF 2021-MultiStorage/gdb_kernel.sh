gdb \
    -ex "add-auto-load-safe-path $(pwd)" \
    -ex "file vmlinux" \
    -ex "target remote localhost:1234" \
    -ex "b *0xffffffffc0000000+0x218" \
    -ex "continue"


