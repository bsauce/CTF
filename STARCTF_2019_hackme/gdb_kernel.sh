gdb \
    -ex "add-auto-load-safe-path $(pwd)" \
    -ex "file vmlinux" \
    -ex 'target remote localhost:1234' \
    -ex 'b *0x0xffffffffc01d3000+0x13A'  \
    -ex 'b *0x0xffffffffc01d3000+0xD1'  \
    -ex 'b *0x0xffffffffc01d3000+0x8D' \
    -ex 'b *0x0xffffffffc01d3000+0x16E' \
    -ex 'continue' 


