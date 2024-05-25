# packer elf
packer elf

## Installation
### Install dependencies
- c++ compiler (g++)
- nasm
- libc libc.so.6
- zlib 1.3.1 libz.so (compress, decompress)

I tested on Arch Linux and Debian (sid).

### Install
1. download the latest [packer](https://github.com/shuichiro-endo/packer)
```
git clone https://github.com/shuichiro-endo/packer.git
```
2. build
```
cd packer/packer-elf
./compile.sh
```

## Usage
```
usage   : ./packer elf_file deflate_compression_level(1-9)
example : ./packer main 9
```

## Notes
### How to change libc.so filename in packer.cpp
1. check libc.so filename
```
> find /usr -name "libc.so.*"

/usr/lib/x86_64-linux-gnu/libc.so.6
```

2. modify packer.cpp
```
...

#define LIBC_SO "libc.so.6"

...
```

3. build
```
cd packer/packer-elf
./compile.sh
```

### How to change libz version in stub.asm
1. check libz.so version (e.g. 1.2.13)
```
> find /usr -name "libz.so.*"

/usr/lib/x86_64-linux-gnu/libz.so.1.2.13
/usr/lib/x86_64-linux-gnu/libz.so.1
```

2. get hex string
```
> echo -n "1.2.13" | rev | hexdump -C

00000000  33 31 2e 32 2e 31                                 |31.2.1|
00000006
```

3. modify stub.asm
```
...

decompress_image:
;    xor     rax, rax
;    mov     eax, 0xdeadbede
;    xor     eax, 0xdeadbeef
;    rol     rax, 32
;    xor     rbx, rbx
;    mov     ebx, 0xf09e90de
;    xor     ebx, 0xdeadbeef
;    add     rax, rbx
    mov     qword [r15 - 0x38], 0x33312e322e31 ; 0x33312e322e31 1.2.13 libz.so version

    mov     r14, rsp                ; save rsp
    and     rsp, -16                ; 16 bytes alignment

    call    inf

    mov     rsp, r14                ; load rsp

    ret

...
```
Note: You can encrypt it using xor as you like.

4. build
```
cd packer/packer-elf
./compile.sh
```

## License
This project is licensed under the MIT License.

See the [LICENSE](https://github.com/shuichiro-endo/packer/blob/main/LICENSE) file for details.
