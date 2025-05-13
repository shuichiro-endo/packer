# packer elf
packer elf

## Installation
### Install dependencies
- x86_64 architecture, 64bit, little endian
- c++ compiler (g++)
- nasm
- libc libc.so.6
- zlib 1.3.1 libz.so (compress, decompress)
  
  e.g. debian: zlib1g, zlib1g-dev

  Note: If the version is different, you need to change it in stub.asm. (See [How to change libz.so version in stub.asm](https://github.com/shuichiro-endo/packer/tree/main/packer-elf#how-to-change-libzso-version-in-stubasm).)

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

## Example
```
> cd packer/packer-elf

> cp /usr/bin/ls ls

> file ls
ls: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d1f6561268de19201ceee260d3a4f6662e1e70dd, for GNU/Linux 4.4.0, stripped

> ./packer ls 9
[I] deflate_compression_level: 9
[I] output_elf_file_name: ls_packed
[I] read ls file
[I] ls file size: 142016 bytes
[I] check ls file
[I] dump mapped image
[I] compress image data
[I] read stub.bin file
[I] link data
[I] write ls_packed file
[I] ls_packed file size: 74000 bytes

> chmod 755 ls_packed

> file ls_packed
ls_packed: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, no section header

> readelf -a ls_packed
ELF Header:
Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
Class:                             ELF64
Data:                              2's complement, little endian
Version:                           1 (current)
OS/ABI:                            UNIX - System V
ABI Version:                       0
Type:                              DYN (Position-Independent Executable file)
Machine:                           Advanced Micro Devices X86-64
Version:                           0x1
Entry point address:               0x35000
Start of program headers:          64 (bytes into file)
Start of section headers:          0 (bytes into file)
Flags:                             0x0
Size of this header:               64 (bytes)
Size of program headers:           56 (bytes)
Number of program headers:         7
Size of section headers:           0 (bytes)
Number of section headers:         0
Section header string table index: 0

There are no sections in this file.

There are no section groups in this file.

Program Headers:
Type           Offset             VirtAddr           PhysAddr
FileSiz            MemSiz              Flags  Align
PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040
0x0000000000000188 0x0000000000000188  R      0x8
INTERP         0x00000000000001c8 0x00000000000001c8 0x00000000000001c8
0x000000000000001c 0x000000000000001c  R      0x1
[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
0x000000000000020b 0x0000000000025000  RW     0x1000
LOAD           0x0000000000001000 0x0000000000035000 0x0000000000035000
0x0000000000000b45 0x0000000000000b45  R E    0x1000
LOAD           0x0000000000002000 0x0000000000036000 0x0000000000036000
0x000000000000f01a 0x000000000000f01a  R      0x1000
LOAD           0x0000000000012000 0x0000000000046000 0x0000000000046000
0x0000000000000110 0x0000000000000110  RW     0x1000
DYNAMIC        0x0000000000012000 0x0000000000046000 0x0000000000046000
0x0000000000000110 0x0000000000000110  RW     0x8

Dynamic section at offset 0x12000 contains 17 entries:
Tag        Type                         Name/Value
0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
0x000000000000000c (INIT)               0x0
0x000000000000000d (FINI)               0x0
0x0000000000000019 (INIT_ARRAY)         0x0
0x000000000000001b (INIT_ARRAYSZ)       0 (bytes)
0x000000000000001a (FINI_ARRAY)         0x0
0x000000000000001c (FINI_ARRAYSZ)       0 (bytes)
0x0000000000000005 (STRTAB)             0x200
0x0000000000000006 (SYMTAB)             0x1e8
0x000000000000000a (STRSZ)              11 (bytes)
0x000000000000000b (SYMENT)             24 (bytes)
0x0000000000000007 (RELA)               0x0
0x0000000000000008 (RELASZ)             0 (bytes)
0x0000000000000009 (RELAENT)            24 (bytes)
0x000000000000001e (FLAGS)              BIND_NOW
0x000000006ffffffb (FLAGS_1)            Flags: NOW PIE
0x0000000000000000 (NULL)               0x0

There are no relocations in this file.
No processor specific unwind information to decode

Dynamic symbol information is not available for displaying symbols.

No version information found in this file.

> ./ls_packed
README.md  compile.sh  ls  ls_packed  packer  packer.cpp  stub.asm  stub.bin  stub.inc
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

### How to change libz.so version in stub.asm
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
;    mov     qword [r15 - 0x38], rax ; 0x31 2e332e31 1.3.1 libz.so version
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
