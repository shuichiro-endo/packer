; Title:  stub.asm
; Author: Shuichiro Endo

; nasm -f bin stub.asm -o stub.bin

bits 64

%include "stub.inc"

global _main

section .text

_main:
    pushaq                                          ; push registers macro

    ; [ r15 + 0x50 ] save auxiliary vector base address
    ; [ r15 + 0x48 ] save elf image base address
    ; [ r15 + 0x40 ] save decompress data segment address
    ; [ r15 + 0x38 ] save decompress data segment size
    ; [ r15 + 0x30 ] save compressed data segment address
    ; [ r15 + 0x28 ] save compressed data segment size
    ; [ r15 + 0x20 ]
    ; [ r15 + 0x18 ]
    ; [ r15 + 0x10 ] save libc.so base address
    ; [ r15 + 0x8  ] save ld.so base address
    sub     rsp, 0x50
    mov     r15, rsp
    sub     r15, 0x8

    ; [ r15        ] save dlopen function address (libc.so)
    ; [ r15 - 0x8  ] save dlsym function address (libc.so)
    ; [ r15 - 0x10 ] save dlclose function address (libc.so)
    ; [ r15 - 0x18 ] save inflateInit_ function address (libz.so)
    ; [ r15 - 0x20 ] save inflate function address (libz.so)
    ; [ r15 - 0x28 ] save inflateEnd function address (libz.so)
    sub     rsp, 0x30

    ; [ r15 - 0x30 ] save libz.so handle address
    sub     rsp, 0x8

    ; [ r15 - 0x38 ] save libz.so version
    sub     rsp, 0x8
    
    ; [ r15 - 0x138] save ld.so filepath
    sub     rsp, 0x100

    mov     rdi, r15
    add     rdi, 0xd0                               ; argc
    call    get_auxiliary_vector_base_address
    mov     qword [r15 + 0x50], rax

    mov     rdi, qword [r15 + 0x50]                 ; auxiliary vector base address
    mov     rsi, AT_PHDR
    call    get_auxiliary_vector_value
    sub     rax, _Elf64_Ehdr_size
    mov     qword [r15 + 0x48], rax                 ; elf image base address

    mov     rdi, qword [r15 + 0x50]                 ; auxiliary vector base address
    mov     rsi, AT_BASE
    call    get_auxiliary_vector_value
    mov     qword [r15 + 0x8], rax                  ; ld.so base address

    mov     rdi, qword [r15 + 0x48]                 ; elf image base address
    mov     rsi, 0x2                                ; program header[2]: load (decompress data)
    call    get_segment_address_size
    mov     qword [r15 + 0x40], rax                 ; decompress data segment address
    mov     qword [r15 + 0x38], rdx                 ; decompress data segment size

    mov     rdi, qword [r15 + 0x48]                 ; elf image base address
    mov     rsi, 0x4                                ; program header[4]: load (compressed data)
    call    get_segment_address_size
    mov     qword [r15 + 0x30], rax                 ; compressed data segment address
    mov     qword [r15 + 0x28], rdx                 ; compressed data segment size

    mov     rdi, qword [r15 + 0x40]                 ; decompress data segment address
    mov     rsi, qword [r15 + 0x38]                 ; decompress data segment size
    call    get_libc_base_address
    mov     qword [r15 + 0x10], rax                 ; libc.so base address

    mov     rdi, qword [r15 + 0x10]                 ; libc.so base address
    call    get_libc_function_address
    mov     qword [r15], rax                        ; dlopen function address (libc.so)
    mov     qword [r15 - 0x8], rdx                  ; dlsym function address (libc.so)
    mov     qword [r15 - 0x10], rcx                 ; dlclose function address (libc.so)

    mov     rdi, qword [r15]                        ; dlopen function address (libc.so)
    call    dlopen_libz
    mov     qword [r15 - 0x30], rax                 ; libz.so handle address

    mov     rdi, qword [r15 - 0x8]                  ; dlsym function address (libc.so)
    mov     rsi, rax                                ; libz.so handle address
    call    get_libz_function_address
    mov     qword [r15 - 0x18], rax                 ; inflateInit_ function address (libz.so)
    mov     qword [r15 - 0x20], rdx                 ; inflate function address (libz.so)
    mov     qword [r15 - 0x28], rcx                 ; inflateEnd function address (libz.so)

    mov     rdi, qword [r15 + 0x30]                 ; compressed data segment address
    mov     rsi, qword [r15 + 0x28]                 ; compressed data segment size
    mov     rdx, qword [r15 + 0x40]                 ; decompress data segment address
    call    decompress_image

    mov     rdi, qword [r15 + 0x40]                 ; decompress data segment address
    call    fix_memory_protect

    mov     rdi, qword [r15 - 0x10]                 ; dlclose function address (libc.so)
    mov     rsi, qword [r15 - 0x30]                 ; libz.so handle address
    call    dlclose_libz

    mov     rdi, qword [r15 + 0x50]                 ; auxiliary vector base address
    mov     rsi, qword [r15 + 0x48]                 ; elf image base address
    call    fix_auxiliary_vector

    mov     rdi, qword [r15 + 0x48]                 ; elf image base address
    lea     rsi, qword [r15 - 0x138]                ; ld.so filepath
    call    get_ld_filepath

    mov     rdi, qword [r15 + 0x8]                  ; ld.so base address
    lea     rsi, qword [r15 - 0x138]                ; ld.so filepath
    call    fix_ld

    mov     rdi, qword [r15 + 0x10]                 ; libc.so base address
    call    unmap_libc

    mov     rdi, qword [r15 + 0x8]                  ; ld.so base address
    call    lookup_oep

    push    rax                                     ; push oep
    lea     rsp, [rsp + 0x8]

    ; remove saved address
    ; 10 base address
    ; 6 function address
    ; 2 libz.so data
    ; 1 ld.so filepath
    add     rsp, 0x190

    popaq                                           ; pop registers macro

    ; clear registers
    xor     rax, rax
    xor     rbx, rbx
    xor     rcx, rcx
    xor     rdx, rdx
    xor     rsi, rsi
    xor     rdi, rdi
    xor     rbp, rbp
    xor     r8, r8
    xor     r9, r9
    xor     r10, r10
    xor     r11, r11
    xor     r12, r12
    xor     r13, r13
    xor     r14, r14
    xor     r15, r15

    jmp     qword [rsp - 0x210]                     ; jump oep


get_auxiliary_vector_base_address:
    xor     rcx, rcx
    xor     rdx, rdx

search_stack:
    mov     rax, qword [rdi + 0x8 * rdx]
    inc     rdx
    cmp     rax, 0x0
    jnz     search_stack
    inc     rcx
    cmp     rcx, 0x2
    jne     search_stack

get_auxiliary_vector_base_address_done:
    lea     rax, qword [rdi + 0x8 * rdx]
    ret


get_auxiliary_vector_value:
    xor     rcx, rcx

search_auxiliary_vector:
    mov     rax, _Elf64_auxv_t_size
    mul     rcx
    mov     rbx, qword [rdi + rax]
    mov     rdx, qword [rdi + rax + _Elf64_auxv_t.a_val]
    inc     rcx
    cmp     rbx, AT_NULL                        ; end
    je      get_auxiliary_vector_value_done
    cmp     rbx, rsi
    jne     search_auxiliary_vector

get_auxiliary_vector_value_done:
    mov     rax, rdx
    ret


get_segment_address_size:
    mov     rbx, qword [rdi + _Elf64_Ehdr.e_phoff]
    add     rbx, rdi                                    ; program header

    xor     rax, rax
    mov     ax, word [rdi + _Elf64_Ehdr.e_phentsize]
    mov     rcx, rsi
    mul     rcx
    add     rbx, rax

    mov     rax, qword [rbx + _Elf64_Phdr.p_vaddr]
    add     rax, rdi                                    ; segment address
    mov     rdx, qword [rbx + _Elf64_Phdr.p_memsz]      ; segment memory size
    mov     rcx, qword [rbx + _Elf64_Phdr.p_filesz]     ; segment file size
    ret


get_libc_base_address:
    xor     rax, rax
    mov     eax, 0xdedece8e
    xor     eax, 0xdeadbeef
    rol     rax, 32
    xor     rbx, rbx
    mov     ebx, 0xb382d883
    xor     ebx, 0xdeadbeef
    add     rax, rbx
    push    rax                         ; 0x007370616d2f666c    lf/maps

    xor     rax, rax
    mov     eax, 0xbbde918c
    xor     eax, 0xdeadbeef
    rol     rax, 32
    xor     rbx, rbx
    mov     ebx, 0xb1dfcec0
    xor     ebx, 0xdeadbeef
    add     rax, rbx
    push    rax                         ; 0x65732f636f72702f    /proc/se
    mov     rax, rsp

    push    rdi
    push    rsi
    mov     rdi, rax                    ; 1st argument: const char *filename
    mov     rsi, O_RDONLY               ; 2nd argument: int flags
    mov     rdx, 0x0                    ; 3rd argument: int mode
    mov     rax, 0x2                    ; sys_open
    syscall
    pop     rsi
    pop     rdi
    add     rsp, 0x10
    
    mov     rdx, rsi                    ; 3rd argument: size_t count
    mov     rsi, rdi                    ; 2nd argument: char *buf
    mov     rdi, rax                    ; 1st argument: unsigned int fd
    mov     rax, 0x0                    ; sys_read
    syscall
    mov     rcx, rax

    mov     rdi, rdi                    ; 1st argument: unsigned int fd
    mov     rax, 0x3                    ; sys_close
    syscall

    xor     rax, rax
    mov     eax, 0xdec2cdc1
    xor     eax, 0xdeadbeef
    rol     rax, 32
    xor     rbx, rbx
    mov     ebx, 0xbdcfd783
    xor     ebx, 0xdeadbeef
    add     rax, rbx
    push    rax
    mov     r14, rsp                    ; 0x6f732e6362696c libc.so
    mov     rdi, rsi
    xor     rax, rax
    xor     rbx, rbx
    xor     rdx, rdx
    
search_libc_from_maps:
    mov     al, byte [rdi]
    inc     rdi
    dec     rcx
    cmp     rcx, 0x0
    je      search_libc_from_maps_error
    cmp     al, 0xa
    je      return_char
    mov     bl, byte [r14 + rdx]
    cmp     al, bl
    jne     reset_pos
    cmp     rdx, 0x6                    ; 0-6 strlen("libc.so")
    je      search_libc_from_maps_done
    inc     rdx
    jmp     search_libc_from_maps

return_char:
    mov     rsi, rdi
    xor     rdx, rdx
    jmp     search_libc_from_maps

reset_pos:
    xor     rdx, rdx
    jmp     search_libc_from_maps

search_libc_from_maps_error:
    add     rsp, 0x8
    xor     rax, rax
    ret

search_libc_from_maps_done:
    add     rsp, 0x8
    mov     rdi, rsi
    call    convert_char_to_long

get_libc_base_address_done:
    ret


convert_char_to_long:
    xor     rax, rax
    xor     rcx, rcx
    xor     rdx, rdx

get_charactor:
    mov     al, byte [rdi + rcx]
    inc     rcx
    cmp     al, 0x2d
    je      convert_char_to_long_done
    cmp     al, 0x39
    jle     number
    sub     al, 0x57
    rol     rdx, 4
    add     dl, al
    jmp     get_charactor

number:
    sub     al, 0x30
    rol     rdx, 4
    add     dl, al
    jmp     get_charactor

convert_char_to_long_done:
    mov     rax, rdx
    ret


get_libc_function_address:
    ; dlopen
    mov     esi, 0xfb512a1b         ; dlopen crc32 hash
    call    get_function_address
    push    rax

    ; dlsym
    mov     esi, 0x40296778         ; dlsym crc32 hash
    call    get_function_address
    push    rax

    ; dlclose
    mov     esi, 0x48800e70         ; dlclose crc32 hash
    call    get_function_address
    mov     rcx, rax
    pop     rdx
    pop     rax

    ret


get_function_address:
    mov     rbx, qword [rdi + _Elf64_Ehdr.e_phoff]
    add     rbx, rdi                                    ; program header

    xor     rax, rax
    mov     ax, word [rdi + _Elf64_Ehdr.e_phentsize]
    xor     rcx, rcx
    mov     cx, word [rdi + _Elf64_Ehdr.e_phnum]

search_pt_dynamic:
    mov     edx, dword [rbx]                            ; p_type
    cmp     edx, PT_DYNAMIC
    je      search_pt_dynamic_done
    add     rbx, rax
    dec     rcx
    cmp     rcx, 0x0
    jne     search_pt_dynamic

get_function_address_error:
    xor     rax, rax
    ret

search_pt_dynamic_done:
    mov     rax, qword [rbx + _Elf64_Phdr.p_vaddr]
    add     rax, rdi                                    ; dynamic segment address

    push    rdi
    push    rsi
    push    rax

    mov     rdi, rax
    mov     rsi, DT_STRTAB
    call    search_dynamic
    mov     r12, rax                                    ; string table address
    
    pop     rax
    push    rax

    mov     rdi, rax
    mov     rsi, DT_SYMTAB
    call    search_dynamic
    mov     r13, rax                                    ; symbol table address

    pop     rax
    push    rax

    mov     rdi, rax
    mov     rsi, DT_VERSYM
    call    search_dynamic
    mov     r14, rax                                    ; versym table address

    pop     rax
    pop     rsi
    pop     rdi
    
    add     r13, _Elf64_Sym_size
    add     r14, 0x2                                    ; unsigned short pointer
    xor     rax, rax
    xor     r11, r11                                    ; function address

search_function_address:
    mov     al, byte [r13 + _Elf64_Sym.st_info]
    cmp     al, 0x0
    je      search_function_address_done
    
    mov     eax, dword [r13 + _Elf64_Sym.st_name]
    add     rax, r12
    
    push    rdi
    mov     rdi, rax
    call    generate_crc32_hash
    pop     rdi

    cmp     rax, rsi
    je      check_stb_weak_global

search_function_address_next:
    add     r13, _Elf64_Sym_size
    add     r14, 0x2                                    ; unsigned short pointer
    jmp     search_function_address

check_stb_weak_global:
    xor     rax, rax
    mov     al, byte [r13 + _Elf64_Sym.st_info]
    shr     al, 4
    cmp     al, STB_GLOBAL
    je      check_stt_func

    cmp     al, STB_WEAK
    jne     search_function_address_next

check_function_address_null:
    cmp     r11, 0x0
    jne     search_function_address_next

check_stt_func:
    xor     rax, rax
    mov     al, byte [r13 + _Elf64_Sym.st_info]
    and     al, 0xf
    cmp     al, STT_FUNC
    jne     search_function_address_next

check_non_hidden_version:
    xor     rax, rax
    mov     ax, word [r14]
    and     ax, 0x8000
    jnz     search_function_address_next

    mov     r11, qword [r13 + _Elf64_Sym.st_value]
    add     r11, rdi                                    ; function address

search_function_address_done:
    mov     rax, r11
    ret


search_dynamic:
    mov     rbx, qword [rdi]                            ; d_tag
    cmp     rbx, rsi
    je      search_dynamic_done
    cmp     rbx, DT_NULL
    je      search_dynamic_done
    add     rdi, _Elf64_Dyn_size
    jmp     search_dynamic

search_dynamic_done:
    mov     rax, qword [rdi + _Elf64_Dyn.d_val]
    ret


dlopen_libz:
    xor     rax, rax
    mov     eax, 0xdec2cdc1
    xor     eax, 0xdeadbeef
    rol     rax, 32
    xor     rbx, rbx
    mov     ebx, 0xa4cfd783
    xor     ebx, 0xdeadbeef
    add     rax, rbx
    push    rax                     ; 0x6f732e7a62696c libz.so

    mov     r14, rsp                ; save rsp
    and     rsp, -16                ; 16 bytes alignment

    mov     rax, rdi
    mov     rdi, r14                ; 1st argument: const char *filename
    mov     rsi, RTLD_NOW           ; 2nd argument: int flag
    call    rax                     ; call dlopen

    mov     rsp, r14                ; load rsp
    add     rsp, 0x8                ; remove 8 bytes of libz.so string

    ret


get_libz_function_address:
    push    rdi
    push    rsi

    ; inflateInit_
    xor     rax, rax
    mov     eax, 0x81d9d781
    xor     eax, 0xdeadbeef
    push    rax
    xor     rax, rax
    mov     eax, 0x97c8ca8e
    xor     eax, 0xdeadbeef
    rol     rax, 32
    xor     rbx, rbx
    mov     ebx, 0xb2cbd086
    xor     ebx, 0xdeadbeef
    add     rax, rbx
    push    rax                     ; 0x5f74696e 49657461 6c666e69 inflateInit

    mov     r14, rsp                ; save rsp
    and     rsp, -16                ; 16 bytes alignment

    mov     rax, rdi
    mov     rdi, rsi                ; 1st argument: void *handle
    mov     rsi, r14                ; 2nd argument: const char *symbol
    call    rax                     ; call dlsym

    mov     rsp, r14                ; load rsp
    add     rsp, 0x10               ; remove 16 bytes of inflateInit string

    pop     rsi
    pop     rdi

    push    rax                     ; save inflateInit_ function address

    push    rdi
    push    rsi

    ; inflate
    xor     rax, rax
    mov     eax, 0xdec8ca8e
    xor     eax, 0xdeadbeef
    rol     rax, 32
    xor     rbx, rbx
    mov     ebx, 0xb2cbd086
    xor     ebx, 0xdeadbeef
    add     rax, rbx
    push    rax                     ; 0x657461 6c666e69 inflate

    mov     r14, rsp                ; save rsp
    and     rsp, -16                ; 16 bytes alignment

    mov     rax, rdi
    mov     rdi, rsi                ; 1st argument: void *handle
    mov     rsi, r14                ; 2nd argument: const char *symbol
    call    rax                     ; call dlsym

    mov     rsp, r14                ; load rsp
    add     rsp, 0x8                ; remove 8 bytes of inflate string

    pop     rsi
    pop     rdi

    push    rax                     ; save inflate function address

    push    rdi
    push    rsi

    ; inflateEnd
    xor     rax, rax
    mov     eax, 0xdeadda81
    xor     eax, 0xdeadbeef
    push    rax
    xor     rax, rax
    mov     eax, 0x9bc8ca8e
    xor     eax, 0xdeadbeef
    rol     rax, 32
    xor     rbx, rbx
    mov     ebx, 0xb2cbd086
    xor     ebx, 0xdeadbeef
    add     rax, rbx
    push    rax                     ; 0x646e 45657461 6c666e69 inflateEnd

    mov     r14, rsp                ; save rsp
    and     rsp, -16                ; 16 bytes alignment

    mov     rax, rdi
    mov     rdi, rsi                ; 1st argument: void *handle
    mov     rsi, r14                ; 2nd argument: const char *symbol
    call    rax                     ; call dlsym

    mov     rsp, r14                ; load rsp
    add     rsp, 0x10               ; remove 16 bytes of inflateInit string

    pop     rsi
    pop     rdi

    mov     rcx, rax                ; inflateEnd function address
    pop     rdx                     ; inflate function address
    pop     rax                     ; inflateInit
    ret


decompress_image:
    xor     rax, rax
    mov     eax, 0xdeadbede
    xor     eax, 0xdeadbeef
    rol     rax, 32
    xor     rbx, rbx
    mov     ebx, 0xf09e90de
    xor     ebx, 0xdeadbeef
    add     rax, rbx
    mov     qword [r15 - 0x38], rax ; 0x31 2e332e31 1.3.1 libz.so version

    mov     r14, rsp                ; save rsp
    and     rsp, -16                ; 16 bytes alignment

    call    inf

    mov     rsp, r14                ; load rsp

    ret


inf:
    push    rbp
    mov     rbp, rsp
    push    rbx
    sub     rsp, 0xd8
    mov     qword [rbp - 0xc8], rdi
    mov     qword [rbp - 0xd0], rsi
    mov     qword [rbp - 0xd8], rdx
    mov     rax, rsp
    mov     rbx, rax
    mov     dword [rbp - 0x24], 0x4000
    mov     dword [rbp - 0x28], 0x0
    mov     qword [rbp - 0x18], 0x0
    mov     qword [rbp - 0x20], 0x0
    mov     eax, dword [rbp - 0x24]
    movsxd  rdx, eax
    sub     rdx, 0x1
    mov     qword [rbp - 0x30], rdx
    cdqe
    mov     edx, 0x10
    sub     rdx, 0x1
    add     rax, rdx
    mov     edi, 0x10
    mov     edx, 0x0
    div     rdi
    imul    rax, rax, 0x10
    sub     rsp, rax
    mov     rax, rsp
    mov     qword [rbp - 0x38], rax
    mov     eax, dword [rbp - 0x24]
    movsxd  rdx, eax
    sub     rdx, 0x1
    mov     qword [rbp - 0x40], rdx
    cdqe
    mov     edx, 0x10
    sub     rdx, 0x1
    add     rax, rdx
    mov     esi, 0x10
    mov     edx, 0x0
    div     rsi
    imul    rax, rax, 0x10
    sub     rsp, rax
    mov     rax, rsp
    mov     qword [rbp - 0x48], rax
    mov     qword [rbp - 0x80], 0x0
    mov     qword [rbp - 0x78], 0x0
    mov     qword [rbp - 0x70], 0x0
    mov     dword [rbp - 0xb8], 0x0
    mov     qword [rbp - 0xc0], 0x0
    lea     rax, [rbp - 0xc0]
    mov     edx, 0x70
    lea     rcx, [r15 - 0x38]           ; libz.so version string
    mov     rsi, rcx
    mov     rdi, rax
    call    qword [r15 - 0x18]          ; call inflateInit_
    mov     dword [rbp - 0x28], eax

inf_label_01:
    mov     eax ,dword [rbp - 0x24]
    movsxd  rdx, eax
    mov     rax, qword [rbp - 0x18]
    add     rax, rdx
    cmp     rax, qword [rbp - 0xd0]
    jb      inf_label_02
    mov     rax, qword [rbp - 0xd0]
    mov     ecx, eax
    mov     rax, qword [rbp - 0x18]
    mov     edx, eax
    mov     eax, ecx
    sub     eax, edx
    mov     dword [rbp - 0xb8], eax
    jmp     inf_label_03

inf_label_02:
    mov     eax, dword [rbp - 0x24]
    mov     dword [rbp - 0xb8], eax

inf_label_03:
    mov     eax, dword [rbp - 0xb8]
    test    eax, eax
    je      inf_label_06
    mov     eax, dword [rbp - 0xb8]
    mov     esi, eax
    mov     rdx, qword [rbp - 0xc8]
    mov     rax, qword [rbp - 0x18]
    lea     rcx, [rdx + rax * 1]
    mov     rax, qword [rbp - 0x38]
    mov     rdx, rsi
    mov     rsi, rcx
    mov     rdi, rax
    call    copy_memory
    mov     eax, dword [rbp - 0xb8]
    mov     eax, eax
    add     qword [rbp - 0x18], rax
    mov     rax, qword [rbp - 0x38]
    mov     qword [rbp - 0xc0], rax

inf_label_04:
    mov     eax, dword [rbp - 0x24]
    mov     dword [rbp - 0xa0], eax
    mov     rax, qword [rbp - 0x48]
    mov     qword [rbp - 0xa8],rax
    lea     rax, [rbp - 0xc0]
    mov     esi, 0x0
    mov     rdi, rax
    call    qword [r15 - 0x20]          ; call inflate
    mov     dword [rbp - 0x28], eax
    mov     edx, dword [rbp - 0x24]
    mov     eax, dword [rbp - 0xa0]
    sub     edx, eax
    mov     dword [rbp - 0x4c], edx
    cmp     dword [rbp - 0x4c], 0x0
    je      inf_label_05
    mov     edx, dword [rbp - 0x4c]
    mov     rcx, qword [rbp - 0xd8]
    mov     rax, qword [rbp - 0x20]
    add     rcx, rax
    mov     rax, qword [rbp - 0x48]
    mov     rsi, rax
    mov     rdi, rcx
    call    copy_memory
    mov     eax, dword [rbp - 0x4c]
    add     qword [rbp - 0x20], rax

inf_label_05:
    mov     eax, dword [rbp - 0xa0]
    test    eax, eax
    je      inf_label_04
    cmp     dword [rbp - 0x28], 0x1
    jne     inf_label_01
    jmp     inf_label_07

inf_label_06:
    nop

inf_label_07:
    lea     rax, [rbp - 0xc0]
    mov     rdi, rax
    call    qword [r15 - 0x28]          ; call inflateEnd
    mov     eax, 0x0
    mov     rsp, rbx
    mov     rbx, qword [rbp - 0x8]
    leave
    ret


fix_memory_protect:
    mov     rbx, qword [rdi + _Elf64_Ehdr.e_phoff]          ; decompress data segment address
    add     rbx, rdi                                        ; program header (decompressed elf image)

    xor     rax, rax
    mov     ax, word [rdi + _Elf64_Ehdr.e_phentsize]
    xor     rcx, rcx
    mov     cx, word [rdi + _Elf64_Ehdr.e_phnum]

fix_memory_protect_search_pt_load:
    mov     edx, dword [rbx]                                ; p_type
    cmp     edx, PT_LOAD
    jne     fix_memory_protect_search_pt_load_next_2

fix_memory_protect_fix_load_segment:
    mov     r14, rdi
    mov     r13, rsi

    push    rdi
    push    rsi
    push    rdx
    push    rcx
    push    rax

    mov     rdi, qword [rbx + _Elf64_Phdr.p_memsz]          ; size
    mov     rsi, qword [rbx + _Elf64_Phdr.p_align]          ; align
    call    align_address
    mov     rsi, rax                                        ; 2nd argument: size_t len

    mov     eax, dword [rbx + _Elf64_Phdr.p_flags]          ; flags
    xor     rdx, rdx                                        ; 3rd argument: unsigned long prot

fix_memory_protect_check_pf_r:
    mov     ecx, eax
    and     ecx, PF_R
    jz      fix_memory_protect_check_pf_w
    or      edx, PROT_READ

fix_memory_protect_check_pf_w:
    mov     ecx, eax
    and     ecx, PF_W
    jz      fix_memory_protect_check_pf_x
    or      edx, PROT_WRITE

fix_memory_protect_check_pf_x:
    mov     ecx, eax
    and     ecx, PF_X
    jz      fix_memory_protect_check_pf_done_1
    or      edx, PROT_EXEC

fix_memory_protect_check_pf_done_1:
    mov     rdi, qword [rbx + _Elf64_Phdr.p_vaddr]
    add     rdi, r14                                        ; 1st argument: unsigned long start
    mov     r13, qword [rbx + _Elf64_Phdr.p_align]          ; align
    sub     r13, 1
    not     r13
    and     rdi, r13                                        ; align
    mov     rax, 0xa                                        ; sys_mprotect
    syscall

    pop     rax
    pop     rcx
    pop     rdx
    pop     rsi
    pop     rdi

fix_memory_protect_search_pt_load_next_2:
    add     rbx, rax
    dec     rcx
    cmp     rcx, 0x0
    jne     fix_memory_protect_search_pt_load

fix_memory_protect_done:
    ret


dlclose_libz:
    mov     r14, rsp                ; save rsp
    and     rsp, -16                ; 16 bytes alignment

    mov     rax, rdi
    mov     rdi, rsi                ; 1st argument: void *handle
    call    rax                     ; call dlclose

    mov     rsp, r14                ; load rsp

    ret


fix_auxiliary_vector:
    xor     rcx, rcx

search_fix_auxiliary_vector:
    mov     rax, _Elf64_auxv_t_size
    mul     rcx
    mov     rbx, qword [rdi + rax]
    inc     rcx
    cmp     rbx, AT_NULL                                    ; end
    je      fix_auxiliary_vector_done
    cmp     rbx, AT_PHDR
    je      fix_auxiliary_vector_at_phdr
    cmp     rbx, AT_PHENT
    je      fix_auxiliary_vector_at_phent
    cmp     rbx, AT_PHNUM
    je      fix_auxiliary_vector_at_phnum
    cmp     rbx, AT_ENTRY
    je      fix_auxiliary_vector_at_entry
    jmp     search_fix_auxiliary_vector

fix_auxiliary_vector_at_phdr:
    xor     rdx, rdx
    mov     rdx, qword [rsi + _Elf64_Ehdr.e_phoff]          ; elf image base address
    add     rdx, rsi                                        ; program header address

    mov     qword [rdi + rax + _Elf64_auxv_t.a_val], rdx
    jmp     search_fix_auxiliary_vector

fix_auxiliary_vector_at_phent:
    xor     rdx, rdx
    mov     dx, word [rsi + _Elf64_Ehdr.e_phentsize]        ; elf image base address

    mov     qword [rdi + rax + _Elf64_auxv_t.a_val], rdx
    jmp     search_fix_auxiliary_vector

fix_auxiliary_vector_at_phnum:
    xor     rdx, rdx
    mov     dx, word [rsi + _Elf64_Ehdr.e_phnum]            ; elf image base address

    mov     qword [rdi + rax + _Elf64_auxv_t.a_val], rdx
    jmp     search_fix_auxiliary_vector

fix_auxiliary_vector_at_entry:
    xor     rdx, rdx
    mov     rdx, qword [rsi + _Elf64_Ehdr.e_entry]          ; elf image base address
    add     rdx, rsi                                        ; entrypoint

    mov     qword [rdi + rax + _Elf64_auxv_t.a_val], rdx
    jmp     search_fix_auxiliary_vector

fix_auxiliary_vector_done:
    ret


get_ld_filepath:
    mov     rbx, qword [rdi + _Elf64_Ehdr.e_phoff]
    add     rbx, rdi                                    ; program header

    xor     rax, rax
    mov     ax, word [rdi + _Elf64_Ehdr.e_phentsize]
    xor     rcx, rcx
    mov     cx, word [rdi + _Elf64_Ehdr.e_phnum]

search_pt_interp:
    mov     edx, dword [rbx]                            ; p_type
    cmp     edx, PT_INTERP
    je      search_pt_interp_done
    add     rbx, rax
    dec     rcx
    cmp     rcx, 0x0
    jne     search_pt_interp

search_pt_interp_done:
    xor     rax, rax
    mov     rax, qword [rbx + _Elf64_Phdr.p_vaddr]
    add     rax, rdi                                    ; interpreter filepath address

    xor     rcx, rcx
    mov     rcx, qword [rbx + _Elf64_Phdr.p_memsz]      ; interpreter filepath size

    mov     rdi, rsi                                    ; 1st argument: src
    mov     rsi, rax                                    ; 2nd argument: dest
    mov     rdx, rcx                                    ; 3rd argument: size
    call    copy_memory
    ret


fix_ld:
    mov     rbx, qword [rdi + _Elf64_Ehdr.e_phoff]          ; ld image base address
    add     rbx, rdi                                        ; program header (ld)

    xor     rax, rax
    mov     ax, word [rdi + _Elf64_Ehdr.e_phentsize]
    xor     rcx, rcx
    mov     cx, word [rdi + _Elf64_Ehdr.e_phnum]

fix_ld_search_pt_load:
    mov     edx, dword [rbx]                                ; p_type
    cmp     edx, PT_LOAD
    jne     fix_ld_search_pt_load_next_2

fix_ld_fix_load_segment:
    mov     r14, rdi
    mov     r13, rsi

    push    rdi
    push    rsi
    push    rdx
    push    rcx
    push    rax

    mov     rdi, qword [rbx + _Elf64_Phdr.p_memsz]          ; size
    mov     rsi, qword [rbx + _Elf64_Phdr.p_align]          ; align
    call    align_address
    mov     rsi, rax                                        ; 2nd argument: size_t len

    mov     eax, dword [rbx + _Elf64_Phdr.p_flags]          ; flags
    xor     rdx, rdx                                        ; 3rd argument: unsigned long prot

fix_ld_check_pf_r:
    mov     ecx, eax
    and     ecx, PF_R
    jz      fix_ld_check_pf_x
    or      edx, PROT_READ

fix_ld_check_pf_x:
    mov     ecx, eax
    and     ecx, PF_X
    jz      fix_ld_check_pf_w
    or      edx, PROT_EXEC

fix_ld_check_pf_w:
    mov     ecx, eax
    and     ecx, PF_W
    jz      fix_ld_check_pf_done_2
    or      edx, PROT_WRITE

;   add     rsi, qword [rbx + _Elf64_Phdr.p_align]          ; size + align

fix_ld_check_pf_done_1:
    mov     rdi, qword [rbx + _Elf64_Phdr.p_vaddr]
    add     rdi, r14                                        ; 1st argument: unsigned long start
    mov     r12, qword [rbx + _Elf64_Phdr.p_align]          ; align
    sub     r12, 1
    not     r12
    and     rdi, r12                                        ; align
    mov     rax, 0xa                                        ; sys_mprotect
    syscall

    ; rdi 1st argument: start address
    ; rsi 2nd argument: size
    call    write_zero_memory

    mov     rdi, r13                                        ; 1st argument: const char *filename
    mov     rsi, O_RDONLY                                   ; 2nd argument: int flags
    mov     rdx, 0x0                                        ; 3rd argument: int mode
    mov     rax, 0x2                                        ; sys_open
    syscall
    mov     r12, rax                                        ; fd

    mov     rdx, SEEK_SET                                   ; 3rd argument: unsigned int origin
    mov     rsi, qword [rbx + _Elf64_Phdr.p_offset]         ; 2nd argument: off_t offset
    mov     rdi, r12                                        ; 1st argument: unsigned int fd
    mov     rax, 0x8                                        ; sys_lseek
    syscall

    mov     rdx, qword [rbx + _Elf64_Phdr.p_filesz]         ; 3rd argument: size_t count
    mov     rsi, qword [rbx + _Elf64_Phdr.p_vaddr]
    add     rsi, r14                                        ; 2nd argument: char *buf
    mov     rdi, r12                                        ; 1st argument: unsigned int fd
    mov     rax, 0x0                                        ; sys_read
    syscall

    mov     rdi, r12                    ; 1st argument: unsigned int fd
    mov     rax, 0x3                    ; sys_close
    syscall

    jmp     fix_ld_search_pt_load_next_1

fix_ld_check_pf_done_2:
    mov     rdi, qword [rbx + _Elf64_Phdr.p_vaddr]
    add     rdi, r14                                        ; 1st argument: unsigned long start
    mov     r12, qword [rbx + _Elf64_Phdr.p_align]          ; align
    sub     r12, 1
    not     r12
    and     rdi, r12                                        ; align
    mov     rax, 0xa                                        ; sys_mprotect
    syscall

fix_ld_search_pt_load_next_1:
    pop     rax
    pop     rcx
    pop     rdx
    pop     rsi
    pop     rdi

fix_ld_search_pt_load_next_2:
    add     rbx, rax
    dec     rcx
    cmp     rcx, 0x0
    jne     fix_ld_search_pt_load

fix_ld_done:
    ret


unmap_libc:
    mov     rbx, qword [rdi + _Elf64_Ehdr.e_phoff]          ; libc image base address
    add     rbx, rdi                                        ; program header (libc)

    xor     rax, rax
    mov     ax, word [rdi + _Elf64_Ehdr.e_phentsize]
    xor     rcx, rcx
    mov     cx, word [rdi + _Elf64_Ehdr.e_phnum]

    push    rax
    mul     ecx
    add     rbx, rax
    pop     rax
    sub     rbx, rax                                        ; program header (libc) + e_phentsize * (e_phnum - 1)

    mov     rcx, 0x4                                        ; libc PT_LOAD count: 4

unmap_libc_search_pt_load:
    mov     edx, dword [rbx]                                ; p_type
    cmp     edx, PT_LOAD
    jne     unmap_libc_search_pt_load_next

    mov     r14, rdi
    dec     rcx                                             ; dec libc PT_LOAD count

    push    rdi
    push    rcx
    push    rax


    mov     rdi, qword [rbx + _Elf64_Phdr.p_memsz]          ; size
    mov     rsi, qword [rbx + _Elf64_Phdr.p_align]          ; align
    call    align_address
    mov     rsi, rax                                        ; 2nd argument: size_t len

    mov     rdi, qword [rbx + _Elf64_Phdr.p_vaddr]
    add     rdi, r14                                        ; 1st argument: unsigned long addr
    mov     r12, qword [rbx + _Elf64_Phdr.p_align]          ; align
    sub     r12, 1
    not     r12
    and     rdi, r12                                        ; align
    mov     rax, 0xb                                        ; sys_munmap
    syscall

    pop     rax
    pop     rcx
    pop     rdi

unmap_libc_search_pt_load_next:
    sub     rbx, rax
    cmp     rcx, 0x0
    jne     unmap_libc_search_pt_load

unmap_libc_done:
    ret


lookup_oep:
    mov     rax, rax
    mov     rax, qword [rdi + _Elf64_Ehdr.e_entry]          ; ld.so base address
    add     rax, rdi                                        ; oep

    ret


copy_memory:
    xor     rax, rax

load_store_memory:
    lodsb
    stosb
    dec     rdx
    cmp     rdx, 0x0
    jg      load_store_memory

copy_memory_done:
    ret


write_zero_memory:
    mov     rdx, rsi
    xor     rax, rax

write_zero:
    stosb
    dec     rdx
    cmp     rdx, 0x0
    jg      write_zero

write_zero_memory_done:
    ret


align_address:
    push   rbp
    mov    rbp,rsp
    mov    qword [rbp - 0x8], rdi
    mov    qword [rbp - 0x10], rsi
    mov    rax, qword [rbp - 0x8]
    mov    edx, 0x0
    div    qword [rbp - 0x10]
    mov    rax, rdx
    test   rax, rax
    je     align_address_label_01
    mov    rax, qword [rbp - 0x8]
    mov    edx, 0x0
    div    qword [rbp - 0x10]
    add    rax, 0x1
    imul   rax, qword [rbp - 0x10]
    jmp    align_address_label_02

align_address_label_01:
    mov    rax, qword [rbp - 0x8]
    mov    edx, 0x0
    div    qword [rbp - 0x10]
    imul   rax, qword [rbp - 0x10]

align_address_label_02:
    pop    rbp
    ret


convert_to_lowercase:
    push    rsi
    push    rdi

    mov     rsi, rcx
    mov     rdi, rdx

check_char:
    lodsb    
    cmp     al, 0x0
    je      convert_to_lowercase_done
    cmp     al, 0x41
    jl      store_char
    cmp     al, 0x5a
    jg      store_char
    add     al, 0x20

store_char:
    stosb
    jmp     check_char

convert_to_lowercase_done:
    stosb               ; write null
    mov     rax, rdx
    pop     rdi
    pop     rsi
    ret


generate_crc32_hash:
    or      eax, -1

crc_outer:
    xor     al, byte [rdi]
    push    0x8
    pop     rcx
    
crc_inner:
    shr     eax, 1
    jnc     crc_skip
    xor     eax, 0xEDB88320

crc_skip:
    loop    crc_inner
    inc     rdi
    cmp     byte [rdi], cl
    jne     crc_outer
    not     eax

generate_crc32_hash_done:
    ret

