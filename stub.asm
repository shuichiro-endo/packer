; Title:  stub.asm
; Author: Shuichiro Endo

; nasm -f bin stub.asm -o stub.bin

bits 64

%include "stub.inc"

global _main

section .text

_main:
    pushaq                         ; push registers macro

    ; save 1 pe image base address
    sub     rsp, 0x8

    ; save 4 dll base address(ntdll.dll, kernel32.dll, kernelbase.dll, apphelp.dll)
    sub     rsp, 0x20
    mov     rbp, rsp
    sub     rbp, 0x8
    
    ; save 4 function address(RtlDecompressBuffer, GetProcAddress, LoadLibraryA, VirtualProtect)
    sub     rsp, 0x20
    
    call    get_address
    
    call    recover_nt_header_1
    
    call    decompress_image
    
    call    recover_nt_header_2
    
    call    lookup_oep
    
    push    rax                    ; push oep
    lea     rsp, [rsp + 0x8]

    ; remove saved address
    ; 4 function address(RtlDecompressBuffer, GetProcAddress, LoadLibraryA, VirtualProtect)
    ; 4 dll base address(ntdll.dll, kernel32.dll, kernelbase.dll, apphelp.dll)
    ; 1 pe image base address
    add     rsp, 0x48

    popaq                          ; pop registers macro
    jmp     qword [rsp - 0xC8]     ; jump oep

get_address:
    pushaq
    
    push    peb64
    pop     rsi
    gs lodsq
    
    mov     r8, qword [rax + image_base_address]
    mov     qword [rbp + 0x28], r8                          ; save pe image base address
    
    mov     rax, qword [rax + ldr]
    mov     rsi, qword [rax + in_memory_order_module_list]
    lodsq
    mov     r8, qword [rax + dll_base]
    mov     qword [rbp + 0x20], r8                          ; save ntdll.dll base address
    xchg    rax, rsi
    lodsq
    mov     r8, qword [rax + dll_base]
    mov     qword [rbp + 0x18], r8                          ; save kernel32.dll base address
    xchg    rax, rsi
    lodsq
    mov     r8, qword [rax + dll_base]
    mov     qword [rbp + 0x10], r8                          ; save kernelbase.dll base address
    xchg    rax, rsi
    lodsq
    mov     r8, qword [rax + dll_base]
    mov     qword [rbp + 0x8], r8                           ; save apphelp.dll base address

    ; RtlDecompressBuffer
    mov     rdx, 0x52FE26D8                                 ; RtlDecompressBuffer crc32 hash
    mov     rcx, [rbp + 0x20]                               ; ntdll.dll base address
    call    parse_exports_crc
    mov     [rbp], rax    

    ; GetProcAddress
    mov     rdx, 0xC97C1FFF                                 ; GetProcAddress crc32 hash
    mov     rcx, [rbp + 0x18]                               ; kernel32.dll base address
    call    parse_exports_crc
    mov     [rbp - 0x8], rax
    
    ; LoadLibraryA
    mov     rdx, 0x3FC1BD8D                                 ; LoadLibraryA crc32 hash
    mov     rcx, [rbp + 0x18]                               ; kernel32.dll base address
    call    parse_exports_crc
    mov     [rbp - 0x10], rax  
    
    ; VirtualProtect
    mov     rdx, 0x10066F2F                                 ; VirtualProtect crc32 hash
    mov     rcx, [rbp + 0x18]                               ; kernel32.dll base address
    call    parse_exports_crc
    mov     [rbp - 0x18], rax

    popaq
    ret

recover_nt_header_1:
    pushaq

    lea     r9, [rsp - 8]               ; 4th argument: PDWORD lpflOldProtect
    mov     r8, PAGE_READWRITE          ; 3rd argument: DWORD  flNewProtect
    mov     rdx, 0x1000                 ; 2nd argument: SIZE_T dwSize
    mov     rcx, qword [rbp + 0x28]     ; 1st argument: LPVOID lpAddress
    sub     rsp, 0x28                   ; 32 bytes of shadow space and 8 bytes argument space (lpflOldProtect)
    call    qword [rbp - 0x18]          ; VirtualProtect
    add     rsp, 0x28                   ; remove 32 bytes of shadow space and 8 bytes argument space (lpflOldProtect)

    popaq
    ret

parse_exports_crc:
    push    rbp

    mov     r15, rcx        ; dll base address
    mov     rsi, rdx        ; crc32 hash
    mov     eax, dword [r15 + _IMAGE_DOS_HEADER.e_lfanew]
    mov     ebx, dword [r15 + rax + IMAGE_DIRECTORY_ENTRY_EXPORT]
    add     rbx, r15        ; add dll base address
    xor     rdx, rdx
    
walk_names_crc:
    mov     eax, dword [rbx + _IMAGE_EXPORT_DIRECTORY.AddressOfNames]
    add     rax, r15        ; add dll base address
    mov     edi, dword [rax + rdx * 4]
    add     rdi, r15        ; add dll base address
    inc     edx

    push    rcx
    mov     rcx, rdi
    call    generate_crc32_hash
    pop     rcx
    
    cmp     rsi, rax
    jne     walk_names_crc

    mov     edi, dword [rbx + _IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]
    add     rdi, r15        ; add dll base address
    dec     rdx
    movzx   edi, word [rdi + rdx * 2]
    mov     eax, dword [rbx + _IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]
    add     rax, r15        ; add dll base address
    mov     eax, dword [rax + rdi * 4]
    add     rax, r15        ; add dll base address

parse_exports_crc_done:
    pop     rbp
    ret

decompress_image:
    pushaq
    
    lea     rdx, [rsp - 8]
    push    rdx                             ; 6th argument: PULONG FinalUncompressedSize    
    mov     rdx, 0x32303061746164           ; data002 (compressed data section)
    mov     rcx, qword [rbp + 0x28]         ; pe image base address
    call    lookup_section_info
    add     rax, qword [rbp + 0x28]         ; vircual address + pe image base address
    push    rbx                             ; 5th argument: ULONG  CompressedBufferSize
    push    rax                             ; PUCHAR CompressedBuffer
    
    mov     rdx, 0x30303061746164           ; data000 (decompressed data section)
    mov     rcx, qword [rbp + 0x28]         ; pe image base address
    call    lookup_section_info
    add     rax, qword [rbp + 0x28]         ; vircual address + pe image base address
    push    rbx                             ; ULONG  UncompressedBufferSize
    push    rax                             ; PUCHAR UncompressedBuffer

    mov     rcx, COMPRESSION_FORMAT_LZNT1   ; 1st argument: USHORT CompressionFormat
    pop     rdx                             ; 2nd argument: PUCHAR UncompressedBuffer
    pop     r8                              ; 3rd argument: ULONG  UncompressedBufferSize
    pop     r9                              ; 4th argument: PUCHAR CompressedBuffer
    sub     rsp, 0x20                       ; 32 bytes of shadow space
    call    qword [rbp]                     ; RtlDecompressBuffer
    add     rsp, 0x30                       ; remove 32 bytes of shadow space and 16 bytes argument space
    
    call    fetch_nt_header
    mov     rbx, rax
    
fix_iat:
    push    rbx
    lea     rdx, [rbx + IMAGE_DIRECTORY_ENTRY_IMPORT]
    mov     ecx, dword [rdx]
    add     rcx, [rbp + 0x28]       ; add pe image base address
    
import_dll:
    mov     eax, dword [rcx + _IMAGE_IMPORT_DESCRIPTOR.Name]
    test    eax, eax
    jz      fix_iat_done
    add     rax, [rbp + 0x28]       ; add pe image base address

    push    rax
    push    rcx
    push    rdx

    mov     rcx, rax
    mov     rdx, qword [rbp + 0x28]
    add     rdx, 0xA00              ; lowercase space
    call    convert_to_lowercase
    mov     r14, rax

    pop     rdx
    pop     rcx
    pop     rax

check_import_dll_crc:
    push    rcx
    mov     rcx, r14
    call    generate_crc32_hash
    mov     r13, rax
    pop     rcx

check_import_dll_crc_ntdll:
    mov     r12, 0x84C05E40
    cmp     r12, r13                ; ntdll.dll crc32 hash
    jne     check_import_dll_crc_kernel32
    mov     rax, qword [rbp + 0x20]
    jmp     imported_dll

check_import_dll_crc_kernel32:
    mov     r12, 0x6AE69F02
    cmp     r12, r13                ; kernel32.dll crc32 hash
    jne     check_import_dll_crc_kernelbase
    mov     rax, qword [rbp + 0x18]
    jmp     imported_dll

check_import_dll_crc_kernelbase:
    mov     r12, 0xA7DC6E73
    cmp     r12, r13                ; kernelbase.dll crc32 hash
    jne     check_import_dll_crc_apphelp
    mov     rax, qword [rbp + 0x10]
    jmp     imported_dll

check_import_dll_crc_apphelp:
    mov     r12, 0x222CFBD2
    cmp     r12, r13                ; apphelp.dll crc32 hash
    jne     call_loadlibrary_1
    mov     rax, qword [rbp + 0x8]
    jmp     imported_dll

call_loadlibrary_1:
    push    rcx
    sub     rsp, 0x20               ; 32 bytes of shadow space
    mov     rcx, r14
    call    qword [rbp - 0x10]      ; LoadLibraryA
    add     rsp, 0x20               ; remove 32 bytes of shadow space
    pop     rcx

imported_dll:
    mov     rbx, rax    
    mov     edi, dword [rcx + _IMAGE_IMPORT_DESCRIPTOR.FirstThunk]
    add     rdi, qword [rbp + 0x28] ; add pe image base address
    
import_thunks:
    mov     rsi, rdi
    lodsq
    test    rax, rax
    jz      import_next
    add     rax, qword [rbp + 0x28] ; add pe image base address
    lea     rax, [rax + 2]          ; PIMAGE_IMPORT_BY_NAME->Name
    push    rcx
    mov     rcx, rbx
    mov     rdx, rax
    call    parse_exports
    pop     rcx
    stosq
    jmp     import_thunks

import_next:
    lea     rcx, [rcx + _IMAGE_IMPORT_DESCRIPTOR_size]
    jmp     import_dll

fix_iat_done:
    pop     rbx

fix_reloc:
    push    rbx

    xor     rdi, rdi
    mov     edi, dword [rbx + IMAGE_DIRECTORY_ENTRY_RELOCS]
    add     rdi, qword [rbp + 0x28]     ; add pe image base address
    xor     rcx, rcx
    
reloc_block:
    push    _IMAGE_BASE_RELOCATION_size
    pop     rdx
    
reloc_addr:
    movzx   rax, word [rdi + rdx]
    push    rax
    and     ah, 0xf0
    cmp     ah, IMAGE_REL_BASED_DIR64 << 4
    pop     rax
    jne     reloc_abs
    and     ah, 0x0f
    add     eax, dword [rdi + _IMAGE_BASE_RELOCATION.PageRVA]
    add     rax, qword [rbp + 0x28]     ; add pe image base address
    mov     rsi, qword [rax]
    sub     rsi, qword [rbx + _IMAGE_NT_HEADERS64.OptionalHeader + _IMAGE_OPTIONAL_HEADER64.ImageBase]
    add     rsi, qword [rbp + 0x28]     ; add pe image base address
    mov     qword [rax], rsi
    xor     eax, eax

reloc_abs:
    test    eax, eax        ; check for IMAGE_REL_BASED_ABSOLUTE
    jne     fix_reloc_done
    inc     edx
    inc     edx
    cmp     dword [rdi + _IMAGE_BASE_RELOCATION.SizeOfBlock], edx
    jg      reloc_addr
    add     ecx, edx
    add     rdi, rdx
    cmp     dword [rbx + IMAGE_DIRECTORY_ENTRY_RELOCS + 4], ecx     ; Size
    jg      reloc_block

fix_reloc_done:
    pop     rbx
    
decompress_image_done:
    popaq
    ret

lookup_section_info:
    push    rbp
    push    r8

    mov     r8, rcx
    mov     eax, dword [r8 + _IMAGE_DOS_HEADER.e_lfanew]
    add     rax, r8     ; nt header address
    movzx   ecx, word [rax + _IMAGE_NT_HEADERS64.FileHeader + _IMAGE_FILE_HEADER.SizeOfOptionalHeader]
    lea     rcx, qword [rax + rcx + _IMAGE_NT_HEADERS64.OptionalHeader]

check_section_name:
    xor     rbx, rbx
    mov     rbx, qword [rcx + _IMAGE_SECTION_HEADER.Name]
    add     rcx, _IMAGE_SECTION_HEADER_size
    cmp     rbx, rdx
    jne     check_section_name

    sub     rcx, _IMAGE_SECTION_HEADER_size
    mov     eax, dword [rcx + _IMAGE_SECTION_HEADER.VirtualAddress]
    mov     ebx, dword [rcx + _IMAGE_SECTION_HEADER.VirtualSize]
    mov     edx, dword [rcx + _IMAGE_SECTION_HEADER.SizeOfRawData]

    pop     r8
    pop     rbp
    ret

fetch_nt_header:
    push    rbp
    
    mov     rdx, 0x33303061746164       ; data003 (input pe nt header section)
    mov     rcx, qword [rbp + 0x28]     ; pe image base address
    call    lookup_section_info
    add     rax, qword [rbp + 0x28]     ; vircual address + pe image base address

    pop     rbp
    ret

parse_exports:
    push    rbp
    push    rbx
    push    rdi
    push    r8

    mov     r15, rcx    ; dll base address
    mov     rsi, rdx    ; function name pointer address
    mov     eax, dword [r15 + _IMAGE_DOS_HEADER.e_lfanew]
    mov     ebx, dword [r15 + rax + IMAGE_DIRECTORY_ENTRY_EXPORT]
    add     rbx, r15    ; add dll base address
    xor     rdx, rdx
    
walk_names:
    mov     eax, dword [rbx + _IMAGE_EXPORT_DIRECTORY.AddressOfNames]
    add     rax, r15    ; add dll base address
    mov     edi, dword [rax + rdx * 4]
    add     rdi, r15    ; add dll base address
    inc     edx
    mov     r8, rsi
    mov     r9, rdi
    xor     ecx, ecx
    
count_size:
    inc     ecx
    cmp     byte [r8], 0
    je      count_size_done
    inc     r8
    jmp     count_size

count_size_done:
    mov     r8, rsi

check_name:
    cmp     ecx, 0
    je      check_name_done
    movzx   r10, byte [r8]
    movzx   r11, byte [r9]
    cmp     r10b, r11b
    jne     walk_names
    dec     ecx
    inc     r8
    inc     r9
    jmp     check_name

check_name_done:
    dec     rdx
    mov     ecx, dword [rbx + _IMAGE_EXPORT_DIRECTORY.Base]
    mov     edi, dword [rbx + _IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]
    add     rdi, r15                    ; add dll base address
    movzx   edi, word [rdi + rdx * 2]
    mov     eax, dword [rbx + _IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]
    add     rax, r15                    ; add dll base address
    mov     eax, dword [rax + rdi * 4]
    add     rax, r15                    ; add dll base address

check_forwarder:
    mov     r8, rax                     ; function address

    mov     rdx, 0x61746164722E         ; .rdata section
    mov     rcx, r15                    ; dll image base address
    call    lookup_section_info
    add     rax, r15                    ; vircual address + dll image base address

    cmp     rax, r8
    jg      check_forwarder_done
    add     rax, rbx                    ; vircual address + virtual size + dll image base address
    cmp     rax, r8
    jl      check_forwarder_done

    mov     r10, qword [rbp + 0x28]
    add     r10, 0xA00                  ; forwarder dll name space
    mov     r11, qword [rbp + 0x28]
    add     r11, 0xB00                  ; forwarder function name space

    push    rsi
    push    rdi
    mov     rsi, r8
    mov     rdi, r10

copy_forwarder_dll_name:
    lodsb
    cmp     al, 0x2e    ; . (dot) charactor
    je      copy_forwarder_dll_name_done
    stosb
    jmp     copy_forwarder_dll_name
    
copy_forwarder_dll_name_done:
    mov     al, 0x0
    stosb               ; write null

    mov     rdi, r11
    
copy_forwarder_function_name:
    lodsb
    stosb
    cmp     al, 0x0
    jne     copy_forwarder_function_name
    
copy_forwarder_function_name_done:
    pop     rdi
    pop     rsi

check_forwarder_dll_name:
    mov     rcx, qword [rbp + 0x28]
    add     rcx, 0xA00              ; lowercase space
    mov     rdx, rcx
    call    convert_to_lowercase
    mov     r14, rax

check_forwarder_dll_name_crc:
    push    rcx
    mov     rcx, r14
    call    generate_crc32_hash
    mov     r13, rax
    pop     rcx

check_forwarder_dll_name_crc_ntdll:
    mov     r12, 0xC6EF63DE
    cmp     r12, r13                ; ntdll crc32 hash
    jne     check_import_dll_crc_kernel32
    mov     rax, qword [rbp + 0x20]
    jmp     imported_forwarder_dll

check_forwarder_dll_name_crc_kernel32:
    mov     r12, 0x204C64E5
    cmp     r12, r13                ; kernel32 crc32 hash
    jne     check_import_dll_crc_kernelbase
    mov     rax, qword [rbp + 0x18]
    jmp     imported_forwarder_dll

check_forwarder_dll_name_crc_kernelbase:
    mov     r12, 0x0C8ED797
    cmp     r12, r13                ; kernelbase crc32 hash
    jne     check_import_dll_crc_apphelp
    mov     rax, qword [rbp + 0x10]
    jmp     imported_forwarder_dll

check_forwarder_dll_name_crc_apphelp:
    mov     r12, 0x6B9EF691
    cmp     r12, r13                ; apphelp crc32 hash
    jne     call_loadlibrary_2
    mov     rax, qword [rbp + 0x10]
    jmp     imported_forwarder_dll

call_loadlibrary_2:
    sub     rsp, 0x20               ; 32 bytes of shadow space
    mov     rcx, r10                ; forwarder dll name address
    call    qword [rbp - 0x10]      ; LoadLibraryA
    add     rsp, 0x20               ; remove 32 bytes of shadow space

imported_forwarder_dll:
    mov     rcx, rax                ; forwarder dll base address
    mov     rdx, r11                ; forwarder dll function name address
    call    parse_exports

    jmp     parse_exports_done

check_forwarder_done:
    mov     rax, r8

parse_exports_done:
    pop     r8
    pop     rdi
    pop     rbx
    pop     rbp
    ret

recover_nt_header_2:
    pushaq

    call    fetch_nt_header
    mov     rcx, rdx                    ; data003 (input pe nt header section) SizeOfRawData
    mov     rsi, rax                    ; data003 (input pe nt header section) VirtualAddress + pe image base address
    mov     rdx, qword [rbp + 0x28]     ; pe image base address
    mov     edi, dword [rdx + _IMAGE_DOS_HEADER.e_lfanew]
    add     rdi, rdx                    ; nt header address
    rep     movsb    

    lea     r9, [rsp - 8]               ; 4th argument: PDWORD lpflOldProtect
    mov     r8, PAGE_READONLY           ; 3rd argument: DWORD  flNewProtect
    mov     rdx, 0x1000                 ; 2nd argument: SIZE_T dwSize
    mov     rcx, qword [rbp + 0x28]     ; 1st argument: LPVOID lpAddress
    sub     rsp, 0x28                   ; 32 bytes of shadow space and 8 bytes argument space (lpflOldProtect)
    call    qword [rbp - 0x18]          ; VirtualProtect
    add     rsp, 0x28                   ; remove 32 bytes of shadow space and 8 bytes argument space (lpflOldProtect)

    popaq
    ret

lookup_oep:
    push    rbp

    mov     rax, qword [rbp + 0x28] ; add image base address
    mov     ebx, dword [rax + _IMAGE_DOS_HEADER.e_lfanew]
    add     rax, rbx
    lea     rax, [rax + _IMAGE_NT_HEADERS64.OptionalHeader]
    mov     ebx, dword [rax + _IMAGE_OPTIONAL_HEADER64.AddressOfEntryPoint]
    add     rbx, qword [rbp + 0x28] ; add image base address
    mov     rax, rbx

    pop     rbp
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
    push    rdi

    mov     rdi, rcx
    or      eax, -1

crc_outer:
    xor     al, byte [rdi]
    push    8
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
    pop     rdi
    ret

