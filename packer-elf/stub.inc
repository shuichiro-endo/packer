; Title:  stub.inc
; Author: Shuichiro Endo

O_RDONLY                    equ     0x0
O_WRONLY                    equ     0x1
O_RDWR                      equ     0x2

SEEK_SET                    equ     0x0
SEEK_CUR                    equ     0x1
SEEK_END                    equ     0x2

RTLD_NOW                    equ     0x1

PROT_READ                   equ     0x1
PROT_WRITE                  equ     0x2
PROT_EXEC                   equ     0x4

PT_LOAD                     equ     0x1
PT_DYNAMIC                  equ     0x2
PT_INTERP                   equ     0x3

PF_X                        equ     0x1
PF_W                        equ     0x2
PF_R                        equ     0x4

DT_NULL                     equ     0x0
DT_STRTAB                   equ     0x5
DT_SYMTAB                   equ     0x6
DT_VERSYM                   equ     0x6ffffff0

STB_GLOBAL                  equ     0x1
STB_WEAK                    equ     0x2

STT_FUNC                    equ     0x2

AT_NULL                     equ     0x0
AT_PHDR                     equ     0x3
AT_PHENT                    equ     0x4
AT_PHNUM                    equ     0x5
AT_PAGESZ                   equ     0x6
AT_BASE                     equ     0x7
AT_ENTRY                    equ     0x9


struc _Elf64_auxv_t
.a_type         resq 1
.a_val          resq 1
endstruc

struc _Elf64_Ehdr
.e_ident        resb 16
.e_type         resw 1
.e_machine      resw 1
.e_version      resd 1
.e_entry        resq 1
.e_phoff        resq 1
.e_shoff        resq 1
.e_flags        resd 1
.e_ehsize       resw 1
.e_phentsize    resw 1
.e_phnum        resw 1
.e_shentsize    resw 1
.e_shnum        resw 1
.e_shstrndx     resw 1
endstruc

struc _Elf64_Phdr
.p_type         resd 1
.p_flags        resd 1
.p_offset       resq 1
.p_vaddr        resq 1
.p_paddr        resq 1
.p_filesz       resq 1
.p_memsz        resq 1
.p_align        resq 1
endstruc

struc _Elf64_Dyn
.d_tag          resq 1
.d_val          resq 1
endstruc

struc _Elf64_Sym
.st_name        resd 1
.st_info        resb 1
.st_other       resb 1
.st_shndx       resw 1
.st_value       resq 1
.st_size        resq 1
endstruc


%macro pushaq 0
    push rax
    push rbx
    push rcx
    push rdx
    push rbp
    push rdi
    push rsi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
%endmacro

%macro popaq 0
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rsi
    pop rdi
    pop rbp
    pop rdx
    pop rcx
    pop rbx
    pop rax
%endmacro

