; Title:  stub.inc
; Author: Shuichiro Endo

peb64                         equ       60h
image_base_address            equ       10h   
ldr                           equ       18h

in_memory_order_module_list   equ       20h
dll_base                      equ       20h

IMAGE_DIRECTORY_ENTRY_EXPORT  equ       88h
IMAGE_DIRECTORY_ENTRY_IMPORT  equ       90h
IMAGE_DIRECTORY_ENTRY_RELOCS  equ       0b0h

IMAGE_ORDINAL_FLAG64          equ       8000000000000000h

IMAGE_REL_BASED_DIR64         equ       0ah

COMPRESSION_FORMAT_LZNT1      equ       02h

PAGE_EXECUTE                  equ       10h
PAGE_EXECUTE_READ             equ       20h
PAGE_EXECUTE_READWRITE        equ       40h
PAGE_EXECUTE_WRITECOPY        equ       80h
PAGE_NOACCESS                 equ       01h
PAGE_READONLY                 equ       02h
PAGE_READWRITE                equ       04h
PAGE_WRITECOPY                equ       08h
PAGE_TARGETS_INVALID          equ       40000000h
PAGE_TARGETS_NO_UPDATE        equ       40000000h

SCN_MEM_EXECUTE_READ_WRITE    equ       0e0000000h
SCN_MEM_EXECUTE_READ          equ       60000000h
SCN_MEM_READ_WRITE            equ       0c0000000h
SCN_MEM_EXECUTE               equ       20000000h
SCN_MEM_READ                  equ       40000000h
SCN_MEM_WRITE                 equ       80000000h


struc _IMAGE_DOS_HEADER
.e_magic:       resw 1
.e_cblp:        resw 1
.e_cp:          resw 1
.e_crlc:        resw 1
.e_cparhdr:     resw 1
.e_minalloc:    resw 1
.e_maxalloc:    resw 1
.e_ss:          resw 1
.e_sp:          resw 1
.e_csum:        resw 1
.e_ip:          resw 1
.e_cs:          resw 1
.e_lfarlc:      resw 1
.e_ovno:        resw 1
.e_res:         resw 4
.e_oemid:       resw 1
.e_oeminfo:     resw 1
.e_res2:        resw 10
.e_lfanew:      resd 1
endstruc

struc _IMAGE_FILE_HEADER
.Machine:               resw 1
.NumberOfSections:      resw 1
.TimeDateStamp:         resd 1
.PointerToSymbolTable:  resd 1
.NumberOfSymbols:       resd 1
.SizeOfOptionalHeader:  resw 1
.Characteristics:       resw 1
endstruc

struc _IMAGE_DATA_DIRECTORY
.VirtualAddress:    resd 1
.Size:              resd 1
endstruc

struc _IMAGE_OPTIONAL_HEADER64
.Magic:                         resw 1
.MajorLinkerVersion:            resb 1
.MinorLinkerVersion:            resb 1
.SizeOfCode:                    resd 1
.SizeOfInitializedData:         resd 1
.SizeOfUninitializedData:       resd 1
.AddressOfEntryPoint:           resd 1
.BaseOfCode:                    resd 1
.ImageBase:                     resq 1
.SectionAlignment:              resd 1
.FileAlignment:                 resd 1
.MajorOperatingSystemVersion:   resw 1
.MinorOperatingSystemVersion:   resw 1
.MajorImageVersion:             resw 1
.MinorImageVersion:             resw 1
.MajorSubsystemVersion:         resw 1
.MinorSubsystemVersion:         resw 1
.Win32VersionValue:             resd 1
.SizeOfImage:                   resd 1
.SizeOfHeaders:                 resd 1
.CheckSum:                      resd 1
.Subsystem:                     resw 1
.DllCharacteristics:            resw 1
.SizeOfStackReserve:            resq 1
.SizeOfStackCommit:             resq 1
.SizeOfHeapReserve:             resq 1
.SizeOfHeapCommit:              resq 1
.LoaderFlags:                   resd 1
.NumberOfRvaAndSizes:           resd 1
.DataDirectory:                 resb _IMAGE_DATA_DIRECTORY_size
endstruc

struc _IMAGE_NT_HEADERS64
.Signature:         resd 1
.FileHeader:        resb _IMAGE_FILE_HEADER_size
.OptionalHeader:    resb _IMAGE_OPTIONAL_HEADER64_size
endstruc

struc _IMAGE_SECTION_HEADER
.Name:                  resb 8
.VirtualSize:           resd 1
.VirtualAddress:        resd 1
.SizeOfRawData:         resd 1
.PointerToRawData:      resd 1
.PointerToRelocations:  resd 1
.PointerToLinenumbers:  resd 1
.NumberOfRelocations:   resw 1
.NumberOfLinenumbers:   resw 1
.Characteristics:       resd 1
endstruc

struc _IMAGE_IMPORT_DESCRIPTOR
.OriginalFirstThunk:    resd 1
.TimeDateStamp:         resd 1
.ForwarderChain:        resd 1
.Name:                  resd 1
.FirstThunk:            resd 1
endstruc

struc _IMAGE_EXPORT_DIRECTORY
.Characteristics:        resd 1
.TimeDateStamp:          resd 1
.MajorVersion:           resw 1
.MinorVersion:           resw 1
.Name:                   resd 1
.Base:                   resd 1
.NumberOfFunctions:      resd 1
.NumberOfNames:          resd 1
.AddressOfFunctions:     resd 1
.AddressOfNames:         resd 1
.AddressOfNameOrdinals:  resd 1
endstruc

struc _IMAGE_BASE_RELOCATION
.PageRVA:           resd 1
.SizeOfBlock:       resd 1
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

