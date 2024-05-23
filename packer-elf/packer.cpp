/*
 * Title:  packer.cpp
 * Author: Shuichiro Endo
 *
 * g++ packer.cpp -o packer -lz
 */

#define _DEBUG

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <elf.h>
#include <zlib.h>

#define MAX_FILE_SIZE 10240000  // 10 MB
#define CHUNK_SIZE 16384    // 0x4000


static void print_bytes(unsigned char *input, int input_length)
{
    printf("%08x  ", 0);
    for(int i=0; i<input_length; i++){
        if(i != 0 && i%16 == 0){
            printf("\n%08x  ", i);
        }else if(i%16 == 8){
            printf(" ");
        }
        printf("%02x ", input[i]);
    }
    printf("\n");

    return;
}


static Elf64_Xword align_memory_address(Elf64_Xword address, Elf64_Xword align)
{
    if(address % align){
        return (((address / align) + 1) * align);
    }

    return ((address / align) * align);
}


static Elf64_Xword get_image_size(char *buffer)
{
    Elf64_Ehdr *elf_header_pointer = (Elf64_Ehdr *)buffer;
    Elf64_Off e_phoff = elf_header_pointer->e_phoff;
    Elf64_Half e_phnum = elf_header_pointer->e_phnum;
    Elf64_Phdr *elf_program_header_pointer = (Elf64_Phdr *)(buffer + e_phoff);
    Elf64_Xword image_size = 0;


    for(Elf64_Off i=0; i<e_phnum; i++){
        if(elf_program_header_pointer[i].p_type == PT_LOAD){
            image_size = align_memory_address(elf_program_header_pointer[i].p_vaddr + elf_program_header_pointer[i].p_memsz, elf_program_header_pointer[i].p_align);
        }
    }

    return image_size;
}


static Elf64_Phdr *get_program_header(char *buffer)
{
    Elf64_Ehdr *elf_header_pointer = (Elf64_Ehdr *)buffer;
    Elf64_Off e_phoff = elf_header_pointer->e_phoff;
    Elf64_Half e_phnum = elf_header_pointer->e_phnum;
    Elf64_Phdr *elf_program_header_pointer = (Elf64_Phdr *)(buffer + e_phoff);

    return elf_program_header_pointer;
}


static char *get_interpreter(char *buffer)
{
    Elf64_Ehdr *elf_header_pointer = (Elf64_Ehdr *)buffer;
    Elf64_Off e_phoff = elf_header_pointer->e_phoff;
    Elf64_Half e_phnum = elf_header_pointer->e_phnum;
    Elf64_Phdr *elf_program_header_pointer = (Elf64_Phdr *)(buffer + e_phoff);
    char *interpreter_pointer = NULL;


    for(Elf64_Off i=0; i<e_phnum; i++){
        if(elf_program_header_pointer[i].p_type == PT_INTERP){
            interpreter_pointer = buffer + elf_program_header_pointer[i].p_offset;
            break;
        }
    }

    return interpreter_pointer;
}


static bool check_elf_file(char *buffer)
{
    Elf64_Ehdr *elf_header_pointer = NULL;


    elf_header_pointer = (Elf64_Ehdr *)buffer;
    if(elf_header_pointer->e_ident[EI_MAG0] != ELFMAG0 || elf_header_pointer->e_ident[EI_MAG1] != ELFMAG1 || elf_header_pointer->e_ident[EI_MAG2] != ELFMAG2 || elf_header_pointer->e_ident[EI_MAG3] != ELFMAG3){
        printf("[E] invalid elf format\n");
        return false;
    }

    if(elf_header_pointer->e_ident[EI_CLASS] != ELFCLASS64){
        printf("[E] not a 64bit object\n");
        return false;
    }

    if(elf_header_pointer->e_ident[EI_DATA] != ELFDATA2LSB){
        printf("[E] not little endian\n");
        return false;
    }

    if(elf_header_pointer->e_ident[EI_OSABI] != ELFOSABI_SYSV){
        printf("[E] not SYSV\n");
        return false;
    }

    if(!(elf_header_pointer->e_type == ET_EXEC || elf_header_pointer->e_type == ET_DYN)){
        printf("[E] not a executable file\n");
        return false;
    }

    if(elf_header_pointer->e_machine != EM_X86_64){
        printf("[E] not AMD x86-64 architecture\n");
        return false;
    }

    if(elf_header_pointer->e_version != EV_CURRENT){
        printf("[E] invalid elf version\n");
        return false;
    }


    return true;
}


static bool dump_mapped_image(char *input_elf_buffer, char *image_buffer, Elf64_Xword image_size)
{
    Elf64_Ehdr *elf_header_pointer = (Elf64_Ehdr *)input_elf_buffer;
    Elf64_Off e_phoff = elf_header_pointer->e_phoff;
    Elf64_Half e_phnum = elf_header_pointer->e_phnum;
    Elf64_Phdr *elf_program_header_pointer = (Elf64_Phdr *)(input_elf_buffer + e_phoff);


    for(Elf64_Off i=0; i<e_phoff; i++){
        if(elf_program_header_pointer[i].p_type == PT_LOAD){
            if(elf_program_header_pointer[i].p_vaddr + elf_program_header_pointer[i].p_filesz > image_size){
                return false;
            }
            memcpy(image_buffer + elf_program_header_pointer[i].p_vaddr, input_elf_buffer + elf_program_header_pointer[i].p_offset, elf_program_header_pointer[i].p_filesz);
        }
    }

    return true;
}


static int compress_data(char *image_buffer, Elf64_Xword image_size, char *compressed_image_buffer, Elf64_Xword *compressed_image_size, int deflate_compression_level)
{
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque =Z_NULL;

    unsigned char in[CHUNK_SIZE];
    unsigned char out[CHUNK_SIZE];

    int flush = 0;
    unsigned int have;
    int ret = 0;

    Elf64_Xword input_count = 0;
    Elf64_Xword output_count = 0;


    ret = deflateInit(&strm, deflate_compression_level);
    if(ret != Z_OK){
        return ret;
    }

    do{
        if(input_count + CHUNK_SIZE >= image_size){
            strm.avail_in = image_size - input_count;
            flush = Z_FINISH;
        }else{
            strm.avail_in = CHUNK_SIZE;
            flush = Z_NO_FLUSH;
        }

        bzero(in, CHUNK_SIZE);
        memcpy(in, image_buffer + input_count, strm.avail_in);
        strm.next_in = in;
        input_count += strm.avail_in;

        do{
            strm.avail_out = CHUNK_SIZE;
            strm.next_out = out;

            ret = deflate(&strm, flush);
            if(ret == Z_STREAM_ERROR){
                printf("[E] deflate error:%d\n", ret);
                goto error;
            }

            have = CHUNK_SIZE - strm.avail_out;
            if(have > 0){
                if(output_count + have > image_size){
                    printf("[E] allocated memory size error\n");
                    goto error;
                }
                memcpy(compressed_image_buffer + output_count, out, have);
                output_count += have;
                bzero(out, CHUNK_SIZE);
            }
        }while(strm.avail_out == 0);

        if(strm.avail_in != 0){
            printf("[E] avail_in error:%d\n", strm.avail_in);
            goto error;
        }
    }while(flush != Z_FINISH);

    *compressed_image_size = output_count;
    deflateEnd(&strm);
    return Z_OK;

error:
    deflateEnd(&strm);
    return Z_ERRNO;
}


static Elf64_Xword get_headers_size(char *buffer)
{
    Elf64_Ehdr *elf_header_pointer = (Elf64_Ehdr *)buffer;

    return (Elf64_Xword)(elf_header_pointer->e_ehsize + elf_header_pointer->e_phentsize * elf_header_pointer->e_phnum);
}


static bool encrypt_headers(char *headers_buffer, Elf64_Xword headers_size, char *encrypted_headers_buffer, Elf64_Xword *encrypted_headers_size)
{
    unsigned char key[] = {0xef, 0xbe, 0xad, 0xde, 0x0};
    Elf64_Xword key_length = 4;

    for(Elf64_Xword i=0; i<headers_size; i++){
        encrypted_headers_buffer[i] = (char)headers_buffer[i] ^ (char)key[i % key_length];
    }

    *encrypted_headers_size = headers_size;

    return true;
}


static bool link_data(char *input_elf_buffer, char *output_elf_buffer, Elf64_Xword *output_elf_size, char *stub_buffer, Elf64_Xword stub_size, char *compressed_image_buffer, Elf64_Xword compressed_image_size, char *encrypted_headers_buffer, Elf64_Xword encrypted_headers_size)
{
    Elf64_Ehdr *input_elf_header_pointer = (Elf64_Ehdr *)input_elf_buffer;
    Elf64_Ehdr *output_elf_header_pointer = (Elf64_Ehdr *)output_elf_buffer;
    Elf64_Phdr *output_program_header_pointer = NULL;

    Elf64_Xword output_offset = 0;

    char *input_interpreter_pointer = NULL;
    char *output_interpreter_pointer = NULL;
    Elf64_Xword output_interpreter_offset = 0;
    Elf64_Xword output_interpreter_length = 0;

    char *output_dt_needed_libc_string_pointer = NULL;        // DT_NEEDED
    Elf64_Xword output_dt_needed_libc_string_length = 0;      // DT_NEEDED
    Elf64_Xword output_dt_needed_libc_string_offset = 0;      // DT_NEEDED

    Elf64_Xword output_dt_strtab_string_offset = 0;     // DT_STRTAB
    Elf64_Xword output_dt_strsz_string_size = 0;        // DT_STRSZ

    Elf64_Xword output_dt_symtab_offset = 0;            // DT_SYMTAB
    Elf64_Xword output_dt_syment_size = 0x18;           // DT_SYMENT

    Elf64_Xword output_dt_relaent_size = 0x18;          // DT_RELAENT

    Elf64_Xword stub_address_addition = 0x10000;

    Elf64_Dyn *output_dynamic_pointer = NULL;
    int dymamic_count = 0;


    // copy elf header
    memcpy(output_elf_buffer, input_elf_buffer, input_elf_header_pointer->e_ehsize);

    // fix elf header
    output_elf_header_pointer->e_phnum = 0x8;   // PHDR + INTERP + LOAD * 5 + DYNAMIC
    output_elf_header_pointer->e_shoff = 0x0;
    output_elf_header_pointer->e_shentsize = 0x0;
    output_elf_header_pointer->e_shnum = 0x0;
    output_elf_header_pointer->e_shstrndx = 0x0;

    // program header[0]: program header
    output_program_header_pointer = get_program_header(output_elf_buffer);
    output_program_header_pointer[0].p_type = PT_PHDR;
    output_program_header_pointer[0].p_flags = PF_R;
    output_program_header_pointer[0].p_offset = output_elf_header_pointer->e_phoff;
    output_program_header_pointer[0].p_vaddr = output_elf_header_pointer->e_phoff;
    output_program_header_pointer[0].p_paddr = output_elf_header_pointer->e_phoff;
    output_program_header_pointer[0].p_filesz = sizeof(Elf64_Phdr) * output_elf_header_pointer->e_phnum;
    output_program_header_pointer[0].p_memsz = sizeof(Elf64_Phdr) * output_elf_header_pointer->e_phnum;
    output_program_header_pointer[0].p_align = 0x8;

    // interpreter
    input_interpreter_pointer = get_interpreter(input_elf_buffer);
    if(input_interpreter_pointer == NULL){
        printf("[E] get_interpreter error\n");
        return false;
    }
    output_interpreter_offset = output_program_header_pointer[0].p_offset + output_program_header_pointer[0].p_filesz;
    output_interpreter_pointer = output_elf_buffer + output_interpreter_offset;
    output_interpreter_length = strlen(input_interpreter_pointer) + 1;
    memcpy(output_interpreter_pointer, input_interpreter_pointer, output_interpreter_length);

    output_offset = align_memory_address(output_interpreter_offset + output_interpreter_length, output_program_header_pointer[0].p_align);

    // dynamic[]: DT_SYMTAB
    output_dt_symtab_offset = output_offset;
    output_offset = align_memory_address(output_offset + output_dt_syment_size, output_program_header_pointer[0].p_align);

    // dynamic[]: DT_STRTAB
    output_dt_strtab_string_offset = output_offset;
    output_dt_strsz_string_size = 0;    // update after

    // dynamic[]: DT_NEEDED libc.so.6
    output_offset++;                // write \0
    output_dt_strsz_string_size++;  // write \0
    output_dt_needed_libc_string_offset = 0x1;  // string table offset
    output_dt_needed_libc_string_pointer = output_elf_buffer + output_offset;
    output_dt_needed_libc_string_length = strlen("libc.so.6");
    memcpy(output_dt_needed_libc_string_pointer, "libc.so.6", output_dt_needed_libc_string_length);

    output_offset += output_dt_needed_libc_string_length + 1;
    output_dt_strsz_string_size += output_dt_needed_libc_string_length + 1;

    // program header[1]: interpreter
    output_program_header_pointer[1].p_type = PT_INTERP;
    output_program_header_pointer[1].p_flags = PF_R;
    output_program_header_pointer[1].p_offset = output_interpreter_offset;
    output_program_header_pointer[1].p_vaddr = output_interpreter_offset;
    output_program_header_pointer[1].p_paddr = output_interpreter_offset;
    output_program_header_pointer[1].p_filesz = output_interpreter_length;
    output_program_header_pointer[1].p_memsz = output_interpreter_length;
    output_program_header_pointer[1].p_align = 0x1;

    // program header[2]: load (decompress data)
    output_program_header_pointer[2].p_type = PT_LOAD;
    output_program_header_pointer[2].p_flags = PF_R | PF_W;
    output_program_header_pointer[2].p_offset = 0x0;
    output_program_header_pointer[2].p_vaddr = 0x0;
    output_program_header_pointer[2].p_paddr = 0x0;
    output_program_header_pointer[2].p_filesz = output_offset;  // elf header + program header + interpreter + symbol table + string table
    output_program_header_pointer[2].p_memsz = get_image_size(input_elf_buffer);   // image_size
    output_program_header_pointer[2].p_align = 0x1000;

    // program header[3]: load (stub)
    output_program_header_pointer[3].p_type = PT_LOAD;
    output_program_header_pointer[3].p_flags = PF_R | PF_X;
    output_program_header_pointer[3].p_offset = align_memory_address(output_program_header_pointer[2].p_offset + output_program_header_pointer[2].p_filesz, output_program_header_pointer[2].p_align);
    output_program_header_pointer[3].p_vaddr = align_memory_address(output_program_header_pointer[2].p_memsz + stub_address_addition, output_program_header_pointer[2].p_align);
    output_program_header_pointer[3].p_paddr = align_memory_address(output_program_header_pointer[2].p_memsz + stub_address_addition, output_program_header_pointer[2].p_align);
    output_program_header_pointer[3].p_filesz = stub_size;
    output_program_header_pointer[3].p_memsz = stub_size;
    output_program_header_pointer[3].p_align = 0x1000;
    memcpy(output_elf_buffer + output_program_header_pointer[3].p_offset, stub_buffer, stub_size);

    // program header[4]: load (compressed data)
    output_program_header_pointer[4].p_type = PT_LOAD;
    output_program_header_pointer[4].p_flags = PF_R;
    output_program_header_pointer[4].p_offset = align_memory_address(output_program_header_pointer[3].p_offset + output_program_header_pointer[3].p_filesz, output_program_header_pointer[3].p_align);
    output_program_header_pointer[4].p_vaddr = align_memory_address(output_program_header_pointer[3].p_vaddr + output_program_header_pointer[3].p_memsz, output_program_header_pointer[3].p_align);
    output_program_header_pointer[4].p_paddr = align_memory_address(output_program_header_pointer[3].p_paddr + output_program_header_pointer[3].p_memsz, output_program_header_pointer[3].p_align);
    output_program_header_pointer[4].p_filesz = compressed_image_size;
    output_program_header_pointer[4].p_memsz = compressed_image_size;
    output_program_header_pointer[4].p_align = 0x1000;
    memcpy(output_elf_buffer + output_program_header_pointer[4].p_offset, compressed_image_buffer, compressed_image_size);

    // program header[5]: load (saved input elf and program header)
    output_program_header_pointer[5].p_type = PT_LOAD;
    output_program_header_pointer[5].p_flags = PF_R | PF_W;
    output_program_header_pointer[5].p_offset = align_memory_address(output_program_header_pointer[4].p_offset + output_program_header_pointer[4].p_filesz, output_program_header_pointer[4].p_align);
    output_program_header_pointer[5].p_vaddr = align_memory_address(output_program_header_pointer[4].p_vaddr + output_program_header_pointer[4].p_memsz, output_program_header_pointer[4].p_align);
    output_program_header_pointer[5].p_paddr = align_memory_address(output_program_header_pointer[4].p_paddr + output_program_header_pointer[4].p_memsz, output_program_header_pointer[4].p_align);
    output_program_header_pointer[5].p_filesz = encrypted_headers_size;
    output_program_header_pointer[5].p_memsz = encrypted_headers_size;
    output_program_header_pointer[5].p_align = 0x1000;
    memcpy(output_elf_buffer + output_program_header_pointer[5].p_offset, encrypted_headers_buffer, encrypted_headers_size);

    // program header[6]: load dynamic
    output_dynamic_pointer = (Elf64_Dyn *)(output_elf_buffer + align_memory_address(output_program_header_pointer[5].p_offset + output_program_header_pointer[5].p_filesz, output_program_header_pointer[5].p_align));
    dymamic_count = 0;

    // dynamic[]: DT_NEEDED libc.so.6
    output_dynamic_pointer[dymamic_count].d_tag = DT_NEEDED;
    output_dynamic_pointer[dymamic_count].d_un.d_val = output_dt_needed_libc_string_offset;
    dymamic_count++;

    //dynamic[]: DT_INIT
    output_dynamic_pointer[dymamic_count].d_tag = DT_INIT;
    output_dynamic_pointer[dymamic_count].d_un.d_ptr = 0x0;
    dymamic_count++;

    // dynamic[]: DT_FINI
    output_dynamic_pointer[dymamic_count].d_tag = DT_FINI;
    output_dynamic_pointer[dymamic_count].d_un.d_ptr = 0x0;
    dymamic_count++;

    // dynamic[]: DT_INIT_ARRAY
    output_dynamic_pointer[dymamic_count].d_tag = DT_INIT_ARRAY;
    output_dynamic_pointer[dymamic_count].d_un.d_ptr = 0x0;
    dymamic_count++;

    // dynamic[]: DT_INIT_ARRAYSZ
    output_dynamic_pointer[dymamic_count].d_tag = DT_INIT_ARRAYSZ;
    output_dynamic_pointer[dymamic_count].d_un.d_val = 0x0;
    dymamic_count++;

    // dynamic[]: DT_FINI_ARRAY
    output_dynamic_pointer[dymamic_count].d_tag = DT_FINI_ARRAY;
    output_dynamic_pointer[dymamic_count].d_un.d_ptr = 0x0;
    dymamic_count++;

    // dynamic[]: DT_FINI_ARRAYSZ
    output_dynamic_pointer[dymamic_count].d_tag = DT_FINI_ARRAYSZ;
    output_dynamic_pointer[dymamic_count].d_un.d_val = 0x0;
    dymamic_count++;

    // dynamic[]: DT_GNU_HASH
    // output_dynamic_pointer[dymamic_count].d_tag = DT_GNU_HASH;
    // output_dynamic_pointer[dymamic_count].d_un.d_val = 0x0;
    // dymamic_count++;

    // dynamic[]: DT_STRTAB
    output_dynamic_pointer[dymamic_count].d_tag = DT_STRTAB;
    output_dynamic_pointer[dymamic_count].d_un.d_ptr = output_dt_strtab_string_offset;
    dymamic_count++;

    // dynamic[]: DT_SYMTAB
    output_dynamic_pointer[dymamic_count].d_tag = DT_SYMTAB;
    output_dynamic_pointer[dymamic_count].d_un.d_ptr = output_dt_symtab_offset;
    dymamic_count++;

    // dynamic[]: DT_STRSZ
    output_dynamic_pointer[dymamic_count].d_tag = DT_STRSZ;
    output_dynamic_pointer[dymamic_count].d_un.d_val = output_dt_strsz_string_size;
    dymamic_count++;

    // dynamic[]: DT_SYMENT
    output_dynamic_pointer[dymamic_count].d_tag = DT_SYMENT;
    output_dynamic_pointer[dymamic_count].d_un.d_val = output_dt_syment_size;
    dymamic_count++;

    // dynamic[]: DT_DEBUG
    // output_dynamic_pointer[dymamic_count].d_tag = DT_DEBUG;
    // output_dynamic_pointer[dymamic_count].d_un.d_val = 0x0;
    // dymamic_count++;

    // dynamic[]: DT_RELA
    output_dynamic_pointer[dymamic_count].d_tag = DT_RELA;
    output_dynamic_pointer[dymamic_count].d_un.d_ptr = 0x0;
    dymamic_count++;

    // dynamic[]: DT_RELASZ
    output_dynamic_pointer[dymamic_count].d_tag = DT_RELASZ;
    output_dynamic_pointer[dymamic_count].d_un.d_val = 0x0;
    dymamic_count++;

    // dynamic[]: DT_RELAENT
    output_dynamic_pointer[dymamic_count].d_tag = DT_RELAENT;
    output_dynamic_pointer[dymamic_count].d_un.d_val = output_dt_relaent_size;
    dymamic_count++;

    // dynamic[]: DT_FLAGS
    output_dynamic_pointer[dymamic_count].d_tag = DT_FLAGS;
    output_dynamic_pointer[dymamic_count].d_un.d_val = DF_BIND_NOW;
    dymamic_count++;

    // dynamic[]: DT_FLAGS_1
    output_dynamic_pointer[dymamic_count].d_tag = DT_FLAGS_1;
    output_dynamic_pointer[dymamic_count].d_un.d_val = DF_1_NOW | DF_1_PIE;
    dymamic_count++;

    // dynamic[]: DT_VERNEED
    // output_dynamic_pointer[dymamic_count].d_tag = DT_VERNEED;
    // output_dynamic_pointer[dymamic_count].d_un.d_ptr = 0x0;
    // dymamic_count++;

    // dynamic[]: DT_VERNEEDNUM
    // output_dynamic_pointer[dymamic_count].d_tag = DT_VERNEEDNUM;
    // output_dynamic_pointer[dymamic_count].d_un.d_val = 0x0;
    // dymamic_count++;

    // dynamic[]: DT_VERSYM
    // output_dynamic_pointer[dymamic_count].d_tag = DT_VERSYM;
    // output_dynamic_pointer[dymamic_count].d_un.d_ptr = 0x0;
    // dymamic_count++;

    // dynamic[]: DT_RELR
    // output_dynamic_pointer[dymamic_count].d_tag = DT_RELR;
    // output_dynamic_pointer[dymamic_count].d_un.d_ptr = 0x0;
    // dymamic_count++;

    // dynamic[]: DT_RELRSZ
    // output_dynamic_pointer[dymamic_count].d_tag = DT_RELRSZ;
    // output_dynamic_pointer[dymamic_count].d_un.d_val = 0x0;
    // dymamic_count++;

    // dynamic[]: DT_RELRENT
    // output_dynamic_pointer[dymamic_count].d_tag = DT_RELRENT;
    // output_dynamic_pointer[dymamic_count].d_un.d_val = 0x0;
    // dymamic_count++;

    // dynamic[]: DT_NULL
    output_dynamic_pointer[dymamic_count].d_tag = DT_NULL;
    output_dynamic_pointer[dymamic_count].d_un.d_val = 0x0;
    dymamic_count++;

    output_program_header_pointer[6].p_type = PT_LOAD;
    output_program_header_pointer[6].p_flags = PF_R | PF_W;
    output_program_header_pointer[6].p_offset = align_memory_address(output_program_header_pointer[5].p_offset + output_program_header_pointer[5].p_filesz, output_program_header_pointer[5].p_align);
    output_program_header_pointer[6].p_vaddr = align_memory_address(output_program_header_pointer[5].p_vaddr + output_program_header_pointer[5].p_memsz, output_program_header_pointer[5].p_align);
    output_program_header_pointer[6].p_paddr = align_memory_address(output_program_header_pointer[5].p_paddr + output_program_header_pointer[5].p_memsz, output_program_header_pointer[5].p_align);
    output_program_header_pointer[6].p_filesz = 0x10 * dymamic_count;
    output_program_header_pointer[6].p_memsz = 0x10 * dymamic_count;
    output_program_header_pointer[6].p_align = 0x1000;

    // program header[7]: dynamic
    output_program_header_pointer[7].p_type = PT_DYNAMIC;
    output_program_header_pointer[7].p_flags = PF_W | PF_R;
    output_program_header_pointer[7].p_offset = output_program_header_pointer[6].p_offset;
    output_program_header_pointer[7].p_vaddr = output_program_header_pointer[6].p_vaddr;
    output_program_header_pointer[7].p_paddr = output_program_header_pointer[6].p_paddr;
    output_program_header_pointer[7].p_filesz = output_program_header_pointer[6].p_filesz;
    output_program_header_pointer[7].p_memsz = output_program_header_pointer[6].p_memsz;
    output_program_header_pointer[7].p_align = 0x8;

    // write entry point
    output_elf_header_pointer->e_entry = output_program_header_pointer[3].p_vaddr;  // stub

    // output pe size
    *output_elf_size = output_program_header_pointer[6].p_offset + output_program_header_pointer[6].p_filesz;

    return true;
}


static void usage(char *filename)
{
    printf("usage   : %s elf_file deflate_compression_level(1-9)\n", filename);
    printf("example : %s main 9\n", filename);

    return;
}


int main(int argc, char **argv)
{
    int deflate_compression_level = 0;

    char *input_elf_file_name = NULL;
    char *output_elf_file_name = NULL;

    FILE *file_pointer = NULL;

    char *input_elf_buffer = NULL;
    Elf64_Xword input_elf_size = 0;

    char *image_buffer = NULL;
    Elf64_Xword image_size = 0;

    char *compressed_image_buffer = NULL;
    Elf64_Xword compressed_image_size = 0;

    char *stub_buffer = NULL;
    Elf64_Xword stub_size = 0;

    char *headers_buffer = NULL;
    Elf64_Xword headers_size = 0;

    char *encrypted_headers_buffer = NULL;
    Elf64_Xword encrypted_headers_size = 0;

    char *output_elf_buffer = NULL;
    Elf64_Xword output_elf_size = 0;


    if(argc != 3){
        usage(argv[0]);
        return 0;
    }

    if(strlen(argv[1]) > 200){
        printf("[E] input elf file name length is too long.\n");
        return -1;
    }

    deflate_compression_level = atoi(argv[2]);
    if(deflate_compression_level < 1 || deflate_compression_level > 9){
        printf("[W] invalid compression_level:%d\n", deflate_compression_level);
        deflate_compression_level = Z_DEFAULT_COMPRESSION;
    }
    if(deflate_compression_level == Z_DEFAULT_COMPRESSION){
        printf("[I] deflate_compression_level:Z_DEFAULT_COMPRESSION(%d)\n", Z_DEFAULT_COMPRESSION);
    }else{
        printf("[I] deflate_compression_level:%d\n", deflate_compression_level);
    }


    input_elf_file_name = argv[1];
    output_elf_file_name = new char[256];
    strncpy(output_elf_file_name, input_elf_file_name, strlen(input_elf_file_name));
    strncpy(output_elf_file_name + strlen(output_elf_file_name), "_packed\00", 8);
    printf("[I] output_elf_file_name: %s\n", output_elf_file_name);


    printf("[I] read %s file\n", input_elf_file_name);
    file_pointer = fopen(input_elf_file_name, "rb");
    if(file_pointer != NULL){
        fseek(file_pointer, 0, SEEK_END);
        input_elf_size = ftell(file_pointer);
        input_elf_buffer = (char *)calloc(input_elf_size + 1, sizeof(char));
        fseek(file_pointer, 0, SEEK_SET);
        fread(input_elf_buffer, sizeof(char), input_elf_size, file_pointer);
        fclose(file_pointer);
    }else{
        printf("[E] %s file open error\n", input_elf_file_name);
        goto error;
    }
    if(input_elf_size > MAX_FILE_SIZE){
        printf("[E] input elf file size error: %ld bytes\n", input_elf_size);
        goto error;
    }
    printf("[I] %s file size:%ld\n", input_elf_file_name, input_elf_size);


    printf("[I] check %s file\n", input_elf_file_name);
    if(!check_elf_file(input_elf_buffer)){
        printf("[E] check_elf_file error\n");
        goto error;
    }


    printf("[I] dump mapped image\n");
    image_size = get_image_size(input_elf_buffer);
    image_buffer = (char *)calloc(image_size, sizeof(char));
    if(!dump_mapped_image(input_elf_buffer, image_buffer, image_size)){
        printf("[E] dump_mapped_image error\n");
        goto error;
    }
//    print_bytes((unsigned char *)image_buffer, image_size);


    printf("[I] compress image data\n");
    compressed_image_buffer = (char *)calloc(image_size, sizeof(char));
    if(compress_data(image_buffer, image_size, compressed_image_buffer, &compressed_image_size, deflate_compression_level) != Z_OK){
        printf("[E] compress_data error\n");
        goto error;
    }
//    print_bytes((unsigned char *)compressed_image_buffer, compressed_image_size);


    printf("[I] encrypt headers\n");
    headers_buffer = input_elf_buffer;
    headers_size = get_headers_size(input_elf_buffer);
    encrypted_headers_buffer = (char *)calloc(headers_size, sizeof(char));
    if(!encrypt_headers(headers_buffer, headers_size, encrypted_headers_buffer, &encrypted_headers_size)){
        printf("[E] encrypt_headers error\n");
        goto error;
    }
//    print_bytes((unsigned char *)encrypted_headers_buffer, encrypted_headers_size);


    printf("[I] read stub.bin file\n");
    file_pointer = fopen("stub.bin", "rb");
    if(file_pointer != NULL){
        fseek(file_pointer, 0, SEEK_END);
        stub_size = ftell(file_pointer);
        stub_buffer = (char *)calloc(stub_size + 1, sizeof(char));
        fseek(file_pointer, 0, SEEK_SET);
        fread(stub_buffer, sizeof(char), stub_size, file_pointer);
        fclose(file_pointer);
    }else{
        printf("[E] stub.bin file open error\n");
        goto error;
    }
//    print_bytes((unsigned char *)stub_buffer, stub_size);


    printf("[I] link data\n");
    output_elf_buffer = (char *)calloc(MAX_FILE_SIZE+5000000, sizeof(char));
    if(!link_data(input_elf_buffer, output_elf_buffer, &output_elf_size, stub_buffer, stub_size, compressed_image_buffer, compressed_image_size, encrypted_headers_buffer, encrypted_headers_size)){
        printf("[E] link_data error\n");
        goto error;
    }


    printf("[I] write %s file\n", output_elf_file_name);
    file_pointer = fopen(output_elf_file_name, "wb");
    if(file_pointer != NULL){
        fwrite(output_elf_buffer, sizeof(char), output_elf_size, file_pointer);
        fclose(file_pointer);
    }else{
        printf("[E] %s file open error\n", output_elf_file_name);
        goto error;
    }
    printf("[I] %s file size: %ld bytes\n", output_elf_file_name, output_elf_size);


    delete [] output_elf_file_name;
    free(input_elf_buffer);
    free(image_buffer);
    free(compressed_image_buffer);
    free(encrypted_headers_buffer);
    free(stub_buffer);
    free(output_elf_buffer);
    return 0;

error:
    delete [] output_elf_file_name;
    free(input_elf_buffer);
    free(image_buffer);
    free(compressed_image_buffer);
    free(encrypted_headers_buffer);
    free(stub_buffer);
    free(output_elf_buffer);
    return -1;
}

