/*
 * Title:  packer.cpp
 * Author: Shuichiro Endo
 */

#define _DEBUG

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <Windows.h>

#define MAX_FILE_SIZE 10240000  // 10 MB


typedef DWORD (WINAPI *_RtlGetCompressionWorkSpaceSize)(USHORT CompressionFormatAndEngine, PULONG CompressBufferWorkSpaceSize, PULONG CompressFragmentWorkSpaceSize);
typedef DWORD (WINAPI *_RtlCompressBuffer)(USHORT CompressionFormatAndEngine, PUCHAR UncompressedBuffer, ULONG UncompressedBufferSize, PUCHAR CompressedBuffer, ULONG CompressedBufferSize, ULONG UncompressedChunkSize, PULONG FinalCompressedSize, PVOID WorkSpace);


static DWORD align_memory_address(DWORD address, DWORD align)
{
    return ((((address) / (align)) + 1) * (align));
}


static PIMAGE_NT_HEADERS64 get_nt_header(char *buffer)
{
    PIMAGE_DOS_HEADER dos_header_pointer = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS64 nt_header_pointer = (PIMAGE_NT_HEADERS64)((LPBYTE)buffer + dos_header_pointer->e_lfanew);

    return nt_header_pointer;
}


static PIMAGE_FILE_HEADER get_file_header(char *buffer)
{
    PIMAGE_DOS_HEADER dos_header_pointer = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS64 nt_header_pointer = (PIMAGE_NT_HEADERS64)((LPBYTE)buffer + dos_header_pointer->e_lfanew);
    PIMAGE_FILE_HEADER file_header_pointer = (PIMAGE_FILE_HEADER)&nt_header_pointer->FileHeader;

    return file_header_pointer;
}


static PIMAGE_OPTIONAL_HEADER64 get_optional_header_64(char *buffer)
{
    PIMAGE_DOS_HEADER dos_header_pointer = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS64 nt_header_pointer = (PIMAGE_NT_HEADERS64)((LPBYTE)buffer + dos_header_pointer->e_lfanew);
    PIMAGE_OPTIONAL_HEADER64 optional_header_64_pointer = (PIMAGE_OPTIONAL_HEADER64)&nt_header_pointer->OptionalHeader;

    return optional_header_64_pointer;
}


static PIMAGE_SECTION_HEADER get_section_header(char *buffer)
{
    PIMAGE_DOS_HEADER dos_header_pointer = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_SECTION_HEADER section_header_pointer = (PIMAGE_SECTION_HEADER)((LPBYTE)buffer + dos_header_pointer->e_lfanew + sizeof(IMAGE_NT_HEADERS64));

    return section_header_pointer;
}


static DWORD get_section_count(char *buffer)
{
    PIMAGE_FILE_HEADER file_header_pointer = get_file_header(buffer);

    return (DWORD)file_header_pointer->NumberOfSections;
}


static bool check_pe_file(char *buffer)
{
    PIMAGE_DOS_HEADER dos_header_pointer = NULL;
    PIMAGE_NT_HEADERS32 nt_header_32_pointer = NULL;
    PIMAGE_NT_HEADERS64 nt_header_64_pointer = NULL;
    PIMAGE_FILE_HEADER file_header_pointer = NULL;
    PIMAGE_OPTIONAL_HEADER32 optional_header_32_pointer = NULL;
    PIMAGE_OPTIONAL_HEADER64 optional_header_64_pointer = NULL;


    dos_header_pointer = (PIMAGE_DOS_HEADER)buffer;
    if(dos_header_pointer->e_magic != IMAGE_DOS_SIGNATURE){
        printf("[E] invalid dos format\n");
        return false;
    }

    nt_header_64_pointer = (PIMAGE_NT_HEADERS64)((LPBYTE)buffer + dos_header_pointer->e_lfanew);
    if(nt_header_64_pointer->Signature != IMAGE_NT_SIGNATURE){
        printf("[E] invalid pe format\n");
        return false;
    }

    file_header_pointer = (PIMAGE_FILE_HEADER)&nt_header_64_pointer->FileHeader;
    if(!(file_header_pointer->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) || (file_header_pointer->Characteristics & IMAGE_FILE_DLL)){
        printf("[E] invalid executable image\n");
        return false;
    }

    nt_header_32_pointer = (PIMAGE_NT_HEADERS32)((LPBYTE)buffer + dos_header_pointer->e_lfanew);
    optional_header_32_pointer = (PIMAGE_OPTIONAL_HEADER32)&nt_header_32_pointer->OptionalHeader;
    optional_header_64_pointer = (PIMAGE_OPTIONAL_HEADER64)&nt_header_64_pointer->OptionalHeader;
    if(optional_header_32_pointer->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC || optional_header_64_pointer->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC){
        printf("[E] invalid architecture: this file is not a 64bit executable image\n");
        return false;
    }

    return true;
}


static bool dump_mapped_image(char *input_pe_buffer, char *image_buffer, DWORD *image_size)
{
    PIMAGE_FILE_HEADER file_header_pointer = get_file_header(input_pe_buffer);
    PIMAGE_SECTION_HEADER section_header_pointer = get_section_header(input_pe_buffer);


    for(size_t i=0; i<file_header_pointer->NumberOfSections; i++){
        memcpy(image_buffer + section_header_pointer[i].VirtualAddress - section_header_pointer[0].VirtualAddress, input_pe_buffer + section_header_pointer[i].PointerToRawData, section_header_pointer[i].SizeOfRawData);
    }

    return true;
}


static bool compress_data(char *image_buffer, DWORD image_size, char *compressed_image_buffer, DWORD *compressed_image_size)
{
    _RtlGetCompressionWorkSpaceSize RtlGetCompressionWorkSpaceSize = (_RtlGetCompressionWorkSpaceSize)GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlGetCompressionWorkSpaceSize");
    _RtlCompressBuffer RtlCompressBuffer = (_RtlCompressBuffer)GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlCompressBuffer");
    UCHAR *compress_buffer_workspace = NULL;
    ULONG compress_buffer_workspace_size = 0;
    ULONG compress_fragment_workspace_size = 0;
    DWORD status = 0;


    status = RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_LZNT1|COMPRESSION_ENGINE_STANDARD, &compress_buffer_workspace_size, &compress_fragment_workspace_size);
    if(status != 0){
        printf("[E] RtlGetCompressionWorkSpaceSize error:%08x\n", status);
        goto error;
    }

    compress_buffer_workspace = (UCHAR *)calloc(compress_buffer_workspace_size, sizeof(UCHAR));
    status = RtlCompressBuffer(COMPRESSION_FORMAT_LZNT1|COMPRESSION_ENGINE_STANDARD, (PUCHAR)image_buffer, image_size, (PUCHAR)compressed_image_buffer, image_size, 4096, compressed_image_size, compress_buffer_workspace);
    if(status != 0){
        printf("[E] RtlCompressBuffer error:%08x\n", status);
        goto error;
    }

    free(compress_buffer_workspace);
    return true;

error:
    free(compress_buffer_workspace);
    return false;
}


static bool link_data(char *input_pe_buffer, char *output_pe_buffer, DWORD *output_pe_size, char *stub_buffer, DWORD stub_size, char *compressed_image_buffer, DWORD compressed_image_size)
{
    PIMAGE_SECTION_HEADER output_pe_section_header = NULL;
    WORD size_of_optional_header = get_file_header(input_pe_buffer)->SizeOfOptionalHeader;
    DWORD section_alignment = get_optional_header_64(input_pe_buffer)->SectionAlignment;
    DWORD file_alignment = get_optional_header_64(input_pe_buffer)->FileAlignment;
    DWORD nt_header_64_size = sizeof(IMAGE_NT_HEADERS64);
    DWORD data_directory_size = sizeof(IMAGE_DATA_DIRECTORY);
    DWORD input_pe_section_count = get_section_count(input_pe_buffer) + 1;
    DWORD section_size = sizeof(IMAGE_SECTION_HEADER) * input_pe_section_count;


    // copy headers
    memcpy(output_pe_buffer, input_pe_buffer, get_optional_header_64(input_pe_buffer)->SizeOfHeaders);

    // section header
    output_pe_section_header = get_section_header(output_pe_buffer);

    // decompressed data section
    memcpy(&(output_pe_section_header[0].Name), "data000", 8);
    output_pe_section_header[0].Misc.VirtualSize = align_memory_address(get_optional_header_64(output_pe_buffer)->SizeOfImage - get_optional_header_64(output_pe_buffer)->SizeOfHeaders, section_alignment);
    output_pe_section_header[0].VirtualAddress = 0x1000;
    output_pe_section_header[0].SizeOfRawData = 0;
    output_pe_section_header[0].PointerToRawData = get_optional_header_64(output_pe_buffer)->SizeOfHeaders;
    output_pe_section_header[0].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_UNINITIALIZED_DATA;

    // stub section
    memcpy(&(output_pe_section_header[1].Name), "data001", 8);
    output_pe_section_header[1].Misc.VirtualSize = align_memory_address(stub_size, section_alignment);
    output_pe_section_header[1].VirtualAddress = output_pe_section_header[0].VirtualAddress + output_pe_section_header[0].Misc.VirtualSize;
    output_pe_section_header[1].SizeOfRawData = align_memory_address(stub_size, file_alignment);
    output_pe_section_header[1].PointerToRawData = get_optional_header_64(output_pe_buffer)->SizeOfHeaders;
    output_pe_section_header[1].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_CODE;
    memcpy(((PBYTE)output_pe_buffer + output_pe_section_header[1].PointerToRawData), stub_buffer, stub_size);

    // compressed data section
    memcpy(&(output_pe_section_header[2].Name), "data002", 8);
    output_pe_section_header[2].Misc.VirtualSize = align_memory_address(compressed_image_size, section_alignment);
    output_pe_section_header[2].VirtualAddress = output_pe_section_header[1].VirtualAddress + output_pe_section_header[1].Misc.VirtualSize;
    output_pe_section_header[2].SizeOfRawData = align_memory_address(compressed_image_size, file_alignment);
    output_pe_section_header[2].PointerToRawData = output_pe_section_header[1].PointerToRawData +  output_pe_section_header[1].SizeOfRawData;
    output_pe_section_header[2].Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;
    memcpy(((PBYTE)output_pe_buffer + output_pe_section_header[2].PointerToRawData), compressed_image_buffer, compressed_image_size);

    // saved input pe nt and section header section
    memcpy(&(output_pe_section_header[3].Name), "data003", 8);
    output_pe_section_header[3].Misc.VirtualSize = align_memory_address(nt_header_64_size + section_size , section_alignment);
    output_pe_section_header[3].VirtualAddress = output_pe_section_header[2].VirtualAddress + output_pe_section_header[2].Misc.VirtualSize;
    output_pe_section_header[3].SizeOfRawData = align_memory_address(nt_header_64_size + section_size, file_alignment);
    output_pe_section_header[3].PointerToRawData = output_pe_section_header[2].PointerToRawData +  output_pe_section_header[2].SizeOfRawData;
    output_pe_section_header[3].Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;
    memcpy(((PBYTE)output_pe_buffer + output_pe_section_header[3].PointerToRawData), get_nt_header(input_pe_buffer), nt_header_64_size + section_size);
    memset(get_optional_header_64(output_pe_buffer)->DataDirectory, 0, data_directory_size * 15);

    // write entry point
    get_optional_header_64(output_pe_buffer)->AddressOfEntryPoint = output_pe_section_header[1].VirtualAddress;

    // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: The DLL can be relocated at load time.
    get_optional_header_64(output_pe_buffer)->DllCharacteristics &= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

    // fix headers
    get_file_header(output_pe_buffer)->NumberOfSections = 4;
    get_optional_header_64(output_pe_buffer)->SizeOfCode = align_memory_address(output_pe_section_header[1].Misc.VirtualSize , section_alignment);
    get_optional_header_64(output_pe_buffer)->SizeOfInitializedData = align_memory_address(output_pe_section_header[1].Misc.VirtualSize , section_alignment) + align_memory_address(output_pe_section_header[2].Misc.VirtualSize , section_alignment) + align_memory_address(output_pe_section_header[3].Misc.VirtualSize , section_alignment);
    get_optional_header_64(output_pe_buffer)->SizeOfUninitializedData = align_memory_address(output_pe_section_header[0].Misc.VirtualSize , section_alignment);
    get_optional_header_64(output_pe_buffer)->BaseOfCode = output_pe_section_header[1].VirtualAddress;

    get_optional_header_64(output_pe_buffer)->SizeOfImage = output_pe_section_header[get_file_header(output_pe_buffer)->NumberOfSections -1].VirtualAddress + output_pe_section_header[get_file_header(output_pe_buffer)->NumberOfSections -1].Misc.VirtualSize;
    get_optional_header_64(output_pe_buffer)->SizeOfHeaders = 0x400;
    get_optional_header_64(output_pe_buffer)->CheckSum = 0;

    // output pe size
    *output_pe_size = output_pe_section_header[get_file_header(output_pe_buffer)->NumberOfSections -1].PointerToRawData + output_pe_section_header[get_file_header(output_pe_buffer)->NumberOfSections -1].SizeOfRawData;

    return true;
}


static void usage(char *filename)
{
    printf("usage   : %s pe_file\n", filename);
    printf("example : %s main.exe\n", filename);

    return;
}


int main(int argc, char **argv)
{

    char *input_pe_file_name = NULL;
    char *output_pe_file_name = NULL;
    char *char_pointer = NULL;

    FILE *file_pointer = NULL;

    char *input_pe_buffer = NULL;
    DWORD input_pe_size = 0;

    char *image_buffer = NULL;
    DWORD image_size = 0;

    char *compressed_image_buffer = NULL;
    DWORD compressed_image_size = 0;

    char *stub_buffer = NULL;
    DWORD stub_size = 0;

    char *output_pe_buffer = NULL;
    DWORD output_pe_size = 0;


    if(argc != 2){
        usage(argv[0]);
        return 0;
    }else if(strlen(argv[1]) > 200){
        printf("[E] input pe file name length is too long.\n");
        return -1;
    }

    input_pe_file_name = argv[1];
    output_pe_file_name = new char[256];
    char_pointer = strrchr(input_pe_file_name, '.');
    if(char_pointer){
        strncpy(output_pe_file_name, input_pe_file_name, strlen(input_pe_file_name));
        strncpy(strrchr(output_pe_file_name, '.'), "_packed.exe\00", 12);
        printf("[I] output_pe_file_name: %s\n", output_pe_file_name);
    }else{
        printf("[E] input pe file name does not contain dot.\n");
        goto error;
    }


    printf("[I] read %s file\n", input_pe_file_name);
    file_pointer = fopen(input_pe_file_name, "rb");
    if(file_pointer != NULL){
        _fseeki64(file_pointer, 0, SEEK_END);
        input_pe_size = _ftelli64(file_pointer);
        input_pe_buffer = (char *)calloc(input_pe_size + 1, sizeof(char));
        _fseeki64(file_pointer, 0, SEEK_SET);
        fread(input_pe_buffer, sizeof(char), input_pe_size, file_pointer);
        fclose(file_pointer);
    }else{
        printf("[E] %s file open error\n", input_pe_file_name);
        goto error;
    }
    if(input_pe_size > MAX_FILE_SIZE){
        printf("[E] input pe file size error: %ld bytes\n", input_pe_size);
        goto error;
    }
    printf("[I] %s file size:%ld\n", input_pe_file_name, input_pe_size);


    printf("[I] check %s file\n", input_pe_file_name);
    if(!check_pe_file(input_pe_buffer)){
        printf("[E] check_pe_file error\n");
        goto error;
    }


    printf("[I] dump mapped image\n");
    image_size = get_optional_header_64(input_pe_buffer)->SizeOfImage - get_section_header(input_pe_buffer)[0].VirtualAddress;
    image_buffer = (char *)calloc(image_size, sizeof(char));
    if(!dump_mapped_image(input_pe_buffer, image_buffer, &image_size)){
        printf("[E] dump_mapped_image error\n");
        goto error;
    }


    printf("[I] compress image data\n");
    compressed_image_buffer = (char *)calloc(image_size, sizeof(char));
    if(!compress_data(image_buffer, image_size, compressed_image_buffer, &compressed_image_size)){
        printf("[E] compress_data error\n");
        goto error;
    }


    printf("[I] read stub.bin file\n");
    file_pointer = fopen("stub.bin", "rb");
    if(file_pointer != NULL){
        _fseeki64(file_pointer, 0, SEEK_END);
        stub_size = _ftelli64(file_pointer);
        stub_buffer = (char *)calloc(stub_size + 1, sizeof(char));
        _fseeki64(file_pointer, 0, SEEK_SET);
        fread(stub_buffer, sizeof(char), stub_size, file_pointer);
        fclose(file_pointer);
    }else{
        printf("[E] stub.bin file open error\n");
        goto error;
    }


    printf("[I] link data\n");
    output_pe_buffer = (char *)calloc(MAX_FILE_SIZE+5000000, sizeof(char));
    if(!link_data(input_pe_buffer, output_pe_buffer, &output_pe_size, stub_buffer, stub_size, compressed_image_buffer, compressed_image_size)){
        printf("[E] link_data error\n");
        goto error;
    }


    printf("[I] write %s file\n", output_pe_file_name);
    file_pointer = fopen(output_pe_file_name, "wb");
    if(file_pointer != NULL){
        fwrite(output_pe_buffer, sizeof(char), output_pe_size, file_pointer);
        fclose(file_pointer);
    }else{
        printf("[E] %s file open error\n", output_pe_file_name);
        goto error;
    }
    printf("[I] %s file size: %ld bytes\n", output_pe_file_name, output_pe_size);


    delete [] output_pe_file_name;
    free(input_pe_buffer);
    free(image_buffer);
    free(compressed_image_buffer);
    free(stub_buffer);
    free(output_pe_buffer);
    return 0;

error:
    delete [] output_pe_file_name;
    free(input_pe_buffer);
    free(image_buffer);
    free(compressed_image_buffer);
    free(stub_buffer);
    free(output_pe_buffer);
    return -1;
}

