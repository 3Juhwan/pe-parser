#include <stdio.h>

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
#define IMAGE_SIZEOF_SHORT_NAME              8

typedef unsigned long       DWORD;
typedef int                 BOOL;
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef char CHAR;
typedef short SHORT;
typedef long LONG;


typedef struct _IMAGE_DOS_HEADER
{
    WORD e_magic;
    LONG e_lfanew;
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_FILE_HEADER {
    WORD  Machine;
    WORD  NumberOfSections;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER {
    WORD                 Magic;
    DWORD                AddressOfEntryPoint;
    DWORD                BaseOfCode;
    DWORD                ImageBase;
    DWORD                SectionAlignment;
    DWORD                FileAlignment;
    DWORD                SizeOfImage;
    DWORD                SizeOfHeaders;
    DWORD                NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_NT_HEADERS {
    DWORD                   Signature;
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, * PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_SECTION_HEADER {
    BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;


int read_file(BYTE* buf, int size);
int read_dos_header();
void print_dos_header();
int read_nt_header();
void print_nt_header();
int read_file_header();
void print_file_header();
int read_optional_header();
void print_optional_header();
int read_section_header();
void print_section_header();


FILE* fp;
IMAGE_DOS_HEADER dos_header;
IMAGE_NT_HEADERS32 nt_header32;
IMAGE_SECTION_HEADER section_header;
char* file_path;

int main() {
	file_path = "chall1.exe";

    if ((fp = fopen(file_path, "rb")) == NULL) {
        fputs("File Open Error!\n", stderr);
        return -1;
    }

    fseek(fp, 0, SEEK_SET);
    read_dos_header(file_path);
    print_dos_header();

    fseek(fp, dos_header.e_lfanew, SEEK_SET);
    read_nt_header(file_path);
    print_nt_header();

    for (int i = 0; i < nt_header32.FileHeader.NumberOfSections; i++) {
        fseek(fp, dos_header.e_lfanew + 0x108 + i * 0x28, SEEK_SET);
        read_section_header(file_path);
        print_section_header();
    }

    fclose(fp);
}

int read_dos_header() {
    read_file((BYTE*)&dos_header.e_magic, 2);
    fseek(fp, 0x3A, SEEK_CUR);
    read_file((BYTE*)&dos_header.e_lfanew, 4);
}

void print_dos_header() {
    printf("------ DOS HEADER ------\n");
    printf("e_magic: 0x%x\n", dos_header.e_magic);
    printf("e_lfanew: 0x%x\n", dos_header.e_lfanew);
    printf("\n\n");
}

int read_nt_header() {
    read_file((BYTE*)&nt_header32.Signature, 4);
    read_file_header(file_path);
    read_optional_header(file_path);
}

void print_nt_header() {
    printf("------ NT HEADER ------\n");
    printf("Signature: 0x%x\n", nt_header32.Signature);
    printf("\n\n");
    print_file_header();
    print_optional_header();
}

int read_file_header() {
    read_file((BYTE*)&nt_header32.FileHeader.Machine, 2);
    read_file((BYTE*)&nt_header32.FileHeader.NumberOfSections, 2);
    fseek(fp, 0x0C, SEEK_CUR);
    read_file((BYTE*)&nt_header32.FileHeader.SizeOfOptionalHeader, 2);
    read_file((BYTE*)&nt_header32.FileHeader.Characteristics, 2);
}

void print_file_header() {
    printf("------ FILE HEADER ------\n");
    printf("Machine: 0x%x\n", nt_header32.FileHeader.Machine);
    printf("NumberOfSections: 0x%x\n", nt_header32.FileHeader.NumberOfSections);
    printf("SizeOfOptionalHeader: 0x%x\n", nt_header32.FileHeader.SizeOfOptionalHeader);
    printf("Characteristics: 0x%x\n", nt_header32.FileHeader.Characteristics);
    printf("\n\n");
}

int read_optional_header() {
    read_file((BYTE*)&nt_header32.OptionalHeader.Magic, 2);
    fseek(fp, 0x0E, SEEK_CUR);
    read_file((BYTE*)&nt_header32.OptionalHeader.AddressOfEntryPoint, 4);
    fseek(fp, 0x08, SEEK_CUR);
    read_file((BYTE*)&nt_header32.OptionalHeader.ImageBase, 4);
    read_file((BYTE*)&nt_header32.OptionalHeader.SectionAlignment, 4);
    read_file((BYTE*)&nt_header32.OptionalHeader.FileAlignment, 4);
    fseek(fp, 0x10, SEEK_CUR);
    read_file((BYTE*)&nt_header32.OptionalHeader.SizeOfImage, 4);
    read_file((BYTE*)&nt_header32.OptionalHeader.SizeOfHeaders, 4);
    fseek(fp, 0x2C, SEEK_CUR);
    read_file((BYTE*)&nt_header32.OptionalHeader.NumberOfRvaAndSizes, 4);
}

void print_optional_header() {
    printf("------ OPTIONAL HEADER ------\n");
    printf("Magic: 0x%x\n", nt_header32.OptionalHeader.Magic);
    printf("AddressOfEntryPoint: 0x%x\n", nt_header32.OptionalHeader.AddressOfEntryPoint);
    printf("ImageBase: 0x%x\n", nt_header32.OptionalHeader.ImageBase);
    printf("SectionAlignment: 0x%x\n", nt_header32.OptionalHeader.SectionAlignment);
    printf("FileAlignment: 0x%x\n", nt_header32.OptionalHeader.FileAlignment);
    printf("SizeOfImage: 0x%x\n", nt_header32.OptionalHeader.SizeOfImage);
    printf("SizeOfHeaders: 0x%x\n", nt_header32.OptionalHeader.SizeOfHeaders);
    printf("NumberOfRvaAndSizes: 0x%x\n", nt_header32.OptionalHeader.NumberOfRvaAndSizes);
    printf("\n\n");
}

int read_section_header() {
    for (int i = 0; i < IMAGE_SIZEOF_SHORT_NAME;i++) {
        read_file(&section_header.Name[i], 1);
    }
    read_file((BYTE*)&section_header.Misc.VirtualSize, 4);
    read_file((BYTE*)&section_header.VirtualAddress, 4);
    read_file((BYTE*)&section_header.SizeOfRawData, 4);
    read_file((BYTE*)&section_header.PointerToRawData, 4);
    fseek(fp, 0xC, SEEK_CUR);
    read_file((BYTE*)&section_header.Characteristics, 4);
}

void print_section_header() {
    printf("------ SECTION HEADER ------\n");
    printf("Name: ");
    for (int i = 0; i < IMAGE_SIZEOF_SHORT_NAME; i++) {
        printf("%c", section_header.Name[i]);
    }
    printf("\n");
    printf("VirtualSize: 0x%x\n", section_header.Misc.VirtualSize);
    printf("VirtualAddress: 0x%x\n", section_header.VirtualAddress);
    printf("SizeOfRawData: 0x%x\n", section_header.SizeOfRawData);
    printf("PointerToRawData: 0x%x\n", section_header.PointerToRawData);
    printf("Characteristics: 0x%x\n", section_header.Characteristics);
    printf("\n\n");
}

int read_file(BYTE* buf, int size) {
	fread(buf, sizeof(BYTE), size, fp);
	return 0;
}
