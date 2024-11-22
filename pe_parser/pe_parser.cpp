// A basic PE parser

#include <iostream>
#include "Windows.h"

static DWORD rva_to_offset(DWORD rva, UINT_PTR base_address)
{
    WORD i = 0;
    PIMAGE_SECTION_HEADER section_header = NULL;
    PIMAGE_NT_HEADERS nt_headers = NULL;

    nt_headers = (PIMAGE_NT_HEADERS)(base_address + ((PIMAGE_DOS_HEADER)base_address)->e_lfanew);
    section_header = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&nt_headers->OptionalHeader)
        + nt_headers->FileHeader.SizeOfOptionalHeader);

    if (rva < section_header[0].PointerToRawData)
        return rva;

    for (i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
    {
        if (rva >= section_header[i].VirtualAddress &&
            rva < (section_header[i].VirtualAddress + section_header[i].SizeOfRawData))
            return (rva - section_header[i].VirtualAddress + section_header[i].PointerToRawData);
    }

    return 0;
}


int main() {
    // Target file
    LPCSTR file_path = "C:\\Windows\\System32\\ntdll.dll";

    HANDLE file_handle;
    DWORD file_size, bytes_read, import_directory_rva, export_directory_rva;
    PIMAGE_THUNK_DATA thunk = { 0 };
    LPVOID file_buffer;
    PIMAGE_DOS_HEADER dos_header = { 0 };
    PIMAGE_NT_HEADERS nt_header = { 0 };
    PIMAGE_SECTION_HEADER section_header, section_header_import = { 0 };
    PIMAGE_IMPORT_DESCRIPTOR image_import_descriptor = { 0 };
    PIMAGE_THUNK_DATA thunkData = { 0 };

    // Allocate file in memory
    file_handle = CreateFileA(
        file_path,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    if (file_handle == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open file handle: (0x%X)\n", GetLastError());
        CloseHandle(file_handle);
        exit(1);
    }

    file_size = GetFileSize(file_handle, NULL);
    file_buffer = HeapAlloc(GetProcessHeap(), 0, file_size);
    if (file_buffer == NULL) {
        printf("[!] Failed to allocate buffer: (0x%X)\n", GetLastError());
        CloseHandle(file_handle);
        exit(1);
    }

    if (!ReadFile(file_handle, file_buffer, file_size, &bytes_read, NULL)) {
        printf("[!] Failed to read file: (0x%X)\n", GetLastError());
        CloseHandle(file_handle);
        exit(1);
    }


    // Parse DOS Header
    dos_header = (PIMAGE_DOS_HEADER)file_buffer;

    printf("\n========= DOS HEADER =========\n");
    printf("%-38s 0x%X\n", "Magic number", dos_header->e_magic);
    printf("%-38s 0x%X\n", "Bytes on last page of file", dos_header->e_cblp);
    printf("%-38s 0x%X\n", "Pages in file", dos_header->e_cp);
    printf("%-38s 0x%X\n", "Relocations", dos_header->e_crlc);
    printf("%-38s 0x%X\n", "Size of header in paragraphs", dos_header->e_cparhdr);
    printf("%-38s 0x%X\n", "Minimum extra paragraphs needed", dos_header->e_minalloc);
    printf("%-38s 0x%X\n", "Maximum extra paragraphs needed", dos_header->e_maxalloc);
    printf("%-38s 0x%X\n", "Initial (relative) SS value", dos_header->e_ss);
    printf("%-38s 0x%X\n", "Initial SP value", dos_header->e_sp);
    printf("%-38s 0x%X\n", "Checksum", dos_header->e_csum);
    printf("%-38s 0x%X\n", "Initial IP value", dos_header->e_ip);
    printf("%-38s 0x%X\n", "Initial (relative) CS value", dos_header->e_cs);
    printf("%-38s 0x%X\n", "File address of relocation tabl", dos_header->e_lfarlc);
    printf("%-38s 0x%X\n", "Overlay Number", dos_header->e_ovno);
    printf("%-38s 0x%X\n", "OEM identifier (for e_oeminfo)", dos_header->e_oemid);
    printf("%-38s 0x%X\n", "OEM information; e_oemid specific", dos_header->e_oeminfo);
    printf("%-38s 0x%X\n", "File address of new exe header", dos_header->e_lfanew);

    // Parse NT Header
    nt_header = (PIMAGE_NT_HEADERS)((ULONG_PTR)file_buffer + dos_header->e_lfanew);

    printf("\n========= NT HEADER =========\n");
    printf("%-38s 0x%X\n", "Signature", nt_header->Signature);

    printf("\n========= FILE HEADER =========\n");
    printf("%-38s 0x%X\n", "Machine", nt_header->FileHeader.Machine);
    printf("%-38s 0x%X\n", "NumberOfSections", nt_header->FileHeader.NumberOfSections);
    printf("%-38s 0x%X\n", "TimeDateStamp", nt_header->FileHeader.TimeDateStamp);
    printf("%-38s 0x%X\n", "PointerToSymbolTable", nt_header->FileHeader.PointerToSymbolTable);
    printf("%-38s 0x%X\n", "NumberOfSymbols", nt_header->FileHeader.NumberOfSymbols);
    printf("%-38s 0x%X\n", "SizeOfOptionalHeader", nt_header->FileHeader.SizeOfOptionalHeader);
    printf("%-38s 0x%X\n", "Characteristics", nt_header->FileHeader.Characteristics);

    // Parse Optional Header
    printf("\n========= OPTIONAL HEADER =========\n");
    printf("%-38s 0x%X\n", "Magic", nt_header->OptionalHeader.Magic);
    printf("%-38s 0x%X\n", "MajorLinkerVersion", nt_header->OptionalHeader.MajorLinkerVersion);
    printf("%-38s 0x%X\n", "MinorLinkerVersion", nt_header->OptionalHeader.MinorLinkerVersion);
    printf("%-38s 0x%X\n", "SizeOfCode", nt_header->OptionalHeader.SizeOfCode);
    printf("%-38s 0x%X\n", "SizeOfInitializedData", nt_header->OptionalHeader.SizeOfInitializedData);
    printf("%-38s 0x%X\n", "SizeOfUninitializedData", nt_header->OptionalHeader.SizeOfUninitializedData);
    printf("%-38s 0x%X\n", "AddressOfEntryPoint", nt_header->OptionalHeader.AddressOfEntryPoint);
    printf("%-38s 0x%X\n", "BaseOfCode", nt_header->OptionalHeader.BaseOfCode);
    printf("%-38s 0x%llx\n", "ImageBase", nt_header->OptionalHeader.ImageBase);
    printf("%-38s 0x%X\n", "SectionAlignment", nt_header->OptionalHeader.SectionAlignment);
    printf("%-38s 0x%X\n", "FileAlignment", nt_header->OptionalHeader.FileAlignment);
    printf("%-38s 0x%X\n", "MajorOperatingSystemVersion", nt_header->OptionalHeader.MajorOperatingSystemVersion);
    printf("%-38s 0x%X\n", "MinorOperatingSystemVersion", nt_header->OptionalHeader.MinorOperatingSystemVersion);
    printf("%-38s 0x%X\n", "MajorImageVersion", nt_header->OptionalHeader.MajorImageVersion);
    printf("%-38s 0x%X\n", "MinorImageVersion", nt_header->OptionalHeader.MinorImageVersion);
    printf("%-38s 0x%X\n", "MajorSubsystemVersion", nt_header->OptionalHeader.MajorSubsystemVersion);
    printf("%-38s 0x%X\n", "MinorSubsystemVersion", nt_header->OptionalHeader.MinorSubsystemVersion);
    printf("%-38s 0x%X\n", "Win32VersionValue", nt_header->OptionalHeader.Win32VersionValue);
    printf("%-38s 0x%X\n", "SizeOfImage", nt_header->OptionalHeader.SizeOfImage);
    printf("%-38s 0x%X\n", "SizeOfHeaders", nt_header->OptionalHeader.SizeOfHeaders);
    printf("%-38s 0x%X\n", "CheckSum", nt_header->OptionalHeader.CheckSum);
    printf("%-38s 0x%X\n", "Subsystem", nt_header->OptionalHeader.Subsystem);
    printf("%-38s 0x%X\n", "DllCharacteristics", nt_header->OptionalHeader.DllCharacteristics);
    printf("%-38s 0x%llx\n", "SizeOfStackReserve", nt_header->OptionalHeader.SizeOfStackReserve);
    printf("%-38s 0x%llx\n", "SizeOfStackCommit", nt_header->OptionalHeader.SizeOfStackCommit);
    printf("%-38s 0x%llx\n", "SizeOfHeapReserve", nt_header->OptionalHeader.SizeOfHeapReserve);
    printf("%-38s 0x%llx\n", "SizeOfHeapCommit", nt_header->OptionalHeader.SizeOfHeapCommit);
    printf("%-38s 0x%X\n", "LoaderFlags", nt_header->OptionalHeader.LoaderFlags);
    printf("%-38s 0x%X\n", "NumberOfRvaAndSizes", nt_header->OptionalHeader.NumberOfRvaAndSizes);

    // Parse Section Header
    printf("\n========= SECTION HEADERS =========\n");

    section_header = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&nt_header->OptionalHeader) +
        nt_header->FileHeader.SizeOfOptionalHeader);

    
    // Loop through all our section headers
    for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++) {
        printf("%s\n", section_header->Name);
        printf("\t%-38s 0x%X\n", "VirtualSize", section_header->Misc.VirtualSize);
        printf("\t%-38s 0x%X\n", "VirtualAddress", section_header->VirtualAddress);
        printf("\t%-38s 0x%X\n", "SizeOfRawData", section_header->SizeOfRawData);
        printf("\t%-38s 0x%X\n", "PointerToRawData", section_header->PointerToRawData);
        printf("\t%-38s 0x%X\n", "PointerToRelocations", section_header->PointerToRelocations);
        printf("\t%-38s 0x%X\n", "PointerToLinenumbers", section_header->PointerToLinenumbers);
        printf("\t%-38s 0x%X\n", "NumberOfRelocations", section_header->NumberOfRelocations);
        printf("\t%-38s 0x%X\n", "NumberOfLinenumbers", section_header->NumberOfLinenumbers);
        printf("\t%-38s 0x%X\n", "Characteristics", section_header->Characteristics);

        section_header++;
    }

    // Parse imports
    printf("\n========= IMPORTS =========\n");

    import_directory_rva = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    image_import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)((UINT_PTR)file_buffer +
        rva_to_offset(import_directory_rva, (UINT_PTR)file_buffer));

    while (image_import_descriptor->OriginalFirstThunk != 0) {
        printf("\n\n");
        if (image_import_descriptor->Name != 0) {
            printf("%-38s %s\n", "DLL name",
                (BYTE*)(rva_to_offset(image_import_descriptor->Name, (UINT_PTR)file_buffer))
                + (UINT_PTR)file_buffer);
        }
        printf("%-38s 0x%X\n", "FirstThunk", image_import_descriptor->FirstThunk);
        printf("%-38s 0x%X\n", "OriginalFirstThunk", image_import_descriptor->OriginalFirstThunk);
        printf("%-38s 0x%X\n", "TimeDateStamp", image_import_descriptor->TimeDateStamp);
        printf("%-38s 0x%X\n", "ForwarderChain", image_import_descriptor->ForwarderChain);
        printf("%-38s 0x%X\n", "Name", image_import_descriptor->Name);

        printf("Imported functions:\n");
        thunk = (PIMAGE_THUNK_DATA)(rva_to_offset(image_import_descriptor->OriginalFirstThunk, (UINT_PTR)file_buffer) +
            (UINT_PTR)file_buffer);
        
        while (thunk->u1.Function != 0)
        {
            // If the function is imported by ordinal
            if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                printf("\t%-38s %llu\n", "Ordinal", IMAGE_ORDINAL(thunk->u1.Ordinal));
            }
            else {
                PIMAGE_IMPORT_BY_NAME image_import_by_name = (PIMAGE_IMPORT_BY_NAME)(rva_to_offset(
                    thunk->u1.AddressOfData,
                    (UINT_PTR)file_buffer
                ) + (UINT_PTR)file_buffer);
                printf("\t%-38s %s\n", "Name", image_import_by_name->Name);
            }
            
            thunk++;
        }

        image_import_descriptor++;
    }

    // Parse exports
    printf("\n========= EXPORT TABLE =========\n");

    export_directory_rva = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (export_directory_rva != 0) {
        PIMAGE_EXPORT_DIRECTORY export_directory = (PIMAGE_EXPORT_DIRECTORY)((UINT_PTR)file_buffer +
            rva_to_offset(export_directory_rva, (UINT_PTR)file_buffer));

        printf("%-38s 0x%X\n", "Characteristics", export_directory->Characteristics);
        printf("%-38s 0x%X\n", "TimeDateStamp", export_directory->TimeDateStamp);
        printf("%-38s 0x%X\n", "MajorVersion", export_directory->MajorVersion);
        printf("%-38s 0x%X\n", "MinorVersion", export_directory->MinorVersion);
        printf("%-38s %s\n", "Name", (BYTE*)(rva_to_offset(export_directory->Name, (UINT_PTR)file_buffer)) + (UINT_PTR)file_buffer);
        printf("%-38s 0x%X\n", "Base", export_directory->Base);
        printf("%-38s 0x%X\n", "NumberOfFunctions", export_directory->NumberOfFunctions);
        printf("%-38s 0x%X\n", "NumberOfNames", export_directory->NumberOfNames);
        printf("%-38s 0x%X\n", "AddressOfFunctions", export_directory->AddressOfFunctions);
        printf("%-38s 0x%X\n", "AddressOfNames", export_directory->AddressOfNames);
        printf("%-38s 0x%X\n", "AddressOfNameOrdinals", export_directory->AddressOfNameOrdinals);

        DWORD* functions = (DWORD*)((UINT_PTR)file_buffer + rva_to_offset(export_directory->AddressOfFunctions, (UINT_PTR)file_buffer));
        DWORD* names = (DWORD*)((UINT_PTR)file_buffer + rva_to_offset(export_directory->AddressOfNames, (UINT_PTR)file_buffer));
        WORD* ordinals = (WORD*)((UINT_PTR)file_buffer + rva_to_offset(export_directory->AddressOfNameOrdinals, (UINT_PTR)file_buffer));

        printf("Exported functions:\n");
        for (DWORD i = 0; i < export_directory->NumberOfNames; i++) {
            printf("\n\t%-38s %s\n", "Name", (BYTE*)(rva_to_offset(names[i], (UINT_PTR)file_buffer)) + (UINT_PTR)file_buffer);
            printf("\t%-38s 0x%X\n", "Ordinal", ordinals[i]);
            printf("\t%-38s 0x%X\n", "Function Address", functions[ordinals[i]]);
        }
    }
    else {
        printf("No export table found.\n");
    }

    CloseHandle(file_handle);
    HeapFree(GetProcessHeap(), NULL, file_buffer);
    return 0;
}
