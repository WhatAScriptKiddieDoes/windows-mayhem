// Enumerate all open handles using NtQuerySystemInformation + a couple of undocumented structures:
// SYSTEM_HANDLE_INFORMATION and SYSTEM_HANDLE_TABLE_ENTRY_INFO

#include <stdio.h>
#include <Windows.h>
#include <Psapi.h>
#include <winternl.h>
#include <Shlwapi.h>

#pragma comment (lib, "shlwapi")


#define SYSTEMHANDLEINFORMATION 0x10
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

#define ObjectNameInformation 0x1

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _UNICODE_STRING_t {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING_t, * PUNICODE_STRING_t;

typedef enum _POOL_TYPE
{
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, * PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING_t Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;


// Imported functions
typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );

typedef NTSTATUS(NTAPI* _NtQueryObject)(
    HANDLE ObjectHandle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

_NtQuerySystemInformation pNtQuerySystemInformation = NULL;
_NtDuplicateObject pNtDuplicateObject = NULL;
_NtQueryObject pNtQueryObject = NULL;


BOOL resolve_ntfunctions() {
    pNtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(
        GetModuleHandleA("ntdll.dll"),
        "NtQuerySystemInformation"
    );
    if (pNtQuerySystemInformation == NULL) {
        printf("[!] Error resolving NtQuerySystemInformation.\n");
        return FALSE;
    }

    pNtDuplicateObject = (_NtDuplicateObject)GetProcAddress(
        GetModuleHandleA("ntdll.dll"),
        "NtDuplicateObject"
    );
    if (pNtDuplicateObject == NULL) {
        printf("[!] Error resolving NtDuplicateObject.\n");
        return FALSE;
    }

    pNtQueryObject = (_NtQueryObject)GetProcAddress(
        GetModuleHandleA("ntdll.dll"),
        "NtQueryObject"
    );
    if (pNtQueryObject == NULL) {
        printf("[!] Error resolving NtQueryObject.\n");
        return FALSE;
    }
    return TRUE;
}

PSYSTEM_HANDLE_INFORMATION get_system_handle_info() {
    PSYSTEM_HANDLE_INFORMATION info_handle = NULL;
    ULONG info_handle_size = 0x10000;
    NTSTATUS status = -1;

    info_handle = (PSYSTEM_HANDLE_INFORMATION)malloc(info_handle_size);
    if (info_handle == NULL) {
        printf("[!] malloc failed.\n");
        return NULL;
    }

    // Iterate over NtQuerySystemInformation until the output fits in the allocated buffer
    while ((status = pNtQuerySystemInformation(
        SYSTEMHANDLEINFORMATION,
        info_handle,
        info_handle_size,
        NULL
    )) == STATUS_INFO_LENGTH_MISMATCH) {
        info_handle = (PSYSTEM_HANDLE_INFORMATION)realloc(info_handle, info_handle_size *= 2);
        if (info_handle == NULL) {
            printf("[!] realloc failed.\n");
            return NULL;
        }
    }

    if (status != 0) {
        printf("[!] NtQuerySystemInformation failed.\n");
        free(info_handle);
        return NULL;
    }
    return info_handle;
}

POBJECT_TYPE_INFORMATION get_object_type_info(HANDLE handle_dup) {
    NTSTATUS status = -1;

    // Get the object handle type
    POBJECT_TYPE_INFORMATION object_type_information = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
    if (object_type_information == NULL) {
        printf("[!] malloc failed.\n");
        return NULL;
    }

    status = pNtQueryObject(
        handle_dup,
        ObjectTypeInformation,
        object_type_information,
        0x1000,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        free(object_type_information);
        return NULL;
    }
    return object_type_information;
}

PUNICODE_STRING get_object_name_info(HANDLE handle_dup) {
    NTSTATUS status = -1;
    ULONG size = 0;
    PUNICODE_STRING obj_name_info = (PUNICODE_STRING)malloc(0x1000);
    if (obj_name_info == NULL) {
        printf("[!] malloc failed.\n");
        return NULL;
    }

    status = pNtQueryObject(
        handle_dup,
        ObjectNameInformation,
        obj_name_info,
        0x1000,
        &size
    );

    // Reallocate the buffer to fit the output size
    if (!NT_SUCCESS(status)) {
        obj_name_info = (PUNICODE_STRING)realloc(obj_name_info, size);
        if (obj_name_info == NULL) {
            printf("[!] realloc failed.\n");
            return NULL;
        }
        status = pNtQueryObject(
            handle_dup,
            ObjectNameInformation,
            obj_name_info,
            0x1000,
            NULL
        );
    }

    if (!NT_SUCCESS(status)) {
        free(obj_name_info);
        return NULL;
    }
    return obj_name_info;
}

int find_handles(int target_pid) {
    PSYSTEM_HANDLE_INFORMATION system_handle_info = get_system_handle_info();
    if (system_handle_info == NULL) {
        return -1;
    }
    
    NTSTATUS status = -1;
    // With the list of handles, iterate over it to extract the information
    for (DWORD i = 0; i < system_handle_info->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO system_handle_table_entry_info = system_handle_info->Handles[i];
        
        // If in select PID mode, filter all the entries with a different one
        if (target_pid != 0 && system_handle_table_entry_info.UniqueProcessId != target_pid) continue;

        // Get the current process name and duplicate the handle
        char current_proc_name[MAX_PATH] = { 0 };
        HANDLE handle_dup = NULL;
        // Open the process
        HANDLE current_proc_handle = OpenProcess(
            PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
            FALSE,
            system_handle_table_entry_info.UniqueProcessId
        );
        if (current_proc_handle == NULL) {
            continue;
        }
        // Get the name of the target process
        GetProcessImageFileNameA(current_proc_handle, current_proc_name, MAX_PATH);
        // Duplicate the target handle to query its information
        status = pNtDuplicateObject(
            current_proc_handle,
            (void*)system_handle_table_entry_info.HandleValue,
            GetCurrentProcess(),
            &handle_dup,
            0,
            0,
            DUPLICATE_SAME_ACCESS
        );
        if (!NT_SUCCESS(status)) {
            CloseHandle(current_proc_handle);
            continue; // Skip this handle entry
        }

        POBJECT_TYPE_INFORMATION object_type_information = get_object_type_info(handle_dup);
        if (object_type_information == NULL) {
            CloseHandle(handle_dup);
            CloseHandle(current_proc_handle);
            continue;
        }

        // Filter only certain types of object
        const wchar_t* filter = L"DirectoryFileKeyProcessThreadToken";
        // StrStrIW finds the first occurence of a substring within a string (case insensitive)
        if (!StrStrIW(filter, object_type_information->Name.Buffer) ||
            GetFileType(handle_dup) == FILE_TYPE_PIPE) {
            free(object_type_information);
            CloseHandle(handle_dup);
            CloseHandle(current_proc_handle);
            continue;
        }

        PUNICODE_STRING object_name_information = get_object_name_info(handle_dup);
        if (object_name_information == NULL) {
            // Could not get name info on the target handle
            printf(
                "[%#25s: %#5d] [%#7x] (0x%p) %#10x %ls (Could not get the name)\n",
                PathFindFileNameA(current_proc_name),
                GetProcessId(current_proc_handle),
                system_handle_table_entry_info.HandleValue,
                system_handle_table_entry_info.Object,
                system_handle_table_entry_info.GrantedAccess,
                object_type_information->Name.Buffer
            );
            free(object_type_information);
            CloseHandle(handle_dup);
            CloseHandle(current_proc_handle);
            continue;
        }


        // If the handle is a process or thread handle get the process id and name
        int id = 0;
        char handle_proc_name[MAX_PATH] = { 0 };
        // If it is a process
        if (StrStrIW(L"Process", object_type_information->Name.Buffer)) {
            id = GetProcessId(handle_dup);
            GetProcessImageFileNameA(handle_dup, handle_proc_name, MAX_PATH);
        // If it is a thread
        } else if (StrStrIW(L"Thread", object_type_information->Name.Buffer)) {
            id = GetProcessIdOfThread(handle_dup);
            HANDLE h = OpenProcess(
                PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
                FALSE,
                id
            );
            if (h) {
                GetProcessImageFileNameA(h, handle_proc_name, MAX_PATH);
                CloseHandle(h);
            }
            else {
                sprintf_s(handle_proc_name, MAX_PATH, "%s", "non existent?");
            }
        }

        if (object_name_information->Length) {
            printf(id == 0 ? "[%#25s: %#5d] [%#7x] (0x%p) %#10x %ls %ls\n"
                : "[%#25s: %#5d] [%#7x] (0x%p) %#10x %ls %ls [pid: %#5d : %s]\n",
                PathFindFileNameA(current_proc_name),
                GetProcessId(current_proc_handle),
                system_handle_table_entry_info.HandleValue,
                system_handle_table_entry_info.Object,
                system_handle_table_entry_info.GrantedAccess,
                object_type_information->Name.Buffer,
                object_name_information->Buffer,
                id,
                (id != 0) ? PathFindFileNameA(handle_proc_name) : "non existent?"
            );
        }
        else {
            printf(id == 0 ? "[%#25s: %#5d] [%#7x] (0x%p) %#10x %ls\n"
                : "[%#25s: %#5d] [%#7x] (0x%p) %#10x %ls [pid: %#5d : %s]\n",
                PathFindFileNameA(current_proc_name),
                GetProcessId(current_proc_handle),
                system_handle_table_entry_info.HandleValue,
                system_handle_table_entry_info.Object,
                system_handle_table_entry_info.GrantedAccess,
                object_type_information->Name.Buffer,
                id,
                (id != 0) ? PathFindFileNameA(handle_proc_name) : "non existent?"
            );
        }
        free(object_name_information);
        free(object_type_information);
        CloseHandle(handle_dup);
        CloseHandle(current_proc_handle);

    }
    free(system_handle_info);
    return 0;
}

int main()
{
    if (!resolve_ntfunctions())
        return -1;
    int target_pid = 0; // All processes
    find_handles(target_pid);
    return 0;
}
