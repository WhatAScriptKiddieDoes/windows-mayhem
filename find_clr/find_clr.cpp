// CLR processes are an interesting target for injection because they typically already contain RWX memory region.
// To find .NET processes, there are two approaches:
// - Find a process with a loaded clr.dll module through module enumeration
// - Find a process that has an handle open to the Section \BaseNamedObject\Cor_Private_IPCBlock_v4_{{PID}}
// The following is an implementation of method 2.

#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <strsafe.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Shlwapi.lib")


typedef NTSTATUS(NTAPI* _NtGetNextProcess)(
	HANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	ULONG HandleAttributes,
	ULONG Flags,
	PHANDLE NewProcessHandle
	);

// Undocumented API
typedef NTSTATUS(NTAPI* _NtOpenSection)(
	PHANDLE             SectionHandle,
	ACCESS_MASK          DesiredAccess,
	POBJECT_ATTRIBUTES   ObjectAttributes
	);

_NtGetNextProcess pNtGetNextProcess = NULL;
_NtOpenSection pNtOpenSection = NULL;

BOOL resolve_ntfunctions() {
	pNtGetNextProcess = (_NtGetNextProcess)GetProcAddress(
		GetModuleHandleA("ntdll.dll"),
		"NtGetNextProcess"
	);
	if (pNtGetNextProcess == NULL) {
		printf("[!] Error resolving NtGetNextProcess.\n");
		return FALSE;
	}
	pNtOpenSection = (_NtOpenSection)GetProcAddress(
		GetModuleHandleA("ntdll.dll"),
		"NtOpenSection"
	);
	if (pNtOpenSection == NULL) {
		printf("[!] Error resolving NtOpenSection.\n");
		return FALSE;
	}
	return TRUE;
}

BOOL find_rwx(HANDLE proc) {
	LPVOID address = 0;
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	char proc_name[MAX_PATH];
	if (GetProcessImageFileNameA(
		proc,
		proc_name,
		MAX_PATH
	) == 0) {
		printf("[!] GetProcessImageFileNameA failed.\n");
	}

	while (VirtualQueryEx(proc, address, &mbi, sizeof(mbi))) {
		address = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
		if (mbi.Protect == PAGE_EXECUTE_READWRITE && mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
			// Found RWX
			printf("[%d] [%s] base: %#18llu (%#6llu kB | %#7llu)\n",
				GetProcessId(proc),
				proc_name,
				mbi.BaseAddress,
				mbi.RegionSize / 1024,
				mbi.RegionSize
			);
		}
	}
	return TRUE;
}

BOOL find_clr() {
	int pid = 0;
	WCHAR wchar_pid[32] = { 0 };
	HANDLE current_proc_handle = NULL;
	NTSTATUS status;

	// Set up the CLR name to search
	WCHAR clr_section_object_path[] = L"\\BaseNamedObjects\\Cor_Private_IPCBlock_v4_";
	UNICODE_STRING clr_section_name_unicode = { 0 };
	int buffer_size = 512;
	clr_section_name_unicode.Buffer = (PWSTR)malloc(buffer_size);
	if (clr_section_name_unicode.Buffer == NULL) {
		printf("[!] malloc failed.\n");
		return FALSE;
	}

	// Search for the CLR in each process
	while (!pNtGetNextProcess(
		current_proc_handle,
		MAXIMUM_ALLOWED,
		0,
		0,
		&current_proc_handle
	)) {
		// Get the process PID into a WCHAR string and build the search UNICODE_STRING
		pid = GetProcessId(current_proc_handle);
		swprintf_s(wchar_pid, L"%d", pid);
		ZeroMemory(clr_section_name_unicode.Buffer, buffer_size); // Clear buffer
		// Copy the first part to the buffer
		// wcslen counts the characters in two-bytes chunks
		memcpy(clr_section_name_unicode.Buffer, clr_section_object_path, wcslen(clr_section_object_path) * 2);
		// Concat the WCHAR version of the PID
		StringCchCatW(clr_section_name_unicode.Buffer, buffer_size, wchar_pid);
		// Set the other parameters
		clr_section_name_unicode.Length = wcslen(clr_section_name_unicode.Buffer) * 2;
		clr_section_name_unicode.MaximumLength = clr_section_name_unicode.Length + 1;

		OBJECT_ATTRIBUTES object_attributes = { 0 };
		
		// Try to open the section
		InitializeObjectAttributes(
			&object_attributes,
			&clr_section_name_unicode,
			OBJ_CASE_INSENSITIVE,
			NULL,
			NULL
		);
		HANDLE section_handle = NULL;
		status = pNtOpenSection(&section_handle, SECTION_QUERY, &object_attributes);
		if (NT_SUCCESS(status)) {
			// CLR found!
			//printf("[*] Match on process %d\n", GetProcessId(current_proc_handle));
			CloseHandle(section_handle);
			find_rwx(current_proc_handle);
		}

	}
	return FALSE;
}



int main()
{
	if (!resolve_ntfunctions())
		return -1;
	find_clr();
	return 0;
}

