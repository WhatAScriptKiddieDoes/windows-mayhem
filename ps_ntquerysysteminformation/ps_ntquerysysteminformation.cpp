#include <Windows.h>
#include <stdio.h>
#include<winternl.h>
#pragma comment(lib, "ntdll.lib")

#define SYSTEMPROCESSINFORMATION 5

typedef NTSTATUS(WINAPI* NtQuerySystemInformation_t) (
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);


int find_process(const wchar_t* process_name) {
	int pid = -1;
	NtQuerySystemInformation_t pNtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(
		GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation"
	);
	if (pNtQuerySystemInformation == NULL) {
		printf("[!] Error resolving NtQuerySystemInformation.\n");
		return -1;
	}

	PVOID buffer = NULL;
	DWORD buffer_size = 0;
	// Initial call to NtQuerySystemInformation to get the output buffer size
	pNtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)SYSTEMPROCESSINFORMATION,
		0,
		0,
		&buffer_size
	);

	// Allocate buffer
	buffer = VirtualAlloc(NULL, buffer_size, MEM_COMMIT, PAGE_READWRITE);
	if (buffer == NULL) {
		printf("[!] VirtualAlloc failed.\n");
		return -1;
	}

	SYSTEM_PROCESS_INFORMATION* proc_info = (SYSTEM_PROCESS_INFORMATION*)buffer;
	if (pNtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)SYSTEMPROCESSINFORMATION,
		buffer,
		buffer_size,
		&buffer_size
	) != 0) {
		printf("[!] NtQuerySystemInformation failed.\n");
		VirtualFree(buffer, buffer_size, MEM_RELEASE);
		return -1;
	}

	while (TRUE) {
		if (lstrcmpiW(process_name, proc_info->ImageName.Buffer) == 0) {
			pid = (int)proc_info->UniqueProcessId;
			printf("[*] Process found at PID %d\n", pid);
		}

		// Check if it is the latest
		if (proc_info->NextEntryOffset == 0) {
			break;
		}

		proc_info = (SYSTEM_PROCESS_INFORMATION*)((ULONG_PTR)proc_info + proc_info->NextEntryOffset);
	}

	VirtualFree(buffer, buffer_size, MEM_RELEASE);
	return 0;
}

int main()
{
	// Search for notepad.exe PID
	const wchar_t* proc = L"notepad.exe";
	find_process(proc);
	return 0;
}