// Enumerate processes with NtGetNextProcess.
// NtGetNextProcess gets an handle to each process without having to use OpenProcess, which can be used for other stuff ;)
// The Process Hacker source code is a goldmine to find useful API:
// https://processhacker.sourceforge.io/doc/termator_8c_source.html

#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <shlwapi.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Shlwapi.lib")


typedef NTSTATUS(NTAPI* _NtGetNextProcess)(
	_In_ HANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ ULONG HandleAttributes,
	_In_ ULONG Flags,
	_Out_ PHANDLE NewProcessHandle
	);


int find_process(const char* process_name) {
	int pid = -1;
	_NtGetNextProcess pNtGetNextProcess = (_NtGetNextProcess)GetProcAddress(
		GetModuleHandle(L"ntdll.dll"), "NtGetNextProcess"
	);
	if (pNtGetNextProcess == NULL) {
		printf("[!] Error resolving NtGetNextProcess.\n");
		return -1;
	}

	HANDLE proc_handle = NULL;
	char proc_temp_name[MAX_PATH];

	while (!pNtGetNextProcess(
		proc_handle,
		MAXIMUM_ALLOWED,
		0,
		0,
		&proc_handle)) {
		if (GetProcessImageFileNameA(
			proc_handle,
			proc_temp_name,
			MAX_PATH
		) != 0 && lstrcmpiA(process_name, PathFindFileNameA(proc_temp_name)) == 0) {
			pid = GetProcessId(proc_handle);
			printf("[*] Process found at PID %d\n", pid);
		}
	}
		
	return 0;
}

int main()
{
	// Search for notepad.exe PID
	const char* proc = "notepad.exe";
	find_process(proc);
	return 0;
}