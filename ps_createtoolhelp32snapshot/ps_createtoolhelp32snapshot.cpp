// Process enumeration using the classic CreateToolhelp32Snapshot method.

#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

// Search for a process PID using CreateToolhelp32Snapshot
int find_process(const wchar_t* process_name) {
	HANDLE proc_snap;
	PROCESSENTRY32 proc_entry;
	proc_entry.dwSize = sizeof(PROCESSENTRY32);
	int pid = 0;

	proc_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (proc_snap == INVALID_HANDLE_VALUE) {
		printf("[!] CreateToolhelp32Snapshot failed.\n");
		return -1;
	}

	// The first process is the current process
	if (!Process32First(proc_snap, &proc_entry)) {
		printf("[!] Process32First failed.\n");
		CloseHandle(proc_snap);
		return -1;
	}

	// Search for the target process
	while (Process32Next(proc_snap, &proc_entry)) {
		if (_wcsicmp(process_name, proc_entry.szExeFile) == 0) {
			pid = proc_entry.th32ProcessID;
			printf("[*] Process found at PID %d\n", pid);
			break; // Comment the break to find multiple instances
		}
	}
	return 0;
}


int main()
{
	// Search for notepad.exe PID
	const wchar_t* proc = L"notepad.exe";
	find_process(proc);
	return 0;
}
