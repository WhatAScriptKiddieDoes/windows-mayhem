// Loaded modules enumeration using VirtualQueryEx

#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <Psapi.h>

int list_modules(int pid) {
	HANDLE proc_handle = NULL;
	MEMORY_BASIC_INFORMATION mbi;
	char* base = NULL;

	// Same procedure as process enumeration
	proc_handle = OpenProcess(
		PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
		FALSE,
		pid
	);
	if (proc_handle == NULL) {
		return -1;
	}

	// Query the process memory starting from NULL
	while (VirtualQueryEx(
		proc_handle,
		base,
		&mbi,
		sizeof(mbi)
	) == sizeof(MEMORY_BASIC_INFORMATION)) {
		char mod_name[MAX_PATH];
		// Check if the memory region is the base address of an allocation
		if (mbi.AllocationBase == mbi.BaseAddress && mbi.AllocationBase != NULL) {
			// If it is, get the module's file name with GetModuleFileNameEx
			if (GetModuleFileNameExA(
				proc_handle,
				(HMODULE)mbi.AllocationBase, // The base address of the module
				mod_name,
				sizeof(mod_name)
			) != 0) {
				printf("%s\n", mod_name);
			}
		}
		base += mbi.RegionSize;
	}
	CloseHandle(proc_handle);
	return -1;
}


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
			return pid;
		}
	}
	return -1;
}


int main()
{
	// Search for notepad.exe PID
	const wchar_t* proc = L"notepad.exe";
	int pid = find_process(proc);
	if (pid != -1) {
		// List modules loaded by the process
		list_modules(pid);
	}
	return 0;
}
