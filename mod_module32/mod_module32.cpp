#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

// List modules loaded in a target process
int list_modules(int pid) {
	HANDLE module_snap = NULL;
	MODULEENTRY32 module_entry;
	module_entry.dwSize = sizeof(MODULEENTRY32);

	module_snap = CreateToolhelp32Snapshot(
		TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, // Only these two permissions are required to enumerate modules
		pid
	);

	if (module_snap == INVALID_HANDLE_VALUE) {
		printf("[!] CreateToolhelp32Snapshot failed.\n");
		return -1;
	}

	// Iterate over all modules
	if (!Module32First(module_snap, &module_entry)) {
		printf("[!] Module32First failed.\n");
		CloseHandle(module_snap);
		return -1;
	}

	do {
		// Useful information from the module entry:
		// - szExePath: full path to the module
		// - szModule: module name
		// - modBaseAddr: base address of the module
		// - modBaseSize: module size
		printf("%ls\n", module_entry.szModule);
	} while (Module32Next(module_snap, &module_entry));

	// Cleanup
	CloseHandle(module_snap);
	return 0;
}

// Search for a process PID using CreateToolhelp32Snapshot
int find_process(const wchar_t* process_name) {
	HANDLE proc_snap;
	PROCESSENTRY32 proc_entry;
	proc_entry.dwSize = sizeof(PROCESSENTRY32);
	int pid = -1;

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
			break;
		}
	}
	return pid;
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
