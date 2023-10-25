#include <Windows.h>
#include <stdio.h>
#include <psapi.h>

// List loaded modules with EnumProcessModulesEx
int list_modules(int pid) {
	HMODULE hmodules[1024];
	HANDLE proc_handle = NULL;
	DWORD bytes_needed;

	// Same procedure as process enumeration
	proc_handle = OpenProcess(
		PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
		FALSE,
		pid
	);
	if (proc_handle == NULL) {
		return -1;
	}

	if (EnumProcessModulesEx(
		proc_handle,
		hmodules,
		sizeof(hmodules),
		&bytes_needed,
		LIST_MODULES_ALL
	)) {
		// For each module
		for (int i = 0; i < (bytes_needed/sizeof(HMODULE)); i++) {
			char mod_name[MAX_PATH];
			if (GetModuleFileNameExA(
				proc_handle,
				hmodules[i],
				(LPSTR)mod_name,
				sizeof(mod_name) / sizeof(TCHAR)
			)) {
				printf("%s\n", mod_name);
			}
		}
	}
	return -1;
}

// Search for a process PID using EnumProcesses 
int find_process(const wchar_t* process_name) {
	int pid = 0;
	DWORD procs[1024], nproc, ret_bytes;
	TCHAR proc_name[MAX_PATH] = { 0 };


	if (!EnumProcesses(procs, sizeof(procs), &ret_bytes)) {
		return -1;
	}

	// Calculate number of processes returned
	nproc = ret_bytes / sizeof(DWORD);
	for (unsigned int i = 0; i < nproc; i++) {
		// For each process
		if (procs[i] != 0) {
			// Open process handle
			HANDLE proc_handle = OpenProcess(
				PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
				FALSE,
				procs[i]
			);
			if (proc_handle == NULL) {
				continue;
			}

			// Get process modules
			HMODULE module_handle;
			DWORD nmods;
			if (EnumProcessModules(
				proc_handle,
				&module_handle,
				sizeof(module_handle),
				&nmods
			) && GetModuleBaseName(
				proc_handle,
				module_handle,
				(LPWSTR)proc_name,
				sizeof(proc_name) / sizeof(TCHAR)
			) != 0) {
				if (_wcsicmp(process_name, proc_name) == 0) {
					pid = procs[i];
					printf("[*] Process found at PID %d\n", pid);
					return pid;
				}
			}
		}
	}
	return 0;
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