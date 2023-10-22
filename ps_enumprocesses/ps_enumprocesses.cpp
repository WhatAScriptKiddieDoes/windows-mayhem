
#include <Windows.h>
#include <stdio.h>
#include <psapi.h>

// Search for a process PID using CreateToolhelp32Snapshot
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
					continue; // Find multiple instances
				}
			}
		}
	}

		
}

int main()
{
	// Search for notepad.exe PID
	const wchar_t* proc = L"notepad.exe";
	find_process(proc);
	return 0;
}