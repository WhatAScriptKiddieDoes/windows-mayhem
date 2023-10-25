// Process enumeration using Windows Terminal Services.

#include <Windows.h>
#include <stdio.h>
#include <WtsApi32.h>

#pragma comment(lib, "Wtsapi32.lib")

int find_process(const char* process_name) {
	int pid = -1;
	WTS_PROCESS_INFOA* proc_info;
	DWORD proc_info_count = 0;

	if (!WTSEnumerateProcessesA(
		WTS_CURRENT_SERVER_HANDLE,
		0,
		1,
		&proc_info,
		&proc_info_count
	)) {
		printf("[!] WTSEnumerateProcessA failed.\n");
			return -1;
	}

	for (int i = 0; i < proc_info_count; i++) {
		if (lstrcmpiA(process_name, proc_info[i].pProcessName) == 0) {
			pid = proc_info[i].ProcessId;
			printf("[*] Process found at PID %d\n", pid);
			continue;
		}
	}

	WTSFreeMemory(proc_info);
	return 0;

}

int main() {
	// Search for notepad.exe PID
	const char* proc = "notepad.exe";
	find_process(proc);
	return 0;
}