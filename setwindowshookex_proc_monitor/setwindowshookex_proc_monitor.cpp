// Inject a hooking DLL into a target process/every process with a GUI using SetWindowsHookEx

// Be careful when calling UnhookWindowsHookEx, as it may crashes the hooked process depending on the state.
// If a function inside the hooking DLL is in execution, the DLL will be unloaded.
// When the function returns, the program is going to crash. 

#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>

int find_target_pid(const wchar_t* process_name) {
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
			break; // Comment the break to find multiple instances
		}
	}
	CloseHandle(proc_snap);
	return pid;
}

int find_thread_id(int target_pid) {
	int tid = -1;
	THREADENTRY32 thread_entry;
	thread_entry.dwSize = sizeof(thread_entry);

	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	while (Thread32Next(snap, &thread_entry)) {
		if (thread_entry.th32OwnerProcessID == target_pid) {
			tid = thread_entry.th32ThreadID;
			break;
		}
	}
	CloseHandle(snap);
	return tid;
}

int main()
{
	// Hook notepad.exe
	/*
	int tid = -1;
	HANDLE proc = NULL;
	HANDLE thread = NULL;

	
	tid = find_thread_id(find_target_pid(L"notepad.exe"));
	if (tid != -1) {
		HMODULE dll = LoadLibrary(L"global_hooks_lib.dll");
		HOOKPROC hook_proc = (HOOKPROC)GetProcAddress(dll, "Dummy");
		HHOOK debug_hook = SetWindowsHookEx(
			WH_GETMESSAGE,
			hook_proc,
			dll,
			tid
		);

		PostThreadMessageW(tid, WM_RBUTTONDOWN, (WPARAM)0, (LPARAM)0);

		printf("[*] Thread %d hooked.\n", tid);
		getchar();
		UnhookWindowsHookEx(debug_hook);
		return 0;
	}
	else {
		printf("[!] Cannot locate target thread.\n");
		return -1;
	}
	*/

	// Hook every GUI process
	// Load the hooking DLL
	HMODULE dll = LoadLibrary(L"global_hooks_lib.dll");
	// The Dummy function is executed every time the hook is triggered,
	HOOKPROC hook_proc = (HOOKPROC)GetProcAddress(dll, "Dummy");
	// Place the hook
	HHOOK debug_hook = SetWindowsHookEx(
		WH_GETMESSAGE,
		hook_proc,
		dll,
		0
	);
	printf("[*] Hook set. Press any button to unhook and exit.\n");
	getchar();
	UnhookWindowsHookEx(debug_hook);
}
