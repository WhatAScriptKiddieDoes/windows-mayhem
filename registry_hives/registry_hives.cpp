// Registry hives can be used to store data (string, exes, dlls, shellcode...).
// The maximum size of a registry hive is 2GB (the system hive is smaller).
// Microsoft suggests to store long values (more than 2048 bytes) in a file instead.

#include <windows.h>
#include <stdio.h>

int main()
{
	// Write to a registry key
	LPCVOID write_data = "Test key value";
	DWORD size = (DWORD)strlen((char*)write_data);
	if (RegSetKeyValue(
		HKEY_CURRENT_USER,
		L"Software\\Google\\Chrome\\ThirdParty",
		L"NewKey",
		REG_BINARY,
		write_data,
		size
	) != ERROR_SUCCESS) {
		printf("[!] Error setting the target registry key.\n");
		return -1;
	}

	// Read from a registry key
	LPVOID output[1024];
	size = sizeof(output);

	if (RegGetValue(
		HKEY_CURRENT_USER,
		L"Software\\Google\\Chrome\\ThirdParty",
		L"NewKey",
		RRF_RT_REG_BINARY,
		NULL,
		output,
		&size
	) != ERROR_SUCCESS) {
		printf("[!] Error reading the target registry key.\n");
		return -1;
	}

	printf("[*] Registry key read: %s\n", (char*)output);
	return 0;
}