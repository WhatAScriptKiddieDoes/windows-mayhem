// It is possible to craft the creation, modify and access timestamp on files using the NtSetInformationFile function.

#include <windows.h>
#include <stdio.h>

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef enum _FILE_INFORMATION_CLASS {
	FileBasicInformation = 4,
	FileStandardInformation = 5,
	FilePositionInformation = 14,
	FileEndOfFileInformation = 20,
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef struct _FILE_BASIC_INFORMATION {
	LARGE_INTEGER CreationTime;		// Created             
	LARGE_INTEGER LastAccessTime;   // Accessed    
	LARGE_INTEGER LastWriteTime;    // Modifed
	LARGE_INTEGER ChangeTime;       // Entry Modified
	ULONG FileAttributes;
} FILE_BASIC_INFORMATION, * PFILE_BASIC_INFORMATION;

typedef NTSTATUS(WINAPI* pNtQueryInformationFile)(
	HANDLE,
	PIO_STATUS_BLOCK,
	PVOID,
	ULONG,
	FILE_INFORMATION_CLASS
	);

typedef NTSTATUS(WINAPI* pNtSetInformationFile)(
	HANDLE,
	PIO_STATUS_BLOCK,
	PVOID,
	ULONG,
	FILE_INFORMATION_CLASS
	);

BOOL clone_timestamp(char* sourcefile, char* destfile) {
	// Resolve Nt functions
	pNtQueryInformationFile NtQueryInformationFile = (pNtQueryInformationFile)GetProcAddress(
		GetModuleHandle(L"ntdll.dll"), "NtQueryInformationFile");
	if (NtQueryInformationFile == NULL) {
		printf("[!] Error resolving NtQueryInformationFile.\n");
		return FALSE;
	}
	pNtSetInformationFile NtSetInformationFile = (pNtSetInformationFile)GetProcAddress(
		GetModuleHandle(L"ntdll.dll"), "NtSetInformationFile");
	if (NtSetInformationFile == NULL) {
		printf("[!] Error resolving NtSetInformationFile.\n");
		return FALSE;
	}

	// Open target files
	HANDLE hsourcefile = CreateFileA(
		sourcefile,
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);

	if (hsourcefile == INVALID_HANDLE_VALUE) {
		printf("[!] Error opening source file.\n");
		return FALSE;
	}

	HANDLE hdestfile = CreateFileA(
		destfile,
		GENERIC_READ | GENERIC_WRITE | FILE_WRITE_ATTRIBUTES,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);

	if (hdestfile == INVALID_HANDLE_VALUE) {
		printf("[!] Error opening destination file.\n");
		return FALSE;
	}

	IO_STATUS_BLOCK iosb;
	FILE_BASIC_INFORMATION source_fbi, dest_fbi;

	// Get source and destination file information
	if (NtQueryInformationFile(
		hsourcefile,
		&iosb,
		&source_fbi,
		sizeof(FILE_BASIC_INFORMATION),
		FileBasicInformation
	) < 0) {
		printf("[!] Failed NtQueryInformation file on source file.\n");
		CloseHandle(hsourcefile);
		CloseHandle(hdestfile);
		return FALSE;
	}

	if (NtQueryInformationFile(
		hdestfile,
		&iosb,
		&dest_fbi,
		sizeof(FILE_BASIC_INFORMATION),
		FileBasicInformation
	) < 0) {
		printf("[!] Failed NtQueryInformation file on destination file.\n");
		CloseHandle(hsourcefile);
		CloseHandle(hdestfile);
		return FALSE;
	}

	// Set new timestamp and set it on the file
	dest_fbi.LastWriteTime = source_fbi.LastWriteTime;
	dest_fbi.LastAccessTime = source_fbi.LastAccessTime;
	dest_fbi.ChangeTime = source_fbi.ChangeTime;
	dest_fbi.CreationTime = source_fbi.CreationTime;

	if (NtSetInformationFile(
		hdestfile,
		&iosb,
		&dest_fbi,
		sizeof(FILE_BASIC_INFORMATION),
		FileBasicInformation
	) < 0) {
		printf("[!] Failed NtSetInformationFile on destination file.\n");
		CloseHandle(hsourcefile);
		CloseHandle(hdestfile);
		return FALSE;
	}

	CloseHandle(hsourcefile);
	CloseHandle(hdestfile);
	return TRUE;
}



int main(int argc, char* argv[])
{
	if (argc < 3) {
		printf("%s <source_file> <dest_file>\n", argv[0]);
		return -1;
	}

	if (clone_timestamp(argv[1], argv[2])) {
		printf("[*] Operation successful!\n");
	}
	else {
		printf("[!] Operation failed!\n");
	}

	return 0;
}
