// Extended attributes are a very old compatibility feature of the NTFS file system
// NTFS allows the user to create one or more extended attributes associated to a file.
// There are no command line tools that can be used to query the extended attributes on a file.
// The maximum size for a single extended attribute is 64kB (0xffff).

// When files are copied, certain extended attributes may not exist in the copy.

#include <Windows.h>
#include <stdio.h>
#include <winternl.h>

typedef struct _FILE_FULL_EA_INFORMATION {
	ULONG  NextEntryOffset;
	UCHAR  Flags;
	UCHAR  EaNameLength; // Size of the EA name (256 chars)
	USHORT EaValueLength; // Size of the data (max 0xffff)
	CHAR   EaName[1];
} FILE_FULL_EA_INFORMATION, * PFILE_FULL_EA_INFORMATION;

typedef NTSTATUS(WINAPI* pZwQueryEaFile)(
	HANDLE           FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	BOOLEAN          ReturnSingleEntry,
	PVOID            EaList,
	ULONG            EaListLength,
	PULONG           EaIndex,
	BOOLEAN          RestartScan
	);

typedef NTSTATUS(WINAPI* pZwSetEaFile)(
	HANDLE           FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length
	);

pZwQueryEaFile ZwQueryEaFile = NULL;
pZwSetEaFile ZwSetEaFile = NULL;

// Initialize EA functions
BOOL init_ea() {
	ZwQueryEaFile = (pZwQueryEaFile)GetProcAddress(
		GetModuleHandle(L"ntdll.dll"), "ZwQueryEaFile");
	if (ZwQueryEaFile == NULL) {
		printf("[!] Error resolving ZwQueryEaFile.\n");
		return FALSE;
	}
	pZwSetEaFile ZwSetEaFile = (pZwSetEaFile)GetProcAddress(
		GetModuleHandle(L"ntdll.dll"), "ZwSetEaFile");
	if (ZwSetEaFile == NULL) {
		printf("[!] Error resolving ZwSetEaFile.\n");
		return FALSE;
	}
	return TRUE;
}

// Does not check internally for buffer overruns, be careful!
BOOL write_ea(
	HANDLE target_file,
	char* attribute_name,
	UCHAR attribute_name_size,
	char* value,
	USHORT value_size) {

	// Allocate buffer for FILE_FULL_EA_INFORMATION
	LPVOID buffer = malloc(sizeof(FILE_FULL_EA_INFORMATION) + attribute_name_size + value_size);
	if (buffer == NULL) {
		printf("[!] Error allocating buffer\n");
		return FALSE;
	}

	IO_STATUS_BLOCK iosb;
	// Cast the struct to the buffer and set its values
	FILE_FULL_EA_INFORMATION* ea_info = (FILE_FULL_EA_INFORMATION*)buffer;
	ea_info->NextEntryOffset = 0;
	ea_info->Flags = 0;
	ea_info->EaNameLength = attribute_name_size;
	ea_info->EaValueLength = value_size;
	strcpy_s(ea_info->EaName, ea_info->EaNameLength + 1, attribute_name);
	memcpy(ea_info->EaName + ea_info->EaNameLength + 1, value, ea_info->EaValueLength);

	// Write the extended attributes
	if (ZwSetEaFile(
		target_file,
		&iosb,
		buffer,
		sizeof(FILE_FULL_EA_INFORMATION) + attribute_name_size + value_size
	) != 0) {
		printf("[!] Error writing extended attributes\n");
		free(buffer);
		return FALSE;
	}

	return TRUE;
}

BOOL read_ea(HANDLE target_file, PVOID buffer, ULONG buffer_size) {
	IO_STATUS_BLOCK iosb;

	if (ZwQueryEaFile(
		target_file,
		&iosb,
		buffer,
		buffer_size,
		FALSE,
		NULL,
		0,
		NULL,
		TRUE
	) != 0) {
		printf("[!] Error querying extended attributes on file\n");
		return FALSE;
	}
	return TRUE;
}

void parse_and_print_ea(PVOID buffer, size_t buffer_size) {

}

int main(int argc, char* argv[])
{
	if (argc < 2) {
		printf("%s <target_file>\n", argv[0]);
		return -1;
	}

	if (!init_ea()) {
		return -1;
	}

	char ea_name[] = "hidden";
	char ea_value[] = "This is a secret";
	size_t ea_value_size = strlen(ea_value);

	// Open target file
	HANDLE hfile = CreateFileA(
		argv[1],
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);
	if (hfile == INVALID_HANDLE_VALUE) {
		printf("[!] Error opening the target file.\n");
		return -1;
	}

	ULONG output_buf_size = 0x2000;
	PVOID output_buf = malloc(output_buf_size);
	if (output_buf == NULL) {
		printf("[!] Error allocating output buffer\n");
		CloseHandle(hfile);
		return -1;
	}

	if (read_ea(hfile, output_buf, output_buf_size)) {
		parse_and_print_ea(output_buf, output_buf_size);
	}


	CloseHandle(hfile);

	return 0;
}
