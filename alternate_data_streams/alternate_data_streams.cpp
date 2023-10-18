// Alternate data streams can be used to hide data within files or even directories.
// To list alternate data streams:
// cmd> dir /r .

#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[])
{
	// Check the filesystem is of type NTFS
	char fstype[1024];

	if (!GetVolumeInformationA("C:\\", NULL, NULL, NULL, NULL, NULL, fstype, 1024)) {
		printf("[!] Failed to get volume information.\n");
		return -1;
	}

	if (_stricmp(fstype, "NTFS") != 0) {
		printf("[!] Target volume is not of type NTFS.\n");
		return -1;
	}

	// Open file (also works on directories)
	const wchar_t* target_stream = L"C:\\Users\\Administrator\\Desktop\\test.txt:hidden";

	HANDLE hfile = CreateFileW(
		target_stream,
		GENERIC_READ | GENERIC_WRITE | FILE_WRITE_ATTRIBUTES,
		FILE_SHARE_READ, // Allows other CreateFileW with read only access
		NULL,
		OPEN_ALWAYS,
		FILE_FLAG_SEQUENTIAL_SCAN | FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hfile == INVALID_HANDLE_VALUE) {
		printf("[!] Error opening the target file.\n");
		return -1;
	}

	// Write to stream
	BYTE write_data[] = "ADS";
	DWORD bytes_written = 0;

	if (!WriteFile(
		hfile,
		write_data,
		sizeof(write_data),
		&bytes_written,
		NULL
	)) {
		printf("[!] Write to file failed.\n");
		CloseHandle(hfile);
		return -1;
	}

	// Enumerate streams
	WIN32_FIND_STREAM_DATA stream_data;
	HANDLE hstream = FindFirstStreamW(
		target_stream,
		FindStreamInfoStandard,
		&stream_data,
		0
	);

	if (hstream == INVALID_HANDLE_VALUE) {
		printf("[!] Error getting first stream info.\n");
		CloseHandle(hfile);
		return -1;
	}

	printf("[*] Found streams:\n");
	// Loop over all streams
	while (TRUE) {
		printf("(%u) %S\n", stream_data.StreamSize, stream_data.cStreamName);
		if (!FindNextStreamW(hstream, &stream_data)) {
			break;
		}
	}

	FindClose(hstream);

	// Read data from stream
	BYTE output_buf[1024];
	DWORD bytes_read = 0;

	SetFilePointer(
		hfile,
		NULL,
		NULL,
		FILE_BEGIN
	);
	if (ReadFile(hfile, output_buf, sizeof(output_buf), &bytes_read, NULL) && bytes_read > 0) {
		printf("[*] Data read from alternate data stream:\n%s", output_buf);
	}
	else {
		printf("[!] ReadFile failed.\n");
		return -1;
	}

	return 0;
}
