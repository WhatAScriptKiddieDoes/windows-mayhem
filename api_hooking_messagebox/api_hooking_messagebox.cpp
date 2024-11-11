// Example program that patches the address of MessageBoxA to execute a hooked function instead.
// Notice this version works only on x86.

#include <iostream>
#include <Windows.h>

FARPROC messagebox_address = NULL;
char messagebox_original[6] = { 0 };


int __stdcall NewMessageBox(HWND hwnd, LPCSTR text, LPCSTR caption, UINT type) {
    SIZE_T bytes_written = 0;

    printf("MessageBox called!\n");
    printf("Text: %s\n", text);
    printf("Caption: %s\n", caption);

    // Remove the patch (otherwise this function gets called again)
    WriteProcessMemory(
        GetCurrentProcess(),
        messagebox_address,
        messagebox_original,
        6,
        &bytes_written
    );

    return MessageBoxA(hwnd, text, caption, type);
}


int main()
{
    // MessageBox without hooks
    MessageBoxA(NULL, "test", "test", MB_OK);

    HINSTANCE lib = LoadLibraryA("user32.dll");

    if (lib == NULL) {
        printf("[!] LoadLibrary failed (0x%X)\n", GetLastError());
        return -1;
    }
    
    SIZE_T bytes_read = 0;
    SIZE_T bytes_written = 0;

    messagebox_address = GetProcAddress(lib, "MessageBoxA");
    
    // Read the first 6 bytes at MessageBox
    ReadProcessMemory(
        GetCurrentProcess(),
        messagebox_address,
        messagebox_original,
        6,
        &bytes_read);

    void* new_message_box_addr = &NewMessageBox;
    char patch[6] = { 0 };
    memcpy_s(patch, 1, "\x68", 1);
    memcpy_s(patch + 1, 4, &new_message_box_addr, 4);
    memcpy_s(patch + 5, 1, "\xc3", 1);

    WriteProcessMemory(
        GetCurrentProcess(),
        (LPVOID)messagebox_address,
        patch,
        6,
        &bytes_written
    );

    MessageBoxA(NULL, "test", "test", MB_OK);
    return 0;
}