/*
DLLs that are specified in the AppInit_DLLs value in the registry keys
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows or
HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows
are loaded by user32.dll for every process that uses that library.

This can be leverage to hook the creation of every process using user32.dll, by setting the appropriate registry keys.

This technique has two pitfalls:
- It requires local admin privileges to set up.
- Not all processes load user32.dll, but most do.

The AppInit functionality may be disabled on Windows 8 onwards if secure boot is enabled.
*/

#include <Windows.h>
#include <iostream>

bool appinit_setup(const char* dll_path) { // The hooking DLL must be in the C:/ drive
    HKEY key;
    DWORD load_init_data = 0x1;
    DWORD required_signed = 0x0;

    LSTATUS status = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        0,
        KEY_READ | KEY_SET_VALUE,
        &key
    );
    if (status != ERROR_SUCCESS) {
        printf("[!] RegOpenKeyEx failed.\n");
        return false;
    }

    // HLKM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs to the hooking DLL
    status = RegSetValueExA(
        key,
        "AppInit_DLLs",
        0,
        REG_SZ,
        (BYTE*)dll_path,
        strlen(dll_path)
    );
    if (status != ERROR_SUCCESS) {
        printf("[!] RegSetValueExA failed.\n");
        return false;
    }

    // HLKM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\LoadAppInit_DLLs to 0x1
    status = RegSetValueExA(
        key,
        "LoadAppInit_DLLs",
        0,
        REG_DWORD,
        (BYTE*)&load_init_data,
        sizeof(load_init_data)
    );
    if (status != ERROR_SUCCESS) {
        printf("[!] RegSetValueExA failed.\n");
        return false;
    }

    // HLKM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\RequireSignedAppInit_DLLs to 0x0
    status = RegSetValueExA(
        key,
        "RequireSignedAppInit_DLLs",
        0,
        REG_DWORD,
        (BYTE*)&required_signed,
        sizeof(required_signed)
    );
    if (status != ERROR_SUCCESS) {
        printf("[!] RegSetValueExA failed.\n");
        return false;
    }

    RegCloseKey(key);
    return true;
}

// Cleanup the AppInit setup
bool cleanup() {
    HKEY key;
    DWORD load_init_data = 0x0;
    DWORD required_signed = 0x1;
    const char* appinit_dlls = "\0";
    DWORD bytes_out = 0;

    LSTATUS status = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        0,
        KEY_READ | KEY_SET_VALUE,
        &key
    );
    if (status != ERROR_SUCCESS) {
        printf("[!] RegOpenKeyEx failed.\n");
        return false;
    }

    status = RegSetValueExA(
        key,
        "AppInit_DLLs",
        0,
        REG_SZ,
        (BYTE*)appinit_dlls,
        strlen(appinit_dlls)
    );
    if (status != ERROR_SUCCESS) {
        printf("[!] RegSetValueExA failed.\n");
        return false;
    }

    status = RegSetValueExA(
        key,
        "LoadAppInit_DLLs",
        0,
        REG_DWORD,
        (BYTE*)&load_init_data,
        sizeof(load_init_data)
    );
    if (status != ERROR_SUCCESS) {
        printf("[!] RegSetValueExA failed.\n");
        return false;
    }

    status = RegSetValueExA(
        key,
        "RequireSignedAppInit_DLLs",
        0,
        REG_DWORD,
        (BYTE*)&required_signed,
        sizeof(required_signed)
    );
    if (status != ERROR_SUCCESS) {
        printf("[!] RegSetValueExA failed.\n");
        return false;
    }

    RegCloseKey(key);
    return true;
}

int main()
{
    appinit_setup("C:\\PATH\\TO\HOOKDLL");
    printf("[*] AppInit hook set. Press any button to unhook and exit..\n");
    getchar();
    cleanup();
}
