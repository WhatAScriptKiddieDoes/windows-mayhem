// DLL to be loaded into hooked processes

#include <Windows.h>
#include <stdio.h>

// Dummy function used to hook
extern "C" __declspec(dllexport) int Dummy(void) {
    return 0;
}

// Print to debugview
void debug_out(const char* fmt, ...) {
    char dbg_output[4096];
    va_list argp;
    va_start(argp, fmt);
    vsprintf_s(dbg_output, fmt, argp);
    va_end(argp);
    OutputDebugStringA((LPCSTR)dbg_output);

}

// Execute when the DLL is attached to the target
// Ideally it would check the process name and take the correct action (kill the process maybe?)
void execute_on_load(void) {
    char proc_image_name[MAX_PATH];

    HANDLE proc_handle = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        GetCurrentProcessId()
    );

    if (proc_handle) {
        DWORD max_path = MAX_PATH;
        QueryFullProcessImageNameA(proc_handle, 0, proc_image_name, &max_path);
    }

    debug_out("[!] DLL injected into %s\n", proc_image_name);
    return;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(
            0,
            0,
            (LPTHREAD_START_ROUTINE)execute_on_load,
            0,
            0,
            0
        );
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}



