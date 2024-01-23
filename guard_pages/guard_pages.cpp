/*
PAGE_GUARD is a memory protection constant that can be set on memory pages
https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants

Any attempt to access a guard page causes the system to raise an exception STATUS_GUARD_PAGE_VIOLATION
Windows has several methods for exception handling. In this case we use Vector Exception Handling

- In userland, when the exception occurs, Windows will try to send the exception to the debugger (if present)
- If there is no debugger, it will try to locate any registered exception handling routine in the current process
- If there are none, the default exception handling routine is used, which typically terminates the process

The exception handlers is a function that receives a structure of type EXCEPTION_POINTERS
https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_pointers

Page guards can be used as a hooking mechanism:
1. Register an exception handler using the AddVectoredExceptionHandler API call
2. Set a PAGE_GUARD flag on the page the function we want to hook resides into
3. Profit

Since the flag is set on the full page (4096 bytes), this method is not very precise
*/

#include <stdio.h>
#include <Windows.h>

// Same signature as CreateThread, but does something else instead
HANDLE replace_createthread(
    LPSECURITY_ATTRIBUTES rcx,
    SIZE_T rdx,
    LPTHREAD_START_ROUTINE r8,
    LPVOID r9,
    DWORD stck1,
    DWORD stck2
) {
    printf("[!] CreateThread replaced!\n");
    getchar();
    return NULL;
}

LONG WINAPI exception_handler(EXCEPTION_POINTERS* ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
        // Check if the instruction pointer is at CreateThread, if it is, print the registers
        if (ExceptionInfo->ContextRecord->Rip == (DWORD64)&CreateThread) {
            printf("[!] Exception (%#llx): Parameters:\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);
            printf("    | rcx: %#llx\n", ExceptionInfo->ContextRecord->Rcx); // Parameter 1
            printf("    | rdx: %#llx\n", ExceptionInfo->ContextRecord->Rdx); // Parameter 2
            printf("    | r8: %#llx\n", ExceptionInfo->ContextRecord->R8); // Parameter 3
            printf("    | r9: %#llx\n", ExceptionInfo->ContextRecord->R9); // Parameter 4
            printf("    ` rsp: %#llx\n", ExceptionInfo->ContextRecord->Rsp); // The rest is passed on the stack
            getchar();
            // Change the instruction pointer to the function above
            ExceptionInfo->ContextRecord->Rip = (DWORD64)&replace_createthread;
        }
        // The page was just accessed
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    // In case of other exceptions tell Windows to search for another handler
    return EXCEPTION_CONTINUE_SEARCH;
}

int main()
{
    AddVectoredExceptionHandler(1, &exception_handler);
    DWORD old = 0;
    VirtualProtect(&CreateThread, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &old);
    printf("[*] CreateThread memory protection set: %#p\n", &CreateThread);

    // Call CreateThread to Sleep for 5 seconds
    DWORD params = 5000;
    HANDLE thread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)&Sleep, &params, 0, 0);
    WaitForSingleObject(thread, params); // Wait for the thread to finish
    return 0;
}