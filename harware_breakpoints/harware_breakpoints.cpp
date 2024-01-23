/*
The alternative to page guards is to use debug registers, which allow for a more precise definition
of where execution should be intercepted.

There are 7 debug registers in Intel-based CPUs:
- DR0 - DR3 should contain the address of the breakpoint
- DR4 and DR5 are reserved.
- DR6 contains some configuration bits which tell if the debug exception should trigger only in the thread or in the process
- DR7 contains the the main configuration which tells the CPU in what condition the breakpoint should trigger

https://www.intel.com/content/dam/support/us/en/documents/processors/pentium4/sb/253669.pdf

To set up a breakpoint:
1. Set the address of the breakpoint in one debug register (for example DR0)
2. Enable it in DR7, configure the length of it (1 byte in this case) and the trigger (16 and 17 bits to 0 for execution only)

*/
#include <iostream>
#include <Windows.h>

void set_breakpoint(HANDLE thread, DWORD64 address, BOOL set) {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_ALL;
    GetThreadContext(thread, &ctx);

    if (set == TRUE) {
        ctx.Dr0 = address;
        ctx.Dr7 |= (1 << 0); // Enable local DR0 breakpoint (first bit to 1)
        // Break only on execution (set 16 and 17 to 0)
        ctx.Dr7 &= ~(1 << 16);
        ctx.Dr7 &= ~(1 << 17);
    }
    else {
        ctx.Dr0 = NULL;
        ctx.Dr7 &= ~(1 << 0);
    }

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    SetThreadContext(thread, &ctx);
	return;
}

LONG WINAPI exception_handler(EXCEPTION_POINTERS* ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        // Check if the instruction pointer is at CreateThread, if it is, print the registers
        if (ExceptionInfo->ContextRecord->Rip == (DWORD64)&Sleep) {
            printf("[!] Exception (%#llx): Parameters:\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);
            printf("    | rcx: %#llx\n", ExceptionInfo->ContextRecord->Rcx); // Parameter 1
            printf("    | rdx: %#llx\n", ExceptionInfo->ContextRecord->Rdx); // Parameter 2
            printf("    | r8: %#llx\n", ExceptionInfo->ContextRecord->R8); // Parameter 3
            printf("    | r9: %#llx\n", ExceptionInfo->ContextRecord->R9); // Parameter 4
            printf("    ` rsp: %#llx\n", ExceptionInfo->ContextRecord->Rsp); // The rest is passed on the stack

            // The exception handler must continue the execution, otherwise the breakpoint is hit again in a loop
            // Continue the execution by setting the resume flag RF
            ExceptionInfo->ContextRecord->EFlags |= (1 << 16);
            // Alternative by stepping with the instruction pointer
            //ExceptionInfo->ContextRecord->Rip++;
        }
        // The page was just accessed
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    // In case of other exceptions tell Windows to search for another handler
    return EXCEPTION_CONTINUE_SEARCH;
}

int main()
{
	// Add exception handler, as in guard pages
	AddVectoredExceptionHandler(1, &exception_handler);

	set_breakpoint(GetCurrentThread(), (DWORD64)&Sleep, TRUE);

	printf("[*] Breakpoint set!\n");
	printf("[*] Triggering Sleep...\n");
	Sleep(3000);

    set_breakpoint(GetCurrentThread(), (DWORD64)&Sleep, FALSE);
	printf("[*] Breakpoint removed!\n");
    printf("[*] Triggering Sleep...\n");
	Sleep(3000);
	return 0;
}
