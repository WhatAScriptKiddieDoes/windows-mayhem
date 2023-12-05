// Load or unload a driver using the service manager
#include <Windows.h>
#include <iostream>

#define SERVICE_NAME L"ProcExp64"
#define DISPLAY_NAME L"ProcExp64"
#define DRIVER_FULLPATH L"C:\\PATH\\TO\\PROCEXP.sys"


// Enable/disable selected privilege on the target token
BOOL modify_privilege(HANDLE token, LPCTSTR privilege, bool enable_privilege)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, privilege, &luid)) {
        printf("[!] LookupPrivilegeValue() failed with 0x%x\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (enable_privilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("[!] AdjustTokenPrivileges() failed with 0x%x\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("[!] The token does not have the specified privilege.\n");
        return FALSE;
    }

    return TRUE;
}

// Create the driver service if it does not exist
BOOL create_driver_service(LPCWSTR service_name, LPCWSTR display_name, LPCWSTR driver_path) {
    // Get an handle to service manager
    SC_HANDLE sc_manager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (sc_manager == NULL) {
        printf("[!] OpenSCManager failed.\n");
        return FALSE;
    }
    // Try to open the service to check if it already exists
    SC_HANDLE sc_service = OpenServiceW(
        sc_manager,
        service_name,
        SERVICE_ALL_ACCESS
    );

    // If OpenService failed, try to create it as a new one
    if (sc_service == NULL) {
        sc_service = CreateServiceW(
            sc_manager,
            service_name,
            service_name,
            SC_MANAGER_ALL_ACCESS, //SC_MANAGER_CREATE_SERVICE | SERVICE_START | SERVICE_CHANGE_CONFIG,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_IGNORE,
            driver_path,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
        );
    }

    if (sc_service == NULL) {
        printf("[!] Cannot get an handle to the service.\n");
        CloseServiceHandle(sc_manager);
        return FALSE;
    }

    CloseServiceHandle(sc_manager);
    CloseServiceHandle(sc_service);
    return TRUE;
}
// Start the driver service
BOOL start_driver_service(LPCWSTR service_name) {
    // Get an handle to service manager
    SC_HANDLE sc_manager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (sc_manager == NULL) {
        printf("[!] OpenSCManager failed.\n");
        return FALSE;
    }

    // Try to open the service to check if it already exists
    SC_HANDLE sc_service = OpenServiceW(
        sc_manager,
        service_name,
        SERVICE_ALL_ACCESS
    );

    if (sc_service == NULL) {
        printf("[!] OpenServiceW failed.\n");
        CloseServiceHandle(sc_manager);
        return FALSE;
    }

    // https://learn.microsoft.com/en-us/windows/win32/services/starting-a-service
    // Check the status in case the service is not stopped. 
    SERVICE_STATUS_PROCESS service_status;
    DWORD bytes_needed;
    if (!QueryServiceStatusEx(
        sc_service,
        SC_STATUS_PROCESS_INFO,
        (LPBYTE)&service_status,
        sizeof(SERVICE_STATUS_PROCESS),
        &bytes_needed
    )) {
        printf("[!] QueryServiceStatusEx failed.\n");
        CloseServiceHandle(sc_service);
        CloseServiceHandle(sc_manager);
        return FALSE;
    }

    // SERVICE_RUNNING -> return TRUE
    // SERVICE_STOP_PENDING -> wait for SERVICE_STOP, then StartService, wait for SERVICE_RUNNING
    // SERVICE_STOPPED -> StartService, wait for SERVICE_RUNNING
    // SERVICE_START_PENDING -> wait for SERVICE_RUNNING
    // SERVICE_CONTINUE_PENDING, SERVICE_PAUSE_PENDING, SERVICE_PAUSED -> ignore and exit with error

    if (service_status.dwCurrentState == SERVICE_RUNNING) {
        printf("[*] The service is already running\n");
        CloseServiceHandle(sc_service);
        CloseServiceHandle(sc_manager);
        return TRUE;
    }

    DWORD start_tick_count = 0;
    DWORD wait_time = 0;
    DWORD old_checkpoint = 0;
    if (service_status.dwCurrentState == SERVICE_STOP_PENDING) {
        // If the service is in SERVICE_STOP_PENDING, wait for it to stop
        start_tick_count = GetTickCount();
        old_checkpoint = service_status.dwCheckPoint;
        while (service_status.dwCurrentState == SERVICE_STOP_PENDING) {
            // Wait for the wait hint / 10, not less than 1 second and no more than 10 seconds
            wait_time = service_status.dwWaitHint / 10;
            if (wait_time < 1000)
                wait_time = 1000;
            else if (wait_time > 10000)
                wait_time = 10000;
            Sleep(wait_time);

            // Check the current status again
            if (!QueryServiceStatusEx(
                sc_service,
                SC_STATUS_PROCESS_INFO,
                (LPBYTE)&service_status,
                sizeof(SERVICE_STATUS_PROCESS),
                &bytes_needed
            )) {
                printf("QueryServiceStatusEx failed.\n");
                CloseServiceHandle(sc_service);
                CloseServiceHandle(sc_manager);
                return FALSE;
            }

            if (service_status.dwCheckPoint > old_checkpoint) {
                // Continue to wait and check.
                start_tick_count = GetTickCount();
                old_checkpoint = service_status.dwCheckPoint;
            }
            else {
                // Do not wait longer than the wait hint
                if (GetTickCount() - start_tick_count > service_status.dwWaitHint) {
                    printf("[!] Timeout waiting for service to stop\n");
                    CloseServiceHandle(sc_manager);
                    CloseServiceHandle(sc_service);
                    return FALSE;
                }
            }
        }
    }

    if (service_status.dwCurrentState == SERVICE_STOPPED) {
        if (!StartService(
            sc_service,
            0,
            NULL
        )) {
            printf("[!] StartService failed (%d)\n", GetLastError());
            CloseServiceHandle(sc_service);
            CloseServiceHandle(sc_manager);
            return FALSE;
        }
    }

    // Check the current status, should be SERVICE_RUNNING or SERVICE_START_PENDING
    if (!QueryServiceStatusEx(
        sc_service,
        SC_STATUS_PROCESS_INFO,
        (LPBYTE)&service_status,
        sizeof(SERVICE_STATUS_PROCESS),
        &bytes_needed
    )) {
        printf("QueryServiceStatusEx failed.\n");
        CloseServiceHandle(sc_service);
        CloseServiceHandle(sc_manager);
        return FALSE;
    }

    start_tick_count = GetTickCount();
    old_checkpoint = service_status.dwCheckPoint;

    while (service_status.dwCurrentState == SERVICE_START_PENDING) {
        wait_time = service_status.dwWaitHint / 10;
        if (wait_time < 1000)
            wait_time = 1000;
        else if (wait_time > 10000)
            wait_time = 10000;
        Sleep(wait_time);

        if (!QueryServiceStatusEx(
            sc_service,
            SC_STATUS_PROCESS_INFO,
            (LPBYTE)&service_status,
            sizeof(SERVICE_STATUS_PROCESS),
            &bytes_needed
        )) {
            printf("QueryServiceStatusEx failed.\n");
            CloseServiceHandle(sc_manager);
            CloseServiceHandle(sc_service);
            return FALSE;
        }

        if (service_status.dwCheckPoint > old_checkpoint) {
            start_tick_count = GetTickCount();
            old_checkpoint = service_status.dwCheckPoint;
        }
        else
        {
            if (GetTickCount() - start_tick_count > service_status.dwWaitHint)
            {
                printf("[!] Timeout waiting for service to start\n");
                CloseServiceHandle(sc_manager);
                CloseServiceHandle(sc_service);
                return FALSE;
            }
        }
    }

    if (service_status.dwCurrentState != SERVICE_RUNNING)
    {
        printf("[!] Cannot start the service.\n");
        CloseServiceHandle(sc_manager);
        CloseServiceHandle(sc_service);
        return FALSE;
    }
    return TRUE;
}

// Stop the driver service
BOOL stop_driver_service(LPCWSTR service_name) {
    // Get an handle to service manager
    SC_HANDLE sc_manager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (sc_manager == NULL) {
        printf("[!] OpenSCManager failed.\n");
        return FALSE;
    }

    // Try to open the service to check if it already exists
    SC_HANDLE sc_service = OpenServiceW(
        sc_manager,
        service_name,
        SERVICE_ALL_ACCESS
    );

    if (sc_service == NULL) {
        printf("[!] OpenServiceW failed.\n");
        CloseServiceHandle(sc_manager);
        return FALSE;
    }

    // https://learn.microsoft.com/en-us/windows/win32/services/stopping-a-service
    SERVICE_STATUS_PROCESS service_status;
    DWORD bytes_needed = 0;

    if (!QueryServiceStatusEx(
        sc_service,
        SC_STATUS_PROCESS_INFO,
        (LPBYTE)&service_status,
        sizeof(SERVICE_STATUS_PROCESS),
        &bytes_needed
    )) {
        printf("[!] QueryServiceStatusEx failed.\n");
        CloseServiceHandle(sc_service);
        CloseServiceHandle(sc_manager);
        return FALSE;
    }

    // Anything different than SERVICE_STOPPED or SERVICE_STOP_PENDING -> ControlService to SERVICE_CONTROL_STOP,
    // then wait for SERVICE_STOP and DeleteService
    // SERVICE_STOP_PENDING -> wait for SERVICE_STOPPED, then DeleteService
    // SERVICE_STOPPED -> DeleteService

    if (service_status.dwCurrentState != SERVICE_STOPPED &&
        service_status.dwCurrentState != SERVICE_STOP_PENDING) {
        if (!ControlService(sc_service, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS) & service_status)) {
            printf("[!] ControlService failed: %d.\n", GetLastError());
            CloseServiceHandle(sc_manager);
            CloseServiceHandle(sc_service);
            return FALSE;
        }
        // Query the service again
        // Should be in SERVICE_STOPPED or SERVICE_STOP_PENDING now
        if (!QueryServiceStatusEx(
            sc_service,
            SC_STATUS_PROCESS_INFO,
            (LPBYTE)&service_status,
            sizeof(SERVICE_STATUS_PROCESS),
            &bytes_needed
        )) {
            printf("[!] QueryServiceStatusEx failed.\n");
            CloseServiceHandle(sc_service);
            CloseServiceHandle(sc_manager);
            return FALSE;
        }
    }

    // Wait for the service to stop
    DWORD wait_time = 0;
    DWORD start_tick_count = GetTickCount();
    DWORD old_checkpoint = service_status.dwCheckPoint;
    while (service_status.dwCurrentState == SERVICE_STOP_PENDING) {
        wait_time = service_status.dwWaitHint / 10;
        if (wait_time < 1000)
            wait_time = 1000;
        else if (wait_time > 10000)
            wait_time = 10000;
        Sleep(wait_time);

        if (!QueryServiceStatusEx(
            sc_service,
            SC_STATUS_PROCESS_INFO,
            (LPBYTE)&service_status,
            sizeof(SERVICE_STATUS_PROCESS),
            &bytes_needed
        )) {
            printf("[!] QueryServiceStatusEx failed.\n");
            CloseServiceHandle(sc_service);
            CloseServiceHandle(sc_manager);
            return FALSE;
        }

        if (service_status.dwCheckPoint > old_checkpoint) {
            start_tick_count = GetTickCount();
            old_checkpoint = service_status.dwCheckPoint;
        }
        else {
            if (GetTickCount() - start_tick_count > service_status.dwWaitHint) {
                printf("[!] Timeout waiting for service to stop\n");
                CloseServiceHandle(sc_manager);
                CloseServiceHandle(sc_service);
                return FALSE;
            }
        }
    }

    if (!QueryServiceStatusEx(
        sc_service,
        SC_STATUS_PROCESS_INFO,
        (LPBYTE)&service_status,
        sizeof(SERVICE_STATUS_PROCESS),
        &bytes_needed
    )) {
        printf("[!] QueryServiceStatusEx failed (%d)\n", GetLastError());
        CloseServiceHandle(sc_service);
        CloseServiceHandle(sc_manager);
        return FALSE;
    }

    if (service_status.dwCurrentState != SERVICE_STOPPED) {
        printf("[!] Cannot stop the service.\n");
        CloseServiceHandle(sc_manager);
        CloseServiceHandle(sc_service);
        return FALSE;
    }
    return TRUE;
}
// Delete the driver service
BOOL delete_driver_service(LPCWSTR service_name) {
    // Get an handle to service manager
    SC_HANDLE sc_manager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (sc_manager == NULL) {
        printf("[!] OpenSCManager failed.\n");
        return FALSE;
    }

    // Try to open the service to check if it already exists
    SC_HANDLE sc_service = OpenServiceW(
        sc_manager,
        service_name,
        SERVICE_ALL_ACCESS
    );

    if (sc_service == NULL) {
        printf("[!] OpenServiceW failed.\n");
        CloseServiceHandle(sc_manager);
        return FALSE;
    }

    // Check the service is stopped
    SERVICE_STATUS_PROCESS service_status;
    DWORD bytes_needed = 0;
    if (!QueryServiceStatusEx(
        sc_service,
        SC_STATUS_PROCESS_INFO,
        (LPBYTE)&service_status,
        sizeof(SERVICE_STATUS_PROCESS),
        &bytes_needed
    )) {
        printf("[!] QueryServiceStatusEx failed.\n");
        CloseServiceHandle(sc_service);
        CloseServiceHandle(sc_manager);
        return FALSE;
    }

    // If the service is not stopped, attempt to stop it
    if (service_status.dwCurrentState != SERVICE_STOPPED) {
        printf("[!] Service not stopped.\n");
        CloseServiceHandle(sc_service);
        CloseServiceHandle(sc_manager);
        return FALSE;
    }

    if (!DeleteService(sc_service)) {
        printf("[!] DeleteService failed.\n");
        CloseServiceHandle(sc_manager);
        CloseServiceHandle(sc_service);
        return FALSE;
    }
    CloseServiceHandle(sc_manager);
    CloseServiceHandle(sc_service);
    return TRUE;
}


int main(int argc, char** argv)
{
    // Enable SeLoadDriverPrivilege
    HANDLE current_token_handle = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &current_token_handle)) {
        printf("[!] OpenProcessToken() failed with 0x%x\n", GetLastError());
        return -1;
    }

    if (!modify_privilege(current_token_handle, L"SeLoadDriverPrivilege", TRUE)) {
        printf("[!] Cannot enable SeLoadDriverPrivilege\n");
        CloseHandle(current_token_handle);
        return -1;
    }
    CloseHandle(current_token_handle);


    if (!create_driver_service(SERVICE_NAME, DISPLAY_NAME, DRIVER_FULLPATH)) {
        printf("[!] Cannot install driver.\n");
        return -1;
    }

    if (!start_driver_service(SERVICE_NAME)) {
        printf("[!] Cannot start the driver service.\n");
        return -1;
    }
    
    // Unload the driver
    /*
    if (!stop_driver_service(SERVICE_NAME)) {
        printf("[!] Cannot uninstall driver.\n");
        return -1;
    }

    if (!delete_driver_service(SERVICE_NAME)) {
        printf("[!] Cannot uninstall driver.\n");
        return -1;
    }
    */

    return 0;
}

