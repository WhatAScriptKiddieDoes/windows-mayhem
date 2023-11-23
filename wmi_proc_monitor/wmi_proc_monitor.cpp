// Process monitor using WMI notification
#include <iostream>
#include <wbemidl.h>
#include <comdef.h>

#pragma comment(lib, "wbemuuid.lib")


// WMI notifications are sent to an object of type IWbemObjectSink
/*
HRESULT ExecNotificationQueryAsync(
  [in] const BSTR      strQueryLanguage,
  [in] const BSTR      strQuery,
  [in] long            lFlags,
  [in] IWbemContext    *pCtx,
  [in] IWbemObjectSink *pResponseHandler <-- see this
);
*/
class QuerySink : public IWbemObjectSink
{
    LONG m_lRef;
    bool bDone;

public:
    QuerySink() { m_lRef = 0; }
    ~QuerySink() { bDone = TRUE; }

    virtual ULONG STDMETHODCALLTYPE AddRef();
    virtual ULONG STDMETHODCALLTYPE Release();
    virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv);

    // Indicate is executed when a notification is received
    virtual HRESULT STDMETHODCALLTYPE Indicate(
        LONG lObjectCount,
        IWbemClassObject** apObjArray
    );

    virtual HRESULT STDMETHODCALLTYPE SetStatus(
        LONG lFlags,
        HRESULT hResult,
        BSTR strParam,
        IWbemClassObject* pObjParam
    );
};

// Increase the number of references
ULONG QuerySink::AddRef()
{
    return InterlockedIncrement(&m_lRef);
}

// Decrease the number of references. If it zero, destroy the object
ULONG QuerySink::Release()
{
    LONG lRef = InterlockedDecrement(&m_lRef);
    if (lRef == 0)
        delete this;
    return lRef;
}

// Return the pointer to the object itself
HRESULT QuerySink::QueryInterface(REFIID riid, void** ppv)
{
    if (riid == IID_IUnknown || riid == IID_IWbemObjectSink)
    {
        *ppv = (IWbemObjectSink*)this;
        AddRef();
        return WBEM_S_NO_ERROR;
    }
    else return E_NOINTERFACE;
}

// Always return WBEM_S_NO_ERROR
HRESULT QuerySink::SetStatus(
    LONG lFlags,
    HRESULT hResult,
    BSTR strParam,
    IWbemClassObject __RPC_FAR* pObjParam
)
{
    return WBEM_S_NO_ERROR;
}

// This function handles the output of the WMI event
// All the important logic is here
HRESULT QuerySink::Indicate(
    LONG lObjectCount, // Size of apObjArray
    IWbemClassObject** apObjArray// Array of object
)
{
    HRESULT hresult = S_OK;
    _variant_t v;

    // Loop over all received object properties
    for (long i = 0; i < lObjectCount; i++)
    {
        IWbemClassObject* p_obj = apObjArray[i];
        // Get a pointer to the object properties
        hresult = p_obj->Get(_bstr_t(L"TargetInstance"), 0, &v, 0, 0);

        if (!FAILED(hresult)) {
            IUnknown* proc = v;
            // Pointer to the process object interface
            hresult = proc->QueryInterface(IID_IWbemClassObject, (void**)&p_obj);
            
            // Extract the information from the interface
            if (!FAILED(hresult)) {
                _variant_t val;
                
                // Get process name
                hresult = p_obj->Get(L"Name", 0, &val, NULL, NULL);
                if (!FAILED(hresult)) {
                    if (val.vt == VT_NULL || val.vt == VT_EMPTY) {
                        printf("Process name: %s\n", (val.vt == VT_NULL) ? "NULL" : "EMPTY");
                    }
                    else {
                        printf("Process name: %S\n", val.bstrVal);
                    }
                }
                VariantClear(&val);

                // Get process ID
                hresult = p_obj->Get(L"Handle", 0, &val, NULL, NULL);
                if (!FAILED(hresult)) {
                    if (val.vt == VT_NULL || val.vt == VT_EMPTY) {
                        printf("PID: %s\n", (val.vt == VT_NULL) ? "NULL" : "EMPTY");
                    }
                    else {
                        printf("PID: %S\n", val.bstrVal);
                    }
                }
                VariantClear(&val);

                // Get executable path
                hresult = p_obj->Get(L"ExecutablePath", 0, &val, NULL, NULL);
                if (!FAILED(hresult)) {
                    if (val.vt == VT_NULL || val.vt == VT_EMPTY) {
                        printf("Executable path: %s\n", (val.vt == VT_NULL) ? "NULL" : "EMPTY");
                    }
                    else {
                        printf("Executable path: %S\n", val.bstrVal);
                    }
                }
                VariantClear(&val);

                // Get command line
                hresult = p_obj->Get(L"CommandLine", 0, &val, NULL, NULL);
                if (!FAILED(hresult)) {
                    if (val.vt == VT_NULL || val.vt == VT_EMPTY) {
                        printf("Command line: %s\n", (val.vt == VT_NULL) ? "NULL" : "EMPTY");
                    }
                    else {
                        printf("Command line: %S\n", val.bstrVal);
                    }
                }
                VariantClear(&val);
            }
            VariantClear(&v);
        }
    }
    return WBEM_S_NO_ERROR;
}


int main()
{
    // Register the sink object with COM

    // Phase 1: Setup COM
    // Example here https://learn.microsoft.com/en-us/windows/win32/wmisdk/example-creating-a-wmi-application
    HRESULT hresult;
    hresult = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hresult)) {
        printf("[!] CoInitializeEx failed.\n");
        return -1;
    }

    hresult = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL
    );
    if (FAILED(hresult)) {
        printf("[!] CoInitializeSecurity failed.\n");
        CoUninitialize();
        return -1;
    }

    // Create a WbemLocator
    IWbemLocator* ploc = NULL;
    hresult = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        (LPVOID*)&ploc
    );
    if (FAILED(hresult)) {
        printf("[!] CoCreateInstance failed.\n");
        CoUninitialize();
        return -1;
    }

    // Connect to the root\cimv2 namespace
    // Get a pointer to make IWbemService calls
    IWbemServices* pwbem_services = NULL;
    hresult = ploc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), // WMI namespace
        NULL,                    // User name
        NULL,                    // User password
        0,                       // Locale
        NULL,                    // Security flags                 
        0,                       // Authority       
        0,                       // Context object
        &pwbem_services          // IWbemServices proxy
    );
    if (FAILED(hresult)) {
        printf("[!] ConnectServer failed.\n");
        ploc->Release();
        CoUninitialize();
        return -1;
    }

    printf("[*] Connected to the ROOT\\CIMV2 WMI namespace.\n");

    // Set IWbemServices so that impersonation of the client occurs
    hresult = CoSetProxyBlanket(
        pwbem_services,               // The proxy to set
        RPC_C_AUTHN_WINNT,            // Authentication service
        RPC_C_AUTHZ_NONE,             // Authorization service
        NULL,                         // Server principal name
        RPC_C_AUTHN_LEVEL_CALL,       // Authentication level
        RPC_C_IMP_LEVEL_IMPERSONATE,  // Impersonation level
        NULL,                         // Client identity 
        EOAC_NONE                     // Proxy capabilities     
    );
    if (FAILED(hresult)) {
        printf("[!] CoSetProxyBlanket failed.\n");
        pwbem_services->Release();
        ploc->Release();
        CoUninitialize();
        return -1;
    }

    // Phase 2: Create and register the sink
    // Create sink object
    QuerySink* qs = new QuerySink;
    qs->AddRef();

    // Call ExecNotificationQueryAsync to register the callback
    hresult = pwbem_services->ExecNotificationQueryAsync(
        _bstr_t("WQL"),
        _bstr_t("SELECT * FROM __InstanceCreationEvent WITHIN 1 Where TargetInstance ISA 'Win32_Process'"),
        WBEM_FLAG_SEND_STATUS,
        NULL,
        qs
    );
    if (FAILED(hresult)) {
        printf("[!] ExecNotificationQueryAsync failed.\n");
        pwbem_services->Release();
        ploc->Release();
        qs->Release();
        CoUninitialize();
        return -1;
    }

    printf("[*] Waiting for events...\n");
    getchar();

    // Clean up
    pwbem_services->CancelAsyncCall(qs);
    pwbem_services->Release();
    ploc->Release();
    qs->Release();
    CoUninitialize();

    printf("[*] Cleanup done. Exiting...\n");
    return 0;
}
