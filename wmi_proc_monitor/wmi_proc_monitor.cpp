
#include <iostream>
#include <wbemidl.h>
#include <comdef.h>

#pragma comment(lib, "wbemuuid.lib")


// WMI notifications are sent to an object of type IWbemObjectSink
class QuerySink : public IWbemObjectSink
{
    LONG m_lRef;
    bool bDone;

public:
    QuerySink() { m_lRef = 0; }
    ~QuerySink() { bDone = TRUE; }

    virtual ULONG STDMETHODCALLTYPE AddRef();
    virtual ULONG STDMETHODCALLTYPE Release();
    virtual HRESULT STDMETHODCALLTYPE
        QueryInterface(REFIID riid, void** ppv);

    virtual HRESULT STDMETHODCALLTYPE Indicate(
        LONG lObjectCount,
        IWbemClassObject __RPC_FAR* __RPC_FAR* apObjArray
    );

    virtual HRESULT STDMETHODCALLTYPE SetStatus(
        LONG lFlags,
        HRESULT hResult,
        BSTR strParam,
        IWbemClassObject __RPC_FAR* pObjParam
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
    long lObjCount, // Size of pArray
    IWbemClassObject** pArray // Array of object
)
{
    HRESULT hresult = S_OK;
    _variant_t v;

    // Loop over all received object properties
    for (long i = 0; i < lObjCount; i++)
    {
        IWbemClassObject* p_obj = pArray[i];
        hresult = p_obj->Get(_bstr_t(L"TargetInstance"), 0, &v, 0, 0);

        if (!FAILED(hresult)) {
            IUnknown* proc = v; // Pointer to the process object interface
            // TODO
        }

    }

    return WBEM_S_NO_ERROR;
}


int main()
{

}
