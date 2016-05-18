/*
    Copyright 2015-2016 Amebis
    Copyright 2016 GÉANT

    This file is part of GEANTLink.

    GEANTLink is free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    GEANTLink is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with GEANTLink. If not, see <http://www.gnu.org/licenses/>.
*/

#include <StdAfx.h>

using namespace std;
using namespace winstd;


#define ETW_FN_VOID         event_fn_auto    <         &EAPMETHOD_TRACE_EVT_FN_CALL, &EAPMETHOD_TRACE_EVT_FN_RETURN        > _event_auto(*g_ep, __FUNCTION__)
#define ETW_FN_DWORD(res)   event_fn_auto_ret<DWORD  , &EAPMETHOD_TRACE_EVT_FN_CALL, &EAPMETHOD_TRACE_EVT_FN_RETURN_DWORD  > _event_auto(*g_ep, __FUNCTION__, res)
#define ETW_FN_HRESULT(res) event_fn_auto_ret<HRESULT, &EAPMETHOD_TRACE_EVT_FN_CALL, &EAPMETHOD_TRACE_EVT_FN_RETURN_HRESULT> _event_auto(*g_ep, __FUNCTION__, res)


event_provider *g_ep = NULL;


// event_fn_auto actually and winstd::event_auto_res<> do not need an assignment operator actually, so the C4512 warning is safely ignored.
#pragma warning(push)
#pragma warning(disable: 4512)

///
/// Helper class to write an event on entry/exit of scope.
///
/// It writes one string event at creation and another at destruction.
///
template <const EVENT_DESCRIPTOR *event_cons, const EVENT_DESCRIPTOR *event_dest>
class event_fn_auto
{
public:
    inline event_fn_auto(_In_ event_provider &ep, _In_z_ LPCSTR pszFnName) : m_ep(ep)
    {
        EventDataDescCreate(&m_fn_name, pszFnName, (ULONG)(strlen(pszFnName) + 1)*sizeof(*pszFnName));
        m_ep.write(event_cons, 1, &m_fn_name);
    }

    inline ~event_fn_auto()
    {
        m_ep.write(event_dest, 1, &m_fn_name);
    }

protected:
    event_provider &m_ep;               ///< Reference to event provider in use
    EVENT_DATA_DESCRIPTOR m_fn_name;    ///< Function name
};


///
/// Helper template to write an event on entry/exit of scope with one parameter (typically result).
///
/// It writes one string event at creation and another at destruction, with allowing one sprintf type parameter for string event at destruction.
///
template<class T, const EVENT_DESCRIPTOR *event_cons, const EVENT_DESCRIPTOR *event_dest>
class event_fn_auto_ret
{
public:
    inline event_fn_auto_ret(_In_ event_provider &ep, _In_z_ LPCSTR pszFnName, T &result) : m_ep(ep), m_result(result)
    {
        EventDataDescCreate(m_desc + 0, pszFnName, (ULONG)(strlen(pszFnName) + 1)*sizeof(*pszFnName));
        m_ep.write(event_cons, 1, m_desc);
    }

    inline ~event_fn_auto_ret()
    {
        EventDataDescCreate(m_desc + 1, &m_result, sizeof(T));
        m_ep.write(event_dest, 2, m_desc);
    }

protected:
    event_provider &m_ep;               ///< Reference to event provider in use
    T &m_result;                        ///< Function result
    EVENT_DATA_DESCRIPTOR m_desc[2];    ///< Function name and return value
};

#pragma warning(pop)



BOOL WINAPI DllMain(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_ LPVOID lpvReserved)
{
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpvReserved);

    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_ep = new event_provider();
        assert(g_ep);
        g_ep->create(&EAPMETHOD_TRACE_EVENT_PROVIDER);
        g_ep->write<unsigned int>(&EAPMETHOD_TRACE_EVT_MODULE_LOAD, EAPMETHOD_TYPE);
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        assert(g_ep);
        g_ep->write<unsigned int>(&EAPMETHOD_TRACE_EVT_MODULE_UNLOAD, EAPMETHOD_TYPE);
        delete g_ep;

        assert(!_CrtDumpMemoryLeaks());
    }

    return TRUE;
}


//#pragma comment(linker, "/EXPORT:DllRegisterServer,PRIVATE")
//#pragma comment(linker, "/EXPORT:DllUnregisterServer,PRIVATE")


extern "C"
{
    /////
    ///// Registers the EAP method.
    /////
    //HRESULT STDAPICALLTYPE DllRegisterServer()
    //{
    //    HRESULT hr = S_OK;
    //    ETW_FN_HRESULT(hr);

    //    return hr;
    //}


    /////
    ///// Unregisters the EAP method.
    /////
    //HRESULT STDAPICALLTYPE DllUnregisterServer()
    //{
    //    HRESULT hr = S_OK;
    //    ETW_FN_HRESULT(hr);

    //    return hr;
    //}


    ///
    /// Releases all memory associated with an opaque user interface context data buffer.
    ///
    /// \sa [EapPeerFreeMemory function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363606.aspx)
    ///
    __declspec(dllexport) VOID WINAPI EapPeerFreeMemory(_In_ void *pUIContextData)
    {
        ETW_FN_VOID;

        if (pUIContextData) {
            // Since we do security here and some of the BLOBs contain credentials, sanitize every memory block before freeing.
            HANDLE hHeap = GetProcessHeap();
            SecureZeroMemory(pUIContextData, HeapSize(hHeap, 0, pUIContextData));
            HeapFree(hHeap, 0, pUIContextData);
        }
    }


    ///
    /// Releases error-specific memory allocated by the EAP peer method.
    ///
    /// \sa [EapPeerFreeErrorMemory function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363605.aspx)
    ///
    __declspec(dllexport) VOID WINAPI EapPeerFreeErrorMemory(_In_ EAP_ERROR *ppEapError)
    {
        ETW_FN_VOID;

        if (ppEapError) {
            // pRootCauseString and pRepairString always trail the ppEapError to reduce number of (de)allocations.
            HeapFree(GetProcessHeap(), 0, ppEapError);
        }
    }
};
