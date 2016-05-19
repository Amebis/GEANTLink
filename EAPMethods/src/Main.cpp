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


#if EAPMETHOD_TYPE==21
#define _EAPMETHOD_PEER eap::peer_ttls
#else
#error Unknown EAP Method type.
#endif

_EAPMETHOD_PEER g_peer;


///
/// DLL main entry point
///
/// \sa [DllMain entry point](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682583.aspx)
///
BOOL WINAPI DllMain(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_ LPVOID lpvReserved)
{
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpvReserved);

    if (fdwReason == DLL_PROCESS_ATTACH) {
#ifdef _DEBUG
        //Sleep(10000);
#endif
        if (g_peer.create() != ERROR_SUCCESS)
            return FALSE;
    } else if (fdwReason == DLL_PROCESS_DETACH)
        assert(!_CrtDumpMemoryLeaks());

    return TRUE;
}


///
/// Releases all memory associated with an opaque user interface context data buffer.
///
/// \sa [EapPeerFreeMemory function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363606.aspx)
///
VOID WINAPI EapPeerFreeMemory(_In_ void *pUIContextData)
{
    g_peer.free_memory(pUIContextData);
}


///
/// Releases error-specific memory allocated by the EAP peer method.
///
/// \sa [EapPeerFreeErrorMemory function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363605.aspx)
///
VOID WINAPI EapPeerFreeErrorMemory(_In_ EAP_ERROR *ppEapError)
{
    g_peer.free_error_memory(ppEapError);
}


///
/// Obtains a set of function pointers for an implementation of the EAP peer method currently loaded on the EAPHost service.
///
/// \sa [EapPeerGetInfo function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363608.aspx)
///
DWORD WINAPI EapPeerGetInfo(_In_ EAP_TYPE* pEapType, _Out_ EAP_PEER_METHOD_ROUTINES* pEapPeerMethodRoutines, _Out_ EAP_ERROR **ppEapError)
{
    DWORD dwResult = NO_ERROR;
#ifdef _DEBUG
    //Sleep(10000);
#endif

    // Parameter check
    if (!ppEapError)
        dwResult = ERROR_INVALID_PARAMETER;
    else if (!pEapType)
        *ppEapError = g_peer.make_error(dwResult = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pEapType is NULL."), NULL);
    else if (pEapType->type != EAPMETHOD_TYPE)
        *ppEapError = g_peer.make_error(dwResult = ERROR_NOT_SUPPORTED, 0, NULL, NULL, NULL, winstd::wstring_printf(_T(__FUNCTION__) _T(" Input EAP type (%d) does not match the supported EAP type (%d)."), (int)pEapType->type, (int)EAPMETHOD_TYPE).c_str(), NULL);
    else if (!pEapPeerMethodRoutines)
        *ppEapError = g_peer.make_error(dwResult = ERROR_INVALID_PARAMETER, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" pEapPeerMethodRoutines is NULL."), NULL);
    else
        g_peer.get_info(pEapPeerMethodRoutines);

    return dwResult;
}
