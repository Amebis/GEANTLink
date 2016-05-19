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

#pragma comment(lib, "Comctl32.lib")


//////////////////////////////////////////////////////////////////////
// eap::session_ttls
//////////////////////////////////////////////////////////////////////

eap::session_ttls::session_ttls() : session_base()
{
}


//////////////////////////////////////////////////////////////////////
// eap::peer_ui_base
//////////////////////////////////////////////////////////////////////

eap::peer_ttls_ui::peer_ttls_ui() : peer_ui_base()
{
}


DWORD eap::peer_ttls_ui::invoke_config_ui(
    _In_                                 const EAP_METHOD_TYPE *pEapType,
    _In_                                       HWND            hwndParent,
    _In_                                       DWORD           dwFlags,
    _In_                                       DWORD           dwSizeOfConnectionDataIn,
    _In_count_(dwSizeOfConnectionDataIn) const BYTE            *pConnectionDataIn,
    _Out_                                      DWORD           *pdwSizeOfConnectionDataOut,
    _Out_                                      BYTE            **ppConnectionDataOut,
    _Out_                                      EAP_ERROR       **ppEapError)
{
    UNREFERENCED_PARAMETER(pEapType);
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(dwSizeOfConnectionDataIn);
    UNREFERENCED_PARAMETER(pConnectionDataIn);
    UNREFERENCED_PARAMETER(pdwSizeOfConnectionDataOut);
    UNREFERENCED_PARAMETER(ppConnectionDataOut);
    UNREFERENCED_PARAMETER(ppEapError);

    InitCommonControls();
    MessageBox(hwndParent, _T(PRODUCT_NAME_STR) _T(" configuration goes here!"), _T(PRODUCT_NAME_STR) _T(" Settings"), MB_OK);

    return ERROR_SUCCESS;
}


DWORD eap::peer_ttls_ui::invoke_identity_ui(
            _In_                               const EAP_METHOD_TYPE *pEapType,
            _In_                                     DWORD           dwFlags,
            _In_                                     HWND            hwndParent,
            _In_                                     DWORD           dwSizeOfConnectionData,
            _In_count_(dwSizeOfConnectionData) const BYTE            *pConnectionData,
            _In_                                     DWORD           dwSizeOfUserData,
            _In_count_(dwSizeOfUserData)       const BYTE            *pUserData,
            _Out_                                    DWORD           *pdwSizeOfUserDataOut,
            _Out_                                    BYTE            **ppUserDataOut,
            _Out_                                    LPWSTR          *ppwszIdentity,
            _Out_                                    EAP_ERROR       **ppEapError)
{
    UNREFERENCED_PARAMETER(pEapType);
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(dwSizeOfConnectionData);
    UNREFERENCED_PARAMETER(pConnectionData);
    UNREFERENCED_PARAMETER(dwSizeOfUserData);
    UNREFERENCED_PARAMETER(pUserData);
    UNREFERENCED_PARAMETER(pdwSizeOfUserDataOut);
    UNREFERENCED_PARAMETER(ppUserDataOut);
    UNREFERENCED_PARAMETER(ppwszIdentity);
    UNREFERENCED_PARAMETER(ppEapError);

    InitCommonControls();
    MessageBox(hwndParent, _T(PRODUCT_NAME_STR) _T(" credential prompt goes here!"), _T(PRODUCT_NAME_STR) _T(" Credentials"), MB_OK);

    return ERROR_SUCCESS;
}


DWORD eap::peer_ttls_ui::invoke_interactive_ui(
    _In_                              const EAP_METHOD_TYPE *pEapType,
    _In_                                    HWND            hwndParent,
    _In_                                    DWORD           dwSizeofUIContextData,
    _In_count_(dwSizeofUIContextData) const BYTE            *pUIContextData,
    _Out_                                   DWORD           *pdwSizeOfDataFromInteractiveUI,
    _Out_                                   BYTE            **ppDataFromInteractiveUI,
    _Out_                                   EAP_ERROR       **ppEapError)
{
    UNREFERENCED_PARAMETER(pEapType);
    UNREFERENCED_PARAMETER(dwSizeofUIContextData);
    UNREFERENCED_PARAMETER(pUIContextData);
    UNREFERENCED_PARAMETER(pdwSizeOfDataFromInteractiveUI);
    UNREFERENCED_PARAMETER(ppDataFromInteractiveUI);
    UNREFERENCED_PARAMETER(ppEapError);

    InitCommonControls();
    MessageBox(hwndParent, _T(PRODUCT_NAME_STR) _T(" interactive UI goes here!"), _T(PRODUCT_NAME_STR) _T(" Prompt"), MB_OK);

    return ERROR_SUCCESS;
}
