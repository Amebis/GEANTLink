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


//////////////////////////////////////////////////////////////////////
// eap::session_base
//////////////////////////////////////////////////////////////////////

eap::session_base::session_base()
{
}


DWORD eap::session_base::begin(_In_ DWORD dwFlags, _In_ const EapAttributes *pAttributeArray, _In_ HANDLE hTokenImpersonateUser, _In_ DWORD dwSizeofConnectionData, _In_count_(dwSizeofConnectionData) BYTE *pConnectionData, _In_ DWORD dwSizeofUserData, _In_count_(dwSizeofUserData) BYTE *pUserData, _In_ DWORD dwMaxSendPacketSize, _Out_ EAP_ERROR **ppEapError)
{
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(pAttributeArray);
    UNREFERENCED_PARAMETER(hTokenImpersonateUser);
    UNREFERENCED_PARAMETER(dwSizeofConnectionData);
    UNREFERENCED_PARAMETER(pConnectionData);
    UNREFERENCED_PARAMETER(dwSizeofUserData);
    UNREFERENCED_PARAMETER(pUserData);
    UNREFERENCED_PARAMETER(dwMaxSendPacketSize);
    UNREFERENCED_PARAMETER(ppEapError);

    return ERROR_SUCCESS;
}


DWORD eap::session_base::end(_Out_ EAP_ERROR **ppEapError)
{
    UNREFERENCED_PARAMETER(ppEapError);

    return ERROR_SUCCESS;
}


DWORD eap::session_base::process_request_packet(_In_ DWORD dwSizeofReceivePacket, _In_bytecount_(dwSizeofReceivePacket) EapPacket *pReceivePacket, _Out_ EapPeerMethodOutput *pEapOutput, _Out_ EAP_ERROR **ppEapError)
{
    UNREFERENCED_PARAMETER(dwSizeofReceivePacket);
    UNREFERENCED_PARAMETER(pReceivePacket);
    UNREFERENCED_PARAMETER(pEapOutput);
    UNREFERENCED_PARAMETER(ppEapError);

    return ERROR_NOT_SUPPORTED;
}


DWORD eap::session_base::get_response_packet(_Inout_ DWORD *pcbSendPacket, _Out_cap_(*pcbSendPacket) EapPacket *pSendPacket, _Out_ EAP_ERROR **ppEapError)
{
    UNREFERENCED_PARAMETER(pcbSendPacket);
    UNREFERENCED_PARAMETER(pSendPacket);
    UNREFERENCED_PARAMETER(ppEapError);

    return ERROR_NOT_SUPPORTED;
}


DWORD eap::session_base::get_result(_In_ EapPeerMethodResultReason reason, _Out_ EapPeerMethodResult *ppResult, _Out_ EAP_ERROR **ppEapError)
{
    UNREFERENCED_PARAMETER(reason);
    UNREFERENCED_PARAMETER(ppResult);
    UNREFERENCED_PARAMETER(ppEapError);

    return ERROR_NOT_SUPPORTED;
}


DWORD eap::session_base::get_ui_context(_Out_ DWORD *dwSizeOfUIContextData, _Out_cap_(*dwSizeOfUIContextData) BYTE **pUIContextData, _Out_ EAP_ERROR **ppEapError)
{
    UNREFERENCED_PARAMETER(dwSizeOfUIContextData);
    UNREFERENCED_PARAMETER(pUIContextData);
    UNREFERENCED_PARAMETER(ppEapError);

    return ERROR_NOT_SUPPORTED;
}


DWORD eap::session_base::set_ui_context(_In_ DWORD dwSizeOfUIContextData, _In_count_(dwSizeOfUIContextData) const BYTE *pUIContextData, _Out_ EapPeerMethodOutput *pEapOutput, _Out_ EAP_ERROR **ppEapError)
{
    UNREFERENCED_PARAMETER(dwSizeOfUIContextData);
    UNREFERENCED_PARAMETER(pUIContextData);
    UNREFERENCED_PARAMETER(pEapOutput);
    UNREFERENCED_PARAMETER(ppEapError);

    return ERROR_NOT_SUPPORTED;
}


DWORD eap::session_base::get_response_attributes(_Out_ EapAttributes *pAttribs, _Out_ EAP_ERROR **ppEapError)
{
    assert(pAttribs);
    UNREFERENCED_PARAMETER(ppEapError);

    pAttribs->dwNumberOfAttributes = 0;
    pAttribs->pAttribs             = NULL;

    return ERROR_SUCCESS;
}


DWORD eap::session_base::set_response_attributes(_In_ EapAttributes *pAttribs, _Out_ EapPeerMethodOutput *pEapOutput, _Out_ EAP_ERROR **ppEapError)
{
    assert(pAttribs);
    assert(pEapOutput);
    UNREFERENCED_PARAMETER(ppEapError);

    pEapOutput->action             = EapPeerMethodResponseActionNone;
    pAttribs->dwNumberOfAttributes = 0;
    pAttribs->pAttribs             = NULL;

    return ERROR_SUCCESS;
}
