/*
    Copyright 2015-2016 Amebis
    Copyright 2016 GÉANT

    This file is part of GÉANTLink.

    GÉANTLink is free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    GÉANTLink is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with GÉANTLink. If not, see <http://www.gnu.org/licenses/>.
*/

#include "StdAfx.h"

using namespace std;
using namespace winstd;


//////////////////////////////////////////////////////////////////////
// eap::session_tls
//////////////////////////////////////////////////////////////////////

eap::session_tls::session_tls(_In_ module &mod) : session<config_method_tls, credentials_tls, bool, bool>(mod)
{
}


eap::session_tls::session_tls(_In_ const session_tls &other) :
    session<config_method_tls, credentials_tls, bool, bool>(other)
{
}


eap::session_tls::session_tls(_Inout_ session_tls &&other) :
    session<config_method_tls, credentials_tls, bool, bool>(std::move(other))
{
}


eap::session_tls& eap::session_tls::operator=(_In_ const session_tls &other)
{
    if (this != &other)
        (session<config_method_tls, credentials_tls, bool, bool>&)*this = other;

    return *this;
}


eap::session_tls& eap::session_tls::operator=(_Inout_ session_tls &&other)
{
    if (this != &other)
        (session<config_method_tls, credentials_tls, bool, bool>&)*this = std::move(other);

    return *this;
}


//bool eap::session_tls::begin(
//    _In_        DWORD         dwFlags,
//    _In_  const EapAttributes *pAttributeArray,
//    _In_        HANDLE        hTokenImpersonateUser,
//    _In_        DWORD         dwMaxSendPacketSize,
//    _Out_       EAP_ERROR     **ppEapError)
//{
//    if (!session<config_method_tls, credentials_tls, bool, bool>::begin(dwFlags, pAttributeArray, hTokenImpersonateUser, dwMaxSendPacketSize, ppEapError))
//        return false;
//
//
//
//    return true;
//}


bool eap::session_tls::process_request_packet(
    _In_                                       DWORD               dwReceivedPacketSize,
    _In_bytecount_(dwReceivedPacketSize) const EapPacket           *pReceivedPacket,
    _Out_                                      EapPeerMethodOutput *pEapOutput,
    _Out_                                      EAP_ERROR           **ppEapError)
{
    UNREFERENCED_PARAMETER(dwReceivedPacketSize);
    UNREFERENCED_PARAMETER(pReceivedPacket);
    UNREFERENCED_PARAMETER(pEapOutput);
    assert(ppEapError);

    *ppEapError = m_module.make_error(ERROR_NOT_SUPPORTED, _T(__FUNCTION__) _T(" Not supported."));
    return false;
}


bool eap::session_tls::get_result(
    _In_  EapPeerMethodResultReason reason,
    _Out_ EapPeerMethodResult       *ppResult,
    _Out_ EAP_ERROR                 **ppEapError)
{
    UNREFERENCED_PARAMETER(reason);
    UNREFERENCED_PARAMETER(ppResult);
    assert(ppEapError);

    *ppEapError = m_module.make_error(ERROR_NOT_SUPPORTED, _T(__FUNCTION__) _T(" Not supported."));
    return false;
}
