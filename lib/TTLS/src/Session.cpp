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
// eap::session_ttls
//////////////////////////////////////////////////////////////////////

eap::session_ttls::session_ttls(_In_ module *mod) :
    m_version(version_0),
    session<config_method_ttls, credentials_ttls, bool, bool>(mod)
{
}


eap::session_ttls::session_ttls(_In_ const session_ttls &other) :
    m_version(other.m_version),
    session<config_method_ttls, credentials_ttls, bool, bool>(other)
{
}


eap::session_ttls::session_ttls(_Inout_ session_ttls &&other) :
    m_version(std::move(other.m_version)),
    session<config_method_ttls, credentials_ttls, bool, bool>(std::move(other))
{
}


eap::session_ttls& eap::session_ttls::operator=(_In_ const session_ttls &other)
{
    if (this != &other) {
        (session<config_method_ttls, credentials_ttls, bool, bool>&)*this = other;
        m_version = other.m_version;
    }

    return *this;
}


eap::session_ttls& eap::session_ttls::operator=(_Inout_ session_ttls &&other)
{
    if (this != &other) {
        (session<config_method_ttls, credentials_ttls, bool, bool>&)*this = std::move(other);
        m_version = std::move(other.m_version);
    }

    return *this;
}


bool eap::session_ttls::process_request_packet(
    _In_                                       DWORD               dwReceivedPacketSize,
    _In_bytecount_(dwReceivedPacketSize) const EapPacket           *pReceivedPacket,
    _Out_                                      EapPeerMethodOutput *pEapOutput,
    _Out_                                      EAP_ERROR           **ppEapError)
{
    UNREFERENCED_PARAMETER(dwReceivedPacketSize);
    UNREFERENCED_PARAMETER(pReceivedPacket);
    UNREFERENCED_PARAMETER(pEapOutput);
    assert(ppEapError);

    *ppEapError = m_module->make_error(ERROR_NOT_SUPPORTED, _T(__FUNCTION__) _T(" Not supported."));
    return false;
}


bool eap::session_ttls::get_response_packet(
    _Inout_                            DWORD     *pdwSendPacketSize,
    _Inout_bytecap_(*dwSendPacketSize) EapPacket *pSendPacket,
    _Out_                              EAP_ERROR **ppEapError)
{
    UNREFERENCED_PARAMETER(pdwSendPacketSize);
    UNREFERENCED_PARAMETER(pSendPacket);
    assert(ppEapError);

    *ppEapError = m_module->make_error(ERROR_NOT_SUPPORTED, _T(__FUNCTION__) _T(" Not supported."));
    return false;
}


bool eap::session_ttls::get_result(
    _In_  EapPeerMethodResultReason reason,
    _Out_ EapPeerMethodResult       *ppResult,
    _Out_ EAP_ERROR                 **ppEapError)
{
    UNREFERENCED_PARAMETER(reason);
    UNREFERENCED_PARAMETER(ppResult);
    assert(ppEapError);

    *ppEapError = m_module->make_error(ERROR_NOT_SUPPORTED, _T(__FUNCTION__) _T(" Not supported."));
    return false;
}
