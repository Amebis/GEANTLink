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
// eap::method_ttls
//////////////////////////////////////////////////////////////////////

eap::method_ttls::method_ttls(_In_ module &module, _In_ config_method_ttls &cfg, _In_ credentials_ttls &cred) :
    m_version(version_0),
    method_tls(module, cfg, cred)
{
}


eap::method_ttls::method_ttls(_In_ const method_ttls &other) :
    m_version(other.m_version),
    method_tls(other)
{
}


eap::method_ttls::method_ttls(_Inout_ method_ttls &&other) :
    m_version(std::move(other.m_version)),
    method_tls(std::move(other))
{
}


eap::method_ttls& eap::method_ttls::operator=(_In_ const method_ttls &other)
{
    if (this != std::addressof(other)) {
        (method_tls&)*this = other;
        m_version          = other.m_version;
    }

    return *this;
}


eap::method_ttls& eap::method_ttls::operator=(_Inout_ method_ttls &&other)
{
    if (this != std::addressof(other)) {
        (method_tls&)*this = std::move(other);
        m_version          = std::move(other.m_version);
    }

    return *this;
}


//void eap::method_ttls::begin_session(
//    _In_        DWORD         dwFlags,
//    _In_  const EapAttributes *pAttributeArray,
//    _In_        HANDLE        hTokenImpersonateUser,
//    _In_        DWORD         dwMaxSendPacketSize)
//{
//    m_outer.begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, dwMaxSendPacketSize);
//}


void eap::method_ttls::process_request_packet(
    _In_bytecount_(dwReceivedPacketSize) const EapPacket           *pReceivedPacket,
    _In_                                       DWORD               dwReceivedPacketSize,
    _Inout_                                    EapPeerMethodOutput *pEapOutput)
{
    if (pReceivedPacket->Code == EapCodeRequest && (pReceivedPacket->Data[1] & flags_start)) {
        // This is a start EAP-TTLS packet.

        // Determine minimum EAP-TTLS version supported by server and us.
        version_t ver_remote = (version_t)(pReceivedPacket->Data[1] & flags_ver_mask);
        m_version = std::min<version_t>(ver_remote, version_0);
        m_module.log_event(&EAPMETHOD_TTLS_HANDSHAKE_START, event_data((unsigned int)eap_type_ttls), event_data((unsigned char)m_version), event_data((unsigned char)ver_remote), event_data::blank);
    }

    method_tls::process_request_packet(pReceivedPacket, dwReceivedPacketSize, pEapOutput);
}


void eap::method_ttls::get_response_packet(
    _Inout_bytecap_(*dwSendPacketSize) EapPacket *pSendPacket,
    _Inout_                            DWORD     *pdwSendPacketSize)
{
    method_tls::get_response_packet(pSendPacket, pdwSendPacketSize);

    // Change packet type to EAP-TTLS, and add EAP-TTLS version.
    pSendPacket->Data[0]  = (BYTE)eap_type_ttls;
    pSendPacket->Data[1] &= ~flags_ver_mask;
    pSendPacket->Data[1] |= m_version;
}


//void eap::method_ttls::get_result(
//    _In_    EapPeerMethodResultReason reason,
//    _Inout_ EapPeerMethodResult       *ppResult)
//{
//    m_outer.get_result(reason, ppResult);
//}
