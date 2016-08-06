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
    m_outer(module, cfg.m_outer, cred.m_outer),
    method(module, cfg, cred)
{
}


eap::method_ttls::method_ttls(_In_ const method_ttls &other) :
    m_outer(other.m_outer),
    method(other)
{
}


eap::method_ttls::method_ttls(_Inout_ method_ttls &&other) :
    m_outer(std::move(other.m_outer)),
    method(std::move(other))
{
}


eap::method_ttls& eap::method_ttls::operator=(_In_ const method_ttls &other)
{
    if (this != std::addressof(other)) {
        (method&)*this = other;
        m_outer        = other.m_outer;
    }

    return *this;
}


eap::method_ttls& eap::method_ttls::operator=(_Inout_ method_ttls &&other)
{
    if (this != std::addressof(other)) {
        (method&)*this = std::move(other);
        m_outer        = std::move(other.m_outer);
    }

    return *this;
}


bool eap::method_ttls::process_request_packet(
    _In_bytecount_(dwReceivedPacketSize) const EapPacket           *pReceivedPacket,
    _In_                                       DWORD               dwReceivedPacketSize,
    _Out_                                      EapPeerMethodOutput *pEapOutput,
    _Out_                                      EAP_ERROR           **ppEapError)
{
    // Initialize output.
    pEapOutput->fAllowNotifications = TRUE;
    pEapOutput->action              = EapPeerMethodResponseActionDiscard;

    // Is this a valid EAP-TTLS packet?
    if (dwReceivedPacketSize < 6) {
        *ppEapError = m_module.make_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, _T(__FUNCTION__) _T(" Packet is too small. EAP-%s packets should be at least 6B."));
        return false;
    } else if (pReceivedPacket->Data[0] != eap_type_ttls) {
        *ppEapError = m_module.make_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, wstring_printf(_T(__FUNCTION__) _T(" Packet is not EAP-TTLS (expected: %u, received: %u)."), eap_type_ttls, pReceivedPacket->Data[0]).c_str());
        return false;
    }

    return m_outer.process_request_packet(pReceivedPacket, dwReceivedPacketSize, pEapOutput, ppEapError);
}


bool eap::method_ttls::get_response_packet(
    _Inout_bytecap_(*dwSendPacketSize) EapPacket *pSendPacket,
    _Inout_                            DWORD     *pdwSendPacketSize,
    _Out_                              EAP_ERROR **ppEapError)
{
    return m_outer.get_response_packet(pSendPacket, pdwSendPacketSize, ppEapError);
}
