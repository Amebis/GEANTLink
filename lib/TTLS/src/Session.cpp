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

eap::session_ttls::session_ttls(_In_ module &mod) :
    m_phase(phase_handshake_start),
    m_version(version_0),
    session<config_method_ttls, credentials_ttls, bool, bool>(mod)
{
    m_packet_req.m_code  = (EapCode)0;
    m_packet_req.m_id    = 0;
    m_packet_req.m_flags = version_0;

    m_packet_res.m_code  = (EapCode)0;
    m_packet_res.m_id    = 0;
    m_packet_res.m_flags = version_0;
}


eap::session_ttls::session_ttls(_In_ const session_ttls &other) :
    m_phase(other.m_phase),
    m_version(other.m_version),
    session<config_method_ttls, credentials_ttls, bool, bool>(other)
{
    m_packet_req.m_code  = other.m_packet_req.m_code ;
    m_packet_req.m_id    = other.m_packet_req.m_id   ;
    m_packet_req.m_flags = other.m_packet_req.m_flags;
    m_packet_req.m_data  = other.m_packet_req.m_data ;

    m_packet_res.m_code  = other.m_packet_res.m_code ;
    m_packet_res.m_id    = other.m_packet_res.m_id   ;
    m_packet_res.m_flags = other.m_packet_res.m_flags;
    m_packet_res.m_data  = other.m_packet_res.m_data ;
}


eap::session_ttls::session_ttls(_Inout_ session_ttls &&other) :
    m_phase(std::move(other.m_phase)),
    m_version(std::move(other.m_version)),
    session<config_method_ttls, credentials_ttls, bool, bool>(std::move(other))
{
    m_packet_req.m_code  = std::move(other.m_packet_req.m_code );
    m_packet_req.m_id    = std::move(other.m_packet_req.m_id   );
    m_packet_req.m_flags = std::move(other.m_packet_req.m_flags);
    m_packet_req.m_data  = std::move(other.m_packet_req.m_data );

    m_packet_res.m_code  = std::move(other.m_packet_res.m_code );
    m_packet_res.m_id    = std::move(other.m_packet_res.m_id   );
    m_packet_res.m_flags = std::move(other.m_packet_res.m_flags);
    m_packet_res.m_data  = std::move(other.m_packet_res.m_data );
}


eap::session_ttls& eap::session_ttls::operator=(_In_ const session_ttls &other)
{
    if (this != &other) {
        (session<config_method_ttls, credentials_ttls, bool, bool>&)*this = other;
        m_phase              = other.m_phase;
        m_version            = other.m_version;

        m_packet_req.m_code  = other.m_packet_req.m_code ;
        m_packet_req.m_id    = other.m_packet_req.m_id   ;
        m_packet_req.m_flags = other.m_packet_req.m_flags;
        m_packet_req.m_data  = other.m_packet_req.m_data ;

        m_packet_res.m_code  = other.m_packet_res.m_code ;
        m_packet_res.m_id    = other.m_packet_res.m_id   ;
        m_packet_res.m_flags = other.m_packet_res.m_flags;
        m_packet_res.m_data  = other.m_packet_res.m_data ;
    }

    return *this;
}


eap::session_ttls& eap::session_ttls::operator=(_Inout_ session_ttls &&other)
{
    if (this != &other) {
        (session<config_method_ttls, credentials_ttls, bool, bool>&)*this = std::move(other);
        m_phase              = std::move(other.m_phase);
        m_version            = std::move(other.m_version);

        m_packet_req.m_code  = std::move(other.m_packet_req.m_code );
        m_packet_req.m_id    = std::move(other.m_packet_req.m_id   );
        m_packet_req.m_flags = std::move(other.m_packet_req.m_flags);
        m_packet_req.m_data  = std::move(other.m_packet_req.m_data );

        m_packet_res.m_code  = std::move(other.m_packet_res.m_code );
        m_packet_res.m_id    = std::move(other.m_packet_res.m_id   );
        m_packet_res.m_flags = std::move(other.m_packet_res.m_flags);
        m_packet_res.m_data  = std::move(other.m_packet_res.m_data );
    }

    return *this;
}


bool eap::session_ttls::begin(
    _In_        DWORD         dwFlags,
    _In_  const EapAttributes *pAttributeArray,
    _In_        HANDLE        hTokenImpersonateUser,
    _In_        DWORD         dwMaxSendPacketSize,
    _Out_       EAP_ERROR     **ppEapError)
{
    if (dwMaxSendPacketSize <= 10) {
        *ppEapError = m_module.make_error(ERROR_NOT_SUPPORTED, wstring_printf(_T(__FUNCTION__) _T(" Maximum send packet size too small (expected: >%u, received: %u)."), 10, dwMaxSendPacketSize).c_str());
        return false;
    }

    return session<config_method_ttls, credentials_ttls, bool, bool>::begin(dwFlags, pAttributeArray, hTokenImpersonateUser, dwMaxSendPacketSize, ppEapError);
}


bool eap::session_ttls::process_request_packet(
    _In_                                       DWORD               dwReceivedPacketSize,
    _In_bytecount_(dwReceivedPacketSize) const EapPacket           *pReceivedPacket,
    _Out_                                      EapPeerMethodOutput *pEapOutput,
    _Out_                                      EAP_ERROR           **ppEapError)
{
    assert(pReceivedPacket && dwReceivedPacketSize >= 4);
    assert(pEapOutput);
    assert(ppEapError);

    // Initialize output.
    pEapOutput->fAllowNotifications = TRUE;
    pEapOutput->action              = EapPeerMethodResponseActionDiscard;

    // Is this a valid EAP-TTLS packet?
    if (dwReceivedPacketSize < 6) {
        *ppEapError = m_module.make_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, _T(__FUNCTION__) _T(" Packet is too small. EAP-TTLS packets should be at least 6B."));
        return false;
    } else if (pReceivedPacket->Data[0] != eap_type_ttls) {
        *ppEapError = m_module.make_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, wstring_printf(_T(__FUNCTION__) _T(" Packet is not EAP-TTLS (expected: %u, received: %u)."), eap_type_ttls, pReceivedPacket->Data[0]).c_str());
        return false;
    }

    if (pReceivedPacket->Data[1] & ttls_flags_more_frag) {
        if (pReceivedPacket->Data[1] & ttls_flags_length_incl) {
            // First fragment received.
            if (dwReceivedPacketSize < 10) {
                *ppEapError = m_module.make_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, _T(__FUNCTION__) _T(" Packet is too small. EAP-TTLS first fragmented packet should be at least 10B."));
                return false;
            }

            // Start a new packet.
            m_packet_req.m_code  = (EapCode)pReceivedPacket->Code;
            m_packet_req.m_id    = pReceivedPacket->Id;
            m_packet_req.m_flags = pReceivedPacket->Data[1];
            m_packet_req.m_data.reserve(*(DWORD*)(pReceivedPacket->Data + 2));
            m_packet_req.m_data.assign(pReceivedPacket->Data + 6, pReceivedPacket->Data + dwReceivedPacketSize - 4);
        } else {
            // Mid fragment received. Append data.
            m_packet_req.m_data.insert(m_packet_req.m_data.end(), pReceivedPacket->Data + 2, pReceivedPacket->Data + dwReceivedPacketSize - 4);
        }

        // Reply with Acknowledgement packet.
        m_packet_res.m_code  = EapCodeResponse;
        m_packet_res.m_id    = m_packet_req.m_id;
        m_packet_res.m_flags = 0;
        m_packet_res.m_data.clear();
        pEapOutput->action = EapPeerMethodResponseActionSend;
        return true;
    } else if (!m_packet_req.m_data.empty()) {
        // Last fragment received. Append data.
        m_packet_req.m_data.insert(m_packet_req.m_data.end(),
            pReceivedPacket->Data + (!(pReceivedPacket->Data[1] & ttls_flags_length_incl) ? 2 : 6), // Should not include "Length" field (by RFC 5281: https://tools.ietf.org/html/rfc5281#section-9.2.2). Tolerate.
            pReceivedPacket->Data + dwReceivedPacketSize - 4);
    }

    if (  m_packet_req.m_code == EapCodeResponse                                                     &&
          m_packet_req.m_id   == m_packet_res.m_id                                                   &&
        !(m_packet_req.m_flags & (ttls_flags_length_incl | ttls_flags_more_frag | ttls_flags_start)) &&
         (m_packet_res.m_flags &                           ttls_flags_more_frag                   ))
    {
        // This is an Acknowledgement of our fragmented packet response. Send the next fragment.
        pEapOutput->action = EapPeerMethodResponseActionSend;
        return true;
    }

    switch (m_phase) {
        case phase_handshake_start: {
            // Is this an EAP-TTLS Start packet?
            if (m_packet_req.m_code != EapCodeRequest) {
                *ppEapError = m_module.make_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, wstring_printf(_T(__FUNCTION__) _T(" Packet is not a request (expected: %x, received: %x)."), EapCodeRequest, m_packet_req.m_code).c_str());
                return false;
            } else if (!(m_packet_req.m_flags & ttls_flags_start)) {
                *ppEapError = m_module.make_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, wstring_printf(_T(__FUNCTION__) _T(" Packet is not EAP-TTLS Start (expected: %x, received: %x)."), ttls_flags_start, m_packet_req.m_flags).c_str());
                return false;
            }

            // Determine minimum EAP-TTLS version supported by server and us.
            version_t ver_remote = (version_t)(m_packet_req.m_flags & ttls_flags_ver_mask);
            m_version = std::min<version_t>(ver_remote, version_0);
            m_module.log_event(&EAPMETHOD_HANDSHAKE_START, event_data(m_cred.target_suffix()), event_data((unsigned char)m_version), event_data((unsigned char)ver_remote), event_data::blank);

            // Build response packet.
            //if (!m_packet_res.create(EapCodeResponse, pReceivedPacket->Id, eap_type_ttls, (BYTE)m_version)) {
            //    *ppEapError = m_module.make_error(GetLastError(), _T(__FUNCTION__) _T(" Error creating packet."));
            //    return false;
            //}
            break;
        }

        default:
            *ppEapError = m_module.make_error(ERROR_NOT_SUPPORTED, _T(__FUNCTION__) _T(" Not supported."));
            return false;
    }

    return true;
}


bool eap::session_ttls::get_response_packet(
    _Inout_                            DWORD     *pdwSendPacketSize,
    _Inout_bytecap_(*dwSendPacketSize) EapPacket *pSendPacket,
    _Out_                              EAP_ERROR **ppEapError)
{
    assert(pdwSendPacketSize);
    assert(pSendPacket);
    UNREFERENCED_PARAMETER(ppEapError);

    DWORD
        size_data   = (DWORD)m_packet_res.m_data.size(),
        size_packet = size_data + 6;
    WORD size_packet_limit = (WORD)std::min<DWORD>(m_send_packet_size_max, (WORD)-1);
    BYTE *data_dst;

    if (!(m_packet_res.m_flags & ttls_flags_more_frag)) {
        // Not fragmented.
        if (size_packet <= size_packet_limit) {
            // No need to fragment the packet.
            m_packet_res.m_flags &= ~ttls_flags_length_incl; // No need to explicitly include the Length field either.
            data_dst = pSendPacket->Data + 2;
        } else {
            // But it should be fragmented.
            m_packet_res.m_flags |= ttls_flags_length_incl | ttls_flags_more_frag;
            *(DWORD*)(pSendPacket->Data + 2) = (DWORD)size_packet;
            data_dst = pSendPacket->Data + 6;
            size_data   = size_packet_limit - 10;
            size_packet = size_packet_limit;
        }
    } else {
        // Continuing the fragmented packet...
        if (size_packet <= size_packet_limit) {
            // This is the last fragment.
            m_packet_res.m_flags &= ~(ttls_flags_length_incl | ttls_flags_more_frag);
        } else {
            // This is a mid fragment.
            m_packet_res.m_flags &= ~ttls_flags_length_incl;
            size_data   = size_packet_limit - 6;
            size_packet = size_packet_limit;
        }
        data_dst = pSendPacket->Data + 2;
    }

    pSendPacket->Code = (BYTE)m_packet_res.m_code;
    pSendPacket->Id   = m_packet_res.m_id;
    *(WORD*)pSendPacket->Length = htons((WORD)size_packet);
    pSendPacket->Data[0] = (BYTE)eap_type_ttls;
    pSendPacket->Data[1] = m_packet_res.m_flags | (BYTE)m_version;
    memcpy(data_dst, m_packet_res.m_data.data(), size_data);
    m_packet_res.m_data.erase(m_packet_res.m_data.begin(), m_packet_res.m_data.begin() + size_data);
    *pdwSendPacketSize = size_packet;
    return true;
}


bool eap::session_ttls::get_result(
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
