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
// eap::method
//////////////////////////////////////////////////////////////////////

eap::method::method(_In_ module &module, _In_ config_method &cfg, _In_ credentials &cred) :
    m_module(module),
    m_cfg(cfg),
    m_cred(cred)
{
}


eap::method::method(_Inout_ method &&other) :
    m_module  (          other.m_module   ),
    m_cfg     (          other.m_cfg      ),
    m_cred    (          other.m_cred     ),
    m_eap_attr(std::move(other.m_eap_attr))
{
}


eap::method& eap::method::operator=(_Inout_ method &&other)
{
    if (this != std::addressof(other)) {
        assert(std::addressof(m_module) == std::addressof(other.m_module)); // Move method within same module only!
        assert(std::addressof(m_cfg   ) == std::addressof(other.m_cfg   )); // Move method with same configuration only!
        assert(std::addressof(m_cred  ) == std::addressof(other.m_cred  )); // Move method with same credentials only!
        m_eap_attr = std::move(other.m_eap_attr);
    }

    return *this;
}


void eap::method::begin_session(
    _In_        DWORD         dwFlags,
    _In_  const EapAttributes *pAttributeArray,
    _In_        HANDLE        hTokenImpersonateUser,
    _In_opt_    DWORD         dwMaxSendPacketSize)
{
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(pAttributeArray);
    UNREFERENCED_PARAMETER(hTokenImpersonateUser);
    UNREFERENCED_PARAMETER(dwMaxSendPacketSize);

    // Presume authentication will fail with generic protocol failure. (Pesimist!!!)
    // We will reset once we get get_result(Success) call.
    m_cfg.m_last_status = config_method::status_auth_failed;
    m_cfg.m_last_msg.clear();
}


void eap::method::end_session()
{
}


void eap::method::get_result(
    _In_    EapPeerMethodResultReason reason,
    _Inout_ EapPeerMethodResult       *pResult)
{
    assert(pResult);

    switch (reason) {
    case EapPeerMethodResultSuccess: {
        m_module.log_event(&EAPMETHOD_METHOD_SUCCESS, event_data((unsigned int)m_cfg.get_method_id()), event_data::blank);
        m_cfg.m_last_status  = config_method::status_success;
        break;
    }

    case EapPeerMethodResultFailure:
        m_module.log_event(&EAPMETHOD_METHOD_FAILURE_ERROR2, event_data((unsigned int)m_cfg.get_method_id()), event_data((unsigned int)m_cfg.m_last_status), event_data::blank);
        break;

    default:
        throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Not supported.");
    }

    // Always ask EAP host to save the connection data. And it will save it *only* when we report "success".
    // Don't worry. EapHost is well aware of failed authentication condition.
    pResult->fSaveConnectionData = TRUE;
    pResult->fIsSuccess          = TRUE;
}


//////////////////////////////////////////////////////////////////////
// eap::method_noneap
//////////////////////////////////////////////////////////////////////

eap::method_noneap::method_noneap(_In_ module &module, _In_ config_method &cfg, _In_ credentials &cred) : method(module, cfg, cred)
{
}


eap::method_noneap::method_noneap(_Inout_ method_noneap &&other) :
    m_packet_res(std::move(other.m_packet_res)),
    method      (std::move(other             ))
{
}


eap::method_noneap& eap::method_noneap::operator=(_Inout_ method_noneap &&other)
{
    if (this != std::addressof(other)) {
        assert(std::addressof(m_cred) == std::addressof(other.m_cred)); // Move method with same credentials only!
        (method&)*this = std::move(other             );
        m_packet_res   = std::move(other.m_packet_res);
    }

    return *this;
}


void eap::method_noneap::get_response_packet(
    _Inout_bytecap_(*dwSendPacketSize) void  *pSendPacket,
    _Inout_                            DWORD *pdwSendPacketSize)
{
    assert(pdwSendPacketSize);
    assert(pSendPacket);

    size_t size_packet = m_packet_res.size();
    if (size_packet > *pdwSendPacketSize)
        throw invalid_argument(string_printf(__FUNCTION__ " This method does not support packet fragmentation, but the data size is too big to fit in one packet (packet: %u, maximum: %u).", size_packet, *pdwSendPacketSize));

    memcpy(pSendPacket, m_packet_res.data(), size_packet);
    *pdwSendPacketSize = (DWORD)size_packet;
    m_packet_res.clear();
}


void eap::method_noneap::append_avp(_In_ unsigned int code, _In_ unsigned char flags, _In_bytecount_(size) const void *data, _In_ unsigned int size)
{
    unsigned int
        padding = (unsigned int)((4 - size) % 4),
        size_outer;

    m_packet_res.reserve(
        m_packet_res.size() + 
        (size_outer = 
        sizeof(diameter_avp_header) + // Diameter header
        size)                       + // Data
        padding);                     // Data padding

    // Diameter AVP header
    diameter_avp_header hdr;
    *reinterpret_cast<unsigned int*>(hdr.code) = htonl(code);
    hdr.flags = flags;
    hton24(size_outer, hdr.length);
    m_packet_res.insert(m_packet_res.end(), reinterpret_cast<const unsigned char*>(&hdr), reinterpret_cast<const unsigned char*>(&hdr + 1));

    // Data
    m_packet_res.insert(m_packet_res.end(), reinterpret_cast<const unsigned char*>(data), reinterpret_cast<const unsigned char*>(data) + size);
    m_packet_res.insert(m_packet_res.end(), padding, 0);
}


void eap::method_noneap::append_avp(_In_ unsigned int code, _In_ unsigned int vendor_id, _In_ unsigned char flags, _In_bytecount_(size) const void *data, _In_ unsigned int size)
{
    unsigned int
        padding = (unsigned int)((4 - size) % 4),
        size_outer;

    m_packet_res.reserve(
        m_packet_res.size() + 
        (size_outer = 
        sizeof(diameter_avp_header_ven) + // Diameter header
        size)                           + // Data
        padding);                         // Data padding

    // Diameter AVP header
    diameter_avp_header_ven hdr;
    *reinterpret_cast<unsigned int*>(hdr.code) = htonl(code);
    hdr.flags = flags | diameter_avp_flag_vendor;
    hton24(size_outer, hdr.length);
    *reinterpret_cast<unsigned int*>(hdr.vendor) = htonl(vendor_id);
    m_packet_res.insert(m_packet_res.end(), reinterpret_cast<const unsigned char*>(&hdr), reinterpret_cast<const unsigned char*>(&hdr + 1));

    // Data
    m_packet_res.insert(m_packet_res.end(), reinterpret_cast<const unsigned char*>(data), reinterpret_cast<const unsigned char*>(data) + size);
    m_packet_res.insert(m_packet_res.end(), padding, 0);
}
