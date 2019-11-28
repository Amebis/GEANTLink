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

eap::method::method(_In_ module &mod) :
    m_module(mod)
{
}


eap::method::method(_Inout_ method &&other) noexcept :
    m_module(other.m_module)
{
}


eap::method& eap::method::operator=(_Inout_ method &&other) noexcept
{
    if (this != std::addressof(other)) {
        assert(std::addressof(m_module) == std::addressof(other.m_module)); // Move method within same module only!
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
}


void eap::method::end_session()
{
}


void eap::method::get_result(
    _In_    EapPeerMethodResultReason reason,
    _Inout_ EapPeerMethodResult       *pResult)
{
    UNREFERENCED_PARAMETER(reason);
    UNREFERENCED_PARAMETER(pResult);
}


void eap::method::get_ui_context(_Out_ sanitizing_blob &context_data)
{
    // Default implementation returns blank context data.
    context_data.clear();
}


EapPeerMethodResponseAction eap::method::set_ui_context(
    _In_count_(dwUIContextDataSize) const BYTE  *pUIContextData,
    _In_                                  DWORD dwUIContextDataSize)
{
    UNREFERENCED_PARAMETER(pUIContextData);
    UNREFERENCED_PARAMETER(dwUIContextDataSize);

    // Default implementation does nothing with context data.
    return EapPeerMethodResponseActionNone;
}


void eap::method::get_response_attributes(_Out_ EapAttributes *pAttribs)
{
    assert(pAttribs);

    // Default implementation returns no EAP attributes.
    pAttribs->dwNumberOfAttributes = 0;
    pAttribs->pAttribs             = NULL;
}


EapPeerMethodResponseAction eap::method::set_response_attributes(_In_ const EapAttributes *pAttribs)
{
    UNREFERENCED_PARAMETER(pAttribs);

    // Default implementation does nothing with EAP attributes.
    return EapPeerMethodResponseActionNone;
}


//////////////////////////////////////////////////////////////////////
// eap::method_tunnel
//////////////////////////////////////////////////////////////////////

eap::method_tunnel::method_tunnel(_In_ module &mod, _In_ method *inner) :
    m_inner(inner),
    method(mod)
{
}


eap::method_tunnel::method_tunnel(_Inout_ method_tunnel &&other) noexcept :
    m_inner(std::move(other.m_inner)),
    method (std::move(other        ))
{
}


eap::method_tunnel& eap::method_tunnel::operator=(_Inout_ method_tunnel &&other) noexcept
{
    if (this != std::addressof(other)) {
        (method&)*this = std::move(other        );
        m_inner        = std::move(other.m_inner);
    }

    return *this;
}


void eap::method_tunnel::begin_session(
    _In_        DWORD         dwFlags,
    _In_  const EapAttributes *pAttributeArray,
    _In_        HANDLE        hTokenImpersonateUser,
    _In_opt_    DWORD         dwMaxSendPacketSize)
{
    method::begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, dwMaxSendPacketSize);

    assert(m_inner);
    m_inner->begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, dwMaxSendPacketSize);
}


void eap::method_tunnel::end_session()
{
    assert(m_inner);
    m_inner->end_session();

    method::end_session();
}


EapPeerMethodResponseAction eap::method_tunnel::process_request_packet(
    _In_bytecount_(dwReceivedPacketSize) const void  *pReceivedPacket,
    _In_                                       DWORD dwReceivedPacketSize)
{
    assert(m_inner);
    return m_inner->process_request_packet(pReceivedPacket, dwReceivedPacketSize);
}


void eap::method_tunnel::get_response_packet(
    _Out_    sanitizing_blob &packet,
    _In_opt_ DWORD           size_max)
{
    assert(m_inner);
    m_inner->get_response_packet(packet, size_max);
}


void eap::method_tunnel::get_result(
    _In_    EapPeerMethodResultReason reason,
    _Inout_ EapPeerMethodResult       *pResult)
{
    assert(m_inner);
    m_inner->get_result(reason, pResult);
}


void eap::method_tunnel::get_ui_context(_Out_ sanitizing_blob &context_data)
{
    assert(m_inner);

    // Default implementation forwards UI context handling to the inner method.
    m_inner->get_ui_context(context_data);
}


EapPeerMethodResponseAction eap::method_tunnel::set_ui_context(
    _In_count_(dwUIContextDataSize) const BYTE  *pUIContextData,
    _In_                                  DWORD dwUIContextDataSize)
{
    assert(m_inner);

    // Default implementation forwards UI context handling to the inner method.
    return m_inner->set_ui_context(pUIContextData, dwUIContextDataSize);
}


void eap::method_tunnel::get_response_attributes(_Out_ EapAttributes *pAttribs)
{
    assert(m_inner);
    m_inner->get_response_attributes(pAttribs);
}


EapPeerMethodResponseAction eap::method_tunnel::set_response_attributes(_In_ const EapAttributes *pAttribs)
{
    assert(m_inner);
    return m_inner->set_response_attributes(pAttribs);
}


//////////////////////////////////////////////////////////////////////
// eap::method_eap
//////////////////////////////////////////////////////////////////////

eap::method_eap::method_eap(_In_ module &mod, _In_ winstd::eap_type_t eap_method, _In_ method *inner) :
    m_eap_method(eap_method),
    m_id(0),
    m_send_nak(false),
    method_tunnel(mod, inner)
{
}


eap::method_eap::method_eap(_Inout_ method_eap &&other) noexcept :
    m_eap_method (std::move(other.m_eap_method)),
    m_id         (std::move(other.m_id        )),
    m_send_nak   (std::move(other.m_send_nak  )),
    method_tunnel(std::move(other             ))
{
}


eap::method_eap& eap::method_eap::operator=(_Inout_ method_eap &&other) noexcept
{
    if (this != std::addressof(other)) {
        assert(m_eap_method == other.m_eap_method); // Move method within same EAP method type only!
        (method_tunnel&)*this = std::move(other           );
        m_id                  = std::move(other.m_id      );
        m_send_nak            = std::move(other.m_send_nak);
    }

    return *this;
}


void eap::method_eap::begin_session(
    _In_        DWORD         dwFlags,
    _In_  const EapAttributes *pAttributeArray,
    _In_        HANDLE        hTokenImpersonateUser,
    _In_opt_    DWORD         dwMaxSendPacketSize)
{
    // Initialize tunnel method session only.
    method::begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, dwMaxSendPacketSize);

    // Inner method can generate packets of up to 64kB (less the EAP packet header).
    // Initialize inner method with appropriately less packet size maximum.
    if (dwMaxSendPacketSize < sizeof(EapPacket))
        throw invalid_argument(string_printf(__FUNCTION__ " Maximum packet size too small (minimum: %zu, available: %u).", sizeof(EapPacket) + 1, dwMaxSendPacketSize));
    assert(m_inner);
    m_inner->begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, std::min<DWORD>(dwMaxSendPacketSize, MAXWORD) - sizeof(EapPacket));
}


EapPeerMethodResponseAction eap::method_eap::process_request_packet(
    _In_bytecount_(dwReceivedPacketSize) const void  *pReceivedPacket,
    _In_                                       DWORD dwReceivedPacketSize)
{
    assert(dwReceivedPacketSize >= sizeof(EapPacket)); // Request packet should contain an EAP packet header at least.
    auto hdr = reinterpret_cast<const EapPacket*>(pReceivedPacket);

    // This must be an EAP-Request packet.
    if (hdr->Code != EapCodeRequest)
        throw invalid_argument(string_printf(__FUNCTION__ " Unknown EAP packet received (expected: %u, received: %u).", EapCodeRequest, (int)hdr->Code));

    // Check packet size.
    DWORD size_packet = ntohs(*reinterpret_cast<const unsigned short*>(hdr->Length));
    if (size_packet > dwReceivedPacketSize)
        throw invalid_argument(string_printf(__FUNCTION__ " Incorrect EAP packet length (expected: %uB, received: %uB).", size_packet, dwReceivedPacketSize));

    // Save request packet ID to make matching response packet in get_response_packet() later.
    m_id = hdr->Id;

    if (hdr->Data[0] != m_eap_method) {
        // Unsupported EAP method. Respond with Legacy Nak.
        m_send_nak = true;
        return EapPeerMethodResponseActionSend;
    } else {
        // Process the data with underlying method.
        m_send_nak = false;
        return method_tunnel::process_request_packet(hdr->Data + 1, size_packet - sizeof(EapPacket));
    }
}


void eap::method_eap::get_response_packet(
    _Out_    sanitizing_blob &packet,
    _In_opt_ DWORD           size_max)
{
    assert(size_max >= sizeof(EapPacket)); // We should be able to respond with at least an EAP packet header.
    if (size_max > MAXWORD) size_max = MAXWORD; // EAP packets maximum size is 64kB.

    // Prepare EAP packet header.
    EapPacket hdr;
    hdr.Code = (BYTE)EapCodeResponse;
    hdr.Id = m_id;

    if (!m_send_nak) {
        hdr.Data[0] = m_eap_method;

        packet.reserve(size_max); // To avoid reallocation when inserting EAP packet header later.

        // Get data from underlying method.
        method_tunnel::get_response_packet(packet, size_max - sizeof(EapPacket));
    } else {
        // Respond with Legacy Nak suggesting our EAP method to continue.
        hdr.Data[0] = eap_type_nak;

        // Check packet size. We will suggest one EAP method alone, so we need one byte for data.
        size_t size_packet = sizeof(EapPacket) + 1;
        if (size_packet > size_max)
            throw invalid_argument(string_printf(__FUNCTION__ " This method does not support packet fragmentation, but the data size is too big to fit in one packet (packet: %zu, maximum: %u).", size_packet, size_max));
        packet.reserve(size_packet); // To avoid reallocation when inserting EAP packet header later.

        // Data of Legacy Nak packet is a list of supported EAP types: our method alone.
        packet.assign(1, m_eap_method);
    }

    size_t size_packet = packet.size() + sizeof(EapPacket);
    assert(size_packet <= MAXWORD); // Packets spanning over 64kB are not supported.
    *reinterpret_cast<unsigned short*>(hdr.Length) = htons((unsigned short)size_packet);

    // Insert EAP packet header before data.
    packet.insert(packet.begin(), reinterpret_cast<const unsigned char*>(&hdr), reinterpret_cast<const unsigned char*>(&hdr + 1));
}
