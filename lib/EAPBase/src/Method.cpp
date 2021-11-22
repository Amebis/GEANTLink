/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2021 Amebis
    Copyright © 2016 GÉANT
*/

#include "PCH.h"

using namespace std;
using namespace winstd;


//////////////////////////////////////////////////////////////////////
// eap::method
//////////////////////////////////////////////////////////////////////

eap::method::method(_In_ module &mod, _In_opt_ method *inner) :
    m_module(mod),
    m_outer(nullptr),
    m_inner(inner)
{
    if (m_inner)
        m_inner->m_outer = this;
}


void eap::method::begin_session(
    _In_        DWORD         dwFlags,
    _In_  const EapAttributes *pAttributeArray,
    _In_        HANDLE        hTokenImpersonateUser,
    _In_opt_    DWORD         dwMaxSendPacketSize)
{
    if (m_inner)
        m_inner->begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, dwMaxSendPacketSize);
}


void eap::method::end_session()
{
    if (m_inner)
        m_inner->end_session();
}


EapPeerMethodResponseAction eap::method::process_request_packet(
    _In_bytecount_(dwReceivedPacketSize) const void  *pReceivedPacket,
    _In_                                       DWORD dwReceivedPacketSize)
{
    return m_inner ?
        m_inner->process_request_packet(pReceivedPacket, dwReceivedPacketSize) :
        EapPeerMethodResponseActionSend;
}


void eap::method::get_response_packet(
    _Out_    sanitizing_blob &packet,
    _In_opt_ DWORD           size_max)
{
    if (m_inner)
        m_inner->get_response_packet(packet, size_max);
    else
        packet.clear();
}


void eap::method::get_result(
    _In_    EapPeerMethodResultReason reason,
    _Inout_ EapPeerMethodResult       *pResult)
{
    if (m_inner)
        m_inner->get_result(reason, pResult);
}


void eap::method::get_ui_context(_Out_ sanitizing_blob &context_data)
{
    if (m_inner)
        m_inner->get_ui_context(context_data);
    else
        context_data.clear();
}


EapPeerMethodResponseAction eap::method::set_ui_context(
    _In_count_(dwUIContextDataSize) const BYTE  *pUIContextData,
    _In_                                  DWORD dwUIContextDataSize)
{
    return m_inner ?
        m_inner->set_ui_context(pUIContextData, dwUIContextDataSize) :
        EapPeerMethodResponseActionNone;
}


void eap::method::get_response_attributes(_Out_ EapAttributes *pAttribs)
{
    assert(pAttribs);

    if (m_inner)
        m_inner->get_response_attributes(pAttribs);
    else {
        pAttribs->dwNumberOfAttributes = 0;
        pAttribs->pAttribs = NULL;
    }
}


EapPeerMethodResponseAction eap::method::set_response_attributes(_In_ const EapAttributes *pAttribs)
{
    return m_inner ?
        m_inner->set_response_attributes(pAttribs) :
        EapPeerMethodResponseActionNone;
}


//////////////////////////////////////////////////////////////////////
// eap::method_eap
//////////////////////////////////////////////////////////////////////

eap::method_eap::method_eap(_In_ module &mod, _In_ eap_type_t eap_method, _In_ credentials &cred, _In_ method *inner) :
    m_eap_method(eap_method),
    m_cred(cred),
    m_id(0),
    m_result(EapPeerMethodResultUnknown),
    method(mod, inner)
{
}


void eap::method_eap::begin_session(
    _In_        DWORD         dwFlags,
    _In_  const EapAttributes *pAttributeArray,
    _In_        HANDLE        hTokenImpersonateUser,
    _In_opt_    DWORD         dwMaxSendPacketSize)
{
    // Inner method may generate packets of up to 64kB (less the EAP packet header).
    // Initialize inner method with appropriately less packet size maximum.
    if (dwMaxSendPacketSize < sizeof(EapPacket))
        throw invalid_argument(string_printf(__FUNCTION__ " Maximum packet size too small (minimum: %zu, available: %u).", sizeof(EapPacket), dwMaxSendPacketSize));
    method::begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, std::min<DWORD>(dwMaxSendPacketSize, MAXWORD) - sizeof(EapPacket));

    m_result = EapPeerMethodResultUnknown;
    m_packet_res.clear();
}


EapPeerMethodResponseAction eap::method_eap::process_request_packet(
    _In_bytecount_(dwReceivedPacketSize) const void  *pReceivedPacket,
    _In_                                       DWORD dwReceivedPacketSize)
{
    if (dwReceivedPacketSize == 0)
        return EapPeerMethodResponseActionNone;
    if (dwReceivedPacketSize < offsetof(EapPacket, Data))
        throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete EAP packet header.");

    auto hdr = reinterpret_cast<const EapPacket*>(pReceivedPacket);

    // Check packet size.
    DWORD size_packet = ntohs(*reinterpret_cast<const unsigned short*>(hdr->Length));
    if (size_packet > dwReceivedPacketSize)
        throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, string_printf(__FUNCTION__ " Incorrect EAP packet length (expected: %u, received: %u).", size_packet, dwReceivedPacketSize));

    switch (hdr->Code) {
    case EapCodeRequest:
        if (dwReceivedPacketSize < sizeof(EapPacket))
            throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete EAP packet.");

        // Save request packet ID to make matching response packet in get_response_packet() later.
        m_id = hdr->Id;

        if ((eap_type_t)hdr->Data[0] == eap_type_t::identity) {
            // EAP Identity. Respond with identity.
            sanitizing_string identity_utf8;
            WideCharToMultiByte(CP_UTF8, 0, m_cred.get_identity(), identity_utf8, NULL, NULL);
            make_response_packet(eap_type_t::identity, identity_utf8.c_str(), (DWORD)(sizeof(char)*identity_utf8.length()));
            return EapPeerMethodResponseActionSend;
        } else if ((eap_type_t)hdr->Data[0] == m_eap_method) {
            // Process the data with underlying method.
            m_packet_res.clear();
            return method::process_request_packet(hdr->Data + 1, size_packet - sizeof(EapPacket));
        } else {
            // Unsupported EAP method. Respond with Legacy Nak suggesting our EAP method to continue.
            make_response_packet(eap_type_t::nak, &m_eap_method, sizeof(eap_type_t));
            return EapPeerMethodResponseActionSend;
        }

    // Check EAP Success/Failure packets for inner methods.
    case EapCodeSuccess:
    case EapCodeFailure:
        assert(size_packet == 4);
        m_result = (EapPeerMethodResultReason)(hdr->Code - EapCodeSuccess + EapPeerMethodResultSuccess);
        return EapPeerMethodResponseActionResult;

    default:
        throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, string_printf(__FUNCTION__ " Unknown EAP packet received (expected: %u, received: %u).", EapCodeRequest, (int)hdr->Code));
    }
}


void eap::method_eap::get_response_packet(
    _Out_    sanitizing_blob &packet,
    _In_opt_ DWORD           size_max)
{
    assert(size_max >= sizeof(EapPacket)); // We should be able to respond with at least an EAP packet header.
    if (size_max > MAXWORD) size_max = MAXWORD; // EAP packets maximum size is 64kB.
    packet.reserve(size_max); // To avoid reallocation when inserting EAP packet header later.

    if (m_packet_res.empty()) {
        // Get data from underlying method.
        method::get_response_packet(packet, size_max - sizeof(EapPacket));

        size_t size_packet = sizeof(EapPacket) + packet.size();
        if (size_packet > size_max)
            throw invalid_argument(string_printf(__FUNCTION__ " This method does not support packet fragmentation, but the data size is too big to fit in one packet (packet: %zu, maximum: %u).", size_packet, size_max));

        EapPacket hdr;
        hdr.Code    = (BYTE)EapCodeResponse;
        hdr.Id      = m_id;
        assert(size_packet <= MAXWORD); // Packets spanning over 64kB are not supported.
        *reinterpret_cast<unsigned short*>(hdr.Length) = htons((unsigned short)size_packet);
        hdr.Data[0] = (BYTE)m_eap_method;

        // Insert EAP packet header before data.
        packet.insert(packet.begin(),
            reinterpret_cast<const unsigned char*>(&hdr),
            reinterpret_cast<const unsigned char*>(&hdr + 1));
    } else {
        // We have a response packet ready.
        size_t size_packet = m_packet_res.size();
        if (size_packet > size_max)
            throw invalid_argument(string_printf(__FUNCTION__ " This method does not support packet fragmentation, but the data size is too big to fit in one packet (packet: %zu, maximum: %u).", size_packet, size_max));
        packet.assign(m_packet_res.cbegin(), m_packet_res.cend());
    }
}


void eap::method_eap::get_result(
    _In_    EapPeerMethodResultReason reason,
    _Inout_ EapPeerMethodResult       *pResult)
{
    switch (m_result) {
    case EapPeerMethodResultSuccess:
    case EapPeerMethodResultFailure: return method::get_result(m_result, pResult);
    default                        : return method::get_result(reason  , pResult);
    }
}


void eap::method_eap::make_response_packet(
    _In_                                           eap_type_t eap_type,
    _In_bytecount_(dwResponsePacketDataSize) const void       *pResponsePacketData,
    _In_                                           DWORD      dwResponsePacketDataSize)
{
    assert(pResponsePacketData || !dwResponsePacketDataSize);

    size_t size_packet = sizeof(EapPacket) + dwResponsePacketDataSize;

    EapPacket hdr;
    hdr.Code    = (BYTE)EapCodeResponse;
    hdr.Id      = m_id;
    assert(size_packet <= MAXWORD); // Packets spanning over 64kB are not supported.
    *reinterpret_cast<unsigned short*>(hdr.Length) = htons((unsigned short)size_packet);
    hdr.Data[0] = (BYTE)eap_type;

    m_packet_res.reserve(size_packet);
    m_packet_res.assign(
        reinterpret_cast<unsigned char*>(&hdr),
        reinterpret_cast<unsigned char*>(&hdr + 1));
    m_packet_res.insert(m_packet_res.cend(), 
        reinterpret_cast<const unsigned char*>(pResponsePacketData),
        reinterpret_cast<const unsigned char*>(pResponsePacketData) + dwResponsePacketDataSize);
}
