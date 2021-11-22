/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2020 Amebis
    Copyright © 2016 GÉANT
*/

#include "PCH.h"

#pragma comment(lib, "Secur32.lib")

using namespace std;
using namespace winstd;


//////////////////////////////////////////////////////////////////////
// eap::method_eapmsg
//////////////////////////////////////////////////////////////////////

eap::method_eapmsg::method_eapmsg(_In_ module &mod, _In_ method *inner) :
    m_phase(phase_t::unknown),
    method(mod, inner)
{
}


void eap::method_eapmsg::begin_session(
    _In_        DWORD         dwFlags,
    _In_  const EapAttributes *pAttributeArray,
    _In_        HANDLE        hTokenImpersonateUser,
    _In_opt_    DWORD         dwMaxSendPacketSize)
{
    // Inner method may generate packets of up to 16MB (less the Diameter AVP header).
    // Initialize inner method with appropriately less packet size maximum.
    if (dwMaxSendPacketSize < sizeof(diameter_avp_header))
        throw invalid_argument(string_printf(__FUNCTION__ " Maximum packet size too small (minimum: %zu, available: %u).", sizeof(diameter_avp_header), dwMaxSendPacketSize));
    method::begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, std::min<DWORD>(dwMaxSendPacketSize, 0xffffff) - sizeof(diameter_avp_header));

    m_phase = phase_t::identity;
}


EapPeerMethodResponseAction eap::method_eapmsg::process_request_packet(
    _In_bytecount_(dwReceivedPacketSize) const void  *pReceivedPacket,
    _In_                                       DWORD dwReceivedPacketSize)
{
    switch (m_phase) {
    case phase_t::identity:
        // Build EAP-Response/Identity packet.
        EapPacket hdr_req;
        hdr_req.Code = EapCodeRequest;
        hdr_req.Id   = 0;
        *reinterpret_cast<unsigned short*>(hdr_req.Length) = htons(sizeof(EapPacket));
        hdr_req.Data[0] = (BYTE)eap_type_t::identity;

        m_phase = phase_t::finished;
        m_packet_res.clear();
        return method::process_request_packet(&hdr_req, sizeof(EapPacket));

    case phase_t::finished: {
        EapPeerMethodResponseAction action = EapPeerMethodResponseActionNone;
        bool eap_message_found = false;

        // Parse Diameter AVP(s).
        // Process the first EAP-Message, but keep iterating over all to check if there is any additional mandatory AVP we should process.
        for (const unsigned char *pck = reinterpret_cast<const unsigned char*>(pReceivedPacket), *pck_end = pck + dwReceivedPacketSize; pck < pck_end; ) {
            if (pck + sizeof(diameter_avp_header) > pck_end)
                throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete message header.");
            const diameter_avp_header *hdr = reinterpret_cast<const diameter_avp_header*>(pck);
            unsigned int size_msg = ntoh24(hdr->length);
            const unsigned char
                *msg      = reinterpret_cast<const unsigned char*>(hdr + 1),
                *msg_end  = pck + size_msg,
                *msg_next = msg_end + (unsigned int)((4 - size_msg) % 4);
            if (msg_end > pck_end)
                throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete message data.");
            unsigned int code = ntohl(*reinterpret_cast<const unsigned int*>(hdr->code));

            switch (code) {
            case 79: // EAP-Message
                if (!eap_message_found) {
                    action = method::process_request_packet(msg, (DWORD)(msg_end - msg));
                    eap_message_found = true;
                    break;
                }
                // Do not break out of this case to allow continuing with the following case, checking there is no second mandatory EAP-Message present.

            default:
                if (hdr->flags & diameter_avp_flag_mandatory)
                    throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, string_printf(__FUNCTION__ " Unsupported mandatory Diameter AVP (code %u).", code));
            }

            pck = msg_next;
        }

        // Signal get_response_packet() method we did not generate any response data to proxy inner method.
        m_packet_res.clear();

        return action;
    }

    default:
        throw invalid_argument(string_printf(__FUNCTION__ " Unknown phase (phase %u).", m_phase));
    }
}


void eap::method_eapmsg::get_response_packet(
    _Out_    sanitizing_blob &packet,
    _In_opt_ DWORD           size_max)
{
    if (m_packet_res.empty()) {
        if (size_max > 0xffffff) size_max = 0xffffff; // Diameter AVP maximum size is 16MB.

        // Get data from underlying method.
        assert(size_max >= sizeof(diameter_avp_header)); // We should be able to respond with at least Diameter AVP header.
        method::get_response_packet(packet, size_max - sizeof(diameter_avp_header));

        // Prepare EAP-Message Diameter AVP header.
        diameter_avp_header hdr;
        *reinterpret_cast<unsigned int*>(hdr.code) = htonl(79); // EAP-Message=79
        hdr.flags = diameter_avp_flag_mandatory;
        size_t size_packet = packet.size() + sizeof(diameter_avp_header);
        assert(size_packet <= 0xffffff); // Packets spanning over 16MB are not supported.
        hton24((unsigned int)size_packet, hdr.length);

        // Insert EAP header before data.
        packet.insert(packet.begin(), reinterpret_cast<const unsigned char*>(&hdr), reinterpret_cast<const unsigned char*>(&hdr + 1));

        // Add padding.
        packet.insert(packet.end(), (unsigned int)((4 - size_packet) % 4), 0);
    } else {
        // We have a response packet ready.
        size_t size_packet = m_packet_res.size();
        if (size_packet > size_max)
            throw invalid_argument(string_printf(__FUNCTION__ " This method does not support packet fragmentation, but the data size is too big to fit in one packet (packet: %zu, maximum: %u).", size_packet, size_max));

        packet.assign(m_packet_res.cbegin(), m_packet_res.cend());
    }
}


//////////////////////////////////////////////////////////////////////
// eap::method_ttls
//////////////////////////////////////////////////////////////////////

eap::method_ttls::method_ttls(_In_ module &mod, _In_ config_method_ttls &cfg, _In_ credentials_tls_tunnel &cred, _In_ method *inner) :
    method_tls(mod, cfg, cred, inner)
{
}


void eap::method_ttls::push_keying_material()
{
    method_mschapv2_diameter *inner_mschapv2 = dynamic_cast<method_mschapv2_diameter*>(m_inner.get());
    if (inner_mschapv2) {
        // Push EAP-TTLS keying material to inner MSCHAPv2 method.
        SECURITY_STATUS status;
        static const DWORD key_id = 0x02; // EAP-TTLSv0 Challenge Data
        static const SecPkgContext_EapPrfInfo prf_info = { 0, sizeof(key_id), (PBYTE)&key_id };
        if (FAILED(status = SetContextAttributes(m_sc_ctx, SECPKG_ATTR_EAP_PRF_INFO, (void*)&prf_info, sizeof(prf_info))))
            throw sec_runtime_error(status, __FUNCTION__ " Error setting TTLS PRF in Schannel.");

        SecPkgContext_EapKeyBlock key_block;
        if (FAILED(status = QueryContextAttributes(m_sc_ctx, SECPKG_ATTR_EAP_KEY_BLOCK, &key_block)))
            throw sec_runtime_error(status, __FUNCTION__ " Error generating PRF in Schannel.");

        inner_mschapv2->set_challenge_data(key_block.rgbKeys, key_block.rgbKeys[sizeof(challenge_mschapv2)]);

        SecureZeroMemory(&key_block, sizeof(key_block));
    }
}


void eap::method_ttls::get_keying_material(_Out_ sanitizing_blob_xf<32> &recv_key, _Out_ sanitizing_blob_xf<32> &send_key)
{
    // Derive MSK keys.
    DWORD key_id = 0x01; // EAP-TTLSv0 Keying Material
    const SecPkgContext_EapPrfInfo prf_info = { 0, sizeof(key_id), (PBYTE)&key_id };
    SECURITY_STATUS status = SetContextAttributes(m_sc_ctx, SECPKG_ATTR_EAP_PRF_INFO, (void*)&prf_info, sizeof(prf_info));
    if (FAILED(status))
        throw sec_runtime_error(status, __FUNCTION__ " Error setting PRF in Schannel.");

    SecPkgContext_EapKeyBlock key_block;
    status = QueryContextAttributes(m_sc_ctx, SECPKG_ATTR_EAP_KEY_BLOCK, &key_block);
    if (FAILED(status))
        throw sec_runtime_error(status, __FUNCTION__ " Error generating MSK in Schannel.");
    memcpy(recv_key.data, key_block.rgbKeys     , 32);
    memcpy(send_key.data, key_block.rgbKeys + 32, 32);
    SecureZeroMemory(&key_block, sizeof(key_block));
}
