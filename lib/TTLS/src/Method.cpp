/*
    Copyright 2015-2018 Amebis
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

#pragma comment(lib, "Secur32.lib")

using namespace std;
using namespace winstd;


//////////////////////////////////////////////////////////////////////
// eap::method_defrag
//////////////////////////////////////////////////////////////////////

eap::method_defrag::method_defrag(_In_ module &mod, _In_ method *inner) :
    m_send_res(false),
    method_tunnel(mod, inner)
{
}


eap::method_defrag::method_defrag(_Inout_ method_defrag &&other) noexcept :
    m_data_req   (std::move(other.m_data_req)),
    m_data_res   (std::move(other.m_data_res)),
    m_send_res   (std::move(other.m_send_res)),
    method_tunnel(std::move(other           ))
{
}


eap::method_defrag& eap::method_defrag::operator=(_Inout_ method_defrag &&other) noexcept
{
    if (this != std::addressof(other)) {
        (method_tunnel&)*this = std::move(other           );
        m_data_req            = std::move(other.m_data_req);
        m_data_res            = std::move(other.m_data_res);
        m_send_res            = std::move(other.m_send_res);
    }

    return *this;
}


void eap::method_defrag::begin_session(
    _In_        DWORD         dwFlags,
    _In_  const EapAttributes *pAttributeArray,
    _In_        HANDLE        hTokenImpersonateUser,
    _In_opt_    DWORD         dwMaxSendPacketSize)
{
    // Initialize tunnel method session only.
    method::begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, dwMaxSendPacketSize);

    // Inner method can generate packets of up to 4GB.
    assert(m_inner);
    m_inner->begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, MAXDWORD);
}


EapPeerMethodResponseAction eap::method_defrag::process_request_packet(
    _In_bytecount_(dwReceivedPacketSize) const void  *pReceivedPacket,
    _In_                                       DWORD dwReceivedPacketSize)
{
    assert(dwReceivedPacketSize >= 1); // Request packet should contain flags at least.
    auto data_packet = reinterpret_cast<const unsigned char*>(pReceivedPacket);

    // Get packet content pointer and size for more readable code later on.
    const unsigned char *data_content;
    size_t size_content;
    if (data_packet[0] & flags_req_length_incl) {
        // Length field is included.
        data_content = data_packet          + 5;
        size_content = dwReceivedPacketSize - 5;
    } else {
        // Length field not included.
        data_content = data_packet          + 1;
        size_content = dwReceivedPacketSize - 1;
    }

    // Do the defragmentation.
    if (data_packet[0] & flags_req_more_frag) {
        if (m_data_req.empty()) {
            // Start a new packet.
            if (data_packet[0] & flags_req_length_incl) {
                // Preallocate data according to the Length field.
                m_data_req.reserve(ntohl(*reinterpret_cast<const unsigned int*>(data_packet + 1)));
            }
        }
        m_data_req.insert(m_data_req.end(), data_content, data_content + size_content);

        // Respond with ACK packet (empty packet).
        m_data_res.clear();
        m_send_res = true;
        return EapPeerMethodResponseActionSend;
    } else if (!m_data_req.empty()) {
        // Last fragment received. Append data.
        m_data_req.insert(m_data_req.end(), data_content, data_content + size_content);
    } else {
        // This is a complete non-fragmented packet.
        m_data_req.assign(data_content, data_content + size_content);
    }

    if (m_send_res) {
        // We are sending a fragmented message.
        if (m_data_req.empty() && (data_packet[0] & (flags_req_length_incl | flags_req_more_frag | flags_req_start)) == 0) {
            // Received packet is the ACK of our fragmented message packet. Send the next fragment.
            return EapPeerMethodResponseActionSend;
        } else
            throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " ACK expected.");
    }

    // Process the data with underlying method.
    auto action = method_tunnel::process_request_packet(m_data_req.data(), (DWORD)m_data_req.size());

    // Packet was processed. Clear its data since we use the absence of data to detect first of fragmented message packages.
    m_data_req.clear();
    return action;
}


void eap::method_defrag::get_response_packet(
    _Out_    sanitizing_blob &packet,
    _In_opt_ DWORD           size_max)
{
    assert(size_max > 5); // We can not do the fragmentation if we have less space than flags+length+at least one byte of data.

    if (!m_send_res) {
        // Get data from underlying method.
        method_tunnel::get_response_packet(m_data_res, MAXDWORD);
    }

    size_t size_data = m_data_res.size();
    assert(size_data <= MAXDWORD); // Packets spanning over 4GB are not supported.

    packet.clear();
    if (size_data + 1 > size_max) {
        // Write one fragment.
        packet.push_back(flags_res_length_incl | flags_res_more_frag);
        unsigned int length = htonl((unsigned int)size_data);
        packet.insert(packet.end(), reinterpret_cast<const unsigned char*>(&length), reinterpret_cast<const unsigned char*>(&length + 1));
        auto data_begin = m_data_res.begin() + 0, data_end = data_begin + (size_max - 5);
        packet.insert(packet.end(), data_begin, data_end);
        m_data_res.erase(data_begin, data_end);
        m_send_res = true;
    } else {
        // Write single/last fragment.
        packet.push_back(0);
        packet.insert(packet.end(), m_data_res.begin(), m_data_res.end());
        m_data_res.clear();
        m_send_res = false;
    }
}


//////////////////////////////////////////////////////////////////////
// eap::method_eapmsg
//////////////////////////////////////////////////////////////////////

eap::method_eapmsg::method_eapmsg(_In_ module &mod, _In_ const wchar_t *identity, _In_ method *inner) :
    m_identity(identity),
    m_phase(phase_unknown),
    method_tunnel(mod, inner)
{
}


eap::method_eapmsg::method_eapmsg(_Inout_ method_eapmsg &&other) noexcept :
    m_identity   (std::move(other.m_identity  )),
    m_phase      (std::move(other.m_phase     )),
    m_packet_res (std::move(other.m_packet_res)),
    method_tunnel(std::move(other             ))
{
}


eap::method_eapmsg& eap::method_eapmsg::operator=(_Inout_ method_eapmsg &&other) noexcept
{
    if (this != std::addressof(other)) {
        (method_tunnel&)*this = std::move(other             );
        m_identity            = std::move(other.m_identity  );
        m_phase               = std::move(other.m_phase     );
        m_packet_res          = std::move(other.m_packet_res);
    }

    return *this;
}


void eap::method_eapmsg::begin_session(
    _In_        DWORD         dwFlags,
    _In_  const EapAttributes *pAttributeArray,
    _In_        HANDLE        hTokenImpersonateUser,
    _In_opt_    DWORD         dwMaxSendPacketSize)
{
    // Initialize tunnel method session only.
    method::begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, dwMaxSendPacketSize);

    // Inner method can generate packets of up to 16MB (less the Diameter AVP header).
    // Initialize inner method with appropriately less packet size maximum.
    if (dwMaxSendPacketSize < sizeof(diameter_avp_header))
        throw invalid_argument(string_printf(__FUNCTION__ " Maximum packet size too small (minimum: %zu, available: %u).", sizeof(diameter_avp_header) + 1, dwMaxSendPacketSize));
    assert(m_inner);
    m_inner->begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, std::min<DWORD>(dwMaxSendPacketSize, 0xffffff) - sizeof(diameter_avp_header));

    m_phase = phase_identity;
}


EapPeerMethodResponseAction eap::method_eapmsg::process_request_packet(
    _In_bytecount_(dwReceivedPacketSize) const void  *pReceivedPacket,
    _In_                                       DWORD dwReceivedPacketSize)
{
    switch (m_phase) {
    case phase_identity: {
        // Convert identity to UTF-8.
        sanitizing_string identity_utf8;
        WideCharToMultiByte(CP_UTF8, 0, m_identity, identity_utf8, NULL, NULL);

        // Build EAP-Response/Identity packet.
        auto size_identity = identity_utf8.length(), size_packet = size_identity + sizeof(EapPacket);
        assert(size_packet <= MAXWORD); // Packets spanning over 64kB are not supported.
        eap_packet pck;
        if (!pck.create(EapCodeResponse, 0, (WORD)size_packet))
            throw win_runtime_error(__FUNCTION__ " EapPacket creation failed.");
        pck->Data[0] = eap_type_identity;
        memcpy(pck->Data + 1, identity_utf8.data(), size_identity);

        // Diameter AVP (EAP-Message=79)
        m_packet_res.clear();
        diameter_avp_append(79, diameter_avp_flag_mandatory, (const EapPacket*)pck, (unsigned int)size_packet, m_packet_res);

        m_phase = phase_finished;
        return EapPeerMethodResponseActionSend;
    }

    case phase_finished: {
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
                    action = method_tunnel::process_request_packet(msg, (DWORD)(msg_end - msg));
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
        assert(size_max >= sizeof(diameter_avp_header)); // We should be able to respond with at least Diameter AVP header.

        if (size_max > 0xffffff) size_max = 0xffffff; // Diameter AVP maximum size is 16MB.

        // Get data from underlying method.
        method_tunnel::get_response_packet(packet, size_max - sizeof(diameter_avp_header));

        // Prepare EAP-Message Diameter AVP header.
        diameter_avp_header hdr;
        *reinterpret_cast<unsigned int*>(hdr.code) = htonl(79);
        hdr.flags = diameter_avp_flag_mandatory;
        size_t size_packet = packet.size() + sizeof(diameter_avp_header);
        assert(size_packet <= 0xffffff); // Packets spanning over 16MB are not supported.
        hton24((unsigned int)size_packet, hdr.length);

        // Insert EAP header before data.
        packet.insert(packet.begin(), reinterpret_cast<const unsigned char*>(&hdr), reinterpret_cast<const unsigned char*>(&hdr + 1));

        // Add padding.
        packet.insert(packet.end(), (unsigned int)((4 - size_packet) % 4), 0);
    } else {
        if (m_packet_res.size() > size_max)
            throw invalid_argument(string_printf(__FUNCTION__ " This method does not support packet fragmentation, but the data size is too big to fit in one packet (packet: %zu, maximum: %u).", m_packet_res.size(), size_max));

        packet.assign(m_packet_res.begin(), m_packet_res.end());
    }
}


//////////////////////////////////////////////////////////////////////
// eap::method_ttls
//////////////////////////////////////////////////////////////////////

eap::method_ttls::method_ttls(_In_ module &mod, _In_ config_method_ttls &cfg, _In_ credentials_ttls &cred, _In_ method *inner) :
    m_cfg(cfg),
    m_cred(cred),
    m_user_ctx(NULL),
    m_phase(phase_unknown),
    m_packet_res_inner(false),
    method_tunnel(mod, inner)
{
    m_eap_attr_desc.dwNumberOfAttributes = 0;
    m_eap_attr_desc.pAttribs = NULL;
}


eap::method_ttls::method_ttls(_Inout_ method_ttls &&other) noexcept :
    m_cfg             (          other.m_cfg              ),
    m_cred            (          other.m_cred             ),
    m_user_ctx        (std::move(other.m_user_ctx        )),
    m_sc_target_name  (std::move(other.m_sc_target_name  )),
    m_sc_cred         (std::move(other.m_sc_cred         )),
    m_sc_queue        (std::move(other.m_sc_queue        )),
    m_sc_ctx          (std::move(other.m_sc_ctx          )),
    m_sc_cert         (std::move(other.m_sc_cert         )),
    m_phase           (std::move(other.m_phase           )),
    m_packet_res      (std::move(other.m_packet_res      )),
    m_packet_res_inner(std::move(other.m_packet_res_inner)),
    m_eap_attr        (std::move(other.m_eap_attr        )),
    method_tunnel     (std::move(other                   ))
{
    m_eap_attr_desc.dwNumberOfAttributes = (DWORD)m_eap_attr.size();
    m_eap_attr_desc.pAttribs = m_eap_attr.data();
}


eap::method_ttls& eap::method_ttls::operator=(_Inout_ method_ttls &&other) noexcept
{
    if (this != std::addressof(other)) {
        assert(std::addressof(m_cfg ) == std::addressof(other.m_cfg )); // Move method within same configuration only!
        assert(std::addressof(m_cred) == std::addressof(other.m_cred)); // Move method within same credentials only!
        (method_tunnel&)*this = std::move(other                   );
        m_user_ctx            = std::move(other.m_user_ctx        );
        m_sc_target_name      = std::move(other.m_sc_target_name  );
        m_sc_cred             = std::move(other.m_sc_cred         );
        m_sc_queue            = std::move(other.m_sc_queue        );
        m_sc_ctx              = std::move(other.m_sc_ctx          );
        m_sc_cert             = std::move(other.m_sc_cert         );
        m_phase               = std::move(other.m_phase           );
        m_packet_res          = std::move(other.m_packet_res      );
        m_packet_res_inner    = std::move(other.m_packet_res_inner);
        m_eap_attr            = std::move(other.m_eap_attr        );
    }

    return *this;
}


void eap::method_ttls::begin_session(
    _In_        DWORD         dwFlags,
    _In_  const EapAttributes *pAttributeArray,
    _In_        HANDLE        hTokenImpersonateUser,
    _In_opt_    DWORD         dwMaxSendPacketSize)
{
    // In TLS, maximum packet length can precisely be calculated only after handshake is complete.
    // Therefore, we allow inner method same maximum packet size as this method.
    // Initialize tunnel and inner method session with same parameters.
    method_tunnel::begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, dwMaxSendPacketSize);

    // Presume authentication will fail with generic protocol failure. (Pesimist!!!)
    // We will reset once we get get_result(Success) call.
    m_cfg.m_last_status = config_method::status_auth_failed;
    m_cfg.m_last_msg.clear();

    m_user_ctx = hTokenImpersonateUser;
    user_impersonator impersonating(m_user_ctx);

    // Build (expected) server name(s) for Schannel.
    m_sc_target_name.clear();
    for (auto name = m_cfg.m_server_names.cbegin(), name_end = m_cfg.m_server_names.cend(); name != name_end; ++name) {
        if (name != m_cfg.m_server_names.cbegin())
            m_sc_target_name += _T(';');
#ifdef _UNICODE
        m_sc_target_name.insert(m_sc_target_name.end(), name->begin(), name->end());
#else
        string buf;
        WideCharToMultiByte(CP_ACP, 0, name, buf, NULL, NULL);
        m_sc_target_name.insert(m_sc_target_name.end(), buf.begin(), buf.end());
#endif
    }

    // Prepare client credentials for Schannel.
    PCCERT_CONTEXT certs[] = { m_cred.m_cert ? (PCCERT_CONTEXT)m_cred.m_cert : NULL };
    SCHANNEL_CRED cred = {
        SCHANNEL_CRED_VERSION,                                                // dwVersion
        m_cred.m_cert ? 1ul : 0ul,                                            // cCreds
        certs,                                                                // paCred
        NULL,                                                                 // hRootStore: Not valid for client credentials
        0,                                                                    // cMappers
        NULL,                                                                 // aphMappers
        0,                                                                    // cSupportedAlgs: Use system configured default
        NULL,                                                                 // palgSupportedAlgs: Use system configured default
        SP_PROT_TLS1_X_CLIENT | (SP_PROT_TLS1_2_CLIENT<<2),                   // grbitEnabledProtocols: TLS 1.x
        0,                                                                    // dwMinimumCipherStrength: Use system configured default
        0,                                                                    // dwMaximumCipherStrength: Use system configured default
        0,                                                                    // dwSessionLifespan: Use system configured default = 10hr
#if EAP_TLS >= EAP_TLS_SCHANNEL_FULL
        SCH_CRED_AUTO_CRED_VALIDATION                                     |   // dwFlags: Let Schannel verify server certificate
#else
        SCH_CRED_MANUAL_CRED_VALIDATION                                   |   // dwFlags: Prevent Schannel verify server certificate (we want to use custom root CA store and multiple name checking)
#endif
        SCH_CRED_CACHE_ONLY_URL_RETRIEVAL_ON_CREATE                       |   // dwFlags: Do not attempt online revocation check - we do not expect to have network connection yet
        SCH_CRED_IGNORE_NO_REVOCATION_CHECK                               |   // dwFlags: Ignore no-revocation-check errors - as we cannot check for revocation, it makes little sense to insist certificate has to have revocation set-up
        SCH_CRED_IGNORE_REVOCATION_OFFLINE                                |   // dwFlags: Ignore offline-revocation errors - we do not expect to have network connection yet
        SCH_CRED_NO_DEFAULT_CREDS                                         |   // dwFlags: If client certificate we provided is not acceptable, do not try to select one on your own
        (m_cfg.m_server_names.empty() ? SCH_CRED_NO_SERVERNAME_CHECK : 0) |   // dwFlags: When no expected server name is given, do not do the server name check.
        0x00400000ul /*SCH_USE_STRONG_CRYPTO*/,                               // dwFlags: Do not use broken ciphers
        0                                                                     // dwCredFormat
    };
    SECURITY_STATUS stat = m_sc_cred.acquire(NULL, UNISP_NAME, SECPKG_CRED_OUTBOUND, NULL, &cred);
    if (FAILED(stat))
        throw sec_runtime_error(stat, __FUNCTION__ " Error acquiring Schannel credentials handle.");

    m_phase = phase_handshake_init;
}


EapPeerMethodResponseAction eap::method_ttls::process_request_packet(
    _In_bytecount_(dwReceivedPacketSize) const void  *pReceivedPacket,
    _In_                                       DWORD dwReceivedPacketSize)
{
    assert(pReceivedPacket || dwReceivedPacketSize == 0);

    user_impersonator impersonating(m_user_ctx);

    switch (m_phase) {
    case phase_handshake_init: {
        m_module.log_event(&EAPMETHOD_METHOD_HANDSHAKE_START2, event_data((unsigned int)eap_type_ttls), event_data::blank);

        // Prepare input buffer(s).
        SecBuffer buf_in[] = {
            { (unsigned long)dwReceivedPacketSize, SECBUFFER_TOKEN, const_cast<void*>(pReceivedPacket) },
            { 0, SECBUFFER_EMPTY, NULL },
        };
        SecBufferDesc buf_in_desc = { SECBUFFER_VERSION, _countof(buf_in), buf_in };

        // Prepare output buffer(s).
        SecBuffer buf_out[] = {
            { 0, SECBUFFER_TOKEN, NULL },
            { 0, SECBUFFER_ALERT, NULL },
        };
        sec_buffer_desc buf_out_desc(buf_out, _countof(buf_out));

        // Initialize Schannel security context and process initial data.
        SECURITY_STATUS status = m_sc_ctx.initialize(
            m_sc_cred,
            !m_sc_target_name.empty() ? m_sc_target_name.c_str() : NULL,
            ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_INTEGRITY | ISC_REQ_STREAM | /*ISC_REQ_USE_SUPPLIED_CREDS |*/ ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY,
            0,
            &buf_in_desc,
            &buf_out_desc);

        // In a desparate attempt to make Schannel remember and resume the TLS session, we send it the SCHANNEL_SESSION_TOKEN/SSL_SESSION_ENABLE_RECONNECTS
        SCHANNEL_SESSION_TOKEN token_session = { SCHANNEL_SESSION, SSL_SESSION_ENABLE_RECONNECTS };
        SecBuffer token[] = { { sizeof(token_session), SECBUFFER_TOKEN, &token_session } };
        SecBufferDesc token_desc = { SECBUFFER_VERSION, _countof(token), token };
        ApplyControlToken(m_sc_ctx, &token_desc);

        if (status == SEC_I_CONTINUE_NEEDED) {
            // Send Schannel's token.
            assert(buf_out[0].BufferType == SECBUFFER_TOKEN);
            assert(m_sc_ctx.m_attrib & ISC_RET_ALLOCATED_MEMORY);
            m_packet_res.assign(reinterpret_cast<const unsigned char*>(buf_out[0].pvBuffer), reinterpret_cast<const unsigned char*>(buf_out[0].pvBuffer) + buf_out[0].cbBuffer);
            if (buf_in[1].BufferType == SECBUFFER_EXTRA) {
                // Server appended extra data.
                m_sc_queue.assign(reinterpret_cast<const unsigned char*>(pReceivedPacket) + dwReceivedPacketSize - buf_in[1].cbBuffer, reinterpret_cast<const unsigned char*>(pReceivedPacket) + dwReceivedPacketSize);
            } else
                m_sc_queue.clear();

            m_phase = phase_handshake_cont;
            m_packet_res_inner = false;
            return EapPeerMethodResponseActionSend;
        } else if (FAILED(status)) {
            if (m_sc_ctx.m_attrib & ISC_RET_EXTENDED_ERROR) {
                // Send alert.
                assert(buf_out[1].BufferType == SECBUFFER_ALERT);
                assert(m_sc_ctx.m_attrib & ISC_RET_ALLOCATED_MEMORY);
                m_packet_res.assign(reinterpret_cast<const unsigned char*>(buf_out[1].pvBuffer), reinterpret_cast<const unsigned char*>(buf_out[1].pvBuffer) + buf_out[1].cbBuffer);
                m_packet_res_inner = false;
                return EapPeerMethodResponseActionSend;
            } else
                throw sec_runtime_error(status, __FUNCTION__ " Schannel error.");
        } else
            throw sec_runtime_error(status, __FUNCTION__ " Unexpected Schannel result.");
    }

    case phase_handshake_cont: {
        m_sc_queue.insert(m_sc_queue.end(), reinterpret_cast<const unsigned char*>(pReceivedPacket), reinterpret_cast<const unsigned char*>(pReceivedPacket) + dwReceivedPacketSize);

        // Prepare input buffer(s).
        SecBuffer buf_in[] = {
            { (unsigned long)m_sc_queue.size(), SECBUFFER_TOKEN, m_sc_queue.data() },
            { 0, SECBUFFER_EMPTY, NULL },
        };
        SecBufferDesc buf_in_desc = { SECBUFFER_VERSION, _countof(buf_in), buf_in };

        // Prepare output buffer(s).
        SecBuffer buf_out[] = {
            { 0, SECBUFFER_TOKEN, NULL },
            { 0, SECBUFFER_ALERT, NULL },
        };
        sec_buffer_desc buf_out_desc(buf_out, _countof(buf_out));

        // Process Schannel data.
        SECURITY_STATUS status = m_sc_ctx.process(
            m_sc_cred,
            !m_sc_target_name.empty() ? m_sc_target_name.c_str() : NULL,
            ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_INTEGRITY | ISC_REQ_STREAM | /*ISC_REQ_USE_SUPPLIED_CREDS |*/ ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY,
            0,
            &buf_in_desc,
            &buf_out_desc);

        if (status == SEC_E_OK) {
            // Get server certificate.
            if (FAILED(status = QueryContextAttributes(m_sc_ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (PVOID)&m_sc_cert)))
                throw sec_runtime_error(status, __FUNCTION__ " Error retrieving server certificate from Schannel.");

            // Add all trusted root CAs to server certificate's store. This allows CertGetIssuerCertificateFromStore() in the following CRL check to test the root CA for revocation too.
            // verify_server_trust(), ignores all self-signed certificates from the server certificate's store, and rebuilds its own trusted root store, so we are safe to do this.
            for (auto c = m_cfg.m_trusted_root_ca.cbegin(), c_end = m_cfg.m_trusted_root_ca.cend(); c != c_end; ++c)
                CertAddCertificateContextToStore(m_sc_cert->hCertStore, *c, CERT_STORE_ADD_REPLACE_EXISTING, NULL);

            // Verify cached CRL (entire chain).
            reg_key key;
            if (key.open(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\") _T(VENDOR_NAME_STR) _T("\\") _T(PRODUCT_NAME_STR) _T("\\TLSCRL"), 0, KEY_READ)) {
                wstring hash_unicode;
                vector<unsigned char> hash, subj;
                for (cert_context c(m_sc_cert); c;) {
                    if (CertGetCertificateContextProperty(c, CERT_HASH_PROP_ID, hash)) {
                        hash_unicode.clear();
                        hex_enc enc;
                        enc.encode(hash_unicode, hash.data(), hash.size());
                        if (RegQueryValueExW(key, hash_unicode.c_str(), NULL, NULL, subj) == ERROR_SUCCESS) {
                            // A certificate in the chain is found to be revoked as compromised.
                            m_cfg.m_last_status = config_method::status_server_compromised;
                            throw com_runtime_error(CRYPT_E_REVOKED, __FUNCTION__ " Server certificate or one of its issuer's certificate has been found revoked as compromised. Your credentials were probably sent to this server during previous connection attempts, thus changing your credentials (in a safe manner) is strongly advised. Please, contact your helpdesk immediately.");
                        }
                    }

                    DWORD flags = 0;
                    c = CertGetIssuerCertificateFromStore(m_sc_cert->hCertStore, c, NULL, &flags);
                    if (!c) break;
                }
            }

#if EAP_TLS < EAP_TLS_SCHANNEL_FULL
            // Verify server certificate chain.
            verify_server_trust();
#endif
        }

        if (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED) {
            // Send Schannel's token.
            assert(buf_out[0].BufferType == SECBUFFER_TOKEN);
            assert(m_sc_ctx.m_attrib & ISC_RET_ALLOCATED_MEMORY);
            m_packet_res.assign(reinterpret_cast<const unsigned char*>(buf_out[0].pvBuffer), reinterpret_cast<const unsigned char*>(buf_out[0].pvBuffer) + buf_out[0].cbBuffer);
            if (buf_in[1].BufferType == SECBUFFER_EXTRA) {
                // Server appended extra data.
                m_sc_queue.erase(m_sc_queue.begin(), m_sc_queue.end() - buf_in[1].cbBuffer);
            } else
                m_sc_queue.clear();

            if (status == SEC_I_CONTINUE_NEEDED) {
                // Blame credentials if we fail beyond this point.
                m_cfg.m_last_status = config_method::status_cred_invalid;
                m_packet_res_inner = false;
            } else {
                SecPkgContext_Authority auth;
                if (FAILED(status = QueryContextAttributes(m_sc_ctx, SECPKG_ATTR_AUTHORITY, &auth))) {
                    m_module.log_event(&EAPMETHOD_TLS_QUERY_FAILED, event_data((unsigned int)SECPKG_ATTR_AUTHORITY), event_data(status), event_data::blank);
                    auth.sAuthorityName = _T("");
                }

                SecPkgContext_ConnectionInfo info;
                if (SUCCEEDED(status = QueryContextAttributes(m_sc_ctx, SECPKG_ATTR_CONNECTION_INFO, &info)))
                    m_module.log_event(&EAPMETHOD_TLS_HANDSHAKE_FINISHED,
                        event_data((unsigned int)eap_type_ttls),
                        event_data(auth.sAuthorityName),
                        event_data(info.dwProtocol),
                        event_data(info.aiCipher),
                        event_data(info.dwCipherStrength),
                        event_data(info.aiHash),
                        event_data(info.dwHashStrength),
                        event_data(info.aiExch),
                        event_data(info.dwExchStrength),
                        event_data::blank);
                else
                    m_module.log_event(&EAPMETHOD_TLS_QUERY_FAILED, event_data((unsigned int)SECPKG_ATTR_CONNECTION_INFO), event_data(status), event_data::blank);

                m_phase = phase_finished;
                m_cfg.m_last_status = config_method::status_success;

                method_mschapv2_diameter *inner_mschapv2 = dynamic_cast<method_mschapv2_diameter*>(m_inner.get());
                if (inner_mschapv2) {
                    // Push keying material to inner MSCHAPv2 method.
                    static const DWORD s_key_id = 0x02; // EAP-TTLSv0 Challenge Data
                    static const SecPkgContext_EapPrfInfo s_prf_info = { 0, sizeof(s_key_id), (PBYTE)&s_key_id };
                    if (FAILED(status = SetContextAttributes(m_sc_ctx, SECPKG_ATTR_EAP_PRF_INFO, (void*)&s_prf_info, sizeof(s_prf_info))))
                        throw sec_runtime_error(status, __FUNCTION__ " Error setting TTLS PRF in Schannel.");

                    SecPkgContext_EapKeyBlock key_block;
                    if (FAILED(status = QueryContextAttributes(m_sc_ctx, SECPKG_ATTR_EAP_KEY_BLOCK, &key_block)))
                        throw sec_runtime_error(status, __FUNCTION__ " Error generating PRF in Schannel.");

                    inner_mschapv2->m_challenge_server.assign(key_block.rgbKeys, key_block.rgbKeys + sizeof(challenge_mschapv2));
                    inner_mschapv2->m_ident = key_block.rgbKeys[sizeof(challenge_mschapv2) + 0];

                    SecureZeroMemory(&key_block, sizeof(key_block));
                }

                // Piggyback initial inner response.
                if (!(m_sc_ctx.m_attrib & ISC_RET_CONFIDENTIALITY))
                    throw runtime_error(__FUNCTION__ " Connection is not encrypted.");

                EapPeerMethodResponseAction action = EapPeerMethodResponseActionDiscard;
                if (m_sc_queue.empty()) {
                    // No extra initial data for inner authentication avaliable.
                    action = method_tunnel::process_request_packet(NULL, 0);
                } else {
                    // Authenticator sent some data for inner authentication. Decrypt it.

                    // Decrypt the message.
                    SecBuffer buf[] = {
                        { (unsigned long)m_sc_queue.size(), SECBUFFER_DATA, m_sc_queue.data() },
                        { 0, SECBUFFER_EMPTY, NULL },
                        { 0, SECBUFFER_EMPTY, NULL },
                        { 0, SECBUFFER_EMPTY, NULL },
                    };
                    SecBufferDesc buf_desc = { SECBUFFER_VERSION, _countof(buf), buf };
                    status = DecryptMessage(m_sc_ctx, &buf_desc, 0, NULL);
                    if (status == SEC_E_OK) {
                        // Process data (only the first SECBUFFER_DATA found).
                        for (size_t i = 0; i < _countof(buf); i++)
                            if (buf[i].BufferType == SECBUFFER_DATA) {
                                action = method_tunnel::process_request_packet(buf[i].pvBuffer, buf[i].cbBuffer);
                                break;
                            }

                        // Queue remaining data for the next time.
                        m_sc_queue.clear();
                        for (size_t i = 0; i < _countof(buf); i++)
                            if (buf[i].BufferType == SECBUFFER_EXTRA)
                                m_sc_queue.insert(m_sc_queue.end(), reinterpret_cast<const unsigned char*>(buf[i].pvBuffer), reinterpret_cast<const unsigned char*>(buf[i].pvBuffer) + buf[i].cbBuffer);
                    } else if (FAILED(status))
                        throw sec_runtime_error(status, __FUNCTION__ " Schannel error.");
                    else
                        throw sec_runtime_error(status, __FUNCTION__ " Unexpected Schannel result.");
                }
                switch (action) {
                case EapPeerMethodResponseActionSend: m_packet_res_inner = true ; break;
                case EapPeerMethodResponseActionNone: m_packet_res_inner = false; break;
                default                             : throw invalid_argument(string_printf(__FUNCTION__ " Inner method returned an unsupported action (action %u).", action));
                }
            }
            return EapPeerMethodResponseActionSend;
        } else if (FAILED(status)) {
            if (m_sc_ctx.m_attrib & ISC_RET_EXTENDED_ERROR) {
                // Send alert.
                assert(buf_out[1].BufferType == SECBUFFER_ALERT);
                assert(m_sc_ctx.m_attrib & ISC_RET_ALLOCATED_MEMORY);
                m_packet_res.assign(reinterpret_cast<const unsigned char*>(buf_out[1].pvBuffer), reinterpret_cast<const unsigned char*>(buf_out[1].pvBuffer) + buf_out[1].cbBuffer);
                m_packet_res_inner = false;
                return EapPeerMethodResponseActionSend;
            } else
                throw sec_runtime_error(status, __FUNCTION__ " Schannel error.");
        } else
            throw sec_runtime_error(status, __FUNCTION__ " Unexpected Schannel result.");
    }

    case phase_finished: {
        m_packet_res.clear();
        m_sc_queue.insert(m_sc_queue.end(), reinterpret_cast<const unsigned char*>(pReceivedPacket), reinterpret_cast<const unsigned char*>(pReceivedPacket) + dwReceivedPacketSize);

        if (!(m_sc_ctx.m_attrib & ISC_RET_CONFIDENTIALITY))
            throw runtime_error(__FUNCTION__ " Connection is not encrypted.");

        if (m_sc_queue.empty()) {
            // No extra data for inner authentication.
            return method_tunnel::process_request_packet(NULL, 0);
        } else {
            // Authenticator sent data for inner authentication. Decrypt it.

            // Decrypt the message.
            SecBuffer buf[] = {
                { (unsigned long)m_sc_queue.size(), SECBUFFER_DATA, m_sc_queue.data() },
                { 0, SECBUFFER_EMPTY, NULL },
                { 0, SECBUFFER_EMPTY, NULL },
                { 0, SECBUFFER_EMPTY, NULL },
            };
            SecBufferDesc buf_desc = { SECBUFFER_VERSION, _countof(buf), buf };
            SECURITY_STATUS status = DecryptMessage(m_sc_ctx, &buf_desc, 0, NULL);
            if (status == SEC_E_OK) {
                // Process data (only the first SECBUFFER_DATA found).
                EapPeerMethodResponseAction action = EapPeerMethodResponseActionDiscard;
                for (size_t i = 0; i < _countof(buf); i++)
                    if (buf[i].BufferType == SECBUFFER_DATA) {
                        action = method_tunnel::process_request_packet(buf[i].pvBuffer, buf[i].cbBuffer);
                        break;
                    }

                // Queue remaining data for the next time.
                m_sc_queue.clear();
                for (size_t i = 0; i < _countof(buf); i++)
                    if (buf[i].BufferType == SECBUFFER_EXTRA)
                        m_sc_queue.insert(m_sc_queue.end(), reinterpret_cast<const unsigned char*>(buf[i].pvBuffer), reinterpret_cast<const unsigned char*>(buf[i].pvBuffer) + buf[i].cbBuffer);

                return action;
            } else if (FAILED(status))
                throw sec_runtime_error(status, __FUNCTION__ " Schannel error.");
            else
                throw sec_runtime_error(status, __FUNCTION__ " Unexpected Schannel result.");
        }
    }

    default:
        throw invalid_argument(string_printf(__FUNCTION__ " Unknown phase (phase %u).", m_phase));
    }
}


void eap::method_ttls::get_response_packet(
    _Out_    sanitizing_blob &packet,
    _In_opt_ DWORD           size_max)
{
    if (m_packet_res_inner) {
        // Get maximum allowable packet size.
        SecPkgContext_StreamSizes sizes;
        SECURITY_STATUS status = QueryContextAttributes(m_sc_ctx, SECPKG_ATTR_STREAM_SIZES, &sizes);
        if (FAILED(status))
            throw sec_runtime_error(status, __FUNCTION__ " Error getting Schannel required encryption sizes.");
        if (m_packet_res.size() + sizes.cbHeader + sizes.cbTrailer > size_max)
            throw invalid_argument(string_printf(__FUNCTION__ " This method does not support packet fragmentation, but the data size is too big to fit in one packet (packet: %zu, maximum: %u).", m_packet_res.size(), size_max));
        sizes.cbMaximumMessage = std::min<unsigned long>(sizes.cbMaximumMessage, size_max - (unsigned long)(m_packet_res.size() + sizes.cbHeader + sizes.cbTrailer));

        // Get inner response packet.
        packet.reserve((size_t)sizes.cbHeader + sizes.cbMaximumMessage + sizes.cbTrailer);
        method_tunnel::get_response_packet(packet, sizes.cbMaximumMessage);
        if (!packet.empty()) {
            DWORD size_data = (DWORD)packet.size();

            // Insert and append space for header and trailer.
            packet.insert(packet.begin(), sizes.cbHeader , 0);
            packet.insert(packet.end  (), sizes.cbTrailer, 0);

            // Encrypt the message.
            unsigned char *ptr_data = packet.data();
            SecBuffer buf[] = {
                {  sizes.cbHeader, SECBUFFER_STREAM_HEADER , ptr_data                   },
                {       size_data, SECBUFFER_DATA          , ptr_data += sizes.cbHeader },
                { sizes.cbTrailer, SECBUFFER_STREAM_TRAILER, ptr_data += size_data      },
                {               0, SECBUFFER_EMPTY         , NULL                       },
            };
            SecBufferDesc buf_desc = { SECBUFFER_VERSION, _countof(buf), buf };
            status = EncryptMessage(m_sc_ctx, 0, &buf_desc, 0);
            if (FAILED(status))
                throw sec_runtime_error(status, __FUNCTION__ " Error encrypting message.");

            m_packet_res.insert(m_packet_res.end(), reinterpret_cast<const unsigned char*>(buf[0].pvBuffer), reinterpret_cast<const unsigned char*>(buf[0].pvBuffer) + buf[0].cbBuffer + buf[1].cbBuffer + buf[2].cbBuffer);
        }
    } else if (m_packet_res.size() > size_max)
        throw invalid_argument(string_printf(__FUNCTION__ " This method does not support packet fragmentation, but the data size is too big to fit in one packet (packet: %zu, maximum: %u).", m_packet_res.size(), size_max));

    packet.assign(m_packet_res.begin(), m_packet_res.end());
}


void eap::method_ttls::get_result(
    _In_    EapPeerMethodResultReason reason,
    _Inout_ EapPeerMethodResult       *pResult)
{
    assert(pResult);

    // Get inner result.
    method_tunnel::get_result(reason, pResult);

    if (reason == EapPeerMethodResultSuccess) {
        eap_attr a;

        // Prepare EAP result attributes.
        if (pResult->pAttribArray) {
            m_eap_attr.reserve((size_t)pResult->pAttribArray->dwNumberOfAttributes + 3);
            m_eap_attr.clear();
            // Copy all EAP attributes from inner method up to blank terminator. Exclude any MPPE-Recv-Key or MPPE-Send-Key if found.
            for (auto attr = pResult->pAttribArray->pAttribs, attr_end = pResult->pAttribArray->pAttribs + pResult->pAttribArray->dwNumberOfAttributes; attr != attr_end && attr->eaType; ++attr) {
                if (attr->eaType != eatVendorSpecific || attr->dwLength < 5 || ntohl(*reinterpret_cast<const unsigned int*>(attr->pValue)) != 311 || attr->pValue[4] != 16 && attr->pValue[4] != 17)
                    m_eap_attr.push_back(*attr);
            }
        } else {
            m_eap_attr.reserve(3);
            m_eap_attr.clear();
        }

        // Derive MSK keys.
        static const DWORD s_key_id = 0x01; // EAP-TTLSv0 Keying Material
        static const SecPkgContext_EapPrfInfo s_prf_info = { 0, sizeof(s_key_id), (PBYTE)&s_key_id };
        SECURITY_STATUS status = SetContextAttributes(m_sc_ctx, SECPKG_ATTR_EAP_PRF_INFO, (void*)&s_prf_info, sizeof(s_prf_info));
        if (FAILED(status))
            throw sec_runtime_error(status, __FUNCTION__ " Error setting TTLS PRF in Schannel.");

        SecPkgContext_EapKeyBlock key_block;
        status = QueryContextAttributes(m_sc_ctx, SECPKG_ATTR_EAP_KEY_BLOCK, &key_block);
        if (FAILED(status))
            throw sec_runtime_error(status, __FUNCTION__ " Error generating MSK in Schannel.");
        const unsigned char *_key_block = key_block.rgbKeys;

        // MSK: MPPE-Recv-Key
        a.create_ms_mppe_key(16, _key_block, 32);
        m_eap_attr.push_back(std::move(a));
        _key_block += 32;

        // MSK: MPPE-Send-Key
        a.create_ms_mppe_key(17, _key_block, 32);
        m_eap_attr.push_back(std::move(a));
        _key_block += 32;

        SecureZeroMemory(&key_block, sizeof(key_block));

        // Append blank EAP attribute.
        m_eap_attr.push_back(eap_attr::blank);

        m_eap_attr_desc.dwNumberOfAttributes = (DWORD)m_eap_attr.size();
        m_eap_attr_desc.pAttribs = m_eap_attr.data();
        pResult->pAttribArray = &m_eap_attr_desc;

        m_cfg.m_last_status = config_method::status_success;

        // Spawn certificate revocation verify thread.
        dynamic_cast<peer_ttls&>(m_module).spawn_crl_check(std::move(m_sc_cert));
    }

    // Always ask EAP host to save the connection data. And it will save it *only* when we report "success".
    // Don't worry. EapHost is well aware of failed authentication condition.
    pResult->fSaveConnectionData = TRUE;
    pResult->fIsSuccess          = TRUE;
}


#if EAP_TLS < EAP_TLS_SCHANNEL_FULL

void eap::method_ttls::verify_server_trust() const
{
    for (auto c = m_cfg.m_trusted_root_ca.cbegin(), c_end = m_cfg.m_trusted_root_ca.cend(); c != c_end; ++c) {
        if (m_sc_cert->cbCertEncoded == (*c)->cbCertEncoded &&
            memcmp(m_sc_cert->pbCertEncoded, (*c)->pbCertEncoded, m_sc_cert->cbCertEncoded) == 0)
        {
            // Server certificate found directly on the trusted root CA list.
            m_module.log_event(&EAPMETHOD_TLS_SERVER_CERT_TRUSTED_EX1, event_data((unsigned int)eap_type_ttls), event_data::blank);
            return;
        }
    }

    // Check server name.
    if (!m_cfg.m_server_names.empty()) {
        bool
            has_san = false,
            found   = false;

        // Search subjectAltName2 and subjectAltName.
        for (DWORD idx_ext = 0; !found && idx_ext < m_sc_cert->pCertInfo->cExtension; idx_ext++) {
            unique_ptr<CERT_ALT_NAME_INFO, LocalFree_delete<CERT_ALT_NAME_INFO> > san_info;
            if (strcmp(m_sc_cert->pCertInfo->rgExtension[idx_ext].pszObjId, szOID_SUBJECT_ALT_NAME2) == 0) {
                unsigned char *output = NULL;
                DWORD size_output;
                if (!CryptDecodeObjectEx(
                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                        szOID_SUBJECT_ALT_NAME2,
                        m_sc_cert->pCertInfo->rgExtension[idx_ext].Value.pbData, m_sc_cert->pCertInfo->rgExtension[idx_ext].Value.cbData,
                        CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_ENABLE_PUNYCODE_FLAG,
                        NULL,
                        &output, &size_output))
                    throw win_runtime_error(__FUNCTION__ " Error decoding subjectAltName2 certificate extension.");
                san_info.reset((CERT_ALT_NAME_INFO*)output);
            } else if (strcmp(m_sc_cert->pCertInfo->rgExtension[idx_ext].pszObjId, szOID_SUBJECT_ALT_NAME) == 0) {
                unsigned char *output = NULL;
                DWORD size_output;
                if (!CryptDecodeObjectEx(
                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                        szOID_SUBJECT_ALT_NAME,
                        m_sc_cert->pCertInfo->rgExtension[idx_ext].Value.pbData, m_sc_cert->pCertInfo->rgExtension[idx_ext].Value.cbData,
                        CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_ENABLE_PUNYCODE_FLAG,
                        NULL,
                        &output, &size_output))
                    throw win_runtime_error(__FUNCTION__ " Error decoding subjectAltName certificate extension.");
                san_info.reset((CERT_ALT_NAME_INFO*)output);
            } else {
                // Skip this extension.
                continue;
            }
            has_san = true;

            for (auto s = m_cfg.m_server_names.cbegin(), s_end = m_cfg.m_server_names.cend(); !found && s != s_end; ++s) {
                for (DWORD idx_entry = 0; !found && idx_entry < san_info->cAltEntry; idx_entry++) {
                    if (san_info->rgAltEntry[idx_entry].dwAltNameChoice == CERT_ALT_NAME_DNS_NAME &&
                        _wcsicmp(s->c_str(), san_info->rgAltEntry[idx_entry].pwszDNSName) == 0)
                    {
                        m_module.log_event(&EAPMETHOD_TLS_SERVER_NAME_TRUSTED2, event_data((unsigned int)eap_type_ttls), event_data(san_info->rgAltEntry[idx_entry].pwszDNSName), event_data::blank);
                        found = true;
                    }
                }
            }
        }

        if (!has_san) {
            // Certificate has no subjectAltName. Compare against Common Name.
            wstring subj;
            if (!CertGetNameStringW(m_sc_cert, CERT_NAME_DNS_TYPE, CERT_NAME_STR_ENABLE_PUNYCODE_FLAG, NULL, subj))
                throw win_runtime_error(__FUNCTION__ " Error retrieving server's certificate subject name.");

            for (auto s = m_cfg.m_server_names.cbegin(), s_end = m_cfg.m_server_names.cend(); !found && s != s_end; ++s) {
                if (_wcsicmp(s->c_str(), subj.c_str()) == 0) {
                    m_module.log_event(&EAPMETHOD_TLS_SERVER_NAME_TRUSTED2, event_data((unsigned int)eap_type_ttls), event_data(subj), event_data::blank);
                    found = true;
                }
            }
        }

        if (!found)
            throw sec_runtime_error(SEC_E_WRONG_PRINCIPAL, __FUNCTION__ " Name provided in server certificate is not on the list of trusted server names.");
    }

    if (m_sc_cert->pCertInfo->Issuer.cbData == m_sc_cert->pCertInfo->Subject.cbData &&
        memcmp(m_sc_cert->pCertInfo->Issuer.pbData, m_sc_cert->pCertInfo->Subject.pbData, m_sc_cert->pCertInfo->Issuer.cbData) == 0)
        throw sec_runtime_error(SEC_E_CERT_UNKNOWN, __FUNCTION__ " Server is using a self-signed certificate. Cannot trust it.");

    // Create temporary certificate store of our trusted root CAs.
    cert_store store;
    if (!store.create(CERT_STORE_PROV_MEMORY, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, NULL, 0, NULL))
        throw win_runtime_error(__FUNCTION__ " Error creating temporary certificate store.");
    for (auto c = m_cfg.m_trusted_root_ca.cbegin(), c_end = m_cfg.m_trusted_root_ca.cend(); c != c_end; ++c)
        CertAddCertificateContextToStore(store, *c, CERT_STORE_ADD_REPLACE_EXISTING, NULL);

    // Add all intermediate certificates from the server's certificate chain.
    for (cert_context c(m_sc_cert); c;) {
        DWORD flags = 0;
        c.attach(CertGetIssuerCertificateFromStore(m_sc_cert->hCertStore, c, NULL, &flags));
        if (!c) break;

        if (c->pCertInfo->Issuer.cbData == c->pCertInfo->Subject.cbData &&
            memcmp(c->pCertInfo->Issuer.pbData, c->pCertInfo->Subject.pbData, c->pCertInfo->Issuer.cbData) == 0)
        {
            // Skip the root CA certificates (self-signed). We define in whom we trust!
            continue;
        }

        CertAddCertificateContextToStore(store, c, CERT_STORE_ADD_REPLACE_EXISTING, NULL);
    }

    // Prepare the certificate chain validation, and check.
    CERT_CHAIN_PARA chain_params = {
        sizeof(chain_params),      // cbSize
        {
            USAGE_MATCH_TYPE_AND,  // RequestedUsage.dwType
            {},                    // RequestedUsage.Usage
        },
#ifdef CERT_CHAIN_PARA_HAS_EXTRA_FIELDS
        {},                        // RequestedIssuancePolicy
        1,                         // dwUrlRetrievalTimeout (1ms to speed up checking)
#else
#define _S2(x) #x
#define _S(x) _S2(x)
#pragma message(__FILE__ "(" _S(__LINE__) "): warning X0000: Please define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS constant when compiling this project.")
#endif
    };
    cert_chain_context context;
    if (!context.create(NULL, m_sc_cert, NULL, store, &chain_params, 0))
        throw win_runtime_error(__FUNCTION__ " Error creating certificate chain context.");

    // Check chain validation error flags. Ignore CERT_TRUST_IS_UNTRUSTED_ROOT flag since we check root CA explicitly.
    if (context->TrustStatus.dwErrorStatus != CERT_TRUST_NO_ERROR &&
        (context->TrustStatus.dwErrorStatus & ~CERT_TRUST_IS_UNTRUSTED_ROOT) != CERT_TRUST_NO_ERROR)
    {
        if (context->TrustStatus.dwErrorStatus & (CERT_TRUST_IS_NOT_TIME_VALID | CERT_TRUST_IS_NOT_TIME_NESTED))
            throw sec_runtime_error(SEC_E_CERT_EXPIRED, __FUNCTION__ " Server certificate has expired (or is not valid yet).");
        else if (context->TrustStatus.dwErrorStatus & (CERT_TRUST_IS_UNTRUSTED_ROOT | CERT_TRUST_IS_PARTIAL_CHAIN))
            throw sec_runtime_error(SEC_E_UNTRUSTED_ROOT, __FUNCTION__ " Server's certificate not issued by one of configured trusted root CAs.");
        else
            throw sec_runtime_error(SEC_E_CERT_UNKNOWN, __FUNCTION__ " Error validating server certificate.");
    }

    // Verify Root CA against our trusted root CA list
    if (context->cChain != 1)
        throw sec_runtime_error(SEC_E_CERT_UNKNOWN, __FUNCTION__ " Multiple chain verification not supported.");
    if (context->rgpChain[0]->cElement == 0)
        throw sec_runtime_error(SEC_E_CERT_UNKNOWN, __FUNCTION__ " Can not verify empty certificate chain.");

    PCCERT_CONTEXT cert_root = context->rgpChain[0]->rgpElement[context->rgpChain[0]->cElement-1]->pCertContext;
    for (auto c = m_cfg.m_trusted_root_ca.cbegin(), c_end = m_cfg.m_trusted_root_ca.cend();; ++c) {
        if (c != c_end) {
            if (cert_root->cbCertEncoded == (*c)->cbCertEncoded &&
                memcmp(cert_root->pbCertEncoded, (*c)->pbCertEncoded, cert_root->cbCertEncoded) == 0)
            {
                // Trusted root CA found.
                break;
            }
        } else {
            // Not found.
            throw sec_runtime_error(SEC_E_UNTRUSTED_ROOT, __FUNCTION__ " Server's certificate not issued by one of configured trusted root CAs.");
        }
    }

    m_module.log_event(&EAPMETHOD_TLS_SERVER_CERT_TRUSTED1, event_data((unsigned int)eap_type_ttls), event_data::blank);
}

#endif
