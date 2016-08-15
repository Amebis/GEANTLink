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
// eap::method_tls::packet
//////////////////////////////////////////////////////////////////////

eap::method_tls::packet::packet() :
    m_code((EapCode)0),
    m_id(0),
    m_flags(0)
{
}


eap::method_tls::packet::packet(_In_ const packet &other) :
    m_code (other.m_code ),
    m_id   (other.m_id   ),
    m_flags(other.m_flags),
    m_data (other.m_data )
{
}


eap::method_tls::packet::packet(_Inout_ packet &&other) :
    m_code (std::move(other.m_code )),
    m_id   (std::move(other.m_id   )),
    m_flags(std::move(other.m_flags)),
    m_data (std::move(other.m_data ))
{
}


eap::method_tls::packet& eap::method_tls::packet::operator=(_In_ const packet &other)
{
    if (this != std::addressof(other)) {
        m_code  = other.m_code ;
        m_id    = other.m_id   ;
        m_flags = other.m_flags;
        m_data  = other.m_data ;
    }

    return *this;
}


eap::method_tls::packet& eap::method_tls::packet::operator=(_Inout_ packet &&other)
{
    if (this != std::addressof(other)) {
        m_code  = std::move(other.m_code );
        m_id    = std::move(other.m_id   );
        m_flags = std::move(other.m_flags);
        m_data  = std::move(other.m_data );
    }

    return *this;
}


void eap::method_tls::packet::clear()
{
    m_code  = (EapCode)0;
    m_id    = 0;
    m_flags = 0;
    m_data.clear();
}


//////////////////////////////////////////////////////////////////////
// eap::method_tls
//////////////////////////////////////////////////////////////////////

eap::method_tls::method_tls(_In_ module &module, _In_ config_provider_list &cfg, _In_ credentials_tls &cred) :
    m_cred(cred),
    m_certificate_req(false),
    m_server_hello_done(false),
    m_cipher_spec(false),
    m_server_finished(false),
    m_seq_num_client(0),
    m_seq_num_server(0),
    m_blob_cfg(NULL),
#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
    m_blob_cred(NULL),
#endif
    method(module, cfg, cred)
{
    m_tls_version = tls_version_1_0;
}


eap::method_tls::method_tls(_In_ const method_tls &other) :
    m_cred(other.m_cred),
    m_packet_req(other.m_packet_req),
    m_packet_res(other.m_packet_res),
    m_state(other.m_state),
    m_padding_hmac_client(other.m_padding_hmac_client),
    m_padding_hmac_server(other.m_padding_hmac_server),
    m_key_client(other.m_key_client),
    m_key_server(other.m_key_server),
    m_key_mppe_client(other.m_key_mppe_client),
    m_key_mppe_server(other.m_key_mppe_server),
    m_session_id(other.m_session_id),
    m_server_cert_chain(other.m_server_cert_chain),
    m_hash_handshake_msgs_md5(other.m_hash_handshake_msgs_md5),
    m_hash_handshake_msgs_sha1(other.m_hash_handshake_msgs_sha1),
    m_certificate_req(other.m_certificate_req),
    m_server_hello_done(other.m_server_hello_done),
    m_cipher_spec(other.m_cipher_spec),
    m_server_finished(other.m_server_finished),
    m_seq_num_client(other.m_seq_num_client),
    m_seq_num_server(other.m_seq_num_server),
    method(other)
{
}


eap::method_tls::method_tls(_Inout_ method_tls &&other) :
    m_cred(other.m_cred),
    m_packet_req(std::move(other.m_packet_req)),
    m_packet_res(std::move(other.m_packet_res)),
    m_state(std::move(other.m_state)),
    m_padding_hmac_client(std::move(other.m_padding_hmac_client)),
    m_padding_hmac_server(std::move(other.m_padding_hmac_server)),
    m_key_client(std::move(other.m_key_client)),
    m_key_server(std::move(other.m_key_server)),
    m_key_mppe_client(std::move(other.m_key_mppe_client)),
    m_key_mppe_server(std::move(other.m_key_mppe_server)),
    m_session_id(std::move(other.m_session_id)),
    m_server_cert_chain(std::move(other.m_server_cert_chain)),
    m_hash_handshake_msgs_md5(std::move(other.m_hash_handshake_msgs_md5)),
    m_hash_handshake_msgs_sha1(std::move(other.m_hash_handshake_msgs_sha1)),
    m_certificate_req(std::move(other.m_certificate_req)),
    m_server_hello_done(std::move(other.m_server_hello_done)),
    m_cipher_spec(std::move(other.m_cipher_spec)),
    m_server_finished(std::move(other.m_server_finished)),
    m_seq_num_client(std::move(other.m_seq_num_client)),
    m_seq_num_server(std::move(other.m_seq_num_server)),
    method(std::move(other))
{
}


eap::method_tls::~method_tls()
{
    if (m_blob_cfg)
        m_module.free_memory(m_blob_cfg);

#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
    if (m_blob_cred)
        m_module.free_memory(m_blob_cred);
#endif
}


eap::method_tls& eap::method_tls::operator=(_In_ const method_tls &other)
{
    if (this != std::addressof(other)) {
        assert(std::addressof(m_cred) == std::addressof(other.m_cred)); // Copy method with same credentials only!
        (method&)*this              = other;
        m_packet_req                = other.m_packet_req;
        m_packet_res                = other.m_packet_res;
        m_state                     = other.m_state;
        m_padding_hmac_client       = other.m_padding_hmac_client;
        m_padding_hmac_server       = other.m_padding_hmac_server;
        m_key_client                = other.m_key_client;
        m_key_server                = other.m_key_server;
        m_key_mppe_client           = other.m_key_mppe_client;
        m_key_mppe_server           = other.m_key_mppe_server;
        m_session_id                = other.m_session_id;
        m_server_cert_chain         = other.m_server_cert_chain;
        m_hash_handshake_msgs_md5   = other.m_hash_handshake_msgs_md5;
        m_hash_handshake_msgs_sha1  = other.m_hash_handshake_msgs_sha1;
        m_certificate_req           = other.m_certificate_req;
        m_server_hello_done         = other.m_server_hello_done;
        m_cipher_spec               = other.m_cipher_spec;
        m_server_finished           = other.m_server_finished;
        m_seq_num_client            = other.m_seq_num_client;
        m_seq_num_server            = other.m_seq_num_server;
    }

    return *this;
}


eap::method_tls& eap::method_tls::operator=(_Inout_ method_tls &&other)
{
    if (this != std::addressof(other)) {
        assert(std::addressof(m_cred) == std::addressof(other.m_cred)); // Move method with same credentials only!
        (method&)*this              = std::move(other);
        m_packet_req                = std::move(other.m_packet_req);
        m_packet_res                = std::move(other.m_packet_res);
        m_state                     = std::move(other.m_state);
        m_padding_hmac_client       = std::move(other.m_padding_hmac_client);
        m_padding_hmac_server       = std::move(other.m_padding_hmac_server);
        m_key_client                = std::move(other.m_key_client);
        m_key_server                = std::move(other.m_key_server);
        m_key_mppe_client           = std::move(other.m_key_mppe_client);
        m_key_mppe_server           = std::move(other.m_key_mppe_server);
        m_session_id                = std::move(other.m_session_id);
        m_server_cert_chain         = std::move(other.m_server_cert_chain);
        m_hash_handshake_msgs_md5   = std::move(other.m_hash_handshake_msgs_md5);
        m_hash_handshake_msgs_sha1  = std::move(other.m_hash_handshake_msgs_sha1);
        m_certificate_req           = std::move(other.m_certificate_req);
        m_server_hello_done         = std::move(other.m_server_hello_done);
        m_cipher_spec               = std::move(other.m_cipher_spec);
        m_server_finished           = std::move(other.m_server_finished);
        m_seq_num_client            = std::move(other.m_seq_num_client);
        m_seq_num_server            = std::move(other.m_seq_num_server);
    }

    return *this;
}


void eap::method_tls::begin_session(
    _In_        DWORD         dwFlags,
    _In_  const EapAttributes *pAttributeArray,
    _In_        HANDLE        hTokenImpersonateUser,
    _In_        DWORD         dwMaxSendPacketSize)
{
    method::begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, dwMaxSendPacketSize);

    // Create cryptographics provider.
    if (!m_cp.create(NULL, MS_ENHANCED_PROV, PROV_RSA_FULL))
        throw win_runtime_error(__FUNCTION__ " Error creating cryptographics provider.");

    if (m_cfg.m_providers.empty() || m_cfg.m_providers.front().m_methods.empty())
        throw invalid_argument(__FUNCTION__ " Configuration has no providers and/or methods.");

    const config_provider &cfg_prov(m_cfg.m_providers.front());
    const config_method_tls *cfg_method = dynamic_cast<const config_method_tls*>(cfg_prov.m_methods.front().get());
    assert(cfg_method);

    m_session_id = cfg_method->m_session_id;
    m_state.m_master_secret = cfg_method->m_master_secret;
}


void eap::method_tls::process_request_packet(
    _In_bytecount_(dwReceivedPacketSize) const EapPacket           *pReceivedPacket,
    _In_                                       DWORD               dwReceivedPacketSize,
    _Inout_                                    EapPeerMethodOutput *pEapOutput)
{
    assert(pReceivedPacket && dwReceivedPacketSize >= 4);
    assert(pEapOutput);

    // Is this a valid EAP-TLS packet?
    if (dwReceivedPacketSize < 6)
        throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Packet is too small. EAP-%s packets should be at least 6B.");
    //else if (pReceivedPacket->Data[0] != eap_type_tls) // Skip method check, to allow TTLS extension.
    //    throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, string_printf(__FUNCTION__ " Packet is not EAP-TLS (expected: %u, received: %u).", eap_type_tls, pReceivedPacket->Data[0]));

    // Get packet data pointer and size for more readable code later on.
    const unsigned char *packet_data_ptr;
    size_t packet_data_size;
    if (pReceivedPacket->Data[1] & flags_req_length_incl) {
        // Length field is included.
        packet_data_ptr  = pReceivedPacket->Data + 6;
        packet_data_size = dwReceivedPacketSize - 10;
    } else {
        // Length field not included.
        packet_data_ptr  = pReceivedPacket->Data + 2;
        packet_data_size = dwReceivedPacketSize - 6;
    }

    // Do the TLS defragmentation.
    if (pReceivedPacket->Data[1] & flags_req_more_frag) {
        if (m_packet_req.m_data.empty()) {
            // Start a new packet.
            if (pReceivedPacket->Data[1] & flags_req_length_incl) {
                // Preallocate data according to the Length field.
                size_t size_tot  = ntohl(*(unsigned int*)(pReceivedPacket->Data + 2));
                m_packet_req.m_data.reserve(size_tot);
                m_module.log_event(&EAPMETHOD_TLS_PACKET_RECV_FRAG_FIRST, event_data((unsigned int)eap_type_tls), event_data((unsigned int)packet_data_size), event_data((unsigned int)size_tot), event_data::blank);
            } else {
                // The Length field was not included. Odd. Nevermind, no pre-allocation then.
                m_module.log_event(&EAPMETHOD_TLS_PACKET_RECV_FRAG_FIRST1, event_data((unsigned int)eap_type_tls), event_data((unsigned int)packet_data_size), event_data::blank);
            }
        } else {
            // Mid fragment received.
            m_module.log_event(&EAPMETHOD_TLS_PACKET_RECV_FRAG_MID, event_data((unsigned int)eap_type_tls), event_data((unsigned int)packet_data_size), event_data((unsigned int)m_packet_req.m_data.size()), event_data::blank);
        }
        m_packet_req.m_data.insert(m_packet_req.m_data.end(), packet_data_ptr, packet_data_ptr + packet_data_size);

        // Reply with ACK packet.
        m_packet_res.m_code  = EapCodeResponse;
        m_packet_res.m_id    = pReceivedPacket->Id;
        m_packet_res.m_flags = 0;
        m_packet_res.m_data.clear();
        pEapOutput->fAllowNotifications = FALSE;
        pEapOutput->action = EapPeerMethodResponseActionSend;
        return;
    } else if (!m_packet_req.m_data.empty()) {
        // Last fragment received. Append data.
        m_packet_req.m_data.insert(m_packet_req.m_data.end(), packet_data_ptr, packet_data_ptr + packet_data_size);
        m_module.log_event(&EAPMETHOD_TLS_PACKET_RECV_FRAG_LAST, event_data((unsigned int)eap_type_tls), event_data((unsigned int)packet_data_size), event_data((unsigned int)m_packet_req.m_data.size()), event_data::blank);
    } else {
        // This is a complete non-fragmented packet.
        m_packet_req.m_data.assign(packet_data_ptr, packet_data_ptr + packet_data_size);
        m_module.log_event(&EAPMETHOD_TLS_PACKET_RECV, event_data((unsigned int)eap_type_tls), event_data((unsigned int)packet_data_size), event_data::blank);
    }

    m_packet_req.m_code  = (EapCode)pReceivedPacket->Code;
    m_packet_req.m_id    = pReceivedPacket->Id;
    m_packet_req.m_flags = pReceivedPacket->Data[1];

    if (m_packet_res.m_flags & flags_res_more_frag) {
        // We are sending a fragmented message.
        if (  m_packet_req.m_code == EapCodeRequest    &&
              m_packet_req.m_id   == m_packet_res.m_id &&
              m_packet_req.m_data.empty()              &&
            !(m_packet_req.m_flags & (flags_req_length_incl | flags_req_more_frag | flags_req_start)))
        {
            // This is the ACK of our fragmented message packet. Send the next fragment.
            m_packet_res.m_id++;
            pEapOutput->fAllowNotifications = FALSE;
            pEapOutput->action = EapPeerMethodResponseActionSend;
            return;
        } else
            throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, string_printf(__FUNCTION__ " ACK expected, received %u-%u-%x.", m_packet_req.m_code, m_packet_req.m_id, m_packet_req.m_flags));
    }

    m_packet_res.m_code  = EapCodeResponse;
    m_packet_res.m_id    = m_packet_req.m_id;
    m_packet_res.m_flags = 0;

    if (pReceivedPacket->Code == EapCodeRequest && (m_packet_req.m_flags & flags_req_start)) {
        // This is the TLS start message: (re)initialize method.
        m_module.log_event(&EAPMETHOD_TLS_HANDSHAKE_START2, event_data((unsigned int)eap_type_tls), event_data::blank);

        m_state.m_random_client.reset(m_cp);

        // Generate client randomness.
        m_padding_hmac_client.clear();
        m_padding_hmac_server.clear();
        m_key_client.free();
        m_key_server.free();
        m_key_mppe_client.clear();
        m_key_mppe_server.clear();

        m_server_cert_chain.clear();

        // Create MD5 hash object.
        if (!m_hash_handshake_msgs_md5.create(m_cp, CALG_MD5))
            throw win_runtime_error(__FUNCTION__ " Error creating MD5 hashing object.");

        // Create SHA-1 hash object.
        if (!m_hash_handshake_msgs_sha1.create(m_cp, CALG_SHA1))
            throw win_runtime_error(__FUNCTION__ " Error creating SHA-1 hashing object.");

        m_certificate_req   = false;
        m_server_hello_done = false;
        m_cipher_spec       = false;
        m_server_finished   = false;

        m_seq_num_client = 0;
        m_seq_num_server = 0;

        // Build client hello packet.
        sanitizing_blob hello(make_client_hello());
        hash_handshake(hello);
        sanitizing_blob handshake(make_message(tls_message_type_handshake, hello, m_cipher_spec));
        m_packet_res.m_data.assign(handshake.begin(), handshake.end());
    } else {
        // Process the packet.
        m_packet_res.m_data.clear();
        process_packet(m_packet_req.m_data.data(), m_packet_req.m_data.size());

        if (m_server_finished) {
            // Server finished.
        } else if (m_cipher_spec) {
            // Cipher specified.
        } else if (m_server_hello_done) {
            // Server hello specified.

            // Do we trust this server?
            if (m_server_cert_chain.empty())
                throw win_runtime_error(ERROR_ENCRYPTION_FAILED, __FUNCTION__ " Can not continue without server's certificate.");
            verify_server_trust();

            if (!m_cipher_spec || !m_server_finished) {
                // New session.

                if (m_certificate_req) {
                    // Client certificate requested.
                    sanitizing_blob client_cert(make_client_cert());
                    hash_handshake(client_cert);
                    sanitizing_blob handshake(make_message(tls_message_type_handshake, client_cert, m_cipher_spec));
                    m_packet_res.m_data.insert(m_packet_res.m_data.end(), handshake.begin(), handshake.end());
                }

                // Generate pre-master secret. PMS will get sanitized in its destructor when going out-of-scope.
                tls_master_secret pms(m_cp);

                // Derive master secret.
                static const unsigned char s_label[] = "master secret";
                sanitizing_blob seed(s_label, s_label + _countof(s_label) - 1);
                seed.insert(seed.end(), (const unsigned char*)&m_state.m_random_client, (const unsigned char*)(&m_state.m_random_client + 1));
                seed.insert(seed.end(), (const unsigned char*)&m_state.m_random_server, (const unsigned char*)(&m_state.m_random_server + 1));
                memcpy(&m_state.m_master_secret, prf(pms, seed, sizeof(tls_master_secret)).data(), sizeof(tls_master_secret));

                // Create client key exchange message, and append to packet.
                sanitizing_blob client_key_exchange(make_client_key_exchange(pms));
                hash_handshake(client_key_exchange);
                sanitizing_blob handshake(make_message(tls_message_type_handshake, client_key_exchange, m_cipher_spec));
                m_packet_res.m_data.insert(m_packet_res.m_data.end(), handshake.begin(), handshake.end());

                if (m_certificate_req) {
                    // TODO: Create and append certificate_verify message!
                }
            }

            // Append change cipher spec to packet.
            sanitizing_blob ccs(make_change_chiper_spec());
            m_packet_res.m_data.insert(m_packet_res.m_data.end(), ccs.begin(), ccs.end());

            if (!m_cipher_spec) {
                // Setup encryption.
                derive_keys();
                m_cipher_spec = true;
            }

            // Create finished message, and append to packet.
            sanitizing_blob finished(make_finished());
            hash_handshake(finished);
            sanitizing_blob handshake(make_message(tls_message_type_handshake, finished, m_cipher_spec));
            m_packet_res.m_data.insert(m_packet_res.m_data.end(), handshake.begin(), handshake.end());
        }
    }

    // Request packet was processed. Clear its data since we use the absence of data to detect first of fragmented message packages.
    m_packet_req.m_data.clear();

    pEapOutput->fAllowNotifications = FALSE;
    pEapOutput->action = EapPeerMethodResponseActionSend;
}


void eap::method_tls::get_response_packet(
    _Inout_bytecap_(*dwSendPacketSize) EapPacket *pSendPacket,
    _Inout_                            DWORD     *pdwSendPacketSize)
{
    assert(pdwSendPacketSize);
    assert(pSendPacket);

    unsigned int
        size_data   = (unsigned int)m_packet_res.m_data.size(),
        size_packet = size_data + 6;
    unsigned short size_packet_limit = (unsigned short)std::min<unsigned int>(*pdwSendPacketSize, USHRT_MAX);
    unsigned char *data_dst;

    if (!(m_packet_res.m_flags & flags_res_more_frag)) {
        // Not fragmented.
        if (size_packet <= size_packet_limit) {
            // No need to fragment the packet.
            m_packet_res.m_flags &= ~flags_res_length_incl; // No need to explicitly include the Length field either.
            data_dst = pSendPacket->Data + 2;
            m_module.log_event(&EAPMETHOD_TLS_PACKET_SEND, event_data((unsigned int)eap_type_tls), event_data((unsigned int)size_data), event_data::blank);
        } else {
            // But it should be fragmented.
            m_packet_res.m_flags |= flags_res_length_incl | flags_res_more_frag;
            *(unsigned int*)(pSendPacket->Data + 2) = (unsigned int)size_packet;
            data_dst = pSendPacket->Data + 6;
            size_data   = size_packet_limit - 10;
            size_packet = size_packet_limit;
            m_module.log_event(&EAPMETHOD_TLS_PACKET_SEND_FRAG_FIRST, event_data((unsigned int)eap_type_tls), event_data((unsigned int)size_data), event_data((unsigned int)(m_packet_res.m_data.size() - size_data)), event_data::blank);
        }
    } else {
        // Continuing the fragmented packet...
        if (size_packet > size_packet_limit) {
            // This is a mid fragment.
            m_packet_res.m_flags &= ~flags_res_length_incl;
            size_data   = size_packet_limit - 6;
            size_packet = size_packet_limit;
            m_module.log_event(&EAPMETHOD_TLS_PACKET_SEND_FRAG_MID, event_data((unsigned int)eap_type_tls), event_data((unsigned int)size_data), event_data((unsigned int)(m_packet_res.m_data.size() - size_data)), event_data::blank);
        } else {
            // This is the last fragment.
            m_packet_res.m_flags &= ~(flags_res_length_incl | flags_res_more_frag);
            m_module.log_event(&EAPMETHOD_TLS_PACKET_SEND_FRAG_LAST, event_data((unsigned int)eap_type_tls), event_data((unsigned int)size_data), event_data((unsigned int)(m_packet_res.m_data.size() - size_data)), event_data::blank);
        }
        data_dst = pSendPacket->Data + 2;
    }

    pSendPacket->Code = (BYTE)m_packet_res.m_code;
    pSendPacket->Id   = m_packet_res.m_id;
    *(unsigned short*)pSendPacket->Length = htons((unsigned short)size_packet);
    pSendPacket->Data[0] = (BYTE)eap_type_tls;
    pSendPacket->Data[1] = m_packet_res.m_flags;
    memcpy(data_dst, m_packet_res.m_data.data(), size_data);
    m_packet_res.m_data.erase(m_packet_res.m_data.begin(), m_packet_res.m_data.begin() + size_data);
    *pdwSendPacketSize = size_packet;
}


void eap::method_tls::get_result(
    _In_    EapPeerMethodResultReason reason,
    _Inout_ EapPeerMethodResult       *ppResult)
{
    assert(ppResult);

    config_provider &cfg_prov(m_cfg.m_providers.front());
    config_method_tls *cfg_method = dynamic_cast<config_method_tls*>(cfg_prov.m_methods.front().get());
    assert(cfg_method);

    switch (reason) {
    case EapPeerMethodResultSuccess: {
        if (!m_server_finished)
            throw invalid_argument(__FUNCTION__ " Premature success.");

        // Derive MSK.
        derive_msk();

        // Fill array with RADIUS attributes.
        eap_attr a;
        m_eap_attr.clear();
        m_eap_attr.reserve(3);
        a.create_ms_mppe_key(16, (LPCBYTE)&m_key_mppe_client, sizeof(tls_random));
        m_eap_attr.push_back(std::move(a));
        a.create_ms_mppe_key(17, (LPCBYTE)&m_key_mppe_server, sizeof(tls_random));
        m_eap_attr.push_back(std::move(a));
        m_eap_attr.push_back(eap_attr::blank);

        m_eap_attr_desc.dwNumberOfAttributes = (DWORD)m_eap_attr.size();
        m_eap_attr_desc.pAttribs = m_eap_attr.data();
        ppResult->pAttribArray = &m_eap_attr_desc;

        // Clear credentials as failed.
        cfg_method->m_cred_failed = false;

        ppResult->fIsSuccess = TRUE;
        ppResult->dwFailureReasonCode = ERROR_SUCCESS;

        // Update configuration with session resumption data and prepare BLOB.
        cfg_method->m_session_id    = m_session_id;
        cfg_method->m_master_secret = m_state.m_master_secret;

        break;
    }

    case EapPeerMethodResultFailure:
        // Clear session resumption data.
        cfg_method->m_session_id.clear();
        cfg_method->m_master_secret.clear();

        // Mark credentials as failed, so GUI can re-prompt user.
        cfg_method->m_cred_failed = true;

        ppResult->fIsSuccess = FALSE;
        ppResult->dwFailureReasonCode = EAP_E_AUTHENTICATION_FAILED;

        break;

    default:
        throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Not supported.");
    }

    // Always ask EAP host to save the connection data.
    ppResult->fSaveConnectionData = TRUE;
    m_module.pack(m_cfg, &ppResult->pConnectionData, &ppResult->dwSizeofConnectionData);
    if (m_blob_cfg)
        m_module.free_memory(m_blob_cfg);
    m_blob_cfg = ppResult->pConnectionData;

#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
    ppResult->fSaveUserData = TRUE;
    m_module.pack(m_cred, &ppResult->pUserData, &ppResult->dwSizeofUserData);
    if (m_blob_cred)
        m_module.free_memory(m_blob_cred);
    m_blob_cred = ppResult->pUserData;
#endif
}


eap::sanitizing_blob eap::method_tls::make_client_hello() const
{
    size_t size_data;
    sanitizing_blob msg;
    msg.reserve(
        4                   + // SSL header
        (size_data =
        2                   + // SSL version
        sizeof(tls_random)  + // Client random
        1                   + // Session ID size
        m_session_id.size() + // Session ID
        2                   + // Length of cypher suite list
        2                   + // Cyper suite list
        1                   + // Length of compression suite
        1));                  // Compression suite

    // SSL header
    assert(size_data <= 0xffffff);
    unsigned int ssl_header = htonl((tls_handshake_type_client_hello << 24) | (unsigned int)size_data);
    msg.insert(msg.end(), (unsigned char*)&ssl_header, (unsigned char*)(&ssl_header + 1));

    // SSL version
    msg.insert(msg.end(), (unsigned char*)&m_tls_version, (unsigned char*)(&m_tls_version + 1));

    // Client random
    msg.insert(msg.end(), (unsigned char*)&m_state.m_random_client, (unsigned char*)(&m_state.m_random_client + 1));

    // Session ID
    assert(m_session_id.size() <= 32);
    msg.push_back((unsigned char)m_session_id.size());
    msg.insert(msg.end(), m_session_id.begin(), m_session_id.end());

    // Cypher suite list
    msg.push_back(0x00); // Length of cypher suite is two (in network-byte-order).
    msg.push_back(0x02); // --^
    msg.push_back(0x00); // TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x00 0x0a)
    msg.push_back(0x0a); // --^

    // Compression
    msg.push_back(0x01); // Length of compression section
    msg.push_back(0x00); // No compression (0)

    return msg;
}


eap::sanitizing_blob eap::method_tls::make_client_cert() const
{
    // Select client certificate.
    PCCERT_CONTEXT cert = m_cred.m_cert ? m_cred.m_cert : NULL;

    size_t size_data, size_list;
    sanitizing_blob msg;
    msg.reserve(
        4                                      + // SSL header
        (size_data =
        3                                      + // Certificate list size
        (size_list =
        (cert ? 3 + cert->cbCertEncoded : 0)))); // Certificate (optional)

    // SSL header
    assert(size_data <= 0xffffff);
    unsigned int ssl_header = htonl((tls_handshake_type_certificate << 24) | (unsigned int)size_data);
    msg.insert(msg.end(), (unsigned char*)&ssl_header, (unsigned char*)(&ssl_header + 1));

    // List size
    assert(size_list <= 0xffffff);
    msg.push_back((unsigned char)((size_list >> 16) & 0xff));
    msg.push_back((unsigned char)((size_list >>  8) & 0xff));
    msg.push_back((unsigned char)((size_list      ) & 0xff));

    if (cert) {
        // Cert size
        assert(cert->cbCertEncoded <= 0xffffff);
        msg.push_back((unsigned char)((cert->cbCertEncoded >> 16) & 0xff));
        msg.push_back((unsigned char)((cert->cbCertEncoded >>  8) & 0xff));
        msg.push_back((unsigned char)((cert->cbCertEncoded      ) & 0xff));

        msg.insert(msg.end(), cert->pbCertEncoded, cert->pbCertEncoded + cert->cbCertEncoded);
    }

    return msg;
}


eap::sanitizing_blob eap::method_tls::make_client_key_exchange(_In_ const tls_master_secret &pms) const
{
    // Encrypt pre-master key first.
    sanitizing_blob pms_enc((const unsigned char*)&pms, (const unsigned char*)(&pms + 1));
    crypt_key key;
    if (!key.import_public(m_cp, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &(m_server_cert_chain.front()->pCertInfo->SubjectPublicKeyInfo)))
        throw win_runtime_error(__FUNCTION__ " Error importing server's public key.");
    if (!CryptEncrypt(key,  NULL, TRUE, 0, pms_enc))
        throw win_runtime_error(__FUNCTION__ " Error encrypting PMS.");

    size_t size_data, size_pms_enc = pms_enc.size();
    sanitizing_blob msg;
    msg.reserve(
        4             + // SSL header
        (size_data =
        2             + // Encrypted pre master secret size
        size_pms_enc)); // Encrypted pre master secret

    // SSL header
    assert(size_data <= 0xffffff);
    unsigned int ssl_header = htonl((tls_handshake_type_client_key_exchange << 24) | (unsigned int)size_data);
    msg.insert(msg.end(), (unsigned char*)&ssl_header, (unsigned char*)(&ssl_header + 1));

    // Encrypted pre master secret size
    assert(size_pms_enc <= 0xffff);
    msg.push_back((unsigned char)((size_pms_enc >> 8) & 0xff));
    msg.push_back((unsigned char)((size_pms_enc     ) & 0xff));

    // Encrypted pre master secret
#ifdef _HOST_LOW_ENDIAN
    std::reverse(pms_enc.begin(), pms_enc.end());
#endif
    msg.insert(msg.end(), pms_enc.begin(), pms_enc.end());

    return msg;
}


eap::sanitizing_blob eap::method_tls::make_change_chiper_spec() const
{
    const unsigned char msg_css[] = {
        (unsigned char)tls_message_type_change_cipher_spec, // SSL record type
        m_tls_version.major,                                // SSL major version
        m_tls_version.minor,                                // SSL minor version
        0,                                                  // Message size (high-order byte)
        1,                                                  // Message size (low-order byte)
        1,                                                  // Message: change_cipher_spec is always "1"
    };
    return sanitizing_blob(msg_css, msg_css + _countof(msg_css));
}


eap::sanitizing_blob eap::method_tls::make_finished() const
{
    sanitizing_blob msg;
    msg.reserve(
        4  + // SSL header
        12); // verify_data is 12B

    // SSL header
    unsigned int ssl_header = htonl((tls_handshake_type_finished << 24) | 12);
    msg.insert(msg.end(), (unsigned char*)&ssl_header, (unsigned char*)(&ssl_header + 1));

    // Create label + hash MD5 + hash SHA-1 seed.
    crypt_hash hash;
    static const unsigned char s_label[] = "client finished";
    sanitizing_blob seed(s_label, s_label + _countof(s_label) - 1), hash_data;
    hash = m_hash_handshake_msgs_md5; // duplicate
    if (!CryptGetHashParam(hash, HP_HASHVAL, hash_data, 0))
        throw win_runtime_error(__FUNCTION__ " Error finishing MD5 hash calculation.");
    seed.insert(seed.end(), hash_data.begin(), hash_data.end());
    hash = m_hash_handshake_msgs_sha1; // duplicate
    if (!CryptGetHashParam(hash, HP_HASHVAL, hash_data, 0))
        throw win_runtime_error(__FUNCTION__ " Error finishing SHA-1 hash calculation.");
    seed.insert(seed.end(), hash_data.begin(), hash_data.end());
    sanitizing_blob verify(prf(m_state.m_master_secret, seed, 12));
    msg.insert(msg.end(), verify.begin(), verify.end());

    return msg;
}


eap::sanitizing_blob eap::method_tls::make_message(_In_ tls_message_type_t type, _Inout_ sanitizing_blob &data, _In_ bool encrypt)
{
    size_t size_data = data.size();
    assert(size_data <= 0xffff);
    message_header hdr = {
        (unsigned char)type, // SSL record type
        {
            m_tls_version.major, // SSL major version
            m_tls_version.minor, // SSL minor version
        },
        {
            // Data length (unencrypted, network byte order)
            (unsigned char)((size_data >> 8) & 0xff),
            (unsigned char)((size_data     ) & 0xff),
        }
    };

    sanitizing_blob msg;
    if (encrypt) {
        encrypt_message(&hdr, data);

        // Update message size.
        size_t size_data_enc = data.size();
        *(unsigned short*)hdr.length = htons((unsigned short)size_data_enc);
        msg.reserve(sizeof(message_header) + size_data_enc);
    } else
        msg.reserve(sizeof(message_header) + size_data);

    // TLS header
    msg.assign((const unsigned char*)&hdr, (const unsigned char*)(&hdr + 1));

    // Data
    msg.insert(msg.end(), data.begin(), data.end());

    return msg;
}


void eap::method_tls::derive_keys()
{
    static const unsigned char s_label[] = "key expansion";
    sanitizing_blob seed(s_label, s_label + _countof(s_label) - 1);
    seed.insert(seed.end(), (const unsigned char*)&m_state.m_random_server, (const unsigned char*)(&m_state.m_random_server + 1));
    seed.insert(seed.end(), (const unsigned char*)&m_state.m_random_client, (const unsigned char*)(&m_state.m_random_client + 1));

    sanitizing_blob key_block(prf(m_state.m_master_secret, seed,
        2*m_state.m_size_mac_key +  // client_write_MAC_secret & server_write_MAC_secret (SHA1)
        2*m_state.m_size_enc_key +  // client_write_key        & server_write_key
        2*m_state.m_size_enc_iv )); // client_write_IV         & server_write_IV
    const unsigned char *_key_block = key_block.data();

    // client_write_MAC_secret
    m_padding_hmac_client.resize(sizeof(hash_hmac::padding_t));
    hash_hmac::inner_padding(m_cp, m_state.m_alg_mac, _key_block, m_state.m_size_mac_key, m_padding_hmac_client.data());
    _key_block += m_state.m_size_mac_key;

    // server_write_MAC_secret
    m_padding_hmac_server.resize(sizeof(hash_hmac::padding_t));
    hash_hmac::inner_padding(m_cp, m_state.m_alg_mac, _key_block, m_state.m_size_mac_key, m_padding_hmac_server.data());
    _key_block += m_state.m_size_mac_key;

    // Microsoft CryptoAPI does not support importing clear text session keys.
    // Therefore, we trick it to say the session key is "encrypted" with an exponent-of-one key.
    crypt_key key_exp1;
    if (!key_exp1.create_exp1(m_cp, AT_KEYEXCHANGE))
        throw win_runtime_error(__FUNCTION__ " Error creating exponent-of-one key.");

    // client_write_key
    m_key_client = create_key(m_state.m_alg_encrypt, key_exp1, _key_block, m_state.m_size_enc_key);
    _key_block += m_state.m_size_enc_key;

    // server_write_key
    m_key_server = create_key(m_state.m_alg_encrypt, key_exp1, _key_block, m_state.m_size_enc_key);
    _key_block += m_state.m_size_enc_key;

    if (m_state.m_size_enc_iv) {
        // client_write_IV
        if (!CryptSetKeyParam(m_key_client, KP_IV, _key_block, 0))
            throw win_runtime_error(__FUNCTION__ " Error setting client_write_IV.");
        _key_block += m_state.m_size_enc_iv;

        // server_write_IV
        if (!CryptSetKeyParam(m_key_server, KP_IV, _key_block, 0))
            throw win_runtime_error(__FUNCTION__ " Error setting server_write_IV.");
        _key_block += m_state.m_size_enc_iv;
    }
}


void eap::method_tls::derive_msk()
{
    static const unsigned char s_label[] = "client EAP encryption";
    sanitizing_blob seed(s_label, s_label + _countof(s_label) - 1);
    seed.insert(seed.end(), (const unsigned char*)&m_state.m_random_client, (const unsigned char*)(&m_state.m_random_client + 1));
    seed.insert(seed.end(), (const unsigned char*)&m_state.m_random_server, (const unsigned char*)(&m_state.m_random_server + 1));
    sanitizing_blob key_block(prf(m_state.m_master_secret, seed, 2*sizeof(tls_random)));
    const unsigned char *_key_block = key_block.data();

    // MS-MPPE-Recv-Key
    memcpy(&m_key_mppe_client, _key_block, sizeof(tls_random));
    _key_block += sizeof(tls_random);

    // MS-MPPE-Send-Key
    memcpy(&m_key_mppe_server, _key_block, sizeof(tls_random));
    _key_block += sizeof(tls_random);
}


void eap::method_tls::process_packet(_In_bytecount_(size_pck) const void *_pck, _In_ size_t size_pck)
{
    sanitizing_blob data;

    for (const unsigned char *pck = (const unsigned char*)_pck, *pck_end = pck + size_pck; pck < pck_end; ) {
        if (pck + 5 > pck_end)
            throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete message header.");
        const message_header *hdr = (const message_header*)pck;
        const unsigned char
            *msg     = (const unsigned char*)(hdr + 1),
            *msg_end = msg + ntohs(*(unsigned short*)hdr->length);
        if (msg_end > pck_end)
            throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete message data.");

        if (hdr->version == m_tls_version) {
            // Process TLS 1.0 message.
            switch (hdr->type) {
            case tls_message_type_change_cipher_spec:
                process_change_cipher_spec(msg, msg_end - msg);
                break;

            case tls_message_type_alert:
                if (m_cipher_spec) {
                    sanitizing_blob msg_dec(msg, msg_end);
                    decrypt_message(hdr, msg_dec);
                    process_alert(msg_dec.data(), msg_dec.size());
                } else
                    process_alert(msg, msg_end - msg);
                break;

            case tls_message_type_handshake:
                if (m_cipher_spec) {
                    sanitizing_blob msg_dec(msg, msg_end);
                    decrypt_message(hdr, msg_dec);
                    process_handshake(msg_dec.data(), msg_dec.size());
                } else
                    process_handshake(msg, msg_end - msg);
                break;

            case tls_message_type_application_data: {
                if (!m_cipher_spec)
                    throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Application data should be encrypted.");

                sanitizing_blob msg_dec(msg, msg_end);
                decrypt_message(hdr, msg_dec);
                process_application_data(msg_dec.data(), msg_dec.size());
                break;
            }

            //default:
            //    if (m_cipher_spec) {
            //        sanitizing_blob msg_dec(msg, msg_end);
            //        decrypt_message(hdr, msg_dec);
            //        process_vendor_data(hdr->type, msg_dec.data(), msg_dec.size());
            //    } else
            //        process_vendor_data(hdr->type, msg, msg_end - msg);
            }
        }

        pck = msg_end;
    }
}


void eap::method_tls::process_change_cipher_spec(_In_bytecount_(msg_size) const void *_msg, _In_ size_t msg_size)
{
    if (msg_size < 1)
        throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete change cipher spec.");

    const unsigned char *msg = (const unsigned char*)_msg;
    if (msg[0] != 1)
        throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, string_printf(__FUNCTION__ " Invalid change cipher spec message (expected 1, received %u).", msg[0]));

    m_module.log_event(&EAPMETHOD_TLS_CHANGE_CIPHER_SPEC, event_data((unsigned int)eap_type_tls), event_data::blank);

    if (!m_cipher_spec) {
        // Resuming previous session.
        derive_keys();
        m_cipher_spec = true;
    }
}


void eap::method_tls::process_alert(_In_bytecount_(msg_size) const void *_msg, _In_ size_t msg_size)
{
    if (msg_size < 2)
        throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete alert.");

    const unsigned char *msg = (const unsigned char*)_msg;

    m_module.log_event(&EAPMETHOD_TLS_ALERT, event_data((unsigned int)eap_type_tls), event_data((unsigned char)msg[0]), event_data((unsigned char)msg[1]), event_data::blank);

    //if (msg[0] == alert_level_fatal) {
    //    // Clear session ID to avoid reconnection attempts.
    //    m_session_id.clear();
    //}
}


void eap::method_tls::process_handshake(_In_bytecount_(msg_size) const void *_msg, _In_ size_t msg_size)
{
    for (const unsigned char *msg = (const unsigned char*)_msg, *msg_end = msg + msg_size; msg < msg_end; ) {
        // Parse record header.
        if (msg + sizeof(unsigned int) > msg_end)
            throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete record header.");
        unsigned int hdr = ntohl(*(unsigned int*)msg);
        const unsigned char
            *rec     = msg + sizeof(unsigned int),
            *rec_end = rec + (hdr & 0xffffff);
        if (rec_end > msg_end)
            throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete record data.");

        // Process record.
        unsigned char type = hdr >> 24;
        switch (type) {
            case tls_handshake_type_server_hello:
                // TLS version
                if (rec + 2 > rec_end)
                    throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Server SSL/TLS version missing or incomplete.");
                else if (rec[0] != m_tls_version.major || rec[1] != m_tls_version.minor)
                    throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Unsupported SSL/TLS version.");
                m_state.m_alg_prf = CALG_TLS1PRF;
                rec += 2;

                // Server random
                if (rec + sizeof(m_state.m_random_server) > rec_end)
                    throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Server random missing or incomplete.");
                memcpy(&m_state.m_random_server, rec, sizeof(tls_random));
                rec += sizeof(tls_random);

                // Session ID
                if (rec + 1 > rec_end || rec + 1 + rec[0] > rec_end)
                    throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Session ID missing or incomplete.");
                assert(rec[0] <= 32); // According to RFC 5246 session IDs should not be longer than 32B.
                m_session_id.assign(rec + 1, rec + 1 + rec[0]);
                rec += rec[0] + 1;

                // Cipher
                if (rec + 2 > rec_end)
                    throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Cipher or incomplete.");
                if (rec[0] == 0x00 || rec[1] == 0x0a) {
                    // TLS_RSA_WITH_3DES_EDE_CBC_SHA
                    m_state.m_alg_encrypt    = CALG_3DES;
                    m_state.m_size_enc_key   = 192/8; // 3DES 192bits
                    m_state.m_size_enc_iv    = 64/8;  // 3DES 64bits
                    m_state.m_size_enc_block = 64/8;  // 3DES 64bits
                    m_state.m_alg_mac        = CALG_SHA1;
                    m_state.m_size_mac_key   = 160/8; // SHA-1
                    m_state.m_size_mac_hash  = 160/8; // SHA-1
                } else
                    throw win_runtime_error(ERROR_NOT_SUPPORTED, string_printf(__FUNCTION__ " Other than requested cipher selected (received 0x%02x%02x).", rec[0], rec[1]));

                m_module.log_event(&EAPMETHOD_TLS_SERVER_HELLO, event_data((unsigned int)eap_type_tls), event_data((unsigned int)m_session_id.size()), event_data(m_session_id.data(), (ULONG)m_session_id.size()), event_data::blank);
                break;

            case tls_handshake_type_certificate: {
                // Certificate list size
                if (rec + 3 > rec_end)
                    throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Certificate list size missing or incomplete.");
                const unsigned char
                    *list     = rec  + 3,
                    *list_end = list + ((rec[0] << 16) | (rec[1] << 8) | rec[2]);
                if (list_end > rec_end)
                    throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Certificate list missing or incomplete.");

                m_server_cert_chain.clear();
                while (list < list_end) {
                    // Certificate size
                    if (list + 3 > list_end)
                        throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Certificate size missing or incomplete.");
                    const unsigned char
                        *cert     = list + 3,
                        *cert_end = cert + ((list[0] << 16) | (list[1] << 8) | list[2]);
                    if (cert_end > list_end)
                        throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Certificate rec missing or incomplete.");

                    // Certificate
                    cert_context c;
                    if (!c.create(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cert, (DWORD)(cert_end - cert)))
                        throw win_runtime_error(__FUNCTION__ " Error reading certificate.");
                    m_server_cert_chain.push_back(std::move(c));

                    list = cert_end;
                }

                wstring cert_name(!m_server_cert_chain.empty() ? get_cert_title(m_server_cert_chain.front()) : L"<blank>");
                m_module.log_event(&EAPMETHOD_TLS_CERTIFICATE, event_data((unsigned int)eap_type_tls), event_data(cert_name), event_data::blank);
                break;
            }

            case tls_handshake_type_certificate_request:
                m_certificate_req = true;
                m_module.log_event(&EAPMETHOD_TLS_CERTIFICATE_REQUEST, event_data((unsigned int)eap_type_tls), event_data::blank);
                break;

            case tls_handshake_type_server_hello_done:
                m_server_hello_done = true;
                m_module.log_event(&EAPMETHOD_TLS_SERVER_HELLO_DONE, event_data((unsigned int)eap_type_tls), event_data::blank);
                break;

            case tls_handshake_type_finished: {
                if (!m_cipher_spec)
                    throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Finished message should be encrypted.");

                // According to https://tools.ietf.org/html/rfc5246#section-7.4.9 all verify_data is 12B.
                if (rec_end - rec != 12)
                    throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, string_printf(__FUNCTION__ " Finished record size incorrect (expected 12B, received %uB).", rec_end - rec));

                // Create label + hash MD5 + hash SHA-1 seed.
                crypt_hash hash;
                static const unsigned char s_label[] = "server finished";
                sanitizing_blob seed(s_label, s_label + _countof(s_label) - 1), hash_data;
                hash = m_hash_handshake_msgs_md5; // duplicate
                if (!CryptGetHashParam(hash, HP_HASHVAL, hash_data, 0))
                    throw win_runtime_error(__FUNCTION__ " Error finishing MD5 hash calculation.");
                seed.insert(seed.end(), hash_data.begin(), hash_data.end());
                hash = m_hash_handshake_msgs_sha1; // duplicate
                if (!CryptGetHashParam(hash, HP_HASHVAL, hash_data, 0))
                    throw win_runtime_error(__FUNCTION__ " Error finishing SHA-1 hash calculation.");
                seed.insert(seed.end(), hash_data.begin(), hash_data.end());

                if (memcmp(prf(m_state.m_master_secret, seed, 12).data(), rec, 12))
                    throw win_runtime_error(ERROR_ENCRYPTION_FAILED, __FUNCTION__ " Integrity check failed.");

                m_server_finished = true;
                m_module.log_event(&EAPMETHOD_TLS_FINISHED, event_data((unsigned int)eap_type_tls), event_data::blank);
                break;
            }

            default:
                m_module.log_event(&EAPMETHOD_TLS_HANDSHAKE_IGNORE, event_data((unsigned int)eap_type_tls), event_data(type), event_data::blank);
        }

        msg = rec_end;
    }

    hash_handshake(_msg, msg_size);
}


void eap::method_tls::process_application_data(_In_bytecount_(msg_size) const void *msg, _In_ size_t msg_size)
{
    UNREFERENCED_PARAMETER(msg);
    UNREFERENCED_PARAMETER(msg_size);

    // TODO: Parse application data (Diameter AVP)
}


//void eap::method_tls::process_vendor_data(_In_ unsigned char type, _In_bytecount_(msg_size) const void *msg, _In_ size_t msg_size)
//{
//    UNREFERENCED_PARAMETER(type);
//    UNREFERENCED_PARAMETER(msg);
//    UNREFERENCED_PARAMETER(msg_size);
//}


void eap::method_tls::verify_server_trust() const
{
    assert(!m_server_cert_chain.empty());
    const cert_context &cert = m_server_cert_chain.front();

    const config_provider &cfg_prov(m_cfg.m_providers.front());
    const config_method_tls *cfg_method = dynamic_cast<const config_method_tls*>(cfg_prov.m_methods.front().get());
    assert(cfg_method);

    if (!cfg_method->m_server_names.empty()) {
        // Check server name.

        string subj;
        if (!CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, subj))
            throw win_runtime_error(__FUNCTION__ " Error retrieving server's certificate subject name.");

        for (list<string>::const_iterator s = cfg_method->m_server_names.cbegin(), s_end = cfg_method->m_server_names.cend();; ++s) {
            if (s != s_end) {
                const char
                    *a = s->c_str(),
                    *b = subj.c_str();
                size_t
                    len_a = s->length(),
                    len_b = subj.length();

                if (_stricmp(a, b) == 0 || // Direct match
                    a[0] == '*' && len_b + 1 >= len_a && _stricmp(a + 1, b + len_b - (len_a - 1)) == 0) // "*..." wildchar match
                {
                    m_module.log_event(&EAPMETHOD_TLS_SERVER_NAME_TRUSTED, event_data(subj), event_data::blank);
                    break;
                }
            } else
                throw win_runtime_error(ERROR_INVALID_DOMAINNAME, string_printf(__FUNCTION__ " Server name %s is not on the list of trusted server names.", subj.c_str()).c_str());
        }
    }

    // Create temporary certificate store of our trusted root CAs.
    cert_store store;
    if (!store.create(CERT_STORE_PROV_MEMORY, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, NULL, 0, NULL))
        throw win_runtime_error(ERROR_INVALID_DOMAINNAME, __FUNCTION__ " Error creating temporary certificate store.");
    for (list<cert_context>::const_iterator c = cfg_method->m_trusted_root_ca.cbegin(), c_end = cfg_method->m_trusted_root_ca.cend(); c != c_end; ++c)
        CertAddCertificateContextToStore(store, *c, CERT_STORE_ADD_REPLACE_EXISTING, NULL);

    // Add all certificates from the server's certificate chain, except the first one.
    for (list<cert_context>::const_iterator c = m_server_cert_chain.cbegin(), c_end = m_server_cert_chain.cend(); ++c != c_end;)
        CertAddCertificateContextToStore(store, *c, CERT_STORE_ADD_REPLACE_EXISTING, NULL);

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
    if (!context.create(NULL, cert, NULL, store, &chain_params, 0))
        throw win_runtime_error(ERROR_INVALID_DOMAINNAME, __FUNCTION__ " Error creating certificate chain context.");

    // Check chain validation error flags. Ignore CERT_TRUST_IS_UNTRUSTED_ROOT flag when we check root CA explicitly.
    if (context->TrustStatus.dwErrorStatus != CERT_TRUST_NO_ERROR &&
        (cfg_method->m_trusted_root_ca.empty() || (context->TrustStatus.dwErrorStatus & ~CERT_TRUST_IS_UNTRUSTED_ROOT) != CERT_TRUST_NO_ERROR))
        throw win_runtime_error(context->TrustStatus.dwErrorStatus, "Error validating certificate chain.");

    if (!cfg_method->m_trusted_root_ca.empty()) {
        // Verify Root CA against our trusted root CA list
        if (context->cChain != 1)
            throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Multiple chain verification not supported.");
        if (context->rgpChain[0]->cElement == 0)
            throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Can not verify empty certificate chain.");

        PCCERT_CONTEXT cert_root = context->rgpChain[0]->rgpElement[context->rgpChain[0]->cElement-1]->pCertContext;
        for (list<cert_context>::const_iterator c = cfg_method->m_trusted_root_ca.cbegin(), c_end = cfg_method->m_trusted_root_ca.cend();; ++c) {
            if (c != c_end) {
                if (cert_root->cbCertEncoded == (*c)->cbCertEncoded &&
                    memcmp(cert_root->pbCertEncoded, (*c)->pbCertEncoded, cert_root->cbCertEncoded) == 0)
                {
                    // Trusted root CA found.
                    break;
                }
            } else {
                // Not found.
                throw win_runtime_error(ERROR_FILE_NOT_FOUND, __FUNCTION__ " Server's certificate not issued by one of configured trusted root CAs.");
            }
        }
    }

    m_module.log_event(&EAPMETHOD_TLS_SERVER_CERT_TRUSTED, event_data::blank);
}


void eap::method_tls::encrypt_message(_In_ const message_header *hdr, _Inout_ sanitizing_blob &data)
{
    // Hash sequence number, TLS header, and message.
    size_t size_data = data.size();
    assert(size_data == ntohs(*(unsigned short*)hdr->length));
    hash_hmac hash(m_cp, m_state.m_alg_mac, m_padding_hmac_client.data());
    unsigned __int64 seq_num = htonll(m_seq_num_client);
    if (!CryptHashData(hash, (const BYTE*)&seq_num   , sizeof(seq_num       ), 0) ||
        !CryptHashData(hash, (const BYTE*)hdr        , sizeof(message_header), 0) ||
        !CryptHashData(hash,              data.data(), (DWORD)size_data      , 0))
        throw win_runtime_error(__FUNCTION__ " Error hashing data.");
    sanitizing_blob hmac;
    hash.calculate(hmac);

    size_t size_data_enc =
        size_data  + // TLS message
        hmac.size(); // HMAC hash

    if (m_state.m_size_enc_block) {
        // Block cypher

        // Calculate padding.
        size_data_enc += 1; // Padding length
        unsigned char size_padding = (unsigned char)((m_state.m_size_enc_block - size_data_enc) % m_state.m_size_enc_block);
        size_data_enc += size_padding;

        // Append HMAC hash and padding.
        data.reserve(size_data_enc);
        data.insert(data.end(), hmac.begin(), hmac.end());
        data.insert(data.end(), size_padding + 1, size_padding);
    } else {
        // Stream cipher

        // Append HMAC hash.
        data.reserve(size_data_enc);
        data.insert(data.end(), hmac.begin(), hmac.end());
    }

    // Encrypt.
    assert(size_data_enc < 0xffffffff);
    DWORD size_data_enc2 = (DWORD)size_data_enc;
    if (!CryptEncrypt(m_key_client, NULL, FALSE, 0, data.data(), &size_data_enc2, (DWORD)size_data_enc))
        throw win_runtime_error(__FUNCTION__ " Error encrypting message.");

    // Increment sequence number.
    m_seq_num_client++;
}


void eap::method_tls::decrypt_message(_In_ const message_header *hdr, _Inout_ sanitizing_blob &data)
{
    // Decrypt.
    if (!CryptDecrypt(m_key_server, NULL, FALSE, 0, data))
        throw win_runtime_error(__FUNCTION__ " Error decrypting message.");

    size_t size = data.size();
    if (size) {
        size_t size_data = size;

        if (m_state.m_size_enc_block) {
            // Check padding.
            unsigned char padding = data.back();
            size_data -= padding + 1;
            for (size_t i = size_data, i_end = size - 1; i < i_end; i++)
                if (data[i] != padding)
                    throw invalid_argument(__FUNCTION__ " Incorrect message padding.");
        }

        size_data -= m_state.m_size_mac_hash;

        // Hash sequence number, TLS header (without length), original message length, and message.
        hash_hmac hash(m_cp, m_state.m_alg_mac, m_padding_hmac_server.data());
        unsigned __int64 seq_num = htonll(m_seq_num_server);
        unsigned short size_data2 = htons((unsigned short)size_data);
        if (!CryptHashData(hash, (const BYTE*)&seq_num   ,  sizeof(seq_num), 0) ||
            !CryptHashData(hash, (const BYTE*)hdr        ,                3, 0) ||
            !CryptHashData(hash, (const BYTE*)&size_data2,                2, 0) ||
            !CryptHashData(hash,              data.data(), (DWORD)size_data, 0))
            throw win_runtime_error(__FUNCTION__ " Error hashing data.");
        sanitizing_blob hmac;
        hash.calculate(hmac);

        // Verify hash.
        if (memcmp(&*(data.begin() + size_data), hmac.data(), m_state.m_size_mac_hash) != 0)
            throw win_runtime_error(ERROR_DECRYPTION_FAILED, __FUNCTION__ " Integrity check failed.");

        // Strip hash and padding.
        data.resize(size_data);

        // Increment sequence number.
        m_seq_num_server++;
    }
}


eap::sanitizing_blob eap::method_tls::prf(
    _In_                      const tls_master_secret &secret,
    _In_bytecount_(size_seed) const void              *seed,
    _In_                            size_t            size_seed,
    _In_                            size_t            size) const
{
    sanitizing_blob data;
    data.reserve(size);

    if (m_state.m_alg_prf == CALG_TLS1PRF) {
        // Split secret in two halves.
        size_t
            size_S1 = (sizeof(tls_master_secret) + 1) / 2,
            size_S2 = size_S1;
        const void
            *S1 = &secret,
            *S2 = (const unsigned char*)&secret + (sizeof(tls_master_secret) - size_S2);

        // Precalculate HMAC padding for speed.
        sanitizing_blob
            hmac_padding1(sizeof(hash_hmac::padding_t)),
            hmac_padding2(sizeof(hash_hmac::padding_t));
        hash_hmac::inner_padding(m_cp, CALG_MD5 , S1, size_S1, hmac_padding1.data());
        hash_hmac::inner_padding(m_cp, CALG_SHA1, S2, size_S2, hmac_padding2.data());

        // Prepare A for p_hash.
        sanitizing_blob
            A1((unsigned char*)seed, (unsigned char*)seed + size_seed),
            A2((unsigned char*)seed, (unsigned char*)seed + size_seed);

        sanitizing_blob
            hmac1,
            hmac2;
        data.resize(size);
        for (size_t i = 0, off1 = 0, off2 = 0; i < size; ) {
            if (off1 >= hmac1.size()) {
                // Rehash A.
                hash_hmac hash1(m_cp, CALG_MD5 , hmac_padding1.data());
                if (!CryptHashData(hash1, A1.data(), (DWORD)A1.size(), 0))
                    throw win_runtime_error(__FUNCTION__ " Error hashing A1.");
                hash1.calculate(A1);

                // Hash A and seed.
                hash_hmac hash2(m_cp, CALG_MD5 , hmac_padding1.data());
                if (!CryptHashData(hash2,              A1.data(), (DWORD)A1.size(), 0) ||
                    !CryptHashData(hash2, (const BYTE*)seed     , (DWORD)size_seed, 0))
                    throw win_runtime_error(__FUNCTION__ " Error hashing seed,label or data.");
                hash2.calculate(hmac1);
                off1 = 0;
            }

            if (off2 >= hmac2.size()) {
                // Rehash A.
                hash_hmac hash1(m_cp, CALG_SHA1 , hmac_padding2.data());
                if (!CryptHashData(hash1, A2.data(), (DWORD)A2.size(), 0))
                    throw win_runtime_error(__FUNCTION__ " Error hashing A2.");
                hash1.calculate(A2);

                // Hash A and seed.
                hash_hmac hash2(m_cp, CALG_SHA1 , hmac_padding2.data());
                if (!CryptHashData(hash2,              A2.data(), (DWORD)A2.size(), 0) ||
                    !CryptHashData(hash2, (const BYTE*)seed     , (DWORD)size_seed, 0))
                    throw win_runtime_error(__FUNCTION__ " Error hashing seed,label or data.");
                hash2.calculate(hmac2);
                off2 = 0;
            }

            // XOR combine amount of data we have (and need).
            size_t i_end = std::min<size_t>(i + std::min<size_t>(hmac1.size() - off1, hmac2.size() - off2), size);
            while (i < i_end)
                data[i++] = hmac1[off1++] ^ hmac2[off2++];
        }
    } else {
        // Precalculate HMAC padding for speed.
        sanitizing_blob hmac_padding(sizeof(hash_hmac::padding_t));
        hash_hmac::inner_padding(m_cp, m_state.m_alg_prf, &secret, sizeof(tls_master_secret), hmac_padding.data());

        // Prepare A for p_hash.
        sanitizing_blob A((unsigned char*)seed, (unsigned char*)seed + size_seed);

        sanitizing_blob hmac;
        for (size_t i = 0; i < size; ) {
            // Rehash A.
            hash_hmac hash1(m_cp, m_state.m_alg_prf, hmac_padding.data());
            if (!CryptHashData(hash1, A.data(), (DWORD)A.size(), 0))
                throw win_runtime_error(__FUNCTION__ " Error hashing A.");
            hash1.calculate(A);

            // Hash A and seed.
            hash_hmac hash2(m_cp, m_state.m_alg_prf, hmac_padding.data());
            if (!CryptHashData(hash2,              A.data(), (DWORD)A.size() , 0) ||
                !CryptHashData(hash2, (const BYTE*)seed    , (DWORD)size_seed, 0))
                throw win_runtime_error(__FUNCTION__ " Error hashing seed,label or data.");
            hash2.calculate(hmac);

            size_t n = std::min<size_t>(hmac.size(), size - i);
            data.insert(data.end(), hmac.begin(), hmac.begin() + n);
            i += n;
        }
    }

    return data;
}


HCRYPTKEY eap::method_tls::create_key(
    _In_                              ALG_ID    alg,
    _In_                              HCRYPTKEY key,
    _In_bytecount_(size_secret) const void      *secret,
    _In_                              size_t    size_secret)
{
    if (size_secret > m_state.m_size_enc_key)
        throw invalid_argument(__FUNCTION__ " Secret too big to fit the key.");

    // Get private key's algorithm.
    ALG_ID alg_key;
    if (!CryptGetKeyParam(key, KP_ALGID, alg_key, 0))
        throw win_runtime_error(__FUNCTION__ " Error getting key's algorithm.'");

    // Get private key's length in bytes.
    DWORD size_key = CryptGetKeyParam(key, KP_KEYLEN, size_key, 0) ? size_key/8 : 0;

    // SIMPLEBLOB Format is documented in SDK
    // Copy header to buffer
#pragma pack(push)
#pragma pack(1)
    struct key_blob_prefix {
        PUBLICKEYSTRUC header;
        ALG_ID alg;
    } const prefix = {
        {
            SIMPLEBLOB,
            CUR_BLOB_VERSION,
            0,
            alg,
        },
        alg_key,
    };
#pragma pack(pop)
    sanitizing_blob key_blob;
    key_blob.reserve(sizeof(key_blob_prefix) + size_key);
    key_blob.assign((const unsigned char*)&prefix, (const unsigned char*)(&prefix + 1));

    // Key in EME-PKCS1-v1_5 (RFC 3447).
    key_blob.push_back(0); // Initial zero
    key_blob.push_back(2); // PKCS #1 block type = 2

    // PS
    size_t size_ps = size_key - size_secret - 3;
    assert(size_ps >= 8);
#if 1
    key_blob.insert(key_blob.end(), size_ps, 1);
#else
    // Is random PS required at all? We are importing a clear-text session key with the exponent-of-one key. How low on security can we get?
    key_blob.insert(key_blob.end(), size_ps, 0);
    unsigned char *ps = &*(key_blob.end() - size_ps);
    CryptGenRandom(m_cp, (DWORD)size_ps, ps);
    for (size_t i = 0; i < size_ps; i++)
        if (ps[i] == 0) ps[i] = 1;
#endif

    key_blob.push_back(0); // PS and M zero delimiter

    // M
    key_blob.insert(key_blob.end(), (const unsigned char*)secret, (const unsigned char*)secret + size_secret);

#ifdef _HOST_LOW_ENDIAN
    std::reverse(key_blob.end() - size_key, key_blob.end());
#endif

    // Import the key.
    winstd::crypt_key key_out;
    if (!key_out.import(m_cp, key_blob.data(), (DWORD)key_blob.size(), key, 0))
        throw winstd::win_runtime_error(__FUNCTION__ " Error importing key.");
    return key_out.detach();
}
