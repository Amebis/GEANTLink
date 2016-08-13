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

eap::method_tls::method_tls(_In_ module &module, _In_ config_method_tls &cfg, _In_ credentials_tls &cred) :
    m_cfg(cfg),
    m_cred(cred),
    m_phase(phase_unknown),
    m_send_client_cert(false),
    m_server_hello_done(false),
    m_server_finished(false),
    m_cipher_spec(false),
    m_seq_num(0),
    m_blob_cfg(NULL),
    method(module, cfg, cred)
{
}


eap::method_tls::method_tls(_In_ const method_tls &other) :
    m_cfg(other.m_cfg),
    m_cred(other.m_cred),
    m_phase(other.m_phase),
    m_packet_req(other.m_packet_req),
    m_packet_res(other.m_packet_res),
    m_state(other.m_state),
    m_padding_hmac_client(other.m_padding_hmac_client),
    //m_padding_hmac_server(other.m_padding_hmac_server),
    m_key_client(other.m_key_client),
    m_key_server(other.m_key_server),
    m_key_mppe_send(other.m_key_mppe_send),
    m_key_mppe_recv(other.m_key_mppe_recv),
    m_session_id(other.m_session_id),
    m_server_cert_chain(other.m_server_cert_chain),
    m_hash_handshake_msgs_md5(other.m_hash_handshake_msgs_md5),
    m_hash_handshake_msgs_sha1(other.m_hash_handshake_msgs_sha1),
    m_send_client_cert(other.m_send_client_cert),
    m_server_hello_done(other.m_server_hello_done),
    m_server_finished(other.m_server_finished),
    m_cipher_spec(other.m_cipher_spec),
    m_seq_num(other.m_seq_num),
    method(other)
{
}


eap::method_tls::method_tls(_Inout_ method_tls &&other) :
    m_cfg(other.m_cfg),
    m_cred(other.m_cred),
    m_phase(std::move(other.m_phase)),
    m_packet_req(std::move(other.m_packet_req)),
    m_packet_res(std::move(other.m_packet_res)),
    m_state(std::move(other.m_state)),
    m_padding_hmac_client(std::move(other.m_padding_hmac_client)),
    //m_padding_hmac_server(std::move(other.m_padding_hmac_server)),
    m_key_client(std::move(other.m_key_client)),
    m_key_server(std::move(other.m_key_server)),
    m_key_mppe_send(std::move(other.m_key_mppe_send)),
    m_key_mppe_recv(std::move(other.m_key_mppe_recv)),
    m_session_id(std::move(other.m_session_id)),
    m_server_cert_chain(std::move(other.m_server_cert_chain)),
    m_hash_handshake_msgs_md5(std::move(other.m_hash_handshake_msgs_md5)),
    m_hash_handshake_msgs_sha1(std::move(other.m_hash_handshake_msgs_sha1)),
    m_send_client_cert(std::move(other.m_send_client_cert)),
    m_server_hello_done(std::move(other.m_server_hello_done)),
    m_server_finished(std::move(other.m_server_finished)),
    m_cipher_spec(std::move(other.m_cipher_spec)),
    m_seq_num(std::move(other.m_seq_num)),
    method(std::move(other))
{
}


eap::method_tls::~method_tls()
{
    if (m_blob_cfg)
        m_module.free_memory(m_blob_cfg);
}


eap::method_tls& eap::method_tls::operator=(_In_ const method_tls &other)
{
    if (this != std::addressof(other)) {
        assert(std::addressof(m_cfg ) == std::addressof(other.m_cfg )); // Copy method with same configuration only!
        assert(std::addressof(m_cred) == std::addressof(other.m_cred)); // Copy method with same credentials only!
        (method&)*this              = other;
        m_phase                     = other.m_phase;
        m_packet_req                = other.m_packet_req;
        m_packet_res                = other.m_packet_res;
        m_state                     = other.m_state;
        m_padding_hmac_client       = other.m_padding_hmac_client;
        //m_padding_hmac_server       = other.m_padding_hmac_server;
        m_key_client                = other.m_key_client;
        m_key_server                = other.m_key_server;
        m_key_mppe_send             = other.m_key_mppe_send;
        m_key_mppe_recv             = other.m_key_mppe_recv;
        m_session_id                = other.m_session_id;
        m_server_cert_chain         = other.m_server_cert_chain;
        m_hash_handshake_msgs_md5   = other.m_hash_handshake_msgs_md5;
        m_hash_handshake_msgs_sha1  = other.m_hash_handshake_msgs_sha1;
        m_send_client_cert          = other.m_send_client_cert;
        m_server_hello_done         = other.m_server_hello_done;
        m_server_finished           = other.m_server_finished;
        m_cipher_spec               = other.m_cipher_spec;
        m_seq_num                   = other.m_seq_num;
    }

    return *this;
}


eap::method_tls& eap::method_tls::operator=(_Inout_ method_tls &&other)
{
    if (this != std::addressof(other)) {
        assert(std::addressof(m_cfg ) == std::addressof(other.m_cfg )); // Move method with same configuration only!
        assert(std::addressof(m_cred) == std::addressof(other.m_cred)); // Move method with same credentials only!
        (method&)*this              = std::move(other);
        m_phase                     = std::move(other.m_phase);
        m_packet_req                = std::move(other.m_packet_req);
        m_packet_res                = std::move(other.m_packet_res);
        m_state                     = std::move(other.m_state);
        m_padding_hmac_client       = std::move(other.m_padding_hmac_client);
        //m_padding_hmac_server       = std::move(other.m_padding_hmac_server);
        m_key_client                = std::move(other.m_key_client);
        m_key_server                = std::move(other.m_key_server);
        m_key_mppe_send             = std::move(other.m_key_mppe_send);
        m_key_mppe_recv             = std::move(other.m_key_mppe_recv);
        m_session_id                = std::move(other.m_session_id);
        m_server_cert_chain         = std::move(other.m_server_cert_chain);
        m_hash_handshake_msgs_md5   = std::move(other.m_hash_handshake_msgs_md5);
        m_hash_handshake_msgs_sha1  = std::move(other.m_hash_handshake_msgs_sha1);
        m_send_client_cert          = std::move(other.m_send_client_cert);
        m_server_hello_done         = std::move(other.m_server_hello_done);
        m_server_finished           = std::move(other.m_server_finished);
        m_cipher_spec               = std::move(other.m_cipher_spec);
        m_seq_num                   = std::move(other.m_seq_num);
    }

    return *this;
}


void eap::method_tls::begin_session(
    _In_        DWORD         dwFlags,
    _In_  const EapAttributes *pAttributeArray,
    _In_        HANDLE        hTokenImpersonateUser,
    _In_        DWORD         dwMaxSendPacketSize)
{
    eap::method::begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, dwMaxSendPacketSize);

    // Create cryptographics provider.
    if (!m_cp.create(NULL, MS_ENHANCED_PROV, PROV_RSA_FULL))
        throw win_runtime_error(__FUNCTION__ " Error creating cryptographics provider.");

    m_session_id = m_cfg.m_session_id;
    m_state.m_master_secret = m_cfg.m_master_secret;
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

    if (pReceivedPacket->Code == EapCodeRequest && m_packet_req.m_flags & flags_req_start) {
        // This is the TLS start message: initialize method.
        m_module.log_event(&EAPMETHOD_TLS_HANDSHAKE_START2, event_data((unsigned int)eap_type_tls), event_data::blank);

        m_phase = phase_res_client_hello;
        m_packet_res.clear();

        m_state.m_random_client.reset(m_cp);

        // Generate client randomness.
        m_padding_hmac_client.clear();
        //m_padding_hmac_server.clear();
        m_key_client.free();
        m_key_server.free();
        m_key_mppe_send.clear();
        m_key_mppe_recv.clear();

        m_server_cert_chain.clear();

        // Create MD5 hash object.
        if (!m_hash_handshake_msgs_md5.create(m_cp, CALG_MD5))
            throw win_runtime_error(__FUNCTION__ " Error creating MD5 hashing object.");

        // Create SHA-1 hash object.
        if (!m_hash_handshake_msgs_sha1.create(m_cp, CALG_SHA1))
            throw win_runtime_error(__FUNCTION__ " Error creating SHA-1 hashing object.");

        m_send_client_cert = false;
        m_server_hello_done = false;
        m_server_finished = false;
        m_cipher_spec = false;
        m_seq_num = 0;
    }

    switch (m_phase) {
        case phase_res_client_hello: {
            // Build response packet.
            m_packet_res.m_code  = EapCodeResponse;
            m_packet_res.m_id    = m_packet_req.m_id;
            m_packet_res.m_flags = 0;
            sanitizing_blob hello(make_client_hello());
            sanitizing_blob handshake(make_message(tls_message_type_handshake, hello, m_cipher_spec));
            m_packet_res.m_data.assign(handshake.begin(), handshake.end());
            CryptHashData(m_hash_handshake_msgs_md5 , hello.data(), (DWORD)hello.size(), 0);
            CryptHashData(m_hash_handshake_msgs_sha1, hello.data(), (DWORD)hello.size(), 0);

            m_phase = phase_req_server_hello;

            pEapOutput->fAllowNotifications = FALSE;
            pEapOutput->action = EapPeerMethodResponseActionSend;
            break;
        }

        case phase_req_server_hello: {
            process_packet(m_packet_req.m_data.data(), m_packet_req.m_data.size());

            if (!m_server_hello_done) {
                // Reply with ACK packet and wait for the next packet.
                m_packet_res.m_code  = EapCodeResponse;
                m_packet_res.m_id    = pReceivedPacket->Id;
                m_packet_res.m_flags = 0;
                m_packet_res.m_data.clear();
                pEapOutput->fAllowNotifications = FALSE;
                pEapOutput->action = EapPeerMethodResponseActionSend;
                break;
            }

            // Do we trust this server?
            if (m_server_cert_chain.empty())
                throw win_runtime_error(ERROR_ENCRYPTION_FAILED, __FUNCTION__ " Can not continue without server's certificate.");
            verify_server_trust();

            // Build response packet.
            m_packet_res.m_code  = EapCodeResponse;
            m_packet_res.m_id    = m_packet_req.m_id;
            m_packet_res.m_flags = 0;
            m_packet_res.m_data.clear();

            if (!m_server_finished || !m_cipher_spec) {
                // New session.

                if (m_send_client_cert) {
                    // Client certificate requested.
                    sanitizing_blob client_cert(make_client_cert());
                    sanitizing_blob handshake(make_message(tls_message_type_handshake, client_cert, m_cipher_spec));
                    m_packet_res.m_data.insert(m_packet_res.m_data.end(), handshake.begin(), handshake.end());
                    CryptHashData(m_hash_handshake_msgs_md5 , client_cert.data(), (DWORD)client_cert.size(), 0);
                    CryptHashData(m_hash_handshake_msgs_sha1, client_cert.data(), (DWORD)client_cert.size(), 0);
                }

                // Generate pre-master secret. PMS will get sanitized in its destructor when going out-of-scope.
                tls_master_secret pms(m_cp);

                // Derive master secret.
                static const unsigned char s_label[] = "master secret";
                sanitizing_blob seed(s_label, s_label + _countof(s_label) - 1);
                seed.insert(seed.end(), (const unsigned char*)&m_state.m_random_client, (const unsigned char*)(&m_state.m_random_client + 1));
                seed.insert(seed.end(), (const unsigned char*)&m_state.m_random_server, (const unsigned char*)(&m_state.m_random_server + 1));
                memcpy(&m_state.m_master_secret, prf(&pms, sizeof(pms), seed.data(), seed.size(), sizeof(tls_master_secret)).data(), sizeof(tls_master_secret));

                // Create client key exchange message, and append to packet.
                sanitizing_blob client_key_exchange(make_client_key_exchange(pms));
                sanitizing_blob handshake(make_message(tls_message_type_handshake, client_key_exchange, m_cipher_spec));
                m_packet_res.m_data.insert(m_packet_res.m_data.end(), handshake.begin(), handshake.end());
                CryptHashData(m_hash_handshake_msgs_md5 , client_key_exchange.data(), (DWORD)client_key_exchange.size(), 0);
                CryptHashData(m_hash_handshake_msgs_sha1, client_key_exchange.data(), (DWORD)client_key_exchange.size(), 0);

                if (m_send_client_cert) {
                    // TODO: Create and append certificate_verify message!
                }
            }

            // Append change cipher spec to packet.
            sanitizing_blob ccs(make_change_chiper_spec());
            m_packet_res.m_data.insert(m_packet_res.m_data.end(), ccs.begin(), ccs.end());

            if (!m_server_finished || !m_cipher_spec) {
                // Setup encryption.
                derive_keys();
                m_cipher_spec = true;
                m_phase = phase_req_change_chiper_spec;
            } else
                m_phase = phase_finished;

            // Create finished message, and append to packet.
            sanitizing_blob finished(make_finished());
            sanitizing_blob handshake(make_message(tls_message_type_handshake, finished, m_cipher_spec));
            m_packet_res.m_data.insert(m_packet_res.m_data.end(), handshake.begin(), handshake.end());
            CryptHashData(m_hash_handshake_msgs_md5 , finished.data(), (DWORD)finished.size(), 0);
            CryptHashData(m_hash_handshake_msgs_sha1, finished.data(), (DWORD)finished.size(), 0);

            pEapOutput->fAllowNotifications = FALSE;
            pEapOutput->action = EapPeerMethodResponseActionSend;
            break;
        }

        case phase_req_change_chiper_spec:
            process_packet(m_packet_req.m_data.data(), m_packet_req.m_data.size());

            if (!m_cipher_spec || !m_server_finished)
                throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Server did not finish.");

            // TLS finished. Continue to the finished state (no-break case).
            m_phase = phase_finished;

        case phase_finished:
            pEapOutput->fAllowNotifications = FALSE;
            pEapOutput->action = EapPeerMethodResponseActionNone;
            break;

        default:
            throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Not supported.");
    }

    // Request packet was processed. Clear its data since we use the absence of data to detect first of fragmented message packages.
    m_packet_req.m_data.clear();
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

    switch (reason) {
    case EapPeerMethodResultSuccess: {
        if (m_phase < phase_req_change_chiper_spec)
            throw invalid_argument(__FUNCTION__ " Premature success.");

        // Derive MSK.
        derive_msk();

        // Fill array with RADIUS attributes.
        eap_attr a;
        m_eap_attr.clear();
        a.create_ms_mppe_key(16, (LPCBYTE)&m_key_mppe_send, sizeof(tls_random));
        m_eap_attr.push_back(std::move(a));
        a.create_ms_mppe_key(17, (LPCBYTE)&m_key_mppe_recv, sizeof(tls_random));
        m_eap_attr.push_back(std::move(a));
        m_eap_attr.push_back(eap_attr::blank);

        m_eap_attr_desc.dwNumberOfAttributes = (DWORD)m_eap_attr.size();
        m_eap_attr_desc.pAttribs = m_eap_attr.data();
        ppResult->pAttribArray = &m_eap_attr_desc;

        ppResult->fIsSuccess = TRUE;

        // Update configuration with session resumption data and prepare BLOB.
        m_cfg.m_session_id    = m_session_id;
        m_cfg.m_master_secret = m_state.m_master_secret;
        ppResult->fSaveConnectionData = TRUE;

        m_phase = phase_finished;
        break;
    }

    case EapPeerMethodResultFailure:
        // :(
        m_cfg.m_session_id.clear();
        m_cfg.m_master_secret.clear();
        ppResult->fSaveConnectionData = TRUE;
        break;

    default:
        throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Not supported.");
    }

    if (ppResult->fSaveConnectionData) {
        m_module.pack(m_cfg, &ppResult->pConnectionData, &ppResult->dwSizeofConnectionData);
        if (m_blob_cfg)
            m_module.free_memory(m_blob_cfg);
        m_blob_cfg = ppResult->pConnectionData;
    }
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

    // SSL version: TLS 1.0
    msg.push_back(3); // SSL major version
    msg.push_back(1); // SSL minor version

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
    PCCERT_CONTEXT cert;
    if (m_cfg.m_use_preshared) {
        // Using pre-shared credentials.
        const credentials_tls *preshared = dynamic_cast<credentials_tls*>(m_cfg.m_preshared.get());
        cert = preshared && preshared->m_cert ? preshared->m_cert : NULL;
    } else {
        // Using own credentials.
        cert = m_cred.m_cert ? m_cred.m_cert : NULL;
    }

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
    msg.insert(msg.end(), pms_enc.begin(), pms_enc.end());

    return msg;
}


eap::sanitizing_blob eap::method_tls::make_change_chiper_spec()
{
    static const unsigned char s_msg_css[] = {
        (unsigned char)tls_message_type_change_cipher_spec, // SSL record type
        3,                                                  // SSL major version
        1,                                                  // SSL minor version
        0,                                                  // Message size (high-order byte)
        1,                                                  // Message size (low-order byte)
        1,                                                  // Message: change_cipher_spec is always "1"
    };
    return eap::sanitizing_blob(s_msg_css, s_msg_css + _countof(s_msg_css));
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
    sanitizing_blob verify(prf(&m_state.m_master_secret, sizeof(tls_master_secret), seed.data(), seed.size(), 12));
    msg.insert(msg.end(), verify.begin(), verify.end());

    return msg;
}


eap::sanitizing_blob eap::method_tls::make_message(_In_ tls_message_type_t type, _In_ const sanitizing_blob &msg)
{
    size_t size_msg = msg.size();
    eap::sanitizing_blob msg_h;
    msg_h.reserve(
        1        + // SSL record type
        2        + // SSL version
        2        + // Message size
        size_msg); // Message

    // SSL record type
    msg_h.push_back((unsigned char)type);

    // SSL version: TLS 1.0
    msg_h.push_back(3); // SSL major version
    msg_h.push_back(1); // SSL minor version

    // Message
    assert(size_msg <= 0xffff);
    unsigned short size_msg_n = htons((unsigned short)size_msg);
    msg_h.insert(msg_h.end(), (unsigned char*)&size_msg_n, (unsigned char*)(&size_msg_n + 1));
    msg_h.insert(msg_h.end(), msg.begin(), msg.end());

    return msg_h;
}


void eap::method_tls::derive_keys()
{
    sanitizing_blob seed;
    static const unsigned char s_label[] = "key expansion";
    seed.assign(s_label, s_label + _countof(s_label) - 1);
    seed.insert(seed.end(), (const unsigned char*)&m_state.m_random_server, (const unsigned char*)(&m_state.m_random_server + 1));
    seed.insert(seed.end(), (const unsigned char*)&m_state.m_random_client, (const unsigned char*)(&m_state.m_random_client + 1));

    sanitizing_blob key_block(prf(&m_state.m_master_secret, sizeof(tls_master_secret), seed.data(), seed.size(),
        2*m_state.m_size_mac_key +  // client_write_MAC_secret & server_write_MAC_secret (SHA1)
        2*m_state.m_size_enc_key +  // client_write_key        & server_write_key
        2*m_state.m_size_enc_iv )); // client_write_IV         & server_write_IV
    const unsigned char *_key_block = key_block.data();

    // client_write_MAC_secret
    m_padding_hmac_client.resize(sizeof(hash_hmac::padding_t));
    hash_hmac::inner_padding(m_cp, m_state.m_alg_mac, _key_block, m_state.m_size_mac_key, m_padding_hmac_client.data());
    _key_block += m_state.m_size_mac_key;

    // server_write_MAC_secret
    //m_padding_hmac_server.resize(sizeof(hash_hmac::padding_t));
    //hash_hmac::inner_padding(m_cp, m_state.m_alg_mac, _key_block, m_state.m_size_mac_key, m_padding_hmac_server.data());
    _key_block += m_state.m_size_mac_key;

    // client_write_key
    m_key_client = create_key(m_state.m_alg_encrypt, _key_block, m_state.m_size_enc_key);
    _key_block += m_state.m_size_enc_key;

    // server_write_key
    m_key_server = create_key(m_state.m_alg_encrypt, _key_block, m_state.m_size_enc_key);
    _key_block += m_state.m_size_enc_key;

    // client_write_IV
    if (!CryptSetKeyParam(m_key_client, KP_IV, _key_block, 0))
        throw win_runtime_error(__FUNCTION__ " Error setting client_write_IV.");
    _key_block += m_state.m_size_enc_iv;

    // server_write_IV
    if (!CryptSetKeyParam(m_key_server, KP_IV, _key_block, 0))
        throw win_runtime_error(__FUNCTION__ " Error setting server_write_IV.");
    _key_block += m_state.m_size_enc_iv;
}


void eap::method_tls::derive_msk()
{
    sanitizing_blob seed;
    static const unsigned char s_label[] = "ttls keying material";
    seed.assign(s_label, s_label + _countof(s_label) - 1);
    seed.insert(seed.end(), (const unsigned char*)&m_state.m_random_client, (const unsigned char*)(&m_state.m_random_client + 1));
    seed.insert(seed.end(), (const unsigned char*)&m_state.m_random_server, (const unsigned char*)(&m_state.m_random_server + 1));
    sanitizing_blob key_block(prf(&m_state.m_master_secret, sizeof(tls_master_secret), seed.data(), seed.size(), 2*sizeof(tls_random)));
    const unsigned char *_key_block = key_block.data();

    // MS-MPPE-Send-Key
    memcpy(&m_key_mppe_send, _key_block, sizeof(tls_random));
    _key_block += sizeof(tls_random);

    // MS-MPPE-Recv-Key
    memcpy(&m_key_mppe_recv, _key_block, sizeof(tls_random));
    _key_block += sizeof(tls_random);
}


void eap::method_tls::process_packet(_In_bytecount_(size_pck) const void *_pck, _In_ size_t size_pck)
{
    for (const unsigned char *pck = (const unsigned char*)_pck, *pck_end = pck + size_pck; pck < pck_end; ) {
        if (pck + 5 > pck_end)
            throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete message header.");
        const message *hdr = (const message*)pck;
        const unsigned char
            *msg     = hdr->data,
            *msg_end = msg + ntohs(*(unsigned short*)hdr->length);
        if (msg_end > pck_end)
            throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete message data.");

        if (hdr->version.major == 3 && hdr->version.minor == 1) {
            // Process TLS 1.0 message.
            switch (hdr->type) {
            case tls_message_type_change_cipher_spec:
                process_change_cipher_spec(msg, msg_end - msg);
                break;

            case tls_message_type_alert:
                if (m_cipher_spec) {
                    sanitizing_blob msg_dec(msg, msg_end);
                    decrypt_message(msg_dec);
                    process_alert(msg_dec.data(), msg_dec.size());
                } else
                    process_alert(msg, msg_end - msg);
                break;

            case tls_message_type_handshake:
                if (m_cipher_spec) {
                    sanitizing_blob msg_dec(msg, msg_end);
                    decrypt_message(msg_dec);
                    process_handshake(msg_dec.data(), msg_dec.size());
                } else
                    process_handshake(msg, msg_end - msg);
                break;

            case tls_message_type_application_data: {
                if (!m_cipher_spec)
                    throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Application data should be encrypted.");

                sanitizing_blob msg_dec(msg, msg_end);
                decrypt_message(msg_dec);
                process_application_data(msg_dec.data(), msg_dec.size());
                break;
            }

            default:
                if (m_cipher_spec) {
                    sanitizing_blob msg_dec(msg, msg_end);
                    decrypt_message(msg_dec);
                    process_vendor_data(hdr->type, msg_dec.data(), msg_dec.size());
                } else
                    process_vendor_data(hdr->type, msg, msg_end - msg);
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
                else if (rec[0] != 3 || rec[1] != 1)
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
                    m_state.m_alg_encrypt  = CALG_3DES;
                    m_state.m_size_enc_key = 192/8; // 3DES 192bits
                    m_state.m_size_enc_iv  = 64/8;  // 3DES 64bits
                    m_state.m_alg_mac      = CALG_SHA1;
                    m_state.m_size_mac_key = 160/8; // SHA-1
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
                m_send_client_cert = true;
                m_module.log_event(&EAPMETHOD_TLS_CERTIFICATE_REQUEST, event_data((unsigned int)eap_type_tls), event_data::blank);
                break;

            case tls_handshake_type_server_hello_done:
                m_server_hello_done = true;
                m_module.log_event(&EAPMETHOD_TLS_SERVER_HELLO_DONE, event_data((unsigned int)eap_type_tls), event_data::blank);
                break;

            case tls_handshake_type_finished: {
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

                if (memcmp(prf(&m_state.m_master_secret, sizeof(tls_master_secret), seed.data(), seed.size(), 12).data(), rec, 12))
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
}


void eap::method_tls::process_application_data(_In_bytecount_(msg_size) const void *msg, _In_ size_t msg_size)
{
    UNREFERENCED_PARAMETER(msg);
    UNREFERENCED_PARAMETER(msg_size);

    // TODO: Parse application data (Diameter AVP)
}


void eap::method_tls::process_vendor_data(_In_ unsigned char type, _In_bytecount_(msg_size) const void *msg, _In_ size_t msg_size)
{
    UNREFERENCED_PARAMETER(type);
    UNREFERENCED_PARAMETER(msg);
    UNREFERENCED_PARAMETER(msg_size);
}


void eap::method_tls::verify_server_trust() const
{
    assert(!m_server_cert_chain.empty());
    const cert_context &cert = m_server_cert_chain.front();

    if (!m_cfg.m_server_names.empty()) {
        // Check server name.

        string subj;
        if (!CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, subj))
            throw win_runtime_error(__FUNCTION__ " Error retrieving server's certificate subject name.");

        for (list<string>::const_iterator s = m_cfg.m_server_names.cbegin(), s_end = m_cfg.m_server_names.cend();; ++s) {
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
    for (list<cert_context>::const_iterator c = m_cfg.m_trusted_root_ca.cbegin(), c_end = m_cfg.m_trusted_root_ca.cend(); c != c_end; ++c)
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
        (m_cfg.m_trusted_root_ca.empty() || (context->TrustStatus.dwErrorStatus & ~CERT_TRUST_IS_UNTRUSTED_ROOT) != CERT_TRUST_NO_ERROR))
        throw win_runtime_error(context->TrustStatus.dwErrorStatus, "Error validating certificate chain.");

    if (!m_cfg.m_trusted_root_ca.empty()) {
        // Verify Root CA against our trusted root CA list
        if (context->cChain != 1)
            throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Multiple chain verification not supported.");
        if (context->rgpChain[0]->cElement == 0)
            throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Can not verify empty certificate chain.");

        PCCERT_CONTEXT cert_root = context->rgpChain[0]->rgpElement[context->rgpChain[0]->cElement-1]->pCertContext;
        for (list<cert_context>::const_iterator c = m_cfg.m_trusted_root_ca.cbegin(), c_end = m_cfg.m_trusted_root_ca.cend();; ++c) {
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


void eap::method_tls::encrypt_message(_Inout_ sanitizing_blob &msg)
{
    // Create a HMAC hash.
    hash_hmac hash_hmac(m_cp, m_state.m_alg_mac, m_padding_hmac_client.data());

    // Hash sequence number and message.
    unsigned __int64 seq_num = htonll(m_seq_num);
    if (!CryptHashData(hash_hmac, (const BYTE*)&seq_num, sizeof(seq_num), 0) ||
        !CryptHashData(hash_hmac, msg.data(), (DWORD)msg.size(), 0))
        throw win_runtime_error(__FUNCTION__ " Error hashing data.");

    // Calculate hash.
    sanitizing_blob hmac;
    hash_hmac.calculate(hmac);

    // Remove SSL/TLS header (record type, version, message size).
    msg.erase(msg.begin(), msg.begin() + 5);

    size_t size =
        msg.size()  + // TLS message
        hmac.size() + // HMAC hash
        1;            // Padding length

    // Calculate padding.
    DWORD size_block = CryptGetKeyParam(m_key_client, KP_BLOCKLEN, size_block, 0) ? size_block / 8 : 0;
    unsigned char size_padding = (unsigned char)((size_block - size) % size_block);
    size += size_padding;
    msg.reserve(size);

    // Append HMAC hash.
#ifdef _HOST_LOW_ENDIAN
    std::reverse(hmac.begin(), hmac.end());
#endif
    msg.insert(msg.end(), hmac.begin(), hmac.end());

    // Append padding.
    msg.insert(msg.end(), size_padding + 1, size_padding);

    // Encrypt.
    assert(size < 0xffffffff);
    DWORD size2 = (DWORD)size;
    if (!CryptEncrypt(m_key_client, NULL, FALSE, 0, msg.data(), &size2, (DWORD)size))
        throw win_runtime_error(__FUNCTION__ " Error encrypting message.");

    // Increment sequence number.
    m_seq_num++;
}


void eap::method_tls::decrypt_message(_Inout_ sanitizing_blob &msg) const
{
    // Decrypt.
    if (!CryptDecrypt(m_key_server, NULL, FALSE, 0, msg))
        throw win_runtime_error(__FUNCTION__ " Error decrypting message.");

    size_t size = msg.size();
    if (size) {
        // Check padding.
        unsigned char padding = msg.back();
        size_t size_data = size - 1 - padding;
        for (size_t i = size_data, i_end = size - 1; i < i_end; i++)
            if (msg[i] != padding)
                throw invalid_argument(__FUNCTION__ " Incorrect message padding.");

        // Remove padding.
        msg.resize(size_data);
    }
}


eap::sanitizing_blob eap::method_tls::prf(
    _In_bytecount_(size_secret) const void   *secret,
    _In_                              size_t size_secret,
    _In_bytecount_(size_seed)   const void   *seed,
    _In_                              size_t size_seed,
    _In_                              size_t size) const
{
    sanitizing_blob data;
    data.reserve(size);

    if (m_state.m_alg_prf == CALG_TLS1PRF) {
        // Split secret in two halves.
        size_t
            size_S1 = (size_secret + 1) / 2,
            size_S2 = size_S1;
        const void
            *S1 = secret,
            *S2 = (const unsigned char*)secret + (size_secret - size_S2);

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
        hash_hmac::inner_padding(m_cp, m_state.m_alg_prf, secret, size_secret, hmac_padding.data());

        // Prepare A for p_hash.
        sanitizing_blob A((unsigned char*)seed, (unsigned char*)seed + size_seed);

        sanitizing_blob hmac;
        for (size_t i = 0; i < size; ) {
            // Rehash A.
            hash_hmac hash1(m_cp, CALG_MD5 , hmac_padding.data());
            if (!CryptHashData(hash1, A.data(), (DWORD)A.size(), 0))
                throw win_runtime_error(__FUNCTION__ " Error hashing A.");
            hash1.calculate(A);

            // Hash A and seed.
            hash_hmac hash2(m_cp, CALG_MD5 , hmac_padding.data());
            if (!CryptHashData(hash2,              A.data(), (DWORD)A.size() , 0) ||
                !CryptHashData(hash2, (const BYTE*)seed    , (DWORD)size_seed, 0))
                throw win_runtime_error(__FUNCTION__ " Error hashing seed,label or data.");
            hash2.calculate(hmac);

            size_t n = std::min<size_t>(hmac.size(), size - i);
            data.insert(data.end(), hmac.begin(), hmac.begin() + n);
        }
    }

    return data;
}
