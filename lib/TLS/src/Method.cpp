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
// eap::method_tls::random
//////////////////////////////////////////////////////////////////////

eap::method_tls::random::random() :
    time(0)
{
    memset(data, 0, sizeof(data));
}


eap::method_tls::random::random(_In_ const random &other) :
    time(other.time)
{
    memcpy(data, other.data, sizeof(data));
}


eap::method_tls::random::~random()
{
    SecureZeroMemory(data, sizeof(data));
}


eap::method_tls::random& eap::method_tls::random::operator=(_In_ const random &other)
{
    if (this != std::addressof(other)) {
        time = other.time;
        memcpy(data, other.data, sizeof(data));
    }

    return *this;
}


void eap::method_tls::random::clear()
{
    time = 0;
    memset(data, 0, sizeof(data));
}


//////////////////////////////////////////////////////////////////////
// eap::method_tls
//////////////////////////////////////////////////////////////////////

eap::method_tls::method_tls(_In_ module &module, _In_ config_method_tls &cfg, _In_ credentials_tls &cred) :
    m_phase(phase_unknown),
    m_send_client_cert(false),
    m_seq_num(0),
    method(module, cfg, cred)
{
}


eap::method_tls::method_tls(_In_ const method_tls &other) :
    m_phase(other.m_phase),
    m_packet_req(other.m_packet_req),
    m_packet_res(other.m_packet_res),
    m_random_client(other.m_random_client),
    m_random_server(other.m_random_server),
    m_session_id(other.m_session_id),
    m_server_cert_chain(other.m_server_cert_chain),
    m_send_client_cert(other.m_send_client_cert),
    m_hash_handshake_msgs_md5(other.m_hash_handshake_msgs_md5),
    m_hash_handshake_msgs_sha1(other.m_hash_handshake_msgs_sha1),
    m_seq_num(other.m_seq_num),
    method(other)
{
}


eap::method_tls::method_tls(_Inout_ method_tls &&other) :
    m_phase(std::move(other.m_phase)),
    m_packet_req(std::move(other.m_packet_req)),
    m_packet_res(std::move(other.m_packet_res)),
    m_random_client(std::move(other.m_random_client)),
    m_random_server(std::move(other.m_random_server)),
    m_session_id(std::move(other.m_session_id)),
    m_server_cert_chain(std::move(other.m_server_cert_chain)),
    m_send_client_cert(std::move(other.m_send_client_cert)),
    m_hash_handshake_msgs_md5(std::move(other.m_hash_handshake_msgs_md5)),
    m_hash_handshake_msgs_sha1(std::move(other.m_hash_handshake_msgs_sha1)),
    m_seq_num(std::move(other.m_seq_num)),
    method(std::move(other))
{
}


eap::method_tls& eap::method_tls::operator=(_In_ const method_tls &other)
{
    if (this != std::addressof(other)) {
        (method&)*this             = other;
        m_phase                    = other.m_phase;
        m_packet_req               = other.m_packet_req;
        m_packet_res               = other.m_packet_res;
        m_random_client            = other.m_random_client;
        m_random_server            = other.m_random_server;
        m_session_id               = other.m_session_id;
        m_server_cert_chain        = other.m_server_cert_chain;
        m_send_client_cert         = other.m_send_client_cert;
        m_hash_handshake_msgs_md5  = other.m_hash_handshake_msgs_md5;
        m_hash_handshake_msgs_sha1 = other.m_hash_handshake_msgs_sha1;
        m_seq_num                  = other.m_seq_num;
    }

    return *this;
}


eap::method_tls& eap::method_tls::operator=(_Inout_ method_tls &&other)
{
    if (this != std::addressof(other)) {
        (method&)*this             = std::move(other);
        m_phase                    = std::move(other.m_phase);
        m_packet_req               = std::move(other.m_packet_req);
        m_packet_res               = std::move(other.m_packet_res);
        m_random_client            = std::move(other.m_random_client);
        m_random_server            = std::move(other.m_random_server);
        m_session_id               = std::move(other.m_session_id);
        m_server_cert_chain        = std::move(other.m_server_cert_chain);
        m_send_client_cert         = std::move(other.m_send_client_cert);
        m_hash_handshake_msgs_md5  = std::move(other.m_hash_handshake_msgs_md5);
        m_hash_handshake_msgs_sha1 = std::move(other.m_hash_handshake_msgs_sha1);
        m_seq_num                  = std::move(other.m_seq_num);
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
    if (!m_cp.create(NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
        throw win_runtime_error(__FUNCTION__ " Error creating cryptographics provider.");

    // HMAC symmetric key generation sample. To be used later...
    //crypt_hash hash_key;
    //hash_key.create(m_cp, CALG_SHA1, 0, 0);
    //CryptHashData(hash_key, Data1, sizeof(Data1), 0);
    //m_key_hmac.derive(m_cp, CALG_RC4, hash_key, 0);
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
    //    throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, wstring_printf(_T(__FUNCTION__) _T(" Packet is not EAP-TLS (expected: %u, received: %u)."), eap_type_tls, pReceivedPacket->Data[0]).c_str());

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
                m_module.log_event(&EAPMETHOD_PACKET_RECV_FRAG_FIRST, event_data((unsigned int)eap_type_tls), event_data((unsigned int)packet_data_size), event_data((unsigned int)size_tot), event_data::blank);
            } else {
                // The Length field was not included. Odd. Nevermind, no pre-allocation then.
                m_module.log_event(&EAPMETHOD_PACKET_RECV_FRAG_FIRST1, event_data((unsigned int)eap_type_tls), event_data((unsigned int)packet_data_size), event_data::blank);
            }
        } else {
            // Mid fragment received.
            m_module.log_event(&EAPMETHOD_PACKET_RECV_FRAG_MID, event_data((unsigned int)eap_type_tls), event_data((unsigned int)packet_data_size), event_data((unsigned int)m_packet_req.m_data.size()), event_data::blank);
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
        m_module.log_event(&EAPMETHOD_PACKET_RECV_FRAG_LAST, event_data((unsigned int)eap_type_tls), event_data((unsigned int)packet_data_size), event_data((unsigned int)m_packet_req.m_data.size()), event_data::blank);
    } else {
        // This is a complete non-fragmented packet.
        m_packet_req.m_data.assign(packet_data_ptr, packet_data_ptr + packet_data_size);
        m_module.log_event(&EAPMETHOD_PACKET_RECV, event_data((unsigned int)eap_type_tls), event_data((unsigned int)packet_data_size), event_data::blank);
    }

    if (pReceivedPacket->Code == EapCodeRequest && pReceivedPacket->Data[1] & flags_req_start) {
        // This is the TLS start message: initialize method.
        m_phase = phase_client_hello;
        m_packet_res.clear();
        m_key_hmac.free();
        m_key_encrypt.free();
        m_key_decrypt.free();

        // Generate client randomness.
        _time32(&m_random_client.time);
        if (!CryptGenRandom(m_cp, sizeof(m_random_client.data), m_random_client.data))
            throw win_runtime_error(__FUNCTION__ " Error creating client randomness.");
        m_random_server.clear();
        m_server_cert_chain.clear();
        m_send_client_cert = false;
        m_session_id.clear();

        // Create MD5 hash object.
        if (!m_hash_handshake_msgs_md5.create(m_cp, CALG_MD5, NULL, 0))
            throw win_runtime_error(__FUNCTION__ " Error creating MD5 hashing object.");

        // Create SHA-1 hash object.
        if (!m_hash_handshake_msgs_sha1.create(m_cp, CALG_SHA1, NULL, 0))
            throw win_runtime_error(__FUNCTION__ " Error creating SHA-1 hashing object.");

        m_seq_num = 0;
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

    switch (m_phase) {
        case phase_client_hello: {
            m_module.log_event(&EAPMETHOD_HANDSHAKE_START2, event_data((unsigned int)eap_type_tls), event_data::blank);

            // Build response packet.
            m_packet_res.m_code  = EapCodeResponse;
            m_packet_res.m_id    = m_packet_req.m_id;
            m_packet_res.m_flags = 0;
            sanitizing_blob hello(make_client_hello());
            sanitizing_blob handshake(make_handshake(hello));
            m_packet_res.m_data.assign(handshake.begin(), handshake.end());
            pEapOutput->fAllowNotifications = FALSE;
            pEapOutput->action = EapPeerMethodResponseActionSend;

            // Hash the client_hello message.
            CryptHashData(m_hash_handshake_msgs_md5 , hello.data(), (DWORD)hello.size(), 0);
            CryptHashData(m_hash_handshake_msgs_sha1, hello.data(), (DWORD)hello.size(), 0);

            m_phase = phase_server_hello;
            break;
        }

        case phase_server_hello: {
            if (m_packet_req.m_data.size() < 5)
                throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, string_printf(__FUNCTION__ " TLS message too small (expected >=5, received %uB).", m_packet_req.m_data.size()));
            const message *msg = (const message*)m_packet_req.m_data.data();
            if (msg->type != message_type_handshake)
                throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, string_printf(__FUNCTION__ " Wrong TLS message (expected %u, received %uB).", message_type_handshake, msg->type));

            process_handshake(msg->data, std::min<size_t>(ntohs(*(unsigned short*)msg->length), m_packet_req.m_data.size() - 5));

            //break;
        }

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
            m_module.log_event(&EAPMETHOD_PACKET_SEND, event_data((unsigned int)eap_type_tls), event_data((unsigned int)size_data), event_data::blank);
        } else {
            // But it should be fragmented.
            m_packet_res.m_flags |= flags_res_length_incl | flags_res_more_frag;
            *(unsigned int*)(pSendPacket->Data + 2) = (unsigned int)size_packet;
            data_dst = pSendPacket->Data + 6;
            size_data   = size_packet_limit - 10;
            size_packet = size_packet_limit;
            m_module.log_event(&EAPMETHOD_PACKET_SEND_FRAG_FIRST, event_data((unsigned int)eap_type_tls), event_data((unsigned int)size_data), event_data((unsigned int)(m_packet_res.m_data.size() - size_data)), event_data::blank);
        }
    } else {
        // Continuing the fragmented packet...
        if (size_packet > size_packet_limit) {
            // This is a mid fragment.
            m_packet_res.m_flags &= ~flags_res_length_incl;
            size_data   = size_packet_limit - 6;
            size_packet = size_packet_limit;
            m_module.log_event(&EAPMETHOD_PACKET_SEND_FRAG_MID, event_data((unsigned int)eap_type_tls), event_data((unsigned int)size_data), event_data((unsigned int)(m_packet_res.m_data.size() - size_data)), event_data::blank);
        } else {
            // This is the last fragment.
            m_packet_res.m_flags &= ~(flags_res_length_incl | flags_res_more_frag);
            m_module.log_event(&EAPMETHOD_PACKET_SEND_FRAG_LAST, event_data((unsigned int)eap_type_tls), event_data((unsigned int)size_data), event_data((unsigned int)(m_packet_res.m_data.size() - size_data)), event_data::blank);
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
    UNREFERENCED_PARAMETER(reason);
    UNREFERENCED_PARAMETER(ppResult);

    throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Not supported.");
}


eap::sanitizing_blob eap::method_tls::make_client_hello() const
{
    size_t size_data;
    sanitizing_blob msg;
    msg.reserve(
        4                    + // SSL header
        (size_data =
        2                    + // SSL version
        sizeof(random)       + // Client random
        1                    + // Session ID size
        m_session_id.size()  + // Session ID
        2                    + // Length of cypher suite list
        2                    + // Cyper suite list
        1                    + // Length of compression suite
        1));                   // Compression suite

    // SSL header
    assert(size_data <= 0xffffff);
    unsigned int ssl_header = htonl(((unsigned int)client_hello << 24) | (unsigned int)size_data);
    msg.insert(msg.end(), (unsigned char*)&ssl_header, (unsigned char*)(&ssl_header + 1));

    // SSL version: TLS 1.0
    msg.push_back(3); // SSL major version
    msg.push_back(1); // SSL minor version

    // Client random
    msg.insert(msg.end(), (unsigned char*)&m_random_client, (unsigned char*)(&m_random_client + 1));

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


eap::sanitizing_blob eap::method_tls::make_handshake(_In_ const sanitizing_blob &msg)
{
    // Create a handshake.
    size_t size_msg = msg.size();
    eap::sanitizing_blob msg_h;
    msg_h.reserve(
        1        + // SSL record type
        2        + // SSL version
        2        + // Message size
        size_msg); // Message

    // SSL record type
    msg_h.push_back((unsigned char)message_type_handshake);

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
            throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Incomplete record rec.");

        // Process record.
        switch (hdr >> 24) {
            case server_hello:
                // TLS version
                if (rec + 2 > rec_end)
                    throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Server SSL/TLS version missing or incomplete.");
                else if (rec[0] != 3 || rec[1] != 1)
                    throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Unsupported SSL/TLS version.");
                rec += 2;

                // Server random
                if (rec + sizeof(m_random_server) > rec_end)
                    throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Server random missing or incomplete.");
                memcpy(&m_random_server, rec, sizeof(m_random_server));
                rec += sizeof(m_random_server);

                // Session ID
                if (rec + 1 > rec_end || rec + 1 + rec[0] > rec_end)
                    throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Session ID missing or incomplete.");
                assert(rec[0] <= 32); // According to RFC 5246 session IDs should not be longer than 32B.
                m_session_id.assign(rec + 1, rec + 1 + rec[0]);
                rec += rec[0] + 1;

                // Cipher
                if (rec + 2 > rec_end)
                    throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, __FUNCTION__ " Cipher or incomplete.");
                if (rec[0] != 0x00 || rec[1] != 0x0a)
                    throw win_runtime_error(ERROR_NOT_SUPPORTED, string_printf(__FUNCTION__ " Other than requested cipher selected (expected 0x000a, received 0x%02x%02x).", rec[0], rec[1]));

                break;

            case certificate: {
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

                break;
            }

            case certificate_request:
                m_send_client_cert = true;
                break;

            case finished:
                if (rec_end - rec != 12)
                    throw win_runtime_error(EAP_E_EAPHOST_METHOD_INVALID_PACKET, string_printf(__FUNCTION__ " \"finished\" size incorrect (expected 12B, received %u).", rec_end - rec));

                vector<unsigned char> hash, hash_sha1;
                if (!CryptGetHashParam(m_hash_handshake_msgs_md5, HP_HASHVAL, hash, 0))
                    throw win_runtime_error(__FUNCTION__ " Error finishing MD5 hash calculation.");
                if (!CryptGetHashParam(m_hash_handshake_msgs_sha1, HP_HASHVAL, hash_sha1, 0))
                    throw win_runtime_error(__FUNCTION__ " Error finishing SHA-1 hash calculation.");
                hash.insert(hash.end(), hash_sha1.begin(), hash_sha1.end());
        }

        msg = rec_end;
    }
}


void eap::method_tls::encrypt_message(_Inout_ sanitizing_blob &msg)
{
    // Create a HMAC hash.
    crypt_hash hash_hmac;
    static const HMAC_INFO s_hmac_info = { CALG_SHA1 };
    if (!hash_hmac.create(m_cp, CALG_HMAC, m_key_hmac, 0) ||
        !CryptSetHashParam(hash_hmac, HP_HMAC_INFO, (const BYTE*)&s_hmac_info, 0))
        throw win_runtime_error(__FUNCTION__ " Error creating HMAC hash.");

    // Hash sequence number and message.
    unsigned __int64 seq_num = htonll(m_seq_num);
    if (!CryptHashData(hash_hmac, (const BYTE*)&seq_num, sizeof(seq_num), 0) ||
        !CryptHashData(hash_hmac, msg.data(), (DWORD)msg.size(), 0))
        throw win_runtime_error(__FUNCTION__ " Error hashing data.");

    // Calculate hash.
    vector<unsigned char> hmac;
    if (!CryptGetHashParam(hash_hmac, HP_HASHVAL, hmac, 0))
        throw win_runtime_error(__FUNCTION__ " Error finishing hash calculation.");

    // Remove SSL/TLS header (record type, version, message size).
    msg.erase(msg.begin(), msg.begin() + 5);

    size_t size =
        msg.size() + // TLS message
        20         + // HMAC hash (SHA-1)
        1;           // Padding length
    unsigned char padding = (8 - size) % 8;
    size += padding;
    msg.reserve(size);

    // Append HMAC hash.
#ifdef _HOST_LOW_ENDIAN
    std::reverse(hmac.begin(), hmac.end());
#endif
    msg.insert(msg.end(), hmac.begin(), hmac.end());

    // Append padding.
    msg.insert(msg.end(), padding + 1, padding);

    // Encrypt.
    assert(size < 0xffffffff);
    DWORD size2 = (DWORD)size;
    if (!CryptEncrypt(m_key_encrypt, NULL, FALSE, 0, msg.data(), &size2, (DWORD)size))
        throw win_runtime_error(__FUNCTION__ " Error encrypting message.");

    // Increment sequence number.
    m_seq_num++;
}


void eap::method_tls::decrypt_message(_Inout_ sanitizing_blob &msg)
{
    // Decrypt.
    DWORD size = (DWORD)msg.size();
    if (!CryptDecrypt(m_key_decrypt, NULL, FALSE, 0, msg.data(), &size))
        throw win_runtime_error(__FUNCTION__ " Error decrypting message.");

    // Remove padding.
    msg.resize(size - msg.back() - 1);
}


vector<unsigned char> eap::method_tls::p_hash(
    _In_                              ALG_ID                alg,
    _In_bytecount_(size_secret) const void                  *secret,
    _In_                              size_t                size_secret,
    _In_bytecount_(size_seed)   const void                  *seed,
    _In_                              size_t                size_seed,
    _In_                              size_t                size)
{
    // HMAC symmetric key generation.
    crypt_hash hash_key;
    if (!hash_key.create(m_cp, alg, 0, 0))
        throw win_runtime_error(__FUNCTION__ " Error creating key hash.");
    if (!CryptHashData(hash_key, (const BYTE*)secret, (DWORD)size_secret, 0))
        throw win_runtime_error(__FUNCTION__ " Error hashing secret.");
    crypt_key key_hmac;
    key_hmac.derive(m_cp, CALG_RC4, hash_key, 0);
    vector<unsigned char> block;
    const HMAC_INFO hmac_info = { alg };

    vector<unsigned char> data;
    data.reserve(size);

    // https://tools.ietf.org/html/rfc5246#section-5:
    //
    // P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
    //                        HMAC_hash(secret, A(2) + seed) +
    //                        HMAC_hash(secret, A(3) + seed) + ...
    // 
    // where + indicates concatenation.
    // 
    // A() is defined as:
    // 
    //    A(0) = seed
    //    A(i) = HMAC_hash(secret, A(i-1))

    vector<unsigned char> A((unsigned char*)seed, (unsigned char*)seed + size_seed);
    while (data.size() < size) {
        // Hash A.
        crypt_hash hash_hmac1;
        if (!hash_hmac1.create(m_cp, CALG_HMAC, key_hmac, 0) ||
            !CryptSetHashParam(hash_hmac1, HP_HMAC_INFO, (const BYTE*)&hmac_info, 0))
            throw win_runtime_error(__FUNCTION__ " Error creating HMAC hash.");
        if (!CryptHashData(hash_hmac1, A.data(), (DWORD)A.size(), 0))
            throw win_runtime_error(__FUNCTION__ " Error hashing A.");
        if (!CryptGetHashParam(hash_hmac1, HP_HASHVAL, A, 0))
            throw win_runtime_error(__FUNCTION__ " Error finishing hash A calculation.");

        // Hash A and seed.
        crypt_hash hash_hmac2;
        if (!hash_hmac2.create(m_cp, CALG_HMAC, key_hmac, 0) ||
            !CryptSetHashParam(hash_hmac2, HP_HMAC_INFO, (const BYTE*)&hmac_info, 0))
            throw win_runtime_error(__FUNCTION__ " Error creating A+seed hash.");
        if (!CryptHashData(hash_hmac2, A.data(), (DWORD)A.size(), 0) ||
            !CryptHashData(hash_hmac2, (const BYTE*)seed, (DWORD)size_seed, 0))
            throw win_runtime_error(__FUNCTION__ " Error hashing seed.");
        if (!CryptGetHashParam(hash_hmac2, HP_HASHVAL, block, 0))
            throw win_runtime_error(__FUNCTION__ " Error finishing hash A+seed calculation.");

        // Append to output data.
        data.insert(data.end(), block.begin(), block.end());
    }

    return data;
}
