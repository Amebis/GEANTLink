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
// eap::tls_version
//////////////////////////////////////////////////////////////////////

const eap::tls_version eap::tls_version_1_0 = { 3, 1 };
const eap::tls_version eap::tls_version_1_1 = { 3, 2 };
const eap::tls_version eap::tls_version_1_2 = { 3, 3 };


//////////////////////////////////////////////////////////////////////
// eap::tls_random
//////////////////////////////////////////////////////////////////////

void eap::tls_random::randomize(_In_ HCRYPTPROV cp)
{
    _time32((__time32_t*)data);
    if (!CryptGenRandom(cp, sizeof(data) - sizeof(__time32_t), data + sizeof(__time32_t)))
        throw win_runtime_error(__FUNCTION__ " Error creating randomness.");
}


//////////////////////////////////////////////////////////////////////
// eap::tls_master_secret
//////////////////////////////////////////////////////////////////////

eap::tls_master_secret::tls_master_secret()
{
}


eap::tls_master_secret::tls_master_secret(_In_ HCRYPTPROV cp, _In_ tls_version ver)
{
    data[0] = ver.major;
    data[1] = ver.minor;

    if (!CryptGenRandom(cp, sizeof(data) - 2, data + 2))
        throw win_runtime_error(__FUNCTION__ " Error creating PMS randomness.");
}


eap::tls_master_secret::tls_master_secret(_In_ const sanitizing_blob_f<48> &other) :
    sanitizing_blob_xf<48>(other)
{
}


#ifdef _DEBUG

eap::tls_master_secret::tls_master_secret(_Inout_ sanitizing_blob_zf<48> &&other) :
    sanitizing_blob_xf<48>(std::move(other))
{
}

#endif


//////////////////////////////////////////////////////////////////////
// eap::hmac_padding
//////////////////////////////////////////////////////////////////////

eap::hmac_padding::hmac_padding()
{
}


eap::hmac_padding::hmac_padding(
            _In_                               HCRYPTPROV    cp,
            _In_                               ALG_ID        alg,
            _In_bytecount_(size_secret ) const void          *secret,
            _In_                               size_t        size_secret,
            _In_opt_                           unsigned char pad)
{
    if (size_secret > sizeof(hmac_padding)) {
        // If the secret is longer than padding, use secret's hash instead.
        crypt_hash hash;
        if (!hash.create(cp, alg))
            throw win_runtime_error(__FUNCTION__ " Error creating hash.");
        if (!CryptHashData(hash, (const BYTE*)secret, (DWORD)size_secret, 0))
            throw win_runtime_error(__FUNCTION__ " Error hashing.");
        DWORD size_hash = sizeof(hmac_padding);
        if (!CryptGetHashParam(hash, HP_HASHVAL, data, &size_hash, 0))
            throw win_runtime_error(__FUNCTION__ " Error finishing hash.");
        size_secret = size_hash;
    } else
        memcpy(data, secret, size_secret);
    for (size_t i = 0; i < size_secret; i++)
        data[i] ^= pad;
    memset(data + size_secret, pad, sizeof(hmac_padding) - size_secret);
}


eap::hmac_padding::hmac_padding(_In_ const sanitizing_blob_f<64> &other) :
    sanitizing_blob_xf<64>(other)
{
}


#ifdef _DEBUG

eap::hmac_padding::hmac_padding(_Inout_ sanitizing_blob_zf<64> &&other) :
    sanitizing_blob_xf<64>(std::move(other))
{
}

#endif


//////////////////////////////////////////////////////////////////////
// eap::hmac_hash
//////////////////////////////////////////////////////////////////////

eap::hmac_hash::hmac_hash(
    _In_                               HCRYPTPROV cp,
    _In_                               ALG_ID     alg,
    _In_bytecount_(size_secret ) const void       *secret,
    _In_                               size_t     size_secret)
{
    // Prepare inner padding and forward to the other constructor.
    this->hmac_hash::hmac_hash(cp, alg, hmac_padding(cp, alg, secret, size_secret));
}


eap::hmac_hash::hmac_hash(
    _In_       HCRYPTPROV   cp,
    _In_       ALG_ID       alg,
    _In_ const hmac_padding &padding)
{
    // Create inner hash.
    if (!m_hash_inner.create(cp, alg))
        throw win_runtime_error(__FUNCTION__ " Error creating inner hash.");

    // Initialize it with the inner padding.
    if (!CryptHashData(m_hash_inner, padding.data, sizeof(hmac_padding), 0))
        throw win_runtime_error(__FUNCTION__ " Error hashing secret XOR inner padding.");

    // Convert inner padding to outer padding for final calculation.
    hmac_padding padding_out;
    for (size_t i = 0; i < sizeof(hmac_padding); i++)
        padding_out.data[i] = padding.data[i] ^ (0x36 ^ 0x5c);

    // Create outer hash.
    if (!m_hash_outer.create(cp, alg))
        throw win_runtime_error(__FUNCTION__ " Error creating outer hash.");

    // Initialize it with the outer padding.
    if (!CryptHashData(m_hash_outer, padding_out.data, sizeof(hmac_padding), 0))
        throw win_runtime_error(__FUNCTION__ " Error hashing secret XOR inner padding.");
}


//////////////////////////////////////////////////////////////////////
// eap::tls_conn_state
//////////////////////////////////////////////////////////////////////

eap::tls_conn_state::tls_conn_state()
#ifdef _DEBUG
    // Initialize state primitive members for diagnostic purposes.
    :
    m_prov_name     (NULL),
    m_prov_type     (0),
    m_alg_encrypt   (0),
    m_size_enc_key  (0),
    m_size_enc_iv   (0),
    m_size_enc_block(0),
    m_alg_mac       (0),
    m_size_mac_key  (0),
    m_size_mac_hash (0)
#endif
{
}


eap::tls_conn_state::tls_conn_state(_In_ const tls_conn_state &other) :
    m_prov_name     (other.m_prov_name     ),
    m_prov_type     (other.m_prov_type     ),
    m_alg_encrypt   (other.m_alg_encrypt   ),
    m_size_enc_key  (other.m_size_enc_key  ),
    m_size_enc_iv   (other.m_size_enc_iv   ),
    m_size_enc_block(other.m_size_enc_block),
    m_key           (other.m_key           ),
    m_alg_mac       (other.m_alg_mac       ),
    m_size_mac_key  (other.m_size_mac_key  ),
    m_size_mac_hash (other.m_size_mac_hash ),
    m_padding_hmac  (other.m_padding_hmac  )
{
}


eap::tls_conn_state::tls_conn_state(_Inout_ tls_conn_state &&other) :
    m_prov_name     (std::move(other.m_prov_name     )),
    m_prov_type     (std::move(other.m_prov_type     )),
    m_alg_encrypt   (std::move(other.m_alg_encrypt   )),
    m_size_enc_key  (std::move(other.m_size_enc_key  )),
    m_size_enc_iv   (std::move(other.m_size_enc_iv   )),
    m_size_enc_block(std::move(other.m_size_enc_block)),
    m_key           (std::move(other.m_key           )),
    m_alg_mac       (std::move(other.m_alg_mac       )),
    m_size_mac_key  (std::move(other.m_size_mac_key  )),
    m_size_mac_hash (std::move(other.m_size_mac_hash )),
    m_padding_hmac  (std::move(other.m_padding_hmac  ))
{
#ifdef _DEBUG
    // Reinitialize other state primitive members for diagnostic purposes.
    other.m_prov_name      = NULL;
    other.m_prov_type      = 0;
    other.m_alg_encrypt    = 0;
    other.m_size_enc_key   = 0;
    other.m_size_enc_iv    = 0;
    other.m_size_enc_block = 0;
    other.m_alg_mac        = 0;
    other.m_size_mac_key   = 0;
    other.m_size_mac_hash  = 0;
#endif
}


eap::tls_conn_state& eap::tls_conn_state::operator=(_In_ const tls_conn_state &other)
{
    if (this != std::addressof(other)) {
        m_prov_name      = other.m_prov_name     ;
        m_prov_type      = other.m_prov_type     ;
        m_alg_encrypt    = other.m_alg_encrypt   ;
        m_size_enc_key   = other.m_size_enc_key  ;
        m_size_enc_iv    = other.m_size_enc_iv   ;
        m_size_enc_block = other.m_size_enc_block;
        m_key            = other.m_key           ;
        m_alg_mac        = other.m_alg_mac       ;
        m_size_mac_key   = other.m_size_mac_key  ;
        m_size_mac_hash  = other.m_size_mac_hash ;
        m_padding_hmac   = other.m_padding_hmac  ;
    }

    return *this;
}


eap::tls_conn_state& eap::tls_conn_state::operator=(_Inout_ tls_conn_state &&other)
{
    if (this != std::addressof(other)) {
        m_prov_name      = std::move(other.m_prov_name     );
        m_prov_type      = std::move(other.m_prov_type     );
        m_alg_encrypt    = std::move(other.m_alg_encrypt   );
        m_size_enc_key   = std::move(other.m_size_enc_key  );
        m_size_enc_iv    = std::move(other.m_size_enc_iv   );
        m_size_enc_block = std::move(other.m_size_enc_block);
        m_key            = std::move(other.m_key           );
        m_alg_mac        = std::move(other.m_alg_mac       );
        m_size_mac_key   = std::move(other.m_size_mac_key  );
        m_size_mac_hash  = std::move(other.m_size_mac_hash );
        m_padding_hmac   = std::move(other.m_padding_hmac  );

#ifdef _DEBUG
        // Reinitialize other state primitive members for diagnostic purposes.
        other.m_prov_name      = NULL;
        other.m_prov_type      = 0;
        other.m_alg_encrypt    = 0;
        other.m_size_enc_key   = 0;
        other.m_size_enc_iv    = 0;
        other.m_size_enc_block = 0;
        other.m_alg_mac        = 0;
        other.m_size_mac_key   = 0;
        other.m_size_mac_hash  = 0;
#endif
    }

    return *this;
}


void eap::tls_conn_state::set_cipher(_In_ const unsigned char cipher[2])
{
    if (cipher[0] == 0x00 && cipher[1] == 0x0a) {
        // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        m_prov_name      = NULL;
        m_prov_type      = PROV_RSA_AES;
        m_alg_encrypt    = CALG_3DES;
        m_size_enc_key   = 192/8; // 3DES 192bits
        m_size_enc_iv    = 64/8;  // 3DES 64bits
        m_size_enc_block = 64/8;  // 3DES 64bits
        m_alg_mac        = CALG_SHA1;
        m_size_mac_key   = 160/8; // SHA-1
        m_size_mac_hash  = 160/8; // SHA-1
    } else if (cipher[0] == 0x00 && cipher[1] == 0x2f) {
        // TLS_RSA_WITH_AES_128_CBC_SHA
        m_prov_name      = NULL;
        m_prov_type      = PROV_RSA_AES;
        m_alg_encrypt    = CALG_AES_128;
        m_size_enc_key   = 128/8; // AES-128
        m_size_enc_iv    = 128/8; // AES-128
        m_size_enc_block = 128/8; // AES-128
        m_alg_mac        = CALG_SHA1;
        m_size_mac_key   = 160/8; // SHA-1
        m_size_mac_hash  = 160/8; // SHA-1
    } else if (cipher[0] == 0x00 && cipher[1] == 0x3c) {
        // AES128-SHA256
        m_prov_name      = NULL;
        m_prov_type      = PROV_RSA_AES;
        m_alg_encrypt    = CALG_AES_128;
        m_size_enc_key   = 128/8; // AES-128
        m_size_enc_iv    = 128/8; // AES-128
        m_size_enc_block = 128/8; // AES-128
        m_alg_mac        = CALG_SHA_256;
        m_size_mac_key   = 256/8; // SHA-256
        m_size_mac_hash  = 256/8; // SHA-256
    } else if (cipher[0] == 0x00 && cipher[1] == 0x3d) {
        // AES256-SHA256
        m_prov_name      = MS_ENH_RSA_AES_PROV;
        m_prov_type      = PROV_RSA_AES;
        m_alg_encrypt    = CALG_AES_256;
        m_size_enc_key   = 256/8; // AES-256
        m_size_enc_iv    = 128/8; // AES-256
        m_size_enc_block = 128/8; // AES-256
        m_alg_mac        = CALG_SHA_256;
        m_size_mac_key   = 256/8; // SHA-256
        m_size_mac_hash  = 256/8; // SHA-256
    } else if (cipher[0] == 0x00 && cipher[1] == 0x40) {
        // DHE-DSS-AES128-SHA256
        m_prov_name      = MS_ENH_DSS_DH_PROV;
        m_prov_type      = PROV_DSS_DH;
        m_alg_encrypt    = CALG_AES_128;
        m_size_enc_key   = 128/8; // AES-128
        m_size_enc_iv    = 128/8; // AES-128
        m_size_enc_block = 128/8; // AES-128
        m_alg_mac        = CALG_SHA_256;
        m_size_mac_key   = 256/8; // SHA-256
        m_size_mac_hash  = 256/8; // SHA-256
    } else if (cipher[0] == 0x00 && cipher[1] == 0x67) {
        // DHE-RSA-AES128-SHA256
        m_prov_name      = MS_DEF_DH_SCHANNEL_PROV;
        m_prov_type      = PROV_DH_SCHANNEL;
        m_alg_encrypt    = CALG_AES_128;
        m_size_enc_key   = 128/8; // AES-128
        m_size_enc_iv    = 128/8; // AES-128
        m_size_enc_block = 128/8; // AES-128
        m_alg_mac        = CALG_SHA_256;
        m_size_mac_key   = 256/8; // SHA-256
        m_size_mac_hash  = 256/8; // SHA-256
    } else if (cipher[0] == 0x00 && cipher[1] == 0x6a) {
        // DHE-DSS-AES256-SHA256
        m_prov_name      = MS_ENH_DSS_DH_PROV;
        m_prov_type      = PROV_DSS_DH;
        m_alg_encrypt    = CALG_AES_256;
        m_size_enc_key   = 256/8; // AES-256
        m_size_enc_iv    = 128/8; // AES-256
        m_size_enc_block = 128/8; // AES-256
        m_alg_mac        = CALG_SHA_256;
        m_size_mac_key   = 256/8; // SHA-256
        m_size_mac_hash  = 256/8; // SHA-256
    } else if (cipher[0] == 0x00 && cipher[1] == 0x6b) {
        // DHE-RSA-AES256-SHA256
        m_prov_name      = MS_DEF_DH_SCHANNEL_PROV;
        m_prov_type      = PROV_DH_SCHANNEL;
        m_alg_encrypt    = CALG_AES_256;
        m_size_enc_key   = 256/8; // AES-256
        m_size_enc_iv    = 128/8; // AES-256
        m_size_enc_block = 128/8; // AES-256
        m_alg_mac        = CALG_SHA_256;
        m_size_mac_key   = 256/8; // SHA-256
        m_size_mac_hash  = 256/8; // SHA-256
    } else if (cipher[0] == 0xc0 && cipher[1] == 0x23) {
        // ECDHE-ECDSA-AES128-SHA256
        m_prov_name      = MS_ENH_DSS_DH_PROV;
        m_prov_type      = PROV_DSS_DH;
        m_alg_encrypt    = CALG_AES_128;
        m_size_enc_key   = 128/8; // AES-128
        m_size_enc_iv    = 128/8; // AES-128
        m_size_enc_block = 128/8; // AES-128
        m_alg_mac        = CALG_SHA_256;
        m_size_mac_key   = 256/8; // SHA-256
        m_size_mac_hash  = 256/8; // SHA-256
    } else if (cipher[0] == 0xc0 && cipher[1] == 0x24) {
        // ECDHE-ECDSA-AES256-SHA384
        m_prov_name      = MS_ENH_DSS_DH_PROV;
        m_prov_type      = PROV_DSS_DH;
        m_alg_encrypt    = CALG_AES_256;
        m_size_enc_key   = 256/8; // AES-256
        m_size_enc_iv    = 128/8; // AES-256
        m_size_enc_block = 128/8; // AES-256
        m_alg_mac        = CALG_SHA_384;
        m_size_mac_key   = 384/8; // SHA-384
        m_size_mac_hash  = 384/8; // SHA-384
    } else if (cipher[0] == 0xc0 && cipher[1] == 0x27) {
        // ECDHE-RSA-AES128-SHA256
        m_prov_name      = MS_ENH_DSS_DH_PROV;
        m_prov_type      = PROV_DSS_DH;
        m_alg_encrypt    = CALG_AES_128;
        m_size_enc_key   = 128/8; // AES-128
        m_size_enc_iv    = 128/8; // AES-128
        m_size_enc_block = 128/8; // AES-128
        m_alg_mac        = CALG_SHA_256;
        m_size_mac_key   = 256/8; // SHA-256
        m_size_mac_hash  = 256/8; // SHA-256
    } else if (cipher[0] == 0xc0 && cipher[1] == 0x28) {
        // ECDHE-RSA-AES256-SHA384
        m_prov_name      = MS_ENH_DSS_DH_PROV;
        m_prov_type      = PROV_DSS_DH;
        m_alg_encrypt    = CALG_AES_256;
        m_size_enc_key   = 256/8; // AES-256
        m_size_enc_iv    = 128/8; // AES-256
        m_size_enc_block = 128/8; // AES-256
        m_alg_mac        = CALG_SHA_384;
        m_size_mac_key   = 384/8; // SHA-384
        m_size_mac_hash  = 384/8; // SHA-384
    } else
        throw win_runtime_error(ERROR_NOT_SUPPORTED, string_printf(__FUNCTION__ " Unknown cipher (received 0x%02x%02x).", cipher[0], cipher[1]));
}


//////////////////////////////////////////////////////////////////////
// eap::packet_tls
//////////////////////////////////////////////////////////////////////

eap::packet_tls::packet_tls() :
    m_flags(0),
    packet()
{
}


eap::packet_tls::packet_tls(_In_ const packet_tls &other) :
    m_flags(other.m_flags),
    packet (other        )
{
}


eap::packet_tls::packet_tls(_Inout_ packet_tls &&other) :
    m_flags(std::move(other.m_flags)),
    packet (std::move(other        ))
{
}


eap::packet_tls& eap::packet_tls::operator=(_In_ const packet_tls &other)
{
    if (this != std::addressof(other)) {
        (packet&)*this = other;
        m_flags = other.m_flags;
    }

    return *this;
}


eap::packet_tls& eap::packet_tls::operator=(_Inout_ packet_tls &&other)
{
    if (this != std::addressof(other)) {
        (packet&)*this = std::move(other);
        m_flags = std::move(other.m_flags);
    }

    return *this;
}


void eap::packet_tls::clear()
{
    packet::clear();
    m_flags = 0;
}


bool eap::packet_tls::append_frag(_In_ const EapPacket *pck)
{
    assert(pck);

    // Get packet data pointer and size for more readable code later on.
    const unsigned char *packet_data_ptr;
    size_t size_packet_data;
    if (pck->Data[1] & flags_req_length_incl) {
        // Length field is included.
        packet_data_ptr  = pck->Data + 6;
        size_packet_data = ntohs(*(unsigned short*)pck->Length) - 10;
    } else {
        // Length field not included.
        packet_data_ptr  = pck->Data + 2;
        size_packet_data = ntohs(*(unsigned short*)pck->Length) - 6;
    }

    // Do the EAP-TLS defragmentation.
    if (pck->Data[1] & flags_req_more_frag) {
        if (m_data.empty()) {
            // Start a new packet.
            if (pck->Data[1] & flags_req_length_incl) {
                // Preallocate data according to the Length field.
                size_t size_tot  = ntohl(*(unsigned int*)(pck->Data + 2));
                m_data.reserve(size_tot);
                //m_module.log_event(&EAPMETHOD_PACKET_RECV_FRAG_FIRST, event_data((unsigned int)eap_type_tls), event_data((unsigned int)size_packet_data), event_data((unsigned int)size_tot), event_data::blank);
            } else {
                // The Length field was not included. Odd. Nevermind, no pre-allocation then.
                //m_module.log_event(&EAPMETHOD_PACKET_RECV_FRAG_FIRST1, event_data((unsigned int)eap_type_tls), event_data((unsigned int)size_packet_data), event_data::blank);
            }
        } else {
            // Mid fragment received.
            //m_module.log_event(&EAPMETHOD_PACKET_RECV_FRAG_MID, event_data((unsigned int)eap_type_tls), event_data((unsigned int)size_packet_data), event_data((unsigned int)m_data.size()), event_data::blank);
        }
        m_data.insert(m_data.end(), packet_data_ptr, packet_data_ptr + size_packet_data);

        return false;
    } else if (!m_data.empty()) {
        // Last fragment received. Append data.
        m_data.insert(m_data.end(), packet_data_ptr, packet_data_ptr + size_packet_data);
        //m_module.log_event(&EAPMETHOD_PACKET_RECV_FRAG_LAST, event_data((unsigned int)eap_type_tls), event_data((unsigned int)size_packet_data), event_data((unsigned int)m_data.size()), event_data::blank);
    } else {
        // This is a complete non-fragmented packet.
        m_data.assign(packet_data_ptr, packet_data_ptr + size_packet_data);
        //m_module.log_event(&EAPMETHOD_PACKET_RECV, event_data((unsigned int)eap_type_tls), event_data((unsigned int)size_packet_data), event_data::blank);
    }

    m_code  = (EapCode)pck->Code;
    m_id    = pck->Id;
    m_flags = pck->Data[1];

    return true;
}


unsigned short eap::packet_tls::get_frag(_Out_bytecap_(size_pck) EapPacket *pck, _In_ size_t size_max)
{
    assert(pck);

    size_t size_data = m_data.size();
    assert(size_data <= UINT_MAX - 6); // Packets spanning over 4GB are not supported by EAP.
    unsigned int size_packet = (unsigned int)size_data + 6;
    unsigned short size_packet_limit = (unsigned short)std::min<size_t>(size_max, USHRT_MAX);
    unsigned char *data_dst;

    if (!(m_flags & flags_res_more_frag)) {
        // Not fragmented.
        if (size_packet <= size_packet_limit) {
            // No need to fragment the packet.
            m_flags &= ~flags_res_length_incl; // No need to explicitly include the Length field either.
            data_dst = pck->Data + 2;
            //m_module.log_event(&EAPMETHOD_PACKET_SEND, event_data((unsigned int)eap_type_tls), event_data((unsigned int)size_data), event_data::blank);
        } else {
            // But it should be fragmented.
            m_flags |= flags_res_length_incl | flags_res_more_frag;
            *(unsigned int*)(pck->Data + 2) = htonl(size_packet);
            data_dst    = pck->Data + 6;
            size_data   = size_packet_limit - 10;
            size_packet = size_packet_limit;
            //m_module.log_event(&EAPMETHOD_PACKET_SEND_FRAG_FIRST, event_data((unsigned int)eap_type_tls), event_data((unsigned int)size_data), event_data((unsigned int)(m_data.size() - size_data)), event_data::blank);
        }
    } else {
        // Continuing the fragmented packet...
        if (size_packet > size_packet_limit) {
            // This is a mid fragment.
            m_flags &= ~flags_res_length_incl;
            size_data   = size_packet_limit - 6;
            size_packet = size_packet_limit;
            //m_module.log_event(&EAPMETHOD_PACKET_SEND_FRAG_MID, event_data((unsigned int)eap_type_tls), event_data((unsigned int)size_data), event_data((unsigned int)(m_data.size() - size_data)), event_data::blank);
        } else {
            // This is the last fragment.
            m_flags &= ~(flags_res_length_incl | flags_res_more_frag);
            //m_module.log_event(&EAPMETHOD_PACKET_SEND_FRAG_LAST, event_data((unsigned int)eap_type_tls), event_data((unsigned int)size_data), event_data((unsigned int)(m_data.size() - size_data)), event_data::blank);
        }
        data_dst = pck->Data + 2;
    }

    pck->Code = (BYTE)m_code;
    pck->Id   = m_id;
    *(unsigned short*)pck->Length = htons((unsigned short)size_packet);
    pck->Data[0] = (BYTE)eap_type_tls;
    pck->Data[1] = m_flags;
    memcpy(data_dst, m_data.data(), size_data);
    m_data.erase(m_data.begin(), m_data.begin() + size_data);
    return (unsigned short)size_packet;
}
