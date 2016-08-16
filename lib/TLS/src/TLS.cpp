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
