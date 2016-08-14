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
// eap::tls_random
//////////////////////////////////////////////////////////////////////

eap::tls_random::tls_random()
{
    memset(data, 0, sizeof(data));
}


eap::tls_random::tls_random(_In_ const tls_random &other)
{
    memcpy(data, other.data, sizeof(data));
}


eap::tls_random::~tls_random()
{
    SecureZeroMemory(data, sizeof(data));
}


eap::tls_random& eap::tls_random::operator=(_In_ const tls_random &other)
{
    if (this != std::addressof(other))
        memcpy(data, other.data, sizeof(data));

    return *this;
}


void eap::tls_random::clear()
{
    memset(data, 0, sizeof(data));
}


void eap::tls_random::reset(_In_ HCRYPTPROV cp)
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
    memset(data, 0, sizeof(data));
}


eap::tls_master_secret::tls_master_secret(_In_ HCRYPTPROV cp)
{
    data[0] = 3;
    data[1] = 1;

    if (!CryptGenRandom(cp, sizeof(data) - 2, data + 2))
        throw win_runtime_error(__FUNCTION__ " Error creating PMS randomness.");
}


eap::tls_master_secret::tls_master_secret(_In_ const tls_master_secret &other)
{
    memcpy(data, other.data, sizeof(data));
}


eap::tls_master_secret::~tls_master_secret()
{
    SecureZeroMemory(data, sizeof(data));
}


eap::tls_master_secret& eap::tls_master_secret::operator=(_In_ const tls_master_secret &other)
{
    if (this != std::addressof(other))
        memcpy(data, other.data, sizeof(data));

    return *this;
}


void eap::tls_master_secret::clear()
{
    memset(data, 0, sizeof(data));
}


//////////////////////////////////////////////////////////////////////
// eap::tls_conn_state
//////////////////////////////////////////////////////////////////////

eap::tls_conn_state::tls_conn_state() :
    m_alg_prf       (0),
    m_alg_encrypt   (0),
    m_size_enc_key  (0),
    m_size_enc_iv   (0),
    m_size_enc_block(0),
    m_alg_mac       (0),
    m_size_mac_key  (0),
    m_size_mac_hash (0)
{
}


eap::tls_conn_state::tls_conn_state(_In_ const tls_conn_state &other) :
    m_master_secret(other.m_master_secret),
    m_random_client(other.m_random_client),
    m_random_server(other.m_random_server)
{
}


eap::tls_conn_state::tls_conn_state(_Inout_ tls_conn_state &&other) :
    m_master_secret(std::move(other.m_master_secret)),
    m_random_client(std::move(other.m_random_client)),
    m_random_server(std::move(other.m_random_server))
{
}


eap::tls_conn_state& eap::tls_conn_state::operator=(_In_ const tls_conn_state &other)
{
    if (this != std::addressof(other)) {
        m_master_secret = other.m_master_secret;
        m_random_client = other.m_random_client;
        m_random_server = other.m_random_server;
    }

    return *this;
}


eap::tls_conn_state& eap::tls_conn_state::operator=(_Inout_ tls_conn_state &&other)
{
    if (this != std::addressof(other)) {
        m_master_secret = std::move(other.m_master_secret);
        m_random_client = std::move(other.m_random_client);
        m_random_server = std::move(other.m_random_server);
    }

    return *this;
}


//////////////////////////////////////////////////////////////////////
// eap::hash_hmac
//////////////////////////////////////////////////////////////////////

eap::hash_hmac::hash_hmac(
    _In_                               HCRYPTPROV cp,
    _In_                               ALG_ID     alg,
    _In_bytecount_(size_secret ) const void       *secret,
    _In_                               size_t     size_secret)
{
    // Prepare padding.
    sanitizing_blob padding(sizeof(padding_t));
    inner_padding(cp, alg, secret, size_secret, padding.data());

    // Continue with the other constructor.
    this->hash_hmac::hash_hmac(cp, alg, padding.data());
}


eap::hash_hmac::hash_hmac(
    _In_       HCRYPTPROV cp,
    _In_       ALG_ID     alg,
    _In_ const padding_t  padding)
{
    // Create inner hash.
    if (!m_hash_inner.create(cp, alg))
        throw win_runtime_error(__FUNCTION__ " Error creating inner hash.");

    // Initialize it with the inner padding.
    if (!CryptHashData(m_hash_inner, padding, sizeof(padding_t), 0))
        throw win_runtime_error(__FUNCTION__ " Error hashing secret XOR inner padding.");

    // Convert inner padding to outer padding for final calculation.
    padding_t padding_out;
    for (size_t i = 0; i < sizeof(padding_t); i++)
        padding_out[i] = padding[i] ^ (0x36 ^ 0x5c);

    // Create outer hash.
    if (!m_hash_outer.create(cp, alg))
        throw win_runtime_error(__FUNCTION__ " Error creating outer hash.");

    // Initialize it with the outer padding.
    if (!CryptHashData(m_hash_outer, padding_out, sizeof(padding_t), 0))
        throw win_runtime_error(__FUNCTION__ " Error hashing secret XOR inner padding.");
}


void eap::hash_hmac::inner_padding(
    _In_                               HCRYPTPROV cp,
    _In_                               ALG_ID     alg,
    _In_bytecount_(size_secret ) const void       *secret,
    _In_                               size_t     size_secret,
    _Out_                              padding_t  padding)
{
    if (size_secret > sizeof(padding_t)) {
        // If the secret is longer than padding, use secret's hash instead.
        crypt_hash hash;
        if (!hash.create(cp, alg))
            throw win_runtime_error(__FUNCTION__ " Error creating hash.");
        if (!CryptHashData(hash, (const BYTE*)secret, (DWORD)size_secret, 0))
            throw win_runtime_error(__FUNCTION__ " Error hashing.");
        DWORD size_hash = sizeof(padding_t);
        if (!CryptGetHashParam(hash, HP_HASHVAL, padding, &size_hash, 0))
            throw win_runtime_error(__FUNCTION__ " Error finishing hash.");
        size_secret = size_hash;
    } else
        memcpy(padding, secret, size_secret);
    for (size_t i = 0; i < size_secret; i++)
        padding[i] ^= 0x36;
    memset(padding + size_secret, 0x36, sizeof(padding_t) - size_secret);
}
