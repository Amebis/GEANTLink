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

#include "../../EAPBase/include/EAP.h"

namespace eap
{
    ///
    /// TLS packet type
    ///
    /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter: A.1. Record Layer](https://tools.ietf.org/html/rfc5246#appendix-A.1)
    ///
    enum tls_message_type_t;

    ///
    /// TLS handshake type
    ///
    /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter: A.4. Handshake Protocol](https://tools.ietf.org/html/rfc5246#appendix-A.4)
    ///
    enum tls_handshake_type_t;

    ///
    /// TLS alert level
    ///
    /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter: 7.2. Alert Protocol)](https://tools.ietf.org/html/rfc5246#section-7.2)
    ///
    enum tls_alert_level_t;

    ///
    /// TLS alert description
    ///
    /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter: 7.2. Alert Protocol)](https://tools.ietf.org/html/rfc5246#section-7.2)
    ///
    enum tls_alert_desc_t;

    ///
    /// TLS client/server tls_random
    ///
    struct tls_random;

    ///
    /// Master secret
    ///
    /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (8.1. Computing the Master Secret)](https://tools.ietf.org/html/rfc5246#section-8.1)
    ///
    struct tls_master_secret;

    ///
    /// TLS client connection state
    ///
    /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter 6.1. Connection States)](https://tools.ietf.org/html/rfc5246#section-6.1)
    ///
    class tls_conn_state;

    ///
    /// Our own implementation of HMAC hashing
    /// Microsoft's implementation ([MSDN](https://msdn.microsoft.com/en-us/library/windows/desktop/aa382379.aspx)) is flaky.
    ///
    /// \sa [HMAC: Keyed-Hashing for Message Authentication](https://tools.ietf.org/html/rfc2104)
    ///
    class hash_hmac;
}

///
/// Packs a TLS tls_random
///
/// \param[inout] cursor  Memory cursor
/// \param[in]    val     Variable with data to pack
///
inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const eap::tls_random &val);

///
/// Returns packed size of TLS tls_random
///
/// \param[in] val  Data to pack
///
/// \returns Size of data when packed (in bytes)
///
inline size_t pksizeof(_In_ const eap::tls_random &val);

///
/// Unpacks a TLS tls_random
///
/// \param[inout] cursor  Memory cursor
/// \param[out]   val     Variable to receive unpacked value
///
inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ eap::tls_random &val);

///
/// Packs a TLS master secret
///
/// \param[inout] cursor  Memory cursor
/// \param[in]    val     Variable with data to pack
///
inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const eap::tls_master_secret &val);

///
/// Returns packed size of TLS master secret
///
/// \param[in] val  Data to pack
///
/// \returns Size of data when packed (in bytes)
///
inline size_t pksizeof(_In_ const eap::tls_master_secret &val);

///
/// Unpacks a TLS master secret
///
/// \param[inout] cursor  Memory cursor
/// \param[out]   val     Variable to receive unpacked value
///
inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ eap::tls_master_secret &val);

///
/// Packs a TLS connection state
///
/// \param[inout] cursor  Memory cursor
/// \param[in]    val     Variable with data to pack
///
inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const eap::tls_conn_state &val);

///
/// Returns packed size of TLS connection state
///
/// \param[in] val  Data to pack
///
/// \returns Size of data when packed (in bytes)
///
inline size_t pksizeof(_In_ const eap::tls_conn_state &val);

///
/// Unpacks a TLS connection state
///
/// \param[inout] cursor  Memory cursor
/// \param[out]   val     Variable to receive unpacked value
///
inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ eap::tls_conn_state &val);

#pragma once


namespace eap
{
    enum tls_message_type_t {
        tls_message_type_change_cipher_spec = 20,
        tls_message_type_alert              = 21,
        tls_message_type_handshake          = 22,
        tls_message_type_application_data   = 23,
    };


    enum tls_handshake_type_t {
        tls_handshake_type_hello_request       =  0,
        tls_handshake_type_client_hello        =  1,
        tls_handshake_type_server_hello        =  2,
        tls_handshake_type_certificate         = 11,
        tls_handshake_type_server_key_exchange = 12,
        tls_handshake_type_certificate_request = 13,
        tls_handshake_type_server_hello_done   = 14,
        tls_handshake_type_certificate_verify  = 15,
        tls_handshake_type_client_key_exchange = 16,
        tls_handshake_type_finished            = 20
    };


    enum tls_alert_level_t {
        tls_alert_level_warning = 1,
        tls_alert_level_fatal   = 2,
    };


    enum tls_alert_desc_t {
        tls_alert_desc_close_notify            =   0,
        tls_alert_desc_unexpected_message      =  10,
        tls_alert_desc_bad_record_mac          =  20,
        tls_alert_desc_decryption_failed       =  21, // reserved
        tls_alert_desc_record_overflow         =  22,
        tls_alert_desc_decompression_failure   =  30,
        tls_alert_desc_handshake_failure       =  40,
        tls_alert_desc_no_certificate          =  41, // reserved
        tls_alert_desc_bad_certificate         =  42,
        tls_alert_desc_unsupported_certificate =  43,
        tls_alert_desc_certificate_revoked     =  44,
        tls_alert_desc_certificate_expired     =  45,
        tls_alert_desc_certificate_unknown     =  46,
        tls_alert_desc_illegal_parameter       =  47,
        tls_alert_desc_unknown_ca              =  48,
        tls_alert_desc_access_denied           =  49,
        tls_alert_desc_decode_error            =  50,
        tls_alert_desc_decrypt_error           =  51,
        tls_alert_desc_export_restriction      =  60, // reserved
        tls_alert_desc_protocol_version        =  70,
        tls_alert_desc_insufficient_security   =  71,
        tls_alert_desc_internal_error          =  80,
        tls_alert_desc_user_canceled           =  90,
        tls_alert_desc_no_renegotiation        = 100,
        tls_alert_desc_unsupported_extension   = 110,
    };


#pragma pack(push)
#pragma pack(1)
    struct tls_random
    {
        unsigned char data[32]; ///< Randomness

        ///
        /// Constructs a all-zero tls_random
        ///
        tls_random();

        ///
        /// Copies a tls_random
        ///
        /// \param[in] other  Random to copy from
        ///
        tls_random(_In_ const tls_random &other);

        ///
        /// Destructor
        ///
        ~tls_random();

        ///
        /// Copies a tls_random
        ///
        /// \param[in] other  Random to copy from
        ///
        /// \returns Reference to this object
        ///
        tls_random& operator=(_In_ const tls_random &other);

        ///
        /// Empty the tls_random
        ///
        void clear();

        ///
        /// Generate tls_random
        ///
        /// \param[in] cp  Handle of the cryptographics provider
        ///
        void reset(_In_ HCRYPTPROV cp);
    };
#pragma pack(pop)


#pragma pack(push)
#pragma pack(1)
    struct tls_master_secret
    {
        unsigned char data[48];

        ///
        /// Constructs a all-zero master secret
        ///
        tls_master_secret();

        ///
        /// Constructs a pre-master secret
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter 7.4.7.1. RSA-Encrypted Premaster Secret Message)](https://tools.ietf.org/html/rfc5246#section-7.4.7.1)
        ///
        /// \param[in] cp  Handle of the cryptographics provider
        ///
        tls_master_secret(_In_ HCRYPTPROV cp);

        ///
        /// Copies a master secret
        ///
        /// \param[in] other  Random to copy from
        ///
        tls_master_secret(_In_ const tls_master_secret &other);

        ///
        /// Destructor
        ///
        ~tls_master_secret();

        ///
        /// Copies a master secret
        ///
        /// \param[in] other  Random to copy from
        ///
        /// \returns Reference to this object
        ///
        tls_master_secret& operator=(_In_ const tls_master_secret &other);

        ///
        /// Empty the master secret
        ///
        void clear();
    };
#pragma pack(pop)


    class tls_conn_state
    {
    public:
        ///
        /// Constructs a connection state
        ///
        tls_conn_state();

        ///
        /// Copies a connection state
        ///
        /// \param[in] other  Connection state to copy from
        ///
        tls_conn_state(_In_ const tls_conn_state &other);

        ///
        /// Moves a connection state
        ///
        /// \param[in] other  Connection state to move from
        ///
        tls_conn_state(_Inout_ tls_conn_state &&other);

        ///
        /// Copies a connection state
        ///
        /// \param[in] other  Connection state to copy from
        ///
        /// \returns Reference to this object
        ///
        tls_conn_state& operator=(_In_ const tls_conn_state &other);

        ///
        /// Moves a connection state
        ///
        /// \param[in] other  Connection state to move from
        ///
        /// \returns Reference to this object
        ///
        tls_conn_state& operator=(_Inout_ tls_conn_state &&other);

    public:
        ALG_ID m_alg_prf;                   ///> Pseudo-tls_random function algorithm
        ALG_ID m_alg_encrypt;               ///> Bulk encryption algorithm
        size_t m_size_enc_key;              ///> Encryption key size in bytes (has to comply with `m_alg_encrypt`)
        size_t m_size_enc_iv;               ///> Encryption initialization vector size in bytes (has to comply with `m_alg_encrypt`)
        ALG_ID m_alg_mac;                   ///> Message authenticy check algorithm
        size_t m_size_mac_key;              ///> Message authenticy check algorithm key size (has to comply with `m_alg_mac`)
        size_t m_size_mac_hash;             ///> Message authenticy check algorithm result size (has to comply with `m_alg_mac`)
        tls_master_secret m_master_secret;  ///< TLS master secret
        tls_random m_random_client;         ///< Client tls_random
        tls_random m_random_server;         ///< Server tls_random
    };


    class hash_hmac
    {
    public:
        typedef unsigned char padding_t[64];

    public:
        ///
        /// Construct new HMAC hashing object
        ///
        /// \param[in] cp           Handle of the cryptographics provider
        /// \param[in] alg          Hashing algorithm
        /// \param[in] secret       HMAC secret
        /// \param[in] size_secret  \p secret size
        ///
        hash_hmac(
            _In_                               HCRYPTPROV cp,
            _In_                               ALG_ID     alg,
            _In_bytecount_(size_secret ) const void       *secret,
            _In_                               size_t     size_secret);

        ///
        /// Construct new HMAC hashing object using already prepared inner padding
        ///
        /// \param[in] cp           Handle of the cryptographics provider
        /// \param[in] alg          Hashing algorithm
        /// \param[in] padding      HMAC secret XOR inner padding
        ///
        hash_hmac(
            _In_       HCRYPTPROV cp,
            _In_       ALG_ID     alg,
            _In_ const padding_t  padding);

        ///
        /// Provides access to inner hash object to hash data at will.
        ///
        /// \returns Inner hashing object handle
        ///
        inline operator HCRYPTHASH()
        {
            return m_hash_inner;
        }

        ///
        /// Completes hashing and returns hashed data.
        ///
        /// \param[out] val  Calculated hash value
        ///
        template<class _Ty, class _Ax>
        inline void calculate(_Out_ std::vector<_Ty, _Ax> &val)
        {
            // Calculate inner hash.
            if (!CryptGetHashParam(m_hash_inner, HP_HASHVAL, val, 0))
                throw win_runtime_error(__FUNCTION__ " Error calculating inner hash.");

            // Hash inner hash with outer hash.
            if (!CryptHashData(m_hash_outer, (const BYTE*)val.data(), (DWORD)(val.size() * sizeof(_Ty)), 0))
                throw win_runtime_error(__FUNCTION__ " Error hashing inner hash.");

            // Calculate outer hash.
            if (!CryptGetHashParam(m_hash_outer, HP_HASHVAL, val, 0))
                throw win_runtime_error(__FUNCTION__ " Error calculating outer hash.");
        }

        ///
        /// Helper method to pre-derive inner padding for frequent reuse
        ///
        /// \param[in]  cp           Handle of the cryptographics provider
        /// \param[in]  alg          Hashing algorithm
        /// \param[in]  secret       HMAC secret
        /// \param[in]  size_secret  \p secret size
        /// \param[out] padding      HMAC secret XOR inner padding
        ///
        static void inner_padding(
            _In_                               HCRYPTPROV cp,
            _In_                               ALG_ID     alg,
            _In_bytecount_(size_secret ) const void       *secret,
            _In_                               size_t     size_secret,
            _Out_                              padding_t  padding);

    protected:
        winstd::crypt_hash m_hash_inner; ///< Inner hashing object
        winstd::crypt_hash m_hash_outer; ///< Outer hashing object
    };
}


inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const eap::tls_random &val)
{
    eap::cursor_out::ptr_type ptr_end = cursor.ptr + sizeof(eap::tls_random);
    assert(ptr_end <= cursor.ptr_end);
    memcpy(cursor.ptr, val.data, sizeof(eap::tls_random));
    cursor.ptr = ptr_end;
}


inline size_t pksizeof(_In_ const eap::tls_random &val)
{
    UNREFERENCED_PARAMETER(val);
    return sizeof(eap::tls_random);
}


inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ eap::tls_random &val)
{
    eap::cursor_in::ptr_type ptr_end = cursor.ptr + sizeof(eap::tls_random);
    assert(ptr_end <= cursor.ptr_end);
    memcpy(val.data, cursor.ptr, sizeof(eap::tls_random));
    cursor.ptr = ptr_end;
}


inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const eap::tls_master_secret &val)
{
    eap::cursor_out::ptr_type ptr_end = cursor.ptr + sizeof(eap::tls_master_secret);
    assert(ptr_end <= cursor.ptr_end);
    memcpy(cursor.ptr, val.data, sizeof(eap::tls_master_secret));
    cursor.ptr = ptr_end;
}


inline size_t pksizeof(_In_ const eap::tls_master_secret &val)
{
    UNREFERENCED_PARAMETER(val);
    return sizeof(eap::tls_master_secret);
}


inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ eap::tls_master_secret &val)
{
    eap::cursor_in::ptr_type ptr_end = cursor.ptr + sizeof(eap::tls_master_secret);
    assert(ptr_end <= cursor.ptr_end);
    memcpy(val.data, cursor.ptr, sizeof(eap::tls_master_secret));
    cursor.ptr = ptr_end;
}


inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const eap::tls_conn_state &val)
{
    cursor << val.m_master_secret;
    cursor << val.m_random_client;
    cursor << val.m_random_server;
}


inline size_t pksizeof(_In_ const eap::tls_conn_state &val)
{
    return
        pksizeof(val.m_master_secret) +
        pksizeof(val.m_random_client) +
        pksizeof(val.m_random_server);
}


inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ eap::tls_conn_state &val)
{
    cursor >> val.m_master_secret;
    cursor >> val.m_random_client;
    cursor >> val.m_random_server;
}
