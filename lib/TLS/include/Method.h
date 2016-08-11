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

namespace eap
{
    ///
    /// EAP-TLS method
    ///
    class method_tls;
}

#pragma once

#include "../include/Config.h"
#include "../include/Credentials.h"

#include "../../EAPBase/include/Method.h"

#include <WinStd/Crypt.h>

#include <list>
#include <vector>


namespace eap
{
    class method_tls : public method
    {
    public:
        ///
        /// EAP-TLS request packet flags
        ///
        /// \sa [The EAP-TLS Authentication Protocol (Chapter: 3.1 EAP-TLS Request Packet)](https://tools.ietf.org/html/rfc5216#section-3.1)
        ///
        enum flags_req_t {
            flags_req_length_incl = 0x80,   ///< Length included
            flags_req_more_frag   = 0x40,   ///< More fragments
            flags_req_start       = 0x20,   ///< Start
        };

        ///
        /// EAP-TLS response packet flags
        ///
        /// \sa [The EAP-TLS Authentication Protocol (Chapter: 3.2 EAP-TLS Response Packet)](https://tools.ietf.org/html/rfc5216#section-3.2)
        ///
        enum flags_res_t {
            flags_res_length_incl = 0x80,   ///< Length included
            flags_res_more_frag   = 0x40,   ///< More fragments
        };

        ///
        /// TLS packet type
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter: A.1. Record Layer](https://tools.ietf.org/html/rfc5246#appendix-A.1)
        ///
        enum message_type_t  {
            message_type_change_cipher_spec = 20,
            message_type_alert              = 21,
            message_type_handshake          = 22,
            message_type_application_data   = 23,
        };

        ///
        /// TLS handshake type
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter: A.4. Handshake Protocol](https://tools.ietf.org/html/rfc5246#appendix-A.4)
        ///
        enum handshake_type_t {
            handshake_type_hello_request       =  0,
            handshake_type_client_hello        =  1,
            handshake_type_server_hello        =  2,
            handshake_type_certificate         = 11,
            handshake_type_server_key_exchange = 12,
            handshake_type_certificate_request = 13,
            handshake_type_server_hello_done   = 14,
            handshake_type_certificate_verify  = 15,
            handshake_type_client_key_exchange = 16,
            handshake_type_finished            = 20
        };

        ///
        /// TLS alert level
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter: 7.2. Alert Protocol)](https://tools.ietf.org/html/rfc5246#section-7.2)
        ///
        enum alert_level_t {
            alert_level_warning = 1,
            alert_level_fatal   = 2,
        };

        ///
        /// TLS alert description
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter: 7.2. Alert Protocol)](https://tools.ietf.org/html/rfc5246#section-7.2)
        ///
        enum alert_desc_t {
            alert_desc_close_notify            =   0,
            alert_desc_unexpected_message      =  10,
            alert_desc_bad_record_mac          =  20,
            alert_desc_decryption_failed       =  21, // reserved
            alert_desc_record_overflow         =  22,
            alert_desc_decompression_failure   =  30,
            alert_desc_handshake_failure       =  40,
            alert_desc_no_certificate          =  41, // reserved
            alert_desc_bad_certificate         =  42,
            alert_desc_unsupported_certificate =  43,
            alert_desc_certificate_revoked     =  44,
            alert_desc_certificate_expired     =  45,
            alert_desc_certificate_unknown     =  46,
            alert_desc_illegal_parameter       =  47,
            alert_desc_unknown_ca              =  48,
            alert_desc_access_denied           =  49,
            alert_desc_decode_error            =  50,
            alert_desc_decrypt_error           =  51,
            alert_desc_export_restriction      =  60, // reserved
            alert_desc_protocol_version        =  70,
            alert_desc_insufficient_security   =  71,
            alert_desc_internal_error          =  80,
            alert_desc_user_canceled           =  90,
            alert_desc_no_renegotiation        = 100,
            alert_desc_unsupported_extension   = 110,
        };

        ///
        /// EAP-TLS packet (data)
        ///
        class packet
        {
        public:
            ///
            /// Constructs an empty packet
            ///
            packet();

            ///
            /// Copies a packet
            ///
            /// \param[in] other  Packet to copy from
            ///
            packet(_In_ const packet &other);

            ///
            /// Moves a packet
            ///
            /// \param[in] other  Packet to move from
            ///
            packet(_Inout_ packet &&other);

            ///
            /// Copies a packet
            ///
            /// \param[in] other  Packet to copy from
            ///
            /// \returns Reference to this object
            ///
            packet& operator=(_In_ const packet &other);

            ///
            /// Moves a packet
            ///
            /// \param[in] other  Packet to move from
            ///
            /// \returns Reference to this object
            ///
            packet& operator=(_Inout_ packet &&other);

            ///
            /// Empty the packet
            ///
            void clear();

        public:
            EapCode m_code;                             ///< Packet code
            unsigned char m_id;                         ///< Packet ID
            unsigned char m_flags;                      ///< Packet flags
            std::vector<unsigned char> m_data;          ///< Packet data
        };

#pragma pack(push)
#pragma pack(1)
        ///
        /// TLS client/server random
        ///
        struct random
        {
            __time32_t time;        ///< Unix time-stamp
            unsigned char data[28]; ///< Randomness

            ///
            /// Constructs a all-zero random
            ///
            random();

            ///
            /// Copies a random
            ///
            /// \param[in] other  Random to copy from
            ///
            random(_In_ const random &other);

            ///
            /// Destructor
            ///
            ~random();

            ///
            /// Copies a random
            ///
            /// \param[in] other  Random to copy from
            ///
            /// \returns Reference to this object
            ///
            random& operator=(_In_ const random &other);

            ///
            /// Empty the random
            ///
            void clear();

            ///
            /// Generate random
            ///
            /// \param[in] cp  Handle of the cryptographics provider
            ///
            void reset(_In_ HCRYPTPROV cp);
        };
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
        ///
        /// TLS message
        ///
        struct message
        {
            unsigned char type;         ///< Message type (one of `message_type_t` constants)
            struct {
                unsigned char major;    ///< Major version
                unsigned char minor;    ///< Minor version
            } version;                  ///< SSL/TLS version
            unsigned char length[2];    ///< Message length (in network byte order)
            unsigned char data[1];      ///< Message data
        };
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
        ///
        /// Master secret
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (8.1. Computing the Master Secret)](https://tools.ietf.org/html/rfc5246#section-8.1)
        ///
        struct master_secret
        {
            unsigned char data[48];

            ///
            /// Constructs a all-zero master secret
            ///
            master_secret();

            ///
            /// Constructs a pre-master secret
            ///
            /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter 7.4.7.1. RSA-Encrypted Premaster Secret Message)](https://tools.ietf.org/html/rfc5246#section-7.4.7.1)
            ///
            /// \param[in] cp  Handle of the cryptographics provider
            ///
            master_secret(_In_ HCRYPTPROV cp);

            ///
            /// Copies a master secret
            ///
            /// \param[in] other  Random to copy from
            ///
            master_secret(_In_ const master_secret &other);

            ///
            /// Destructor
            ///
            ~master_secret();

            ///
            /// Copies a master secret
            ///
            /// \param[in] other  Random to copy from
            ///
            /// \returns Reference to this object
            ///
            master_secret& operator=(_In_ const master_secret &other);

            ///
            /// Empty the master secret
            ///
            void clear();
        };
#pragma pack(pop)

        ///
        /// Our own implementation of HMAC hashing
        /// Microsoft's implementation ([MSDN](https://msdn.microsoft.com/en-us/library/windows/desktop/aa382379.aspx)) is flaky.
        ///
        /// \sa [HMAC: Keyed-Hashing for Message Authentication](https://tools.ietf.org/html/rfc2104)
        ///
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


        ///
        /// TLS client connection state
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter 6.1. Connection States)](https://tools.ietf.org/html/rfc5246#section-6.1)
        ///
        class conn_state
        {
        public:
            ///
            /// Constructs a connection state
            ///
            conn_state();

            ///
            /// Copies a connection state
            ///
            /// \param[in] other  Connection state to copy from
            ///
            conn_state(_In_ const conn_state &other);

            ///
            /// Moves a connection state
            ///
            /// \param[in] other  Connection state to move from
            ///
            conn_state(_Inout_ conn_state &&other);

            ///
            /// Copies a connection state
            ///
            /// \param[in] other  Connection state to copy from
            ///
            /// \returns Reference to this object
            ///
            conn_state& operator=(_In_ const conn_state &other);

            ///
            /// Moves a connection state
            ///
            /// \param[in] other  Connection state to move from
            ///
            /// \returns Reference to this object
            ///
            conn_state& operator=(_Inout_ conn_state &&other);

        public:
            static const ALG_ID m_alg_prf;          ///> Pseudo-random function algorithm
            static const ALG_ID m_alg_encrypt;      ///> Bulk encryption algorithm
            static const size_t m_size_enc_key;     ///> Encryption key size in bytes (has to comply with `m_alg_encrypt`)
            static const size_t m_size_enc_iv;      ///> Encryption initialization vector size in bytes (has to comply with `m_alg_encrypt`)
            static const ALG_ID m_alg_mac;          ///> Message authenticy check algorithm
            static const size_t m_size_mac_key;     ///> Message authenticy check algorithm key size (has to comply with `m_alg_mac`)
            static const size_t m_size_mac_hash;    ///> Message authenticy check algorithm result size (has to comply with `m_alg_mac`)
            master_secret m_master_secret;          ///< TLS master secret
            random m_random_client;                 ///< Client random
            random m_random_server;                 ///< Server random
        };

    public:
        ///
        /// Constructs an EAP method
        ///
        /// \param[in] mod   EAP module to use for global services
        /// \param[in] cfg   Method configuration
        /// \param[in] cred  User credentials
        ///
        method_tls(_In_ module &module, _In_ config_method_tls &cfg, _In_ credentials_tls &cred);

        ///
        /// Copies an EAP method
        ///
        /// \param[in] other  EAP method to copy from
        ///
        method_tls(_In_ const method_tls &other);

        ///
        /// Moves an EAP method
        ///
        /// \param[in] other  EAP method to move from
        ///
        method_tls(_Inout_ method_tls &&other);

        ///
        /// Copies an EAP method
        ///
        /// \param[in] other  EAP method to copy from
        ///
        /// \returns Reference to this object
        ///
        method_tls& operator=(_In_ const method_tls &other);

        ///
        /// Moves an EAP method
        ///
        /// \param[in] other  EAP method to move from
        ///
        /// \returns Reference to this object
        ///
        method_tls& operator=(_Inout_ method_tls &&other);

        /// \name Packet processing
        /// @{

        ///
        /// Starts an EAP authentication session on the peer EAPHost using the EAP method.
        ///
        /// \sa [EapPeerBeginSession function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363600.aspx)
        ///
        virtual void begin_session(
            _In_        DWORD         dwFlags,
            _In_  const EapAttributes *pAttributeArray,
            _In_        HANDLE        hTokenImpersonateUser,
            _In_        DWORD         dwMaxSendPacketSize);

        ///
        /// Processes a packet received by EAPHost from a supplicant.
        ///
        /// \sa [EapPeerProcessRequestPacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363621.aspx)
        ///
        virtual void process_request_packet(
            _In_bytecount_(dwReceivedPacketSize) const EapPacket           *pReceivedPacket,
            _In_                                       DWORD               dwReceivedPacketSize,
            _Inout_                                    EapPeerMethodOutput *pEapOutput);

        ///
        /// Obtains a response packet from the EAP method.
        ///
        /// \sa [EapPeerGetResponsePacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363610.aspx)
        ///
        virtual void get_response_packet(
            _Inout_bytecap_(*dwSendPacketSize) EapPacket *pSendPacket,
            _Inout_                            DWORD     *pdwSendPacketSize);

        ///
        /// Obtains the result of an authentication session from the EAP method.
        ///
        /// \sa [EapPeerGetResult function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363611.aspx)
        ///
        virtual void get_result(
            _In_    EapPeerMethodResultReason reason,
            _Inout_ EapPeerMethodResult       *ppResult);

        /// @}

    protected:
        ///
        /// Makes a TLS client hello message
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter 7.4.1.2. Client Hello)](https://tools.ietf.org/html/rfc5246#section-7.4.1.2)
        ///
        /// \returns Client hello message
        ///
        sanitizing_blob make_client_hello() const;

        ///
        /// Makes a TLS client certificate message
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter 7.4.6. Client Certificate)](https://tools.ietf.org/html/rfc5246#section-7.4.6)
        ///
        /// \returns Client certificate message
        ///
        sanitizing_blob make_client_cert() const;

        ///
        /// Makes a TLS client key exchange message
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter 7.4.7. Client Key Exchange Message )](https://tools.ietf.org/html/rfc5246#section-7.4.7)
        ///
        /// \param[in] pms_enc  Encoded pre master secret
        ///
        /// \returns Client key exchange message
        ///
        sanitizing_blob make_client_key_exchange(_In_ const sanitizing_blob &pms_enc) const;

        ///
        /// Makes a TLS change cipher spec message
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter A.1. Record Layer)](https://tools.ietf.org/html/rfc5246#appendix-A.1)
        ///
        /// \returns Change cipher spec
        ///
        static eap::sanitizing_blob make_change_chiper_spec();

        ///
        /// Makes a TLS finished message
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter A.1. Record Layer)](https://tools.ietf.org/html/rfc5246#appendix-A.1)
        ///
        /// \returns Change cipher spec
        ///
        eap::sanitizing_blob make_finished();

        ///
        /// Makes a TLS handshake
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter A.1. Record Layer)](https://tools.ietf.org/html/rfc5246#appendix-A.1)
        ///
        /// \param[in]  msg  Handshake data contents
        ///
        /// \returns TLS handshake message
        ///
        static eap::sanitizing_blob make_handshake(_In_ const sanitizing_blob &msg);

        ///
        /// Makes a TLS handshake
        ///
        /// \param[in] msg      Handshake data contents
        /// \param[in] encrypt  Should the message be encrypted?
        ///
        /// \returns TLS handshake message
        ///
        inline eap::sanitizing_blob make_handshake(_In_ const sanitizing_blob &msg, _In_ bool encrypted)
        {
            if (encrypted) {
                // Make unencrypted handshake, encrypt it, then make a new handshake message.
                sanitizing_blob msg_enc(std::move(make_handshake(msg)));
                encrypt_message(msg_enc);
                return make_handshake(msg_enc);
            } else
                return make_handshake(msg);
        }

        ///
        /// Generates keys required by current connection state
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter 6.3. Key Calculation)](https://tools.ietf.org/html/rfc5246#section-6.3)
        ///
        void derive_keys();

        ///
        /// Processes messages in a TLS packet
        ///
        /// \param[in] pck       Packet data
        /// \param[in] size_pck  \p pck size in bytes
        ///
        void process_packet(_In_bytecount_(size_pck) const void *pck, _In_ size_t size_pck);

        ///
        /// Processes a TLS handshake
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter A.1. Record Layer)](https://tools.ietf.org/html/rfc5246#appendix-A.1)
        ///
        /// \param[in] msg      TLS handshake message data
        /// \param[in] msg_size TLS handshake message data size
        ///
        void process_handshake(_In_bytecount_(msg_size) const void *msg, _In_ size_t msg_size);

        ///
        /// Processes a TLS handshake
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter 7.2. Alert Protocol)](https://tools.ietf.org/html/rfc5246#section-7.2)
        ///
        /// \param[in] msg      TLS alert message data
        /// \param[in] msg_size TLS alert message data size
        ///
        void process_alert(_In_bytecount_(msg_size) const void *msg, _In_ size_t msg_size);

        ///
        /// Verifies server's certificate if trusted by configuration
        ///
        void verify_server_trust();

        ///
        /// Encrypt TLS message
        ///
        /// \param[inout] msg         TLS message to encrypt
        ///
        void encrypt_message(_Inout_ sanitizing_blob &msg);

        ///
        /// Decrypt TLS message
        ///
        /// \param[inout] msg  TLS message to decrypt
        ///
        void decrypt_message(_Inout_ sanitizing_blob &msg);

        ///
        /// Calculates pseudo-random P_hash data defined in RFC 5246
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.1 (Chapter 5: HMAC and the Pseudorandom Function)](https://tools.ietf.org/html/rfc4346#section-5)
        ///
        /// \param[in] secret        Hashing secret key
        /// \param[in] size_secret   \p secret size
        /// \param[in] lblseed       Concatenated label and seed
        /// \param[in] size_lblseed  \p lblseed size
        /// \param[in] size          Number of bytes of pseudo-random data required
        ///
        /// \returns Generated pseudo-random data (\p size bytes)
        ///
        sanitizing_blob prf(
            _In_bytecount_(size_secret) const void   *secret,
            _In_                              size_t size_secret,
            _In_bytecount_(size_seed)   const void   *seed,
            _In_                              size_t size_seed,
            _In_                              size_t size);

        ///
        /// Creates a key
        ///
        /// \param[in] alg          Key algorithm
        /// \param[in] secret       Raw key data
        /// \param[in] size_secret  \p secret size
        ///
        /// \returns Key
        ///
        inline HCRYPTKEY create_key(
            _In_                              ALG_ID alg,
            _In_bytecount_(size_secret) const void   *secret,
            _In_                              size_t size_secret)
        {
            assert(size_secret <= 0xffffffff);

            // Prepare exported key BLOB.
            struct key_blob_prefix {
                PUBLICKEYSTRUC header;
                DWORD size;
            } const prefix = {
                {
                    PLAINTEXTKEYBLOB,
                    CUR_BLOB_VERSION,
                    0,
                    alg,
                },
                (DWORD)size_secret,
            };
            sanitizing_blob key_blob;
            key_blob.reserve(sizeof(key_blob_prefix) + size_secret);
            key_blob.assign((const unsigned char*)&prefix, (const unsigned char*)(&prefix + 1));
            key_blob.insert(key_blob.end(), (const unsigned char*)secret, (const unsigned char*)secret + size_secret);

            // Import the key.
            winstd::crypt_key key;
            if (!key.import(m_cp, key_blob.data(), (DWORD)key_blob.size(), NULL, 0))
                throw winstd::win_runtime_error(__FUNCTION__ " Error importing key.");
            return key.detach();
        }

    protected:
        config_method_tls &m_cfg;                               ///< EAP-TLS method configuration
        credentials_tls &m_cred;                                ///< EAP-TLS user credentials

        enum phase_t {
            phase_unknown      = -1,
            phase_client_hello =  0,
            phase_server_hello,
            phase_change_chiper_spec,
            phase_finished,
        } m_phase;                                              ///< Session phase

        packet m_packet_req;                                    ///< Request packet
        packet m_packet_res;                                    ///< Response packet

        winstd::crypt_prov m_cp;                                ///< Cryptography provider

        conn_state m_state;                                     ///< Connection state

        sanitizing_blob m_padding_hmac_client;                  ///< Padding (key) for client side HMAC calculation
        //sanitizing_blob m_padding_hmac_server;                  ///< Padding (key) for server side HMAC calculation
        winstd::crypt_key m_key_client;                         ///< Key for encrypting messages
        winstd::crypt_key m_key_server;                         ///< Key for decrypting messages

        sanitizing_blob m_session_id;                           ///< TLS session ID

        std::list<winstd::cert_context> m_server_cert_chain;    ///< Server certificate chain

        winstd::crypt_hash m_hash_handshake_msgs_md5;           ///< Running MD5 hash of handshake messages sent
        winstd::crypt_hash m_hash_handshake_msgs_sha1;          ///< Running SHA-1 hash of handshake messages sent

        bool m_send_client_cert;                                ///< Did server request client certificate?
        //bool m_server_hello_done;                               ///< Is server hello done?
        bool m_server_finished;                                 ///< Did server send a valid finish message?
        bool m_cipher_spec;                                     ///< Did server specify cipher?

        unsigned __int64 m_seq_num;                             ///< Sequence number for encryption
    };
}
