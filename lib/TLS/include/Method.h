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

#include "Config.h"
#include "Credentials.h"
#include "TLS.h"

#include "../../EAPBase/include/Method.h"

#include <WinStd/Crypt.h>
#include <WinStd/Sec.h>

#include <list>
#include <vector>


namespace eap
{
    class method_tls : public method
    {
    public:
#pragma warning(push)
#pragma warning(disable: 4480)

        ///
        /// EAP-TLS request packet flags
        ///
        /// \sa [The EAP-TLS Authentication Protocol (Chapter: 3.1 EAP-TLS Request Packet)](https://tools.ietf.org/html/rfc5216#section-3.1)
        ///
        enum flags_req_t : unsigned char {
            flags_req_length_incl = 0x80,   ///< Length included
            flags_req_more_frag   = 0x40,   ///< More fragments
            flags_req_start       = 0x20,   ///< Start
        };

        ///
        /// EAP-TLS response packet flags
        ///
        /// \sa [The EAP-TLS Authentication Protocol (Chapter: 3.2 EAP-TLS Response Packet)](https://tools.ietf.org/html/rfc5216#section-3.2)
        ///
        enum flags_res_t : unsigned char {
            flags_res_length_incl = 0x80,   ///< Length included
            flags_res_more_frag   = 0x40,   ///< More fragments
        };

#pragma warning(pop)

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
        /// TLS message
        ///
        struct message_header
        {
            tls_message_type_t type;    ///< Message type (one of `message_type_t` constants)
            tls_version version;        ///< SSL/TLS version
            unsigned char length[2];    ///< Message length (in network byte order)
        };
#pragma pack(pop)

    public:
        ///
        /// Constructs an EAP method
        ///
        /// \param[in] mod   EAP module to use for global services
        /// \param[in] cfg   Connection configuration
        /// \param[in] cred  User credentials
        ///
        method_tls(_In_ module &module, _In_ config_connection &cfg, _In_ credentials_tls &cred);

        ///
        /// Moves an EAP method
        ///
        /// \param[in] other  EAP method to move from
        ///
        method_tls(_Inout_ method_tls &&other);

        ///
        /// Destructor
        ///
        virtual ~method_tls();

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
#if EAP_TLS < EAP_TLS_SCHANNEL
        /// \name Client handshake message generation
        /// @{

        ///
        /// Makes a TLS client hello message
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter 7.4.1.2. Client Hello)](https://tools.ietf.org/html/rfc5246#section-7.4.1.2)
        ///
        /// \returns Client hello message
        ///
        sanitizing_blob make_client_hello();

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
        /// \param[in] pms  Pre-master secret
        ///
        /// \returns Client key exchange message
        ///
        sanitizing_blob make_client_key_exchange(_In_ const tls_master_secret &pms) const;

        ///
        /// Makes a TLS finished message
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter A.1. Record Layer)](https://tools.ietf.org/html/rfc5246#appendix-A.1)
        ///
        /// \returns Change cipher spec
        ///
        eap::sanitizing_blob make_finished() const;

        /// @}

        /// \name Client/Server handshake hashing
        /// @{

        ///
        /// Hashes handshake message for "finished" message validation.
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter 7.4.9. Finished)](https://tools.ietf.org/html/rfc5246#section-7.4.9)
        ///
        /// \param[in] data  Data to hash
        /// \param[in] size  \p data size in bytes
        ///
        inline void hash_handshake(_In_count_(size) const void *data, _In_ size_t size)
        {
            CryptHashData(m_hash_handshake_msgs_md5   , (const BYTE*)data, (DWORD)size, 0);
            CryptHashData(m_hash_handshake_msgs_sha1  , (const BYTE*)data, (DWORD)size, 0);
            CryptHashData(m_hash_handshake_msgs_sha256, (const BYTE*)data, (DWORD)size, 0);
        }

        ///
        /// Hashes handshake message for "finished" message validation.
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter 7.4.9. Finished)](https://tools.ietf.org/html/rfc5246#section-7.4.9)
        ///
        /// \param[in] data  Data to hash
        /// \param[in] size  \p data size in bytes
        ///
        template<class _Ty, class _Ax>
        inline void hash_handshake(_In_ const std::vector<_Ty, _Ax> &data)
        {
            hash_handshake(data.data(), data.size() * sizeof(_Ty));
        }

        /// @}

        ///
        /// Makes a TLS message
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter A.1. Record Layer)](https://tools.ietf.org/html/rfc5246#appendix-A.1)
        ///
        /// \param[in]    type  Message type
        /// \param[inout] data  Message data contents
        ///
        /// \returns TLS message message
        ///
        eap::sanitizing_blob make_message(_In_ tls_message_type_t type, _Inout_ sanitizing_blob &&data);

        /// @}

        /// \name Key derivation
        /// @{

        ///
        /// Generates master session key
        ///
        /// \sa [The EAP-TLS Authentication Protocol (Chapter 2.3. Key Hierarchy)](https://tools.ietf.org/html/rfc5216#section-2.3)
        ///
        virtual void derive_msk();

        /// @}

        /// \name Server message processing
        /// @{

        ///
        /// Processes messages in a TLS packet
        ///
        /// \param[in] pck       Packet data
        /// \param[in] size_pck  \p pck size in bytes
        ///
        void process_packet(_In_bytecount_(size_pck) const void *pck, _In_ size_t size_pck);

        ///
        /// Processes a TLS change_cipher_spec message
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter 7.1. Change Cipher Spec Protocol)](https://tools.ietf.org/html/rfc5246#section-7.1)
        ///
        /// \param[in] msg       TLS change_cipher_spec message data
        /// \param[in] msg_size  TLS change_cipher_spec message data size
        ///
        virtual void process_change_cipher_spec(_In_bytecount_(msg_size) const void *msg, _In_ size_t msg_size);

        ///
        /// Processes a TLS alert message
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter 7.2. Alert Protocol)](https://tools.ietf.org/html/rfc5246#section-7.2)
        ///
        /// \param[in] msg       TLS alert message data
        /// \param[in] msg_size  TLS alert message data size
        ///
        virtual void process_alert(_In_bytecount_(msg_size) const void *msg, _In_ size_t msg_size);

        ///
        /// Processes a TLS handshake message
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter 7.4. Handshake Protocol)](https://tools.ietf.org/html/rfc5246#section-7.4)
        ///
        /// \param[in] msg       TLS handshake message data
        /// \param[in] msg_size  TLS handshake message data size
        ///
        virtual void process_handshake(_In_bytecount_(msg_size) const void *msg, _In_ size_t msg_size);

#else
        ///
        /// Process handshake
        ///
        void process_handshake();

        ///
        /// Process application data
        ///
        void process_application_data();
#endif

        ///
        /// Processes a TLS application_data message
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter 10. Application Data Protocol)](https://tools.ietf.org/html/rfc5246#section-10)
        ///
        /// \param[in] msg       TLS application_data message data
        /// \param[in] msg_size  TLS application_data message data size
        ///
        virtual void process_application_data(_In_bytecount_(msg_size) const void *msg, _In_ size_t msg_size);

        /// @}

#if EAP_TLS < EAP_TLS_SCHANNEL_FULL
        ///
        /// Verifies server's certificate if trusted by configuration
        ///
        void verify_server_trust() const;
#endif

#if EAP_TLS < EAP_TLS_SCHANNEL
        /// \name Encryption
        /// @{

        ///
        /// Encrypt TLS message
        ///
        /// \param[in]    type  Message type
        /// \param[inout] data  TLS message to encrypt
        ///
        void encrypt_message(_In_ tls_message_type_t type, _Inout_ sanitizing_blob &data);

        ///
        /// Decrypt TLS message
        ///
        /// \param[in]    type  Original message type for HMAC verification
        /// \param[inout] data  TLS message to decrypt
        ///
        void decrypt_message(_In_ tls_message_type_t type, _Inout_ sanitizing_blob &data);

        /// @}

        /// \name Pseudo-random generation
        /// @{

        ///
        /// Calculates pseudo-random P_hash data defined in RFC 5246
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.1 (Chapter 5. HMAC and the Pseudorandom Function)](https://tools.ietf.org/html/rfc4346#section-5)
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter 5. HMAC and the Pseudorandom Function)](https://tools.ietf.org/html/rfc5246#section-5)
        ///
        /// \param[in] cp         Handle of the cryptographics provider
        /// \param[in] alg        Hashing Algorithm to use (CALG_TLS1PRF = combination of MD5 and SHA-1, CALG_SHA_256...)
        /// \param[in] secret     Hashing secret key
        /// \param[in] seed       Random seed
        /// \param[in] size_seed  \p seed size
        /// \param[in] size       Number of bytes of pseudo-random data required
        ///
        /// \returns Generated pseudo-random data (\p size bytes)
        ///
        static sanitizing_blob prf(
            _In_                            HCRYPTPROV        cp,
            _In_                            ALG_ID            alg,
            _In_                      const tls_master_secret &secret,
            _In_bytecount_(size_seed) const void              *seed,
            _In_                            size_t            size_seed,
            _In_                            size_t            size);

        ///
        /// Calculates pseudo-random P_hash data defined in RFC 5246
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.1 (Chapter 5. HMAC and the Pseudorandom Function)](https://tools.ietf.org/html/rfc4346#section-5)
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter 5. HMAC and the Pseudorandom Function)](https://tools.ietf.org/html/rfc5246#section-5)
        ///
        /// \param[in] cp      Handle of the cryptographics provider
        /// \param[in] alg     Hashing Algorithm to use (CALG_TLS1PRF = combination of MD5 and SHA-1, CALG_SHA_256...)
        /// \param[in] secret  Hashing secret key
        /// \param[in] seed    Random seed
        /// \param[in] size    Number of bytes of pseudo-random data required
        ///
        /// \returns Generated pseudo-random data (\p size bytes)
        ///
        template<class _Ty, class _Ax>
        inline static sanitizing_blob prf(
            _In_       HCRYPTPROV            cp,
            _In_       ALG_ID                alg,
            _In_ const tls_master_secret     &secret,
            _In_ const std::vector<_Ty, _Ax> &seed,
            _In_       size_t                size)
        {
            return prf(cp, alg, secret, seed.data(), seed.size() * sizeof(_Ty), size);
        }

        /// @}

        ///
        /// Creates a key
        ///
        /// \sa [How to export and import plain text session keys by using CryptoAPI](https://support.microsoft.com/en-us/kb/228786)
        ///
        /// \param[in] cp           Handle of the cryptographics provider
        /// \param[in] alg          Key algorithm
        /// \param[in] key          Key that decrypts \p secret
        /// \param[in] secret       Key data
        /// \param[in] size_secret  \p secret size
        ///
        /// \returns Key
        ///
        HCRYPTKEY create_key(
            _In_                              HCRYPTPROV cp,
            _In_                              ALG_ID     alg,
            _In_                              HCRYPTKEY  key,
            _In_bytecount_(size_secret) const void       *secret,
            _In_                              size_t     size_secret);
#endif

    protected:
        credentials_tls &m_cred;                                ///< EAP-TLS user credentials
        HANDLE m_user_ctx;                                      ///< Handle to user context

        packet m_packet_req;                                    ///< Request packet
        packet m_packet_res;                                    ///< Response packet

#if EAP_TLS < EAP_TLS_SCHANNEL
        winstd::crypt_prov m_cp;                                ///< Cryptography provider for general services
        winstd::crypt_prov m_cp_enc_client;                     ///< Cryptography provider for encryption
        winstd::crypt_prov m_cp_enc_server;                     ///< Cryptography provider for encryption
        winstd::crypt_key m_key_exp1;                           ///< Key for importing derived keys

        tls_version m_tls_version;                              ///< TLS version in use
        ALG_ID m_alg_prf;                                       ///< Pseudo-random function algorithm in use

        tls_conn_state m_state_client;                          ///< Client TLS connection state
        tls_conn_state m_state_client_pending;                  ///< Client TLS connection state (pending)
        tls_conn_state m_state_server;                          ///< Server TLS connection state
        tls_conn_state m_state_server_pending;                  ///< Server TLS connection state (pending)

        tls_master_secret m_master_secret;                      ///< TLS master secret
        tls_random m_random_client;                             ///< Client random
        tls_random m_random_server;                             ///< Server random

        tls_random m_key_mppe_client;                           ///< MS-MPPE-Recv-Key
        tls_random m_key_mppe_server;                           ///< MS-MPPE-Send-Key

        sanitizing_blob m_session_id;                           ///< TLS session ID

        std::list<winstd::cert_context> m_server_cert_chain;    ///< Server certificate chain

        winstd::crypt_hash m_hash_handshake_msgs_md5;           ///< Running MD5 hash of handshake messages
        winstd::crypt_hash m_hash_handshake_msgs_sha1;          ///< Running SHA-1 hash of handshake messages
        winstd::crypt_hash m_hash_handshake_msgs_sha256;        ///< Running SHA-256 hash of handshake messages

        bool m_handshake[tls_handshake_type_max];               ///< Handshake flags (map od handshake messages received)

        enum {
            phase_unknown = -1,                                 ///< Unknown phase
            phase_client_hello = 0,                             ///< Send client hello
            phase_server_hello,                                 ///< Wait for server hello
            phase_change_cipher_spec,                           ///< Wait for change cipher spec
            phase_application_data                              ///< Exchange application data
        } m_phase;                                              ///< What phase is our communication at?

        unsigned __int64 m_seq_num_client;                      ///< Sequence number for encrypting
        unsigned __int64 m_seq_num_server;                      ///< Sequence number for decrypting
#else
        winstd::tstring m_sc_target_name;                       ///< Schannel target name
        winstd::sec_credentials m_sc_cred;                      ///< Schannel client credentials
        std::vector<unsigned char> m_sc_queue;                  ///< TLS data queue
        winstd::sec_context m_sc_ctx;                           ///< Schannel context

        enum {
            phase_unknown = -1,                                 ///< Unknown phase
            phase_handshake_init = 0,                           ///< Handshake initialize
            phase_handshake_cont,                               ///< Handshake continue
            phase_application_data,                             ///< Exchange application data
            phase_shutdown,                                     ///< Connection shut down
        } m_phase, m_phase_prev;                                ///< What phase is our communication at?
#endif

        // The following members are required to avoid memory leakage in get_result()
        EAP_ATTRIBUTES m_eap_attr_desc;                         ///< EAP Radius attributes descriptor
        std::vector<winstd::eap_attr> m_eap_attr;               ///< EAP Radius attributes
        BYTE *m_blob_cfg;                                       ///< Configuration BLOB
#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
        BYTE *m_blob_cred;                                      ///< Credentials BLOB
#endif
    };
}
