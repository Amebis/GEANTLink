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
        /// Destructor
        ///
        virtual ~method_tls();

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
        /// \param[in] pms  Pre-master secret
        ///
        /// \returns Client key exchange message
        ///
        sanitizing_blob make_client_key_exchange(_In_ const tls_master_secret &pms) const;

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
        eap::sanitizing_blob make_finished() const;

        ///
        /// Makes a TLS message
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter A.1. Record Layer)](https://tools.ietf.org/html/rfc5246#appendix-A.1)
        ///
        /// \param[in] type  Message type
        /// \param[in] msg   Message data contents
        ///
        /// \returns TLS message message
        ///
        static eap::sanitizing_blob make_message(_In_ tls_message_type_t type, _In_ const sanitizing_blob &msg);

        ///
        /// Makes a TLS message
        ///
        /// \param[in] type     Message type
        /// \param[in] msg      Message data contents
        /// \param[in] encrypt  Should the message be encrypted?
        ///
        /// \returns TLS message message
        ///
        inline eap::sanitizing_blob make_message(_In_ tls_message_type_t type, _In_ const sanitizing_blob &msg, _In_ bool encrypted)
        {
            if (encrypted) {
                // Make unencrypted handshake, encrypt it, then make a new handshake message.
                sanitizing_blob msg_enc(make_message(type, msg));
                encrypt_message(msg_enc);
                return make_message(type, msg_enc);
            } else
                return make_message(type, msg);
        }

        ///
        /// Generates keys required by current connection state
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter 6.3. Key Calculation)](https://tools.ietf.org/html/rfc5246#section-6.3)
        ///
        void derive_keys();

        ///
        /// Generates master session key
        ///
        void derive_msk();

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
        /// \param[in] msg      TLS change_cipher_spec message data
        /// \param[in] msg_size TLS change_cipher_spec message data size
        ///
        void process_change_cipher_spec(_In_bytecount_(msg_size) const void *msg, _In_ size_t msg_size);

        ///
        /// Processes a TLS alert message
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter 7.2. Alert Protocol)](https://tools.ietf.org/html/rfc5246#section-7.2)
        ///
        /// \param[in] msg      TLS alert message data
        /// \param[in] msg_size TLS alert message data size
        ///
        void process_alert(_In_bytecount_(msg_size) const void *msg, _In_ size_t msg_size);

        ///
        /// Processes a TLS handshake message
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter 7.4. Handshake Protocol)](https://tools.ietf.org/html/rfc5246#section-7.4)
        ///
        /// \param[in] msg      TLS handshake message data
        /// \param[in] msg_size TLS handshake message data size
        ///
        void process_handshake(_In_bytecount_(msg_size) const void *msg, _In_ size_t msg_size);

        ///
        /// Processes a TLS application_data message
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter 10. Application Data Protocol)](https://tools.ietf.org/html/rfc5246#section-10)
        ///
        /// \param[in] msg      TLS application_data message data
        /// \param[in] msg_size TLS application_data message data size
        ///
        void process_application_data(_In_bytecount_(msg_size) const void *msg, _In_ size_t msg_size);

        ///
        /// Verifies server's certificate if trusted by configuration
        ///
        void verify_server_trust() const;

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
        void decrypt_message(_Inout_ sanitizing_blob &msg) const;

        ///
        /// Calculates pseudo-random P_hash data defined in RFC 5246
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.1 (Chapter 5: HMAC and the Pseudorandom Function)](https://tools.ietf.org/html/rfc4346#section-5)
        ///
        /// \param[in] secret       Hashing secret key
        /// \param[in] size_secret  \p secret size
        /// \param[in] seed         Random seed
        /// \param[in] size_seed    \p seed size
        /// \param[in] size         Number of bytes of pseudo-random data required
        ///
        /// \returns Generated pseudo-random data (\p size bytes)
        ///
        sanitizing_blob prf(
            _In_bytecount_(size_secret) const void   *secret,
            _In_                              size_t size_secret,
            _In_bytecount_(size_seed)   const void   *seed,
            _In_                              size_t size_seed,
            _In_                              size_t size) const;

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

        tls_conn_state m_state;                                 ///< TLS connection state for fast reconnect

        sanitizing_blob m_padding_hmac_client;                  ///< Padding (key) for client side HMAC calculation
        //sanitizing_blob m_padding_hmac_server;                  ///< Padding (key) for server side HMAC calculation
        winstd::crypt_key m_key_client;                         ///< Key for encrypting messages
        winstd::crypt_key m_key_server;                         ///< Key for decrypting messages

        tls_random m_key_mppe_send;                             ///< MS-MPPE-Send-Key
        tls_random m_key_mppe_recv;                             ///< MS-MPPE-Recv-Key

        sanitizing_blob m_session_id;                           ///< TLS session ID

        std::list<winstd::cert_context> m_server_cert_chain;    ///< Server certificate chain

        winstd::crypt_hash m_hash_handshake_msgs_md5;           ///< Running MD5 hash of handshake messages sent
        winstd::crypt_hash m_hash_handshake_msgs_sha1;          ///< Running SHA-1 hash of handshake messages sent

        bool m_send_client_cert;                                ///< Did server request client certificate?
        bool m_server_hello_done;                               ///< Is server hello done?
        bool m_server_finished;                                 ///< Did server send a valid finish message?
        bool m_cipher_spec;                                     ///< Did server specify cipher?

        unsigned __int64 m_seq_num;                             ///< Sequence number for encryption

        // The following members are required to avoid memory leakage in get_result()
        EAP_ATTRIBUTES m_eap_attr_desc;                         ///< EAP Radius attributes descriptor
        std::vector<winstd::eap_attr> m_eap_attr;               ///< EAP Radius attributes
        BYTE *m_blob_cfg;                                       ///< Configuration BLOB
    };
}
