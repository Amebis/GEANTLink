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
    /// TLS random
    ///
    struct tls_random_t;

    ///
    /// EAP-TLS request packet flags
    ///
    /// \sa [The EAP-TLS Authentication Protocol (Chapter: 3.1 EAP-TLS Request Packet)](https://tools.ietf.org/html/rfc5216#section-3.1)
    ///
    enum tls_req_flags_t;

    ///
    /// EAP-TLS response packet flags
    ///
    /// \sa [The EAP-TLS Authentication Protocol (Chapter: 3.2 EAP-TLS Response Packet)](https://tools.ietf.org/html/rfc5216#section-3.2)
    ///
    enum tls_res_flags_t;

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
#pragma pack(push)
#pragma pack(1)
    struct tls_random_t {
        unsigned long time;
        unsigned char data[28];
    };
#pragma pack(pop)

    enum tls_req_flags_t {
        tls_req_flags_length_incl = 0x80,   ///< Length included
        tls_req_flags_more_frag   = 0x40,   ///< More fragments
        tls_req_flags_start       = 0x20,   ///< Start
    };

    enum tls_res_flags_t {
        tls_res_flags_length_incl = 0x80,   ///< Length included
        tls_res_flags_more_frag   = 0x40,   ///< More fragments
    };


    class method_tls : public method
    {
    public:
        ///
        /// Constructs an EAP method
        ///
        /// \param[in] mod  EAP module to use for global services
        /// \param[in] cfg  Method configuration
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
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool begin_session(
            _In_        DWORD         dwFlags,
            _In_  const EapAttributes *pAttributeArray,
            _In_        HANDLE        hTokenImpersonateUser,
            _In_        DWORD         dwMaxSendPacketSize,
            _Out_       EAP_ERROR     **ppEapError);

        ///
        /// Processes a packet received by EAPHost from a supplicant.
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        /// \sa [EapPeerProcessRequestPacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363621.aspx)
        ///
        virtual bool process_request_packet(
            _In_bytecount_(dwReceivedPacketSize) const EapPacket           *pReceivedPacket,
            _In_                                       DWORD               dwReceivedPacketSize,
            _Out_                                      EapPeerMethodOutput *pEapOutput,
            _Out_                                      EAP_ERROR           **ppEapError);

        ///
        /// Obtains a response packet from the EAP method.
        ///
        /// \sa [EapPeerGetResponsePacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363610.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool get_response_packet(
            _Inout_bytecap_(*dwSendPacketSize) EapPacket *pSendPacket,
            _Inout_                            DWORD     *pdwSendPacketSize,
            _Out_                              EAP_ERROR **ppEapError);

        /// @}

    protected:
        ///
        /// Makes a TLS client hello message
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter 7.4.1.2. Client Hello](https://tools.ietf.org/html/rfc5246#section-7.4.1.2)
        ///
        /// \returns Client Hello message
        ///
        sanitizing_blob make_client_hello() const;

        ///
        /// Makes a TLS handshake
        ///
        /// \sa [The Transport Layer Security (TLS) Protocol Version 1.2 (Chapter A.1. Record Layer](https://tools.ietf.org/html/rfc5246#appendix-A.1)
        ///
        /// \param[in]  msg         Handshake data contents
        /// \param[in]  encrypt     Should make an encrypted handshake message?
        /// \param[out] msg_h       TLS handshake message
        /// \param[out] ppEapError  Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        bool make_handshake(_In_ const sanitizing_blob &msg, _In_ bool encrypt, _Out_ eap::sanitizing_blob &msg_h, _Out_ EAP_ERROR **ppEapError);

        ///
        /// Encrypt block of data
        ///
        /// \param[in]  msg         TLS message to encrypt
        /// \param[out] msg_enc     Encrypted \p msg
        /// \param[out] ppEapError  Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        bool encrypt_message(_In_ const sanitizing_blob &msg, _Out_ std::vector<unsigned char> &msg_enc, _Out_ EAP_ERROR **ppEapError);

    public:
        enum phase_t {
            phase_client_hello = 0,
            phase_server_hello = 1,
        } m_phase;                                      ///< Session phase

        struct {
            EapCode m_code;                             ///< Packet code
            BYTE m_id;                                  ///< Packet ID
            BYTE m_flags;                               ///< Packet flags
            std::vector<BYTE> m_data;                   ///< Packet data
        }
            m_packet_req,                               ///< Request packet
            m_packet_res;                               ///< Response packet

        winstd::crypt_prov m_cp;                        ///< Cryptography provider
        winstd::crypt_key m_key_hmac;                   ///< Symmetric key for HMAC calculation

        winstd::crypt_key m_key_write;                  ///< Key for encrypting messages

        tls_random_t m_random_client;                   ///< Client random
        tls_random_t m_random_server;                   ///< Server random

        sanitizing_blob m_session_id;                   ///< TLS session ID

        winstd::crypt_hash m_hash_handshake_msgs_md5;   ///< Running MD5 hash of handshake messages sent
        winstd::crypt_hash m_hash_handshake_msgs_sha1;  ///< Running SHA-1 hash of handshake messages sent

    protected:
        unsigned __int64 m_seq_num;                     ///< Sequence number for encryption
    };
}
