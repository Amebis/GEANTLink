/*
    Copyright 2015-2016 Amebis
    Copyright 2016 G�ANT

    This file is part of G�ANTLink.

    G�ANTLink is free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    G�ANTLink is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with G�ANTLink. If not, see <http://www.gnu.org/licenses/>.
*/

namespace eap
{
    ///
    /// TLS random
    ///
    typedef unsigned char tls_random_t[32];

    ///
    /// EAP-TLS packet flags
    ///
    /// \sa [The EAP-TLS Authentication Protocol (Chapter: 3.1 EAP-TLS Request Packet)](https://tools.ietf.org/html/rfc5216#section-3.1)
    ///
    enum tls_flags_t;

    ///
    /// TLS session
    ///
    class session_tls;
}

#pragma once

#include "../include/Config.h"
#include "../include/Credentials.h"

#include "../../EAPBase/include/Session.h"

#include <WinStd/Common.h>
#include <WinStd/Crypt.h>

#include <vector>


namespace eap
{
    enum tls_flags_t {
        tls_flags_length_incl = 0x80,  ///< Length included
        tls_flags_more_frag   = 0x40,  ///< More fragments
        tls_flags_start       = 0x20,  ///< Start
    };


    class session_tls : public session<config_method_tls, credentials_tls, bool, bool>
    {
    public:
        ///
        /// Constructor
        ///
        /// \param[in] mod  EAP module to use for global services
        ///
        session_tls(_In_ module *mod);

        ///
        /// Copies TLS session
        ///
        /// \param[in] other  Session to copy from
        ///
        session_tls(_In_ const session_tls &other);

        ///
        /// Moves TLS session
        ///
        /// \param[in] other  Session to move from
        ///
        session_tls(_Inout_ session_tls &&other);

        ///
        /// Destructor
        ///
        virtual ~session_tls();

        ///
        /// Copies TLS session
        ///
        /// \param[in] other  Session to copy from
        ///
        /// \returns Reference to this object
        ///
        session_tls& operator=(_In_ const session_tls &other);

        ///
        /// Moves TLS session
        ///
        /// \param[in] other  Session to move from
        ///
        /// \returns Reference to this object
        ///
        session_tls& operator=(_Inout_ session_tls &&other);

        /// \name Session start/end
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
        virtual bool begin(
            _In_        DWORD         dwFlags,
            _In_  const EapAttributes *pAttributeArray,
            _In_        HANDLE        hTokenImpersonateUser,
            _In_        DWORD         dwMaxSendPacketSize,
            _Out_       EAP_ERROR     **ppEapError);

        /// @}

        /// \name Packet processing
        /// @{

        ///
        /// Processes a packet received by EAPHost from a supplicant.
        ///
        /// \sa [EapPeerProcessRequestPacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363621.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool process_request_packet(
            _In_                                       DWORD               dwReceivedPacketSize,
            _In_bytecount_(dwReceivedPacketSize) const EapPacket           *pReceivedPacket,
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
            _Inout_                            DWORD     *pdwSendPacketSize,
            _Inout_bytecap_(*dwSendPacketSize) EapPacket *pSendPacket,
            _Out_                              EAP_ERROR **ppEapError);

        ///
        /// Obtains the result of an authentication session from the EAP method.
        ///
        /// \sa [EapPeerGetResult function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363611.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool get_result(
            _In_  EapPeerMethodResultReason reason,
            _Out_ EapPeerMethodResult       *ppResult,
            _Out_ EAP_ERROR                 **ppEapError);

        /// @}

    public:
        enum phase_t {
            phase_handshake_start = 0,
        } m_phase;                                  ///< Session phase

        struct {
            EapCode m_code;                         ///< Packet code
            BYTE m_id;                              ///< Packet ID
            BYTE m_flags;                           ///< Packet flags
            std::vector<BYTE> m_data;               ///< Packet data
        }
            m_packet_req,                           ///< Request packet
            m_packet_res;                           ///< Response packet

        winstd::crypt_prov m_cp;        ///< Cryptography provider

        tls_random_t m_random_client;   ///< Client random
        tls_random_t m_random_server;   ///< Server random

        std::vector<unsigned char, winstd::sanitizing_allocator<unsigned char> > m_session_id;  ///< TLS session ID
    };
}