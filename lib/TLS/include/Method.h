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
    typedef unsigned char tls_random_t[32];

    ///
    /// EAP-TLS packet flags
    ///
    /// \sa [The EAP-TLS Authentication Protocol (Chapter: 3.1 EAP-TLS Request Packet)](https://tools.ietf.org/html/rfc5216#section-3.1)
    ///
    enum tls_flags_t;

    ///
    /// EAP-TLS method
    ///
    class method_tls;
}

#pragma once

#include "../include/Config.h"
#include "../include/Credentials.h"

#include "../../EAPBase/include/Method.h"

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
