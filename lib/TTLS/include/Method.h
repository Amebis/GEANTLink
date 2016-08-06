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
    /// EAP-TTLS packet flags
    ///
    /// \sa [Extensible Authentication Protocol Tunneled Transport Layer Security Authenticated Protocol Version 0 (EAP-TTLSv0) (Chapter: 9.1 Packet Format)](https://tools.ietf.org/html/rfc5281#section-9.1)
    ///
    enum ttls_flags_t;

    ///
    /// EAP-TTLS method
    ///
    class method_ttls;
}

#pragma once

#include "Config.h"
#include "Credentials.h"

#include "../../TLS/include/Method.h"
#include "../../EAPBase/include/Method.h"


namespace eap
{
    enum ttls_flags_t {
        ttls_flags_length_incl = tls_flags_length_incl, ///< Length included
        ttls_flags_more_frag   = tls_flags_more_frag,   ///< More fragments
        ttls_flags_start       = tls_flags_start,       ///< Start
        ttls_flags_ver_mask    = 0x07,                  ///< Version mask
    };


    class method_ttls : public method
    {
    public:
        ///
        /// Constructs an EAP method
        ///
        /// \param[in] mod  EAP module to use for global services
        /// \param[in] cfg  Method configuration
        ///
        method_ttls(_In_ module &module, _In_ config_method_ttls &cfg, _In_ credentials_ttls &cred);

        ///
        /// Copies an EAP method
        ///
        /// \param[in] other  EAP method to copy from
        ///
        method_ttls(_In_ const method_ttls &other);

        ///
        /// Moves an EAP method
        ///
        /// \param[in] other  EAP method to move from
        ///
        method_ttls(_Inout_ method_ttls &&other);

        ///
        /// Copies an EAP method
        ///
        /// \param[in] other  EAP method to copy from
        ///
        /// \returns Reference to this object
        ///
        method_ttls& operator=(_In_ const method_ttls &other);

        ///
        /// Moves an EAP method
        ///
        /// \param[in] other  EAP method to move from
        ///
        /// \returns Reference to this object
        ///
        method_ttls& operator=(_Inout_ method_ttls &&other);

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
        method_tls m_outer; ///< EAP-TLS method
        enum version_t {
            version_0 = 0,  ///< EAP-TTLS v0
        } m_version;        ///< EAP-TTLS version
    };
}
