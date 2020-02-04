/*
    Copyright 2015-2020 Amebis
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
    class method_defrag;
}

#pragma once

#include "../../EAPBase/include/Method.h"


namespace eap
{
    /// \addtogroup EAPBaseMethod
    /// @{

    ///
    /// EAP-(T)TLS/PEAP class defragging method tunnel
    ///
    class method_defrag : public method
    {
    public:
#pragma warning(push)
#pragma warning(disable: 4480)

        ///
        /// EAP-(T)TLS/PEAP request/response packet flags
        ///
        /// \sa [The EAP-TLS Authentication Protocol (Chapter: 3.1 EAP-TLS Request Packet)](https://tools.ietf.org/html/rfc5216#section-3.1)
        /// \sa [The EAP-TLS Authentication Protocol (Chapter: 3.2 EAP-TLS Response Packet)](https://tools.ietf.org/html/rfc5216#section-3.2)
        /// \sa [The EAP-TTLS Authentication Protocol Version 0 (Chapter: 9.1. Packet Format)](https://tools.ietf.org/html/rfc5281#section-9.1)
        /// \sa [Protected EAP Protocol (PEAP) (Chapter: 3.1. PEAP Packet Format)](https://tools.ietf.org/html/draft-josefsson-pppext-eap-tls-eap-05#section-3.1)
        ///
        enum flags_t : unsigned char {
            flags_length_incl     = 0x80,   ///< Length included
            flags_more_frag       = 0x40,   ///< More fragments
            flags_start           = 0x20,   ///< Start
            flags_ver_mask        = 0x07,   ///< Version mask
        };

#pragma warning(pop)

    public:
        ///
        /// Constructs a method
        ///
        /// \param[in] mod          Module to use for global services
        /// \param[in] version_max  Maximum protocol version supported by peer
        /// \param[in] inner        Inner method
        ///
        method_defrag(_In_ module &mod, _In_ unsigned char version_max, _In_ method *inner);

        /// \name Session management
        /// @{

        virtual void begin_session(
            _In_        DWORD         dwFlags,
            _In_  const EapAttributes *pAttributeArray,
            _In_        HANDLE        hTokenImpersonateUser,
            _In_opt_    DWORD         dwMaxSendPacketSize = MAXDWORD);

        /// @}

        /// \name Packet processing
        /// @{

        virtual EapPeerMethodResponseAction process_request_packet(
            _In_bytecount_(dwReceivedPacketSize) const void  *pReceivedPacket,
            _In_                                       DWORD dwReceivedPacketSize);

        virtual void get_response_packet(
            _Out_    sanitizing_blob &packet,
            _In_opt_ DWORD           size_max = MAXDWORD);

        /// @}

    public:
        unsigned char m_version;    ///< Negotiated protocol version

    protected:
        sanitizing_blob m_data_req; ///< Data in request
        sanitizing_blob m_data_res; ///< Data in response
        bool m_send_res;            ///< Are we sending a response?

        ///
        /// Communication phase
        ///
        enum class phase_t {
            unknown = -1,           ///< Unknown phase
            init = 0,               ///< Binding exchange
            established,            ///< Connection established
        } m_phase;                  ///< What phase is our communication at?
    };

    /// @}
}
