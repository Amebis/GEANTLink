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
    class method_eapmsg;
}

#pragma once

#include "Config.h"
#include "Credentials.h"
#include "TTLS.h"

#include "../../EAPBase/include/Method.h"


namespace eap
{
    /// \addtogroup EAPBaseMethod
    /// @{

    ///
    /// Diameter EAP-Message tunnel method
    ///
    class method_eapmsg : public method
    {
    public:
        ///
        /// Constructs a method
        ///
        /// \param[in] mod    Module to use for global services
        /// \param[in] inner  Inner method
        ///
        method_eapmsg(_In_ module &mod, _In_ method *inner);

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

    protected:
        ///
        /// Communication phase
        ///
        enum class phase_t {
            unknown = -1,               ///< Unknown phase
            identity = 0,               ///< Send identity
            finished,                   ///< Connection shut down
        } m_phase;                      ///< What phase is our communication at?

        sanitizing_blob m_packet_res;   ///< Response packet
    };

    /// @}
}
