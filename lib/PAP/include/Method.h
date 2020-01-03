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
    class method_pap_diameter;
}


#pragma once

#include "Config.h"

#include "../../EAPBase/include/Method.h"


namespace eap
{
    /// \addtogroup EAPBaseMethod
    /// @{

    ///
    /// PAP method over Diameter AVP (for use as inner EAP-TTLS)
    ///
    class method_pap_diameter : public method
    {
        WINSTD_NONCOPYABLE(method_pap_diameter)

    public:
        ///
        /// Constructs a PAP method
        ///
        /// \param[in] mod   PAP module to use for global services
        /// \param[in] cfg   Method configuration
        /// \param[in] cred  User credentials
        ///
        method_pap_diameter(_In_ module &mod, _In_ config_method_pap &cfg, _In_ credentials_pass &cred);

        ///
        /// Moves a PAP method
        ///
        /// \param[in] other  PAP method to move from
        ///
        method_pap_diameter(_Inout_ method_pap_diameter &&other) noexcept;

        ///
        /// Moves a PAP method
        ///
        /// \param[in] other  PAP method to move from
        ///
        /// \returns Reference to this object
        ///
        method_pap_diameter& operator=(_Inout_ method_pap_diameter &&other) noexcept;

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

        virtual void get_result(
            _In_    EapPeerMethodResultReason reason,
            _Inout_ EapPeerMethodResult       *pResult);

    protected:
        config_method_pap &m_cfg;       ///< Method configuration
        credentials_pass &m_cred;       ///< Method user credentials

        ///
        /// Communication phase
        ///
        enum {
            phase_unknown = -1,         ///< Unknown phase
            phase_init = 0,             ///< Handshake initialize
            phase_finished,             ///< Connection shut down
        } m_phase;                      ///< What phase is our communication at?

        sanitizing_blob m_packet_res;   ///< Response packet
    };

    /// @}
}
