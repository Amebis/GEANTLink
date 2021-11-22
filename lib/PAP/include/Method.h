/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2020 Amebis
    Copyright © 2016 GÉANT
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
    public:
        ///
        /// Constructs a PAP method
        ///
        /// \param[in] mod   PAP module to use for global services
        /// \param[in] cfg   Method configuration
        /// \param[in] cred  User credentials
        ///
        method_pap_diameter(_In_ module &mod, _In_ config_method_pap &cfg, _In_ credentials_pass &cred);

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
        enum class phase_t {
            unknown = -1,               ///< Unknown phase
            init = 0,                   ///< Handshake initialize
            finished,                   ///< Connection shut down
        } m_phase;                      ///< What phase is our communication at?

        sanitizing_blob m_packet_res;   ///< Response packet
    };

    /// @}
}
