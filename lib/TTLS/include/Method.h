/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2020 Amebis
    Copyright © 2016 GÉANT
*/

namespace eap
{
    class method_eapmsg;
    class method_ttls;
}

#pragma once

#include "Config.h"
#include "Credentials.h"
#include "TTLS.h"

#include "../../TLS/include/Method.h"


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


    ///
    /// EAP-TTLS method
    ///
    class method_ttls : public method_tls
    {
    public:
        ///
        /// Constructs an EAP-TTLS method
        ///
        /// \param[in] mod    EAP module to use for global services
        /// \param[in] cfg    Method configuration
        /// \param[in] cred   User credentials
        /// \param[in] inner  Inner method
        ///
        method_ttls(_In_ module &mod, _In_ config_method_ttls &cfg, _In_ credentials_tls_tunnel &cred, _In_ method *inner);

    protected:
        virtual void push_keying_material();
        virtual void get_keying_material(_Out_ sanitizing_blob_xf<32> &recv_key, _Out_ sanitizing_blob_xf<32> &send_key);
    };

    /// @}
}
