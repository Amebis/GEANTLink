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
    class method_tls_tunnel;
}

#pragma once

#include "Config.h"
#include "Credentials.h"
#include "TTLS.h"

#include "../../EAPBase/include/Method.h"

#include <WinStd/Sec.h>


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
    /// TLS tunnel method
    ///
    class method_tls_tunnel : public method
    {
    public:
        ///
        /// Constructs a TLS tunnel method
        ///
        /// \param[in] mod         EAP module to use for global services
        /// \param[in] eap_method  EAP method type ID
        /// \param[in] cfg         Method configuration
        /// \param[in] cred        User credentials
        /// \param[in] inner       Inner method
        ///
        method_tls_tunnel(_In_ module &mod, _In_ winstd::eap_type_t eap_method, _In_ config_method_tls_tunnel &cfg, _In_ credentials_tls_tunnel &cred, _In_ method *inner);

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
        ///
        /// Decrypts data and forwards it to the inner method.
        ///
        EapPeerMethodResponseAction decrypt_request_data();

#if EAP_TLS < EAP_TLS_SCHANNEL_FULL
        ///
        /// Verifies server certificate if trusted by configuration
        ///
        void verify_server_trust() const;
#endif

    protected:
        const winstd::eap_type_t m_eap_method;      ///< EAP method type
        config_method_tls_tunnel &m_cfg;            ///< Method configuration
        credentials_tls_tunnel &m_cred;             ///< Method user credentials
        HANDLE m_user_ctx;                          ///< Handle to user context
        winstd::tstring m_sc_target_name;           ///< Schannel target name
        winstd::sec_credentials m_sc_cred;          ///< Schannel client credentials
        std::vector<unsigned char> m_sc_queue;      ///< TLS data queue
        winstd::sec_context m_sc_ctx;               ///< Schannel context
        winstd::cert_context m_sc_cert;             ///< Server certificate

        ///
        /// Communication phase
        ///
        enum class phase_t {
            unknown = -1,                           ///< Unknown phase
            handshake_init = 0,                     ///< Handshake initialize
            handshake_cont,                         ///< Handshake continue
            finished,                               ///< Exchange application data
        } m_phase;                                  ///< What phase is our communication at?

        sanitizing_blob m_packet_res;               ///< Response packet
        bool m_packet_res_inner;                    ///< Get and ancrypt data from inner method too?

        std::vector<winstd::eap_attr> m_eap_attr;   ///< EAP attributes returned by get_result() method
        EAP_ATTRIBUTES m_eap_attr_desc;             ///< EAP attributes descriptor (required to avoid memory leakage in get_result())
    };

    /// @}
}
