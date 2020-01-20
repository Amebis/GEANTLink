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
    /// EAP-(T)TLS/PEAP class defragging method tunnel
    ///
    class method_defrag : public method_tunnel
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
        /// \sa [Protected EAP Protocol (PEAP) Version 2 (Chapter: 3.2. PEAPv2 Packet Format)](https://tools.ietf.org/html/draft-josefsson-pppext-eap-tls-eap-10#section-3.2)
        ///
        enum flags_t : unsigned char {
            flags_length_incl     = 0x80,   ///< Length included
            flags_more_frag       = 0x40,   ///< More fragments
            flags_start           = 0x20,   ///< Start
            flags_tls_length_incl = 0x10,   ///< TLS Length included
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


    ///
    /// Diameter EAP-Message tunnel method
    ///
    class method_eapmsg : public method_tunnel
    {
    public:
        ///
        /// Constructs a method
        ///
        /// \param[in] mod       Module to use for global services
        /// \param[in] inner     Inner method
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
    class method_tls_tunnel : public method_tunnel
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
