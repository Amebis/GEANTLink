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
    class method_defrag;
    class method_eapmsg;
    class method_ttls;
}

#pragma once

#include "Config.h"
#include "Credentials.h"

#include "../../EAPBase/include/Method.h"

#include <WinStd/Sec.h>


namespace eap
{
    /// \addtogroup EAPBaseMethod
    /// @{

    ///
    /// EAP-(T)TLS class defragging method tunnel
    ///
    class method_defrag : public method_tunnel
    {
        WINSTD_NONCOPYABLE(method_defrag)

    public:
#pragma warning(push)
#pragma warning(disable: 4480)

        ///
        /// EAP-(T)TLS request packet flags
        ///
        /// \sa [The EAP-TLS Authentication Protocol (Chapter: 3.1 EAP-TLS Request Packet)](https://tools.ietf.org/html/rfc5216#section-3.1)
        /// \sa [The EAP-TTLS Authentication Protocol Version 0 (Chapter: 9.1. Packet Format)](https://tools.ietf.org/html/rfc5281#section-9.1)
        ///
        enum flags_req_t : unsigned char {
            flags_req_length_incl = 0x80,   ///< Length included
            flags_req_more_frag   = 0x40,   ///< More fragments
            flags_req_start       = 0x20,   ///< Start
            flags_req_ver_mask    = 0x07,   ///< Version mask
        };

        ///
        /// EAP-(T)TLS response packet flags
        ///
        /// \sa [The EAP-TLS Authentication Protocol (Chapter: 3.2 EAP-TLS Response Packet)](https://tools.ietf.org/html/rfc5216#section-3.2)
        /// \sa [The EAP-TTLS Authentication Protocol Version 0 (Chapter: 9.1. Packet Format)](https://tools.ietf.org/html/rfc5281#section-9.1)
        ///
        enum flags_res_t : unsigned char {
            flags_res_length_incl = 0x80,   ///< Length included
            flags_res_more_frag   = 0x40,   ///< More fragments
            flags_res_ver_mask    = 0x07,   ///< Version mask
        };

#pragma warning(pop)

    public:
        ///
        /// Constructs a method
        ///
        /// \param[in] mod    Module to use for global services
        /// \param[in] inner  Inner method
        ///
        method_defrag(_In_ module &mod, _In_ method *inner);

        ///
        /// Moves a method
        ///
        /// \param[in] other  Method to move from
        ///
        method_defrag(_Inout_ method_defrag &&other);

        ///
        /// Moves a method
        ///
        /// \param[in] other  Method to move from
        ///
        /// \returns Reference to this object
        ///
        method_defrag& operator=(_Inout_ method_defrag &&other);

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
        DWORD m_size_frag_max;      ///< Maximum size of a fragment
        sanitizing_blob m_data_req; ///< Data in request
        sanitizing_blob m_data_res; ///< Data in response
        bool m_send_res;            ///< Are we sending a response?
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
        /// \param[in] identity  User identity
        /// \param[in] inner     Inner method
        ///
        method_eapmsg(_In_ module &mod, _In_ const wchar_t *identity, _In_ method *inner);

        ///
        /// Moves a method
        ///
        /// \param[in] other  Method to move from
        ///
        method_eapmsg(_Inout_ method_eapmsg &&other);

        ///
        /// Moves a method
        ///
        /// \param[in] other  Method to move from
        ///
        /// \returns Reference to this object
        ///
        method_eapmsg& operator=(_Inout_ method_eapmsg &&other);

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
        std::wstring m_identity;        ///< User identity

        ///
        /// Communication phase
        ///
        enum {
            phase_unknown = -1,         ///< Unknown phase
            phase_identity = 0,         ///< Send identity
            phase_finished,             ///< Connection shut down
        } m_phase;                      ///< What phase is our communication at?

        sanitizing_blob m_packet_res;   ///< Response packet
    };


    ///
    /// TTLS method
    ///
    class method_ttls : public method_tunnel
    {
        WINSTD_NONCOPYABLE(method_ttls)

    public:
        ///
        /// Constructs an TTLS method
        ///
        /// \param[in] mod    EAP module to use for global services
        /// \param[in] cfg    Method configuration
        /// \param[in] cred   User credentials
        /// \param[in] inner  Inner method
        ///
        method_ttls(_In_ module &mod, _In_ config_method_ttls &cfg, _In_ credentials_ttls &cred, _In_ method *inner);

        ///
        /// Moves an TTLS method
        ///
        /// \param[in] other  TTLS method to move from
        ///
        method_ttls(_Inout_ method_ttls &&other);

        ///
        /// Moves an TTLS method
        ///
        /// \param[in] other  TTLS method to move from
        ///
        /// \returns Reference to this object
        ///
        method_ttls& operator=(_Inout_ method_ttls &&other);

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
            _In_  EapPeerMethodResultReason reason,
            _Out_ EapPeerMethodResult       *pResult);

    protected:
#if EAP_TLS < EAP_TLS_SCHANNEL_FULL
        ///
        /// Verifies server's certificate if trusted by configuration
        ///
        void verify_server_trust() const;
#endif

    protected:
        config_method_ttls &m_cfg;                  ///< Method configuration
        credentials_ttls &m_cred;                   ///< Method user credentials
        HANDLE m_user_ctx;                          ///< Handle to user context
        winstd::tstring m_sc_target_name;           ///< Schannel target name
        winstd::sec_credentials m_sc_cred;          ///< Schannel client credentials
        std::vector<unsigned char> m_sc_queue;      ///< TLS data queue
        winstd::sec_context m_sc_ctx;               ///< Schannel context

        ///
        /// Communication phase
        ///
        enum {
            phase_unknown = -1,                     ///< Unknown phase
            phase_handshake_init = 0,               ///< Handshake initialize
            phase_handshake_cont,                   ///< Handshake continue
            phase_finished,                         ///< Exchange application data
        } m_phase;                                  ///< What phase is our communication at?

        sanitizing_blob m_packet_res;               ///< Response packet
        bool m_packet_res_inner;                    ///< Get and ancrypt data from inner method too?

        std::vector<winstd::eap_attr> m_eap_attr;   ///< EAP attributes returned by get_result() method
        EAP_ATTRIBUTES m_eap_attr_desc;             ///< EAP attributes descriptor (required to avoid memory leakage in get_result())
    };

    /// @}
}
