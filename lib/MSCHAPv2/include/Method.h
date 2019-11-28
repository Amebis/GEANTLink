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
    class method_mschapv2_base;
    class method_mschapv2;
    class method_mschapv2_diameter;
}

#pragma once

#include "Config.h"
#include "MSCHAPv2.h"

#include "../../EAPBase/include/Method.h"

#include <list>


namespace eap
{
    /// \addtogroup EAPBaseMethod
    /// @{

    ///
    /// MSCHAPv2 method base class
    ///
    class method_mschapv2_base : public method
    {
        WINSTD_NONCOPYABLE(method_mschapv2_base)

    public:
        ///
        /// Constructs a MSCHAPv2 method
        ///
        /// \param[in] mod   MSCHAPv2 module to use for global services
        /// \param[in] cfg   Method configuration
        /// \param[in] cred  User credentials
        ///
        method_mschapv2_base(_In_ module &mod, _In_ config_method_mschapv2 &cfg, _In_ credentials_pass &cred);

        ///
        /// Moves a MSCHAPv2 method
        ///
        /// \param[in] other  MSCHAPv2 method to move from
        ///
        method_mschapv2_base(_Inout_ method_mschapv2_base &&other) noexcept;

        ///
        /// Moves a MSCHAPv2 method
        ///
        /// \param[in] other  MSCHAPv2 method to move from
        ///
        /// \returns Reference to this object
        ///
        method_mschapv2_base& operator=(_Inout_ method_mschapv2_base &&other) noexcept;

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

        virtual void get_response_packet(
            _Out_    sanitizing_blob &packet,
            _In_opt_ DWORD           size_max = MAXDWORD);

        /// @}

        virtual void get_result(
            _In_    EapPeerMethodResultReason reason,
            _Inout_ EapPeerMethodResult       *pResult);

    protected:
        ///
        /// Processes MSCHAPv2 success message
        ///
        /// \sa [Microsoft PPP CHAP Extensions, Version 2 (Chapter 5. Success Packet)](https://tools.ietf.org/html/rfc2759#section-5)
        ///
        /// \param[in] argv  List of message values
        ///
        void process_success(_In_ const std::list<std::string> &argv);

        ///
        /// Processes MSCHAPv2 error message
        ///
        /// \sa [Microsoft PPP CHAP Extensions, Version 2 (Chapter 6. Failure Packet)](https://tools.ietf.org/html/rfc2759#section-6)
        ///
        /// \param[in] argv  List of message values
        ///
        void process_error(_In_ const std::list<std::string> &argv);

        ///
        /// Splits MSCHAPv2 success or error messages
        ///
        /// \param[in] resp   MSCHAPv2 success or error message (i.e. "E=648 R=1 C=d86e0aa6cb5539e5fb31dd5dc5f6898c V=3 M=Password Expired")
        /// \param[in] count  Number of characters in \p resp
        ///
        /// \returns A list of individual parts of \p resp message (i.e. ("E=648", "R=1", "C=d86e0aa6cb5539e5fb31dd5dc5f6898c", "V=3", "M=Password Expired"))
        ///
        static std::list<std::string> parse_response(_In_count_(count) const char *resp, _In_ size_t count);

    protected:
        config_method_mschapv2 &m_cfg;          ///< Method configuration
        credentials_pass &m_cred;               ///< Method user credentials
        winstd::crypt_prov m_cp;                ///< Cryptography provider for general services

        sanitizing_blob m_challenge_server;     ///< MSCHAP server challenge
        challenge_mschapv2 m_challenge_client;  ///< MSCHAP client challenge
        unsigned char m_ident;                  ///< Ident
        nt_response m_nt_resp;                  ///< NT-Response

        sanitizing_blob m_packet_res;           ///< Response packet
    };


    ///
    /// MSCHAPv2 method
    ///
    class method_mschapv2 : public method_mschapv2_base
    {
        WINSTD_NONCOPYABLE(method_mschapv2)

    public:
        ///
        /// Constructs a MSCHAPv2 method
        ///
        /// \param[in] mod   MSCHAPv2 module to use for global services
        /// \param[in] cfg   Method configuration
        /// \param[in] cred  User credentials
        ///
        method_mschapv2(_In_ module &mod, _In_ config_method_mschapv2 &cfg, _In_ credentials_pass &cred);

        ///
        /// Moves a MSCHAPv2 method
        ///
        /// \param[in] other  MSCHAPv2 method to move from
        ///
        method_mschapv2(_Inout_ method_mschapv2 &&other) noexcept;

        ///
        /// Moves a MSCHAPv2 method
        ///
        /// \param[in] other  MSCHAPv2 method to move from
        ///
        /// \returns Reference to this object
        ///
        method_mschapv2& operator=(_Inout_ method_mschapv2 &&other) noexcept;

        /// \name Packet processing
        /// @{

        virtual EapPeerMethodResponseAction process_request_packet(
            _In_bytecount_(dwReceivedPacketSize) const void  *pReceivedPacket,
            _In_                                       DWORD dwReceivedPacketSize);

        /// @}
    };

    /// @}


    ///
    /// MSCHAPv2 method over Diameter AVP (for use as inner EAP-TTLS)
    ///
    class method_mschapv2_diameter : public method_mschapv2_base
    {
        WINSTD_NONCOPYABLE(method_mschapv2_diameter)

    public:
        ///
        /// Constructs a MSCHAPv2 method
        ///
        /// \param[in] mod   MSCHAPv2 module to use for global services
        /// \param[in] cfg   Method configuration
        /// \param[in] cred  User credentials
        ///
        method_mschapv2_diameter(_In_ module &mod, _In_ config_method_mschapv2 &cfg, _In_ credentials_pass &cred);

        ///
        /// Moves a MSCHAPv2 method
        ///
        /// \param[in] other  MSCHAPv2 method to move from
        ///
        method_mschapv2_diameter(_Inout_ method_mschapv2_diameter &&other) noexcept;

        ///
        /// Moves a MSCHAPv2 method
        ///
        /// \param[in] other  MSCHAPv2 method to move from
        ///
        /// \returns Reference to this object
        ///
        method_mschapv2_diameter& operator=(_Inout_ method_mschapv2_diameter &&other) noexcept;

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

        /// @}

        friend class method_ttls;               // Setting of initial challenge derived from TLS PRF

    protected:
        ///
        /// Processes AVPs in a Diameter packet
        ///
        /// \param[in] pck       Packet data
        /// \param[in] size_pck  \p pck size in bytes
        ///
        void process_packet(_In_bytecount_(size_pck) const void *pck, _In_ size_t size_pck);

    protected:
        ///
        /// Communication phase
        ///
        enum {
            phase_unknown = -1,                 ///< Unknown phase
            phase_init = 0,                     ///< Send client challenge
            phase_challenge_server,             ///< Verify server challenge
            phase_finished,                     ///< Connection shut down
        } m_phase;                              ///< What phase is our communication at?
    };

    /// @}
}
