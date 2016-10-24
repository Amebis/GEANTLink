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
    /// MSCHAPv2 method
    ///
    class method_mschapv2;
}

#pragma once

#include "Config.h"
#include "MSCHAPv2.h"

#include "../../EAPBase/include/Method.h"

#include <list>


namespace eap
{
    class method_mschapv2 : public method_noneap
    {
        WINSTD_NONCOPYABLE(method_mschapv2)

    public:
        ///
        /// Constructs an EAP method
        ///
        /// \param[in] mod   EAP module to use for global services
        /// \param[in] cfg   Method configuration
        /// \param[in] cred  User credentials
        ///
        method_mschapv2(_In_ module &module, _In_ config_method_mschapv2 &cfg, _In_ credentials_pass &cred);

        ///
        /// Moves an EAP method
        ///
        /// \param[in] other  EAP method to move from
        ///
        method_mschapv2(_Inout_ method_mschapv2 &&other);

        ///
        /// Moves an EAP method
        ///
        /// \param[in] other  EAP method to move from
        ///
        /// \returns Reference to this object
        ///
        method_mschapv2& operator=(_Inout_ method_mschapv2 &&other);

        /// \name Packet processing
        /// @{

        ///
        /// Starts an EAP authentication session on the peer EapHost using the EAP method.
        ///
        /// \sa [EapPeerBeginSession function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363600.aspx)
        ///
        virtual void begin_session(
            _In_        DWORD         dwFlags,
            _In_  const EapAttributes *pAttributeArray,
            _In_        HANDLE        hTokenImpersonateUser,
            _In_opt_    DWORD         dwMaxSendPacketSize = MAXDWORD);

        ///
        /// Processes a packet received by EapHost from a supplicant.
        ///
        /// \sa [EapPeerProcessRequestPacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363621.aspx)
        ///
        virtual void process_request_packet(
            _In_bytecount_(dwReceivedPacketSize) const void                *pReceivedPacket,
            _In_                                       DWORD               dwReceivedPacketSize,
            _Out_                                      EapPeerMethodOutput *pEapOutput);

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

        ///
        /// Processes MS-CHAP2-Success AVP
        ///
        /// \sa [Microsoft PPP CHAP Extensions, Version 2 (Chapter 5. Success Packet)](https://tools.ietf.org/html/rfc2759#section-5)
        ///
        /// \param[in] argv  List of message values
        ///
        void process_success(_In_ const std::list<std::string> &argv);

        ///
        /// Processes MS-CHAP-Error AVP
        ///
        /// \sa [Microsoft PPP CHAP Extensions, Version 2 (Chapter 6. Failure Packet)](https://tools.ietf.org/html/rfc2759#section-6)
        ///
        /// \param[in] argv  List of message values
        ///
        void process_error(_In_ const std::list<std::string> &argv);

        ///
        /// Splits MS-CHAP2-Success or MS-CHAP-Error messages
        ///
        /// \param[in] resp   MS-CHAP2-Success or MS-CHAP-Error message (i.e. "E=648 R=1 C=d86e0aa6cb5539e5fb31dd5dc5f6898c V=3 M=Password Expired")
        /// \param[in] count  Number of characters in \p resp
        ///
        /// \returns A list of individual parts of \p resp message (i.e. ("E=648", "R=1", "C=d86e0aa6cb5539e5fb31dd5dc5f6898c", "V=3", "M=Password Expired"))
        ///
        static std::list<std::string> parse_response(_In_count_(count) const char *resp, _In_ size_t count);

    protected:
        credentials_pass &m_cred;               ///< Method user credentials
        winstd::crypt_prov m_cp;                ///< Cryptography provider for general services

        challenge_mschapv2 m_challenge_server;  ///< MSCHAP server challenge
        challenge_mschapv2 m_challenge_client;  ///< MSCHAP client challenge
        unsigned char m_ident;                  ///< Ident
        nt_response m_nt_resp;                  ///< NT-Response
        bool m_success;                         ///< Did we receive MS-CHAP2-Success?

        enum {
            phase_unknown = -1,                 ///< Unknown phase
            phase_init = 0,                     ///< Send client challenge
            phase_challenge_server,             ///< Verify server challenge
            phase_finished,                     ///< Connection shut down
        } m_phase;                              ///< What phase is our communication at?
    };
}
