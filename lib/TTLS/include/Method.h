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
    /// EAP-TTLS method
    ///
    class method_ttls;
}

#pragma once

#include "Config.h"
#include "Credentials.h"
#include "TTLS.h"

#include "../../TLS/include/Method.h"
#include "../../EAPBase/include/Method.h"


namespace eap
{
    class method_ttls : public method_tls
    {
    public:
        ///
        /// Constructs an EAP method
        ///
        /// \param[in] mod   EAP module to use for global services
        /// \param[in] cfg   Method configuration
        /// \param[in] cred  User credentials
        ///
        method_ttls(_In_ module &module, _In_ config_method_ttls &cfg, _In_ credentials_ttls &cred);

        ///
        /// Moves an EAP method
        ///
        /// \param[in] other  EAP method to move from
        ///
        method_ttls(_Inout_ method_ttls &&other);

        ///
        /// Moves an EAP method
        ///
        /// \param[in] other  EAP method to move from
        ///
        /// \returns Reference to this object
        ///
        method_ttls& operator=(_Inout_ method_ttls &&other);

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
        /// Ends an EAP authentication session for the EAP method.
        ///
        /// \sa [EapPeerEndSession function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363604.aspx)
        ///
        virtual void end_session();

        ///
        /// Processes a packet received by EapHost from a supplicant.
        ///
        /// \sa [EapPeerProcessRequestPacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363621.aspx)
        ///
        virtual void process_request_packet(
            _In_bytecount_(dwReceivedPacketSize) const void                *pReceivedPacket,
            _In_                                       DWORD               dwReceivedPacketSize,
            _Inout_                                    EapPeerMethodOutput *pEapOutput);

        ///
        /// Obtains a response packet from the EAP method.
        ///
        /// \sa [EapPeerGetResponsePacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363610.aspx)
        ///
        virtual void get_response_packet(
            _Inout_bytecap_(*dwSendPacketSize) void  *pSendPacket,
            _Inout_                            DWORD *pdwSendPacketSize);

        ///
        /// Obtains the result of an authentication session from the EAP method.
        ///
        /// \sa [EapPeerGetResult function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363611.aspx)
        ///
        virtual void get_result(
            _In_    EapPeerMethodResultReason reason,
            _Inout_ EapPeerMethodResult       *ppResult);

        /// @}

    protected:
        ///
        /// Generates master session key
        ///
        /// \sa [The EAP-TLS Authentication Protocol (Chapter 2.3. Key Hierarchy)](https://tools.ietf.org/html/rfc5216#section-2.3)
        ///
        virtual void derive_msk();

        ///
        /// Generates keying material for inner authentication
        ///
        /// \param[in] size  Number of bytes of keying material required
        ///
        /// \returns Keing material
        ///
        virtual sanitizing_blob derive_challenge(_In_ size_t size);

        ///
        /// Processes an application message
        ///
        /// \param[in] msg       Application message data
        /// \param[in] size_msg  Application message data size
        ///
        virtual void process_application_data(_In_bytecount_(size_msg) const void *msg, _In_ size_t size_msg);

    protected:
        config_method_ttls &m_cfg;          ///< EAP-TTLS method configuration
        credentials_ttls &m_cred;           ///< EAP-TTLS credentials

        #pragma warning(suppress: 4480)
        enum version_t :unsigned char {
            version_0 = 0,                  ///< EAP-TTLS v0
        } m_version;                        ///< EAP-TTLS version

        std::unique_ptr<method> m_inner;    ///< Inner authentication method
    };
}
