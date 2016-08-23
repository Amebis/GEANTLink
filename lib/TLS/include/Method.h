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
    /// EAP-TLS method
    ///
    class method_tls;
}


#pragma once

#include "Config.h"
#include "Credentials.h"
#include "TLS.h"

#include "../../EAPBase/include/Method.h"

#include <WinStd/Crypt.h>
#include <WinStd/Sec.h>

#include <list>
#include <vector>


namespace eap
{
    class method_tls : public method
    {
    public:
#pragma warning(push)
#pragma warning(disable: 4480)

        ///
        /// EAP-TLS request packet flags
        ///
        /// \sa [The EAP-TLS Authentication Protocol (Chapter: 3.1 EAP-TLS Request Packet)](https://tools.ietf.org/html/rfc5216#section-3.1)
        ///
        enum flags_req_t : unsigned char {
            flags_req_length_incl = 0x80,   ///< Length included
            flags_req_more_frag   = 0x40,   ///< More fragments
            flags_req_start       = 0x20,   ///< Start
        };

        ///
        /// EAP-TLS response packet flags
        ///
        /// \sa [The EAP-TLS Authentication Protocol (Chapter: 3.2 EAP-TLS Response Packet)](https://tools.ietf.org/html/rfc5216#section-3.2)
        ///
        enum flags_res_t : unsigned char {
            flags_res_length_incl = 0x80,   ///< Length included
            flags_res_more_frag   = 0x40,   ///< More fragments
        };

#pragma warning(pop)

        ///
        /// EAP-TLS packet (data)
        ///
        class packet
        {
        public:
            ///
            /// Constructs an empty packet
            ///
            packet();

            ///
            /// Copies a packet
            ///
            /// \param[in] other  Packet to copy from
            ///
            packet(_In_ const packet &other);

            ///
            /// Moves a packet
            ///
            /// \param[in] other  Packet to move from
            ///
            packet(_Inout_ packet &&other);

            ///
            /// Copies a packet
            ///
            /// \param[in] other  Packet to copy from
            ///
            /// \returns Reference to this object
            ///
            packet& operator=(_In_ const packet &other);

            ///
            /// Moves a packet
            ///
            /// \param[in] other  Packet to move from
            ///
            /// \returns Reference to this object
            ///
            packet& operator=(_Inout_ packet &&other);

            ///
            /// Empty the packet
            ///
            void clear();

        public:
            EapCode m_code;                             ///< Packet code
            unsigned char m_id;                         ///< Packet ID
            unsigned char m_flags;                      ///< Packet flags
            std::vector<unsigned char> m_data;          ///< Packet data
        };

    public:
        ///
        /// Constructs an EAP method
        ///
        /// \param[in] mod   EAP module to use for global services
        /// \param[in] cfg   Providers configuration
        /// \param[in] cred  User credentials
        ///
        method_tls(_In_ module &module, _In_ config_provider_list &cfg, _In_ credentials_tls &cred);

        ///
        /// Moves an EAP method
        ///
        /// \param[in] other  EAP method to move from
        ///
        method_tls(_Inout_ method_tls &&other);

        ///
        /// Destructor
        ///
        virtual ~method_tls();

        ///
        /// Moves an EAP method
        ///
        /// \param[in] other  EAP method to move from
        ///
        /// \returns Reference to this object
        ///
        method_tls& operator=(_Inout_ method_tls &&other);

        /// \name Packet processing
        /// @{

        ///
        /// Starts an EAP authentication session on the peer EAPHost using the EAP method.
        ///
        /// \sa [EapPeerBeginSession function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363600.aspx)
        ///
        virtual void begin_session(
            _In_        DWORD         dwFlags,
            _In_  const EapAttributes *pAttributeArray,
            _In_        HANDLE        hTokenImpersonateUser,
            _In_        DWORD         dwMaxSendPacketSize);

        ///
        /// Processes a packet received by EAPHost from a supplicant.
        ///
        /// \sa [EapPeerProcessRequestPacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363621.aspx)
        ///
        virtual void process_request_packet(
            _In_bytecount_(dwReceivedPacketSize) const EapPacket           *pReceivedPacket,
            _In_                                       DWORD               dwReceivedPacketSize,
            _Inout_                                    EapPeerMethodOutput *pEapOutput);

        ///
        /// Obtains a response packet from the EAP method.
        ///
        /// \sa [EapPeerGetResponsePacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363610.aspx)
        ///
        virtual void get_response_packet(
            _Inout_bytecap_(*dwSendPacketSize) EapPacket *pSendPacket,
            _Inout_                            DWORD     *pdwSendPacketSize);

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
        /// Process handshake
        ///
        void process_handshake();

        ///
        /// Process application data
        ///
        void process_application_data();

        ///
        /// Processes an application message
        ///
        /// \param[in] msg       Application message data
        /// \param[in] size_msg  Application message data size
        ///
        virtual void process_application_data(_In_bytecount_(size_msg) const void *msg, _In_ size_t size_msg);

#ifndef SCHANNEL_SRV_CERT_CHECK
        ///
        /// Verifies server's certificate if trusted by configuration
        ///
        void verify_server_trust() const;
#endif

    protected:
        credentials_tls &m_cred;                                ///< EAP-TLS user credentials

        packet m_packet_req;                                    ///< Request packet
        packet m_packet_res;                                    ///< Response packet

        HANDLE m_user_ctx;                                      ///< Handle to user context
        winstd::tstring m_sc_target_name;                       ///< Schannel target name
        winstd::sec_credentials m_sc_cred;                      ///< Schannel client credentials
        std::vector<unsigned char> m_sc_queue;                  ///< TLS data queue
        winstd::sec_context m_sc_ctx;                           ///< Schannel context

        enum {
            phase_unknown = -1,                                 ///< Unknown phase
            phase_handshake_init = 0,                           ///< Handshake initialize
            phase_handshake_cont,                               ///< Handshake continue
            phase_application_data,                             ///< Exchange application data
            phase_shutdown,                                     ///< Connection shut down
        } m_phase;                                              ///< What phase is our communication at?

        // The following members are required to avoid memory leakage in get_result()
        EAP_ATTRIBUTES m_eap_attr_desc;                         ///< EAP Radius attributes descriptor
        std::vector<winstd::eap_attr> m_eap_attr;               ///< EAP Radius attributes
        BYTE *m_blob_cfg;                                       ///< Configuration BLOB
#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
        BYTE *m_blob_cred;                                      ///< Credentials BLOB
#endif
    };
}
