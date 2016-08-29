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
    /// PAP method
    ///
    class method_pap;
}


#pragma once

#include "Config.h"
#include "Credentials.h"

#include "../../EAPBase/include/Method.h"


namespace eap
{
    class method_pap : public method
    {
    public:
        ///
        /// EAP-PAP packet (data)
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
            EapCode m_code;         ///< Packet code
            unsigned char m_id;     ///< Packet ID
            sanitizing_blob m_data; ///< Packet data
        };

    public:
        ///
        /// Constructs an EAP method
        ///
        /// \param[in] mod   EAP module to use for global services
        /// \param[in] cfg   Method configuration
        /// \param[in] cred  User credentials
        ///
        method_pap(_In_ module &module, _In_ config_method_pap &cfg, _In_ credentials_pap &cred);

        ///
        /// Moves an EAP method
        ///
        /// \param[in] other  EAP method to move from
        ///
        method_pap(_Inout_ method_pap &&other);

        ///
        /// Moves an EAP method
        ///
        /// \param[in] other  EAP method to move from
        ///
        /// \returns Reference to this object
        ///
        method_pap& operator=(_Inout_ method_pap &&other);

        /// \name Packet processing
        /// @{

        ///
        /// Processes a packet received by EapHost from a supplicant.
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
        credentials_pap &m_cred;    ///< EAP-TLS user credentials

        packet m_packet_res;        ///< Response packet

        enum {
            phase_unknown = -1,     ///< Unknown phase
            phase_init = 0,         ///< Handshake initialize
            phase_finished,         ///< Connection shut down
        } m_phase, m_phase_prev;    ///< What phase is our communication at?
    };
}
