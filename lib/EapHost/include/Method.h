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
    class method_eaphost;
}


#pragma once

#include "Config.h"
#include "Credentials.h"

#include "../../EAPBase/include/Method.h"


namespace eap
{
    /// \addtogroup EAPBaseMethod
    /// @{

    ///
    /// EapHost peer method
    ///
    /// A wrapper class to provide system installed 3rd party EAP methods integration.
    ///
    class method_eaphost : public method
    {
        WINSTD_NONCOPYABLE(method_eaphost)

    public:
        ///
        /// Constructs an EAP method
        ///
        /// \param[in] mod   EAP module to use for global services
        /// \param[in] cfg   Method configuration
        /// \param[in] cred  User credentials
        ///
        method_eaphost(_In_ module &mod, _In_ config_method_eaphost &cfg, _In_ credentials_eaphost &cred);

        ///
        /// Moves an EAP method
        ///
        /// \param[in] other  EAP method to move from
        ///
        method_eaphost(_Inout_ method_eaphost &&other);

        ///
        /// Moves an EAP method
        ///
        /// \param[in] other  EAP method to move from
        ///
        /// \returns Reference to this object
        ///
        method_eaphost& operator=(_Inout_ method_eaphost &&other);

        /// \name Session management
        /// @{

        virtual void begin_session(
            _In_        DWORD         dwFlags,
            _In_  const EapAttributes *pAttributeArray,
            _In_        HANDLE        hTokenImpersonateUser,
            _In_opt_    DWORD         dwMaxSendPacketSize = MAXDWORD);

        virtual void end_session();

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
            _In_   EapPeerMethodResultReason reason,
            _Out_ EapPeerMethodResult       *pResult);

        /// \name User Interaction
        /// @{

        virtual void get_ui_context(
            _Out_ BYTE  **ppUIContextData,
            _Out_ DWORD *pdwUIContextDataSize);

        virtual EapPeerMethodResponseAction set_ui_context(
            _In_count_(dwUIContextDataSize) const BYTE  *pUIContextData,
            _In_                                  DWORD dwUIContextDataSize);

        /// @}

        /// \name EAP Response Attributes
        /// @{

        virtual void get_response_attributes(_Out_ EapAttributes *pAttribs);

        virtual EapPeerMethodResponseAction set_response_attributes(_In_ const EapAttributes *pAttribs);

        /// @}

    protected:
        ///
        /// Converts EapHost peer action to output structure.
        ///
        /// \param[in] action  EapHost peer action
        ///
        /// \returns EAP method output action
        ///
        inline EapPeerMethodResponseAction action_h2p(_In_ EapHostPeerResponseAction action)
        {
            switch (action) {
                case EapHostPeerResponseDiscard            : return EapPeerMethodResponseActionDiscard ;
                case EapHostPeerResponseSend               : return EapPeerMethodResponseActionSend    ;
                case EapHostPeerResponseResult             : return EapPeerMethodResponseActionResult  ;
                case EapHostPeerResponseInvokeUi           : return EapPeerMethodResponseActionInvokeUI;
                case EapHostPeerResponseRespond            : return EapPeerMethodResponseActionRespond ;
                case EapHostPeerResponseStartAuthentication: return EapPeerMethodResponseActionDiscard ; // The session could not be found. So the supplicant either needs to start session again with the same packet or discard the packet.
                case EapHostPeerResponseNone               : return EapPeerMethodResponseActionNone    ;
                default                                    : throw std::invalid_argument(winstd::string_printf(__FUNCTION__ " Unknown action (%u).", action));
            }
        }

    protected:
        config_method_eaphost &m_cfg;   ///< Method configuration
        credentials_eaphost &m_cred;    ///< Method user credentials

        EAP_SESSIONID m_session_id;     ///< EAP session ID
    };

    /// @}
}
