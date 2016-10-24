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
    /// EAPMsg method
    ///
    class method_eapmsg;
}


#pragma once

#include "Config.h"
#include "Credentials.h"

#include "../../EAPBase/include/Method.h"


namespace eap
{
    class method_eapmsg : public method_noneap
    {
        WINSTD_NONCOPYABLE(method_eapmsg)

    public:
        ///
        /// Constructs an EAP method
        ///
        /// \param[in] mod   EAP module to use for global services
        /// \param[in] cfg   Method configuration
        /// \param[in] cred  User credentials
        ///
        method_eapmsg(_In_ module &module, _In_ config_method_eapmsg &cfg, _In_ credentials_eapmsg &cred);

        ///
        /// Moves an EAP method
        ///
        /// \param[in] other  EAP method to move from
        ///
        method_eapmsg(_Inout_ method_eapmsg &&other);

        ///
        /// Moves an EAP method
        ///
        /// \param[in] other  EAP method to move from
        ///
        /// \returns Reference to this object
        ///
        method_eapmsg& operator=(_Inout_ method_eapmsg &&other);

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
            _Out_                                      EapPeerMethodOutput *pEapOutput);

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
            _Inout_ EapPeerMethodResult       *pResult);

        /// @}

        /// \name User Interaction
        /// @{

        ///
        /// Obtains the user interface context from the EAP method.
        ///
        /// \note This function is always followed by the `EapPeerInvokeInteractiveUI()` function, which is followed by the `EapPeerSetUIContext()` function.
        ///
        /// \sa [EapPeerGetUIContext function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363612.aspx)
        ///
        virtual void get_ui_context(
            _Inout_ BYTE  **ppUIContextData,
            _Inout_ DWORD *pdwUIContextDataSize);

        ///
        /// Provides a user interface context to the EAP method.
        ///
        /// \note This function is called after the UI has been raised through the `EapPeerGetUIContext()` function.
        ///
        /// \sa [EapPeerSetUIContext function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363626.aspx)
        ///
        virtual void set_ui_context(
            _In_count_(dwUIContextDataSize) const BYTE                *pUIContextData,
            _In_                                  DWORD               dwUIContextDataSize,
            _Out_                                 EapPeerMethodOutput *pEapOutput);

        /// @}

        /// \name EAP Response Attributes
        /// @{

        ///
        /// Obtains an array of EAP response attributes from the EAP method.
        ///
        /// \sa [EapPeerGetResponseAttributes function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363609.aspx)
        ///
        virtual void get_response_attributes(_Inout_ EapAttributes *pAttribs);

        ///
        /// Provides an updated array of EAP response attributes to the EAP method.
        ///
        /// \sa [EapPeerSetResponseAttributes function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363625.aspx)
        ///
        virtual void set_response_attributes(
            _In_ const EapAttributes       *pAttribs,
            _Out_      EapPeerMethodOutput *pEapOutput);

        /// @}

    protected:
        ///
        /// Converts EapHost peer action to output structure.
        ///
        /// \param[in ] action      EapHost peer action
        /// \param[out] pEapOutput  EAP method output structure
        ///
        inline void action_to_output(
            _In_   EapHostPeerResponseAction action,
            _Out_  EapPeerMethodOutput       *pEapOutput)
        {
            switch (action) {
                case EapHostPeerResponseDiscard            : pEapOutput->action = EapPeerMethodResponseActionDiscard ; break;
                case EapHostPeerResponseSend               : pEapOutput->action = EapPeerMethodResponseActionSend    ; break;
                case EapHostPeerResponseResult             : pEapOutput->action = EapPeerMethodResponseActionResult  ; break;
                case EapHostPeerResponseInvokeUi           : pEapOutput->action = EapPeerMethodResponseActionInvokeUI; break;
                case EapHostPeerResponseRespond            : pEapOutput->action = EapPeerMethodResponseActionRespond ; break;
                case EapHostPeerResponseStartAuthentication: pEapOutput->action = EapPeerMethodResponseActionDiscard ; break; // The session could not be found. So the supplicant either needs to start session again with the same packet or discard the packet.
                case EapHostPeerResponseNone               : pEapOutput->action = EapPeerMethodResponseActionNone    ; break;
                default                                    : throw std::invalid_argument(winstd::string_printf(__FUNCTION__ " Unknown action (%u).", action).c_str());
            }
            pEapOutput->fAllowNotifications = TRUE;
        }

    protected:
        EAP_SESSIONID m_session_id;     ///< EAP session ID

        sanitizing_blob m_ctx_req_blob; ///< Inner UI context request
        sanitizing_blob m_ctx_res_blob; ///< Inner UI context response
    };
}
