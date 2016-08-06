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
    /// TTLS peer
    ///
    class peer_ttls;
}

#pragma once

#include "Config.h"
#include "Credentials.h"
#include "Method.h"


namespace eap
{
    class peer_ttls : public peer
    {
    public:
        ///
        /// Constructs a EAP TTLS peer module
        ///
        peer_ttls();

        ///
        /// Makes a new method config
        ///
        virtual config_method* make_config_method();

        ///
        /// Initializes an EAP peer method for EAPHost.
        ///
        /// \sa [EapPeerGetInfo function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363613.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool initialize(_Out_ EAP_ERROR **ppEapError);

        ///
        /// Shuts down the EAP method and prepares to unload its corresponding DLL.
        ///
        /// \sa [EapPeerShutdown function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363627.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool shutdown(_Out_ EAP_ERROR **ppEapError);

        ///
        /// Returns the user data and user identity after being called by EAPHost.
        ///
        /// \sa [EapPeerGetIdentity function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363607.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool get_identity(
            _In_                                   DWORD     dwFlags,
            _In_count_(dwConnectionDataSize) const BYTE      *pConnectionData,
            _In_                                   DWORD     dwConnectionDataSize,
            _In_count_(dwUserDataSize)       const BYTE      *pUserData,
            _In_                                   DWORD     dwUserDataSize,
            _Out_                                  BYTE      **ppUserDataOut,
            _Out_                                  DWORD     *pdwUserDataOutSize,
            _In_                                   HANDLE    hTokenImpersonateUser,
            _Out_                                  BOOL      *pfInvokeUI,
            _Out_                                  WCHAR     **ppwszIdentity,
            _Out_                                  EAP_ERROR **ppEapError);

        ///
        /// Defines the implementation of an EAP method-specific function that retrieves the properties of an EAP method given the connection and user data.
        ///
        /// \sa [EapPeerGetMethodProperties function](https://msdn.microsoft.com/en-us/library/windows/desktop/hh706636.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool get_method_properties(
            _In_                                   DWORD                     dwVersion,
            _In_                                   DWORD                     dwFlags,
            _In_                                   HANDLE                    hUserImpersonationToken,
            _In_count_(dwConnectionDataSize) const BYTE                      *pConnectionData,
            _In_                                   DWORD                     dwConnectionDataSize,
            _In_count_(dwUserDataSize)       const BYTE                      *pUserData,
            _In_                                   DWORD                     dwUserDataSize,
            _Out_                                  EAP_METHOD_PROPERTY_ARRAY *pMethodPropertyArray,
            _Out_                                  EAP_ERROR                 **ppEapError);

        ///
        /// Converts XML into the configuration BLOB. The XML based credentials can come from group policy or from a system administrator.
        ///
        /// \sa [EapPeerCredentialsXml2Blob function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363603.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool credentials_xml2blob(
            _In_                                   DWORD       dwFlags,
            _In_                                   IXMLDOMNode *pConfigRoot,
            _In_count_(dwConnectionDataSize) const BYTE        *pConnectionData,
            _In_                                   DWORD       dwConnectionDataSize,
            _Out_                                  BYTE        **ppCredentialsOut,
            _Out_                                  DWORD       *pdwCredentialsOutSize,
            _Out_                                  EAP_ERROR   **ppEapError);

        /// \name Session management
        /// @{

        ///
        /// Starts an EAP authentication session on the peer EAPHost using the EAP method.
        ///
        /// \sa [EapPeerBeginSession function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363600.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool begin_session(
            _In_                                   DWORD              dwFlags,
            _In_                           const   EapAttributes      *pAttributeArray,
            _In_                                   HANDLE             hTokenImpersonateUser,
            _In_count_(dwConnectionDataSize) const BYTE               *pConnectionData,
            _In_                                   DWORD              dwConnectionDataSize,
            _In_count_(dwUserDataSize)       const BYTE               *pUserData,
            _In_                                   DWORD              dwUserDataSize,
            _In_                                   DWORD              dwMaxSendPacketSize,
            _Out_                                  EAP_SESSION_HANDLE *phSession,
            _Out_                                  EAP_ERROR          **ppEapError);

        ///
        /// Ends an EAP authentication session for the EAP method.
        ///
        /// \sa [EapPeerEndSession function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363604.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool end_session(
            _In_ EAP_SESSION_HANDLE hSession,
            _Out_ EAP_ERROR **ppEapError);

        ///
        /// Processes a packet received by EAPHost from a supplicant.
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        /// \sa [EapPeerProcessRequestPacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363621.aspx)
        ///
        virtual bool process_request_packet(
            _In_                                       EAP_SESSION_HANDLE  hSession,
            _In_bytecount_(dwReceivedPacketSize) const EapPacket           *pReceivedPacket,
            _In_                                       DWORD               dwReceivedPacketSize,
            _Out_                                      EapPeerMethodOutput *pEapOutput,
            _Out_                                      EAP_ERROR           **ppEapError);

        ///
        /// Obtains a response packet from the EAP method.
        ///
        /// \sa [EapPeerGetResponsePacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363610.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool get_response_packet(
            _In_                               EAP_SESSION_HANDLE hSession,
            _Inout_bytecap_(*dwSendPacketSize) EapPacket          *pSendPacket,
            _Inout_                            DWORD              *pdwSendPacketSize,
            _Out_                              EAP_ERROR          **ppEapError);

        ///
        /// Obtains the result of an authentication session from the EAP method.
        ///
        /// \sa [EapPeerGetResult function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363611.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool get_result(
            _In_  EAP_SESSION_HANDLE        hSession,
            _In_  EapPeerMethodResultReason reason,
            _Out_ EapPeerMethodResult       *ppResult,
            _Out_ EAP_ERROR                 **ppEapError);

        ///
        /// Obtains the user interface context from the EAP method.
        ///
        /// \note This function is always followed by the `EapPeerInvokeInteractiveUI()` function, which is followed by the `EapPeerSetUIContext()` function.
        ///
        /// \sa [EapPeerGetUIContext function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363612.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool get_ui_context(
            _In_  EAP_SESSION_HANDLE hSession,
            _Out_ BYTE               **ppUIContextData,
            _Out_ DWORD              *pdwUIContextDataSize,
            _Out_ EAP_ERROR          **ppEapError);

        ///
        /// Provides a user interface context to the EAP method.
        ///
        /// \note This function is called after the UI has been raised through the `EapPeerGetUIContext()` function.
        ///
        /// \sa [EapPeerSetUIContext function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363626.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool set_ui_context(
            _In_                                  EAP_SESSION_HANDLE  hSession,
            _In_count_(dwUIContextDataSize) const BYTE                *pUIContextData,
            _In_                                  DWORD               dwUIContextDataSize,
            _In_                            const EapPeerMethodOutput *pEapOutput,
            _Out_                                 EAP_ERROR           **ppEapError);

        ///
        /// Obtains an array of EAP response attributes from the EAP method.
        ///
        /// \sa [EapPeerGetResponseAttributes function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363609.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool get_response_attributes(
            _In_  EAP_SESSION_HANDLE hSession,
            _Out_ EapAttributes      *pAttribs,
            _Out_ EAP_ERROR          **ppEapError);

        ///
        /// Provides an updated array of EAP response attributes to the EAP method.
        ///
        /// \sa [EapPeerSetResponseAttributes function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363625.aspx)
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool set_response_attributes(
            _In_       EAP_SESSION_HANDLE  hSession,
            _In_ const EapAttributes       *pAttribs,
            _Out_      EapPeerMethodOutput *pEapOutput,
            _Out_      EAP_ERROR           **ppEapError);

        /// @}

    protected:
        class session {
        public:
            inline session(_In_ module &mod) :
                m_cfg(mod),
                m_cred(mod),
                m_method(mod, m_cfg, m_cred)
            {}

        public:
            config_method_ttls m_cfg;   ///< Method configuration
            credentials_ttls m_cred;    ///< User credentials
            method_ttls m_method;       ///< EAP-TTLS method
        };
    };
}
