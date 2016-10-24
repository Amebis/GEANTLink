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
        WINSTD_NONCOPYABLE(peer_ttls)

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
        /// Initializes an EAP peer method for EapHost.
        ///
        /// \sa [EapPeerGetInfo function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363613.aspx)
        ///
        virtual void initialize();

        ///
        /// Shuts down the EAP method and prepares to unload its corresponding DLL.
        ///
        /// \sa [EapPeerShutdown function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363627.aspx)
        ///
        virtual void shutdown();

        ///
        /// Returns the user data and user identity after being called by EapHost.
        ///
        /// \sa [EapPeerGetIdentity function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363607.aspx)
        ///
        virtual void get_identity(
            _In_                                   DWORD  dwFlags,
            _In_count_(dwConnectionDataSize) const BYTE   *pConnectionData,
            _In_                                   DWORD  dwConnectionDataSize,
            _In_count_(dwUserDataSize)       const BYTE   *pUserData,
            _In_                                   DWORD  dwUserDataSize,
            _Inout_                                BYTE   **ppUserDataOut,
            _Inout_                                DWORD  *pdwUserDataOutSize,
            _In_                                   HANDLE hTokenImpersonateUser,
            _Inout_                                BOOL   *pfInvokeUI,
            _Inout_                                WCHAR  **ppwszIdentity);

        ///
        /// Defines the implementation of an EAP method-specific function that retrieves the properties of an EAP method given the connection and user data.
        ///
        /// \sa [EapPeerGetMethodProperties function](https://msdn.microsoft.com/en-us/library/windows/desktop/hh706636.aspx)
        ///
        virtual void get_method_properties(
            _In_                                   DWORD                     dwVersion,
            _In_                                   DWORD                     dwFlags,
            _In_                                   HANDLE                    hUserImpersonationToken,
            _In_count_(dwConnectionDataSize) const BYTE                      *pConnectionData,
            _In_                                   DWORD                     dwConnectionDataSize,
            _In_count_(dwUserDataSize)       const BYTE                      *pUserData,
            _In_                                   DWORD                     dwUserDataSize,
            _Inout_                                EAP_METHOD_PROPERTY_ARRAY *pMethodPropertyArray);

        ///
        /// Converts XML into the configuration BLOB. The XML based credentials can come from group policy or from a system administrator.
        ///
        /// \sa [EapPeerCredentialsXml2Blob function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363603.aspx)
        ///
        virtual void credentials_xml2blob(
            _In_                                   DWORD       dwFlags,
            _In_                                   IXMLDOMNode *pConfigRoot,
            _In_count_(dwConnectionDataSize) const BYTE        *pConnectionData,
            _In_                                   DWORD       dwConnectionDataSize,
            _Inout_                                BYTE        **ppCredentialsOut,
            _Inout_                                DWORD       *pdwCredentialsOutSize);

        /// \name Session management
        /// @{

        ///
        /// Starts an EAP authentication session on the peer EapHost using the EAP method.
        ///
        /// \sa [EapPeerBeginSession function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363600.aspx)
        ///
        /// \returns Session handle
        ///
        virtual EAP_SESSION_HANDLE begin_session(
            _In_                                   DWORD              dwFlags,
            _In_                           const   EapAttributes      *pAttributeArray,
            _In_                                   HANDLE             hTokenImpersonateUser,
            _In_count_(dwConnectionDataSize) const BYTE               *pConnectionData,
            _In_                                   DWORD              dwConnectionDataSize,
            _In_count_(dwUserDataSize)       const BYTE               *pUserData,
            _In_                                   DWORD              dwUserDataSize,
            _In_                                   DWORD              dwMaxSendPacketSize);

        ///
        /// Ends an EAP authentication session for the EAP method.
        ///
        /// \sa [EapPeerEndSession function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363604.aspx)
        ///
        virtual void end_session(_In_ EAP_SESSION_HANDLE hSession);

        ///
        /// Processes a packet received by EapHost from a supplicant.
        ///
        /// \sa [EapPeerProcessRequestPacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363621.aspx)
        ///
        virtual void process_request_packet(
            _In_                                       EAP_SESSION_HANDLE  hSession,
            _In_bytecount_(dwReceivedPacketSize) const EapPacket           *pReceivedPacket,
            _In_                                       DWORD               dwReceivedPacketSize,
            _Inout_                                    EapPeerMethodOutput *pEapOutput);

        ///
        /// Obtains a response packet from the EAP method.
        ///
        /// \sa [EapPeerGetResponsePacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363610.aspx)
        ///
        virtual void get_response_packet(
            _In_                               EAP_SESSION_HANDLE hSession,
            _Inout_bytecap_(*dwSendPacketSize) EapPacket          *pSendPacket,
            _Inout_                            DWORD              *pdwSendPacketSize);

        ///
        /// Obtains the result of an authentication session from the EAP method.
        ///
        /// \sa [EapPeerGetResult function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363611.aspx)
        ///
        virtual void get_result(
            _In_    EAP_SESSION_HANDLE        hSession,
            _In_    EapPeerMethodResultReason reason,
            _Inout_ EapPeerMethodResult       *pResult);

        ///
        /// Obtains the user interface context from the EAP method.
        ///
        /// \note This function is always followed by the `EapPeerInvokeInteractiveUI()` function, which is followed by the `EapPeerSetUIContext()` function.
        ///
        /// \sa [EapPeerGetUIContext function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363612.aspx)
        ///
        virtual void get_ui_context(
            _In_    EAP_SESSION_HANDLE hSession,
            _Inout_ BYTE               **ppUIContextData,
            _Inout_ DWORD              *pdwUIContextDataSize);

        ///
        /// Provides a user interface context to the EAP method.
        ///
        /// \note This function is called after the UI has been raised through the `EapPeerGetUIContext()` function.
        ///
        /// \sa [EapPeerSetUIContext function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363626.aspx)
        ///
        virtual void set_ui_context(
            _In_                                  EAP_SESSION_HANDLE  hSession,
            _In_count_(dwUIContextDataSize) const BYTE                *pUIContextData,
            _In_                                  DWORD               dwUIContextDataSize,
            _Out_                                 EapPeerMethodOutput *pEapOutput);

        ///
        /// Obtains an array of EAP response attributes from the EAP method.
        ///
        /// \sa [EapPeerGetResponseAttributes function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363609.aspx)
        ///
        virtual void get_response_attributes(
            _In_    EAP_SESSION_HANDLE hSession,
            _Inout_ EapAttributes      *pAttribs);

        ///
        /// Provides an updated array of EAP response attributes to the EAP method.
        ///
        /// \sa [EapPeerSetResponseAttributes function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363625.aspx)
        ///
        virtual void set_response_attributes(
            _In_       EAP_SESSION_HANDLE  hSession,
            _In_ const EapAttributes       *pAttribs,
            _Out_      EapPeerMethodOutput *pEapOutput);

        /// @}

    protected:
        ///
        /// Checks all configured providers and tries to combine credentials.
        ///
        const config_method_ttls* combine_credentials(
            _In_                             DWORD                   dwFlags,
            _In_                       const config_connection       &cfg,
            _In_count_(dwUserDataSize) const BYTE                    *pUserData,
            _In_                             DWORD                   dwUserDataSize,
            _Out_                            credentials_connection& cred_out,
            _In_                             HANDLE                  hTokenImpersonateUser);

    protected:
        class session {
        public:
            session(_In_ module &mod);
            virtual ~session();

        public:
            module &m_module;                       ///< Module
            config_connection m_cfg;                ///< Connection configuration
            credentials_connection m_cred;          ///< Connection credentials
            std::unique_ptr<method_ttls> m_method;  ///< EAP-TTLS method

            // The following members are required to avoid memory leakage in get_result()
            EAP_ATTRIBUTES m_eap_attr_desc; ///< EAP attributes descriptor
            BYTE *m_blob_cfg;               ///< Configuration BLOB
#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
            BYTE *m_blob_cred;              ///< Credentials BLOB
#endif
        };
    };
}
