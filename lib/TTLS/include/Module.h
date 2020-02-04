/*
    Copyright 2015-2020 Amebis
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
    class peer_tls_tunnel;
    class peer_ttls;
}

#pragma once

#include "Config.h"
#include "Credentials.h"
#include "Method.h"
#include "TTLS.h"

#include "..\..\TLS\include\Module.h"


namespace eap
{
    /// \addtogroup EAPBaseModule
    /// @{

    ///
    /// TLS tunnel peer
    ///
    class peer_tls_tunnel : public peer_tls
    {
    public:
        ///
        /// Constructs a TLS tunnel peer module
        ///
        /// \param[in] eap_method  EAP method type ID
        ///
        peer_tls_tunnel(_In_ winstd::eap_type_t eap_method);

        virtual void initialize();
        virtual void shutdown();

        virtual void get_identity(
            _In_                                   DWORD  dwFlags,
            _In_count_(dwConnectionDataSize) const BYTE   *pConnectionData,
            _In_                                   DWORD  dwConnectionDataSize,
            _In_count_(dwUserDataSize)       const BYTE   *pUserData,
            _In_                                   DWORD  dwUserDataSize,
            _Out_                                  BYTE   **ppUserDataOut,
            _Out_                                  DWORD  *pdwUserDataOutSize,
            _In_                                   HANDLE hTokenImpersonateUser,
            _Out_                                  BOOL   *pfInvokeUI,
            _Out_                                  WCHAR  **ppwszIdentity);

        virtual void get_method_properties(
            _In_                                   DWORD                     dwVersion,
            _In_                                   DWORD                     dwFlags,
            _In_                                   HANDLE                    hUserImpersonationToken,
            _In_count_(dwConnectionDataSize) const BYTE                      *pConnectionData,
            _In_                                   DWORD                     dwConnectionDataSize,
            _In_count_(dwUserDataSize)       const BYTE                      *pUserData,
            _In_                                   DWORD                     dwUserDataSize,
            _Out_                                  EAP_METHOD_PROPERTY_ARRAY *pMethodPropertyArray);

        virtual void credentials_xml2blob(
            _In_                                   DWORD       dwFlags,
            _In_                                   IXMLDOMNode *pConfigRoot,
            _In_count_(dwConnectionDataSize) const BYTE        *pConnectionData,
            _In_                                   DWORD       dwConnectionDataSize,
            _Out_                                  BYTE        **ppCredentialsOut,
            _Out_                                  DWORD       *pdwCredentialsOutSize);

        /// \name Session management
        /// @{

        virtual EAP_SESSION_HANDLE begin_session(
            _In_                                   DWORD              dwFlags,
            _In_                           const   EapAttributes      *pAttributeArray,
            _In_                                   HANDLE             hTokenImpersonateUser,
            _In_count_(dwConnectionDataSize) const BYTE               *pConnectionData,
            _In_                                   DWORD              dwConnectionDataSize,
            _In_count_(dwUserDataSize)       const BYTE               *pUserData,
            _In_                                   DWORD              dwUserDataSize,
            _In_                                   DWORD              dwMaxSendPacketSize);

        virtual void end_session(_In_ EAP_SESSION_HANDLE hSession);

        /// @}

        /// \name Packet processing
        /// @{

        virtual void process_request_packet(
            _In_                                       EAP_SESSION_HANDLE  hSession,
            _In_bytecount_(dwReceivedPacketSize) const EapPacket           *pReceivedPacket,
            _In_                                       DWORD               dwReceivedPacketSize,
            _Out_                                      EapPeerMethodOutput *pEapOutput);

        virtual void get_response_packet(
            _In_                                   EAP_SESSION_HANDLE hSession,
            _Out_bytecapcount_(*pdwSendPacketSize) EapPacket          *pSendPacket,
            _Inout_                                DWORD              *pdwSendPacketSize);

        /// @}

        virtual void get_result(
            _In_    EAP_SESSION_HANDLE        hSession,
            _In_    EapPeerMethodResultReason reason,
            _Inout_ EapPeerMethodResult       *pResult);

        /// \name User Interaction
        /// @{

        virtual void get_ui_context(
            _In_  EAP_SESSION_HANDLE hSession,
            _Out_ BYTE               **ppUIContextData,
            _Out_ DWORD              *pdwUIContextDataSize);

        virtual void set_ui_context(
            _In_                                  EAP_SESSION_HANDLE  hSession,
            _In_count_(dwUIContextDataSize) const BYTE                *pUIContextData,
            _In_                                  DWORD               dwUIContextDataSize,
            _Out_                                 EapPeerMethodOutput *pEapOutput);

        /// @}

        /// \name EAP Response Attributes
        /// @{

        virtual void get_response_attributes(
            _In_  EAP_SESSION_HANDLE hSession,
            _Out_ EapAttributes      *pAttribs);

        virtual void set_response_attributes(
            _In_       EAP_SESSION_HANDLE  hSession,
            _In_ const EapAttributes       *pAttribs,
            _Out_      EapPeerMethodOutput *pEapOutput);

        /// @}

    protected:
        ///
        /// Makes a new inner method
        ///
        /// \param[in] cfg   Method configuration
        /// \param[in] cred  Credentials
        ///
        /// \returns A new inner method of given type
        ///
        virtual method* make_method(_In_ config_method_tls_tunnel &cfg, _In_ credentials_tls_tunnel &cred) = 0;

        ///
        /// Checks all configured providers and tries to combine credentials.
        ///
        _Success_(return != 0) const config_method_tls_tunnel* combine_credentials(
            _In_                             DWORD                   dwFlags,
            _In_                       const config_connection       &cfg,
            _In_count_(dwUserDataSize) const BYTE                    *pUserData,
            _In_                             DWORD                   dwUserDataSize,
            _Inout_                          credentials_connection& cred_out,
            _In_                             HANDLE                  hTokenImpersonateUser);

    protected:
        ///
        /// TTL tunnel session
        ///
        class session {
        public:
            ///
            /// Constructs a session
            ///
            session(_In_ module &mod);

            ///
            /// Destructs the session
            ///
            virtual ~session();

        public:
            module &m_module;                   ///< Module
            config_connection m_cfg;            ///< Connection configuration
            credentials_connection m_cred;      ///< Connection credentials
            std::unique_ptr<method> m_method;   ///< EAP method

            // The following members are required to avoid memory leakage in get_result() and get_ui_context().
            BYTE *m_blob_cfg;                   ///< Configuration BLOB
#if EAP_USE_NATIVE_CREDENTIAL_CACHE
            BYTE *m_blob_cred;                  ///< Credentials BLOB
#endif
            BYTE *m_blob_ui_ctx;                ///< User Interface context data
        };
    };


    ///
    /// EAP-TTLS peer
    ///
    class peer_ttls : public peer_tls_tunnel
    {
    public:
        ///
        /// Constructs a EAP-TTLS peer module
        ///
        peer_ttls();

        ///
        /// @copydoc eap::method::make_config_method()
        /// \returns This implementation always returns `eap::config_method_ttls` type of configuration
        ///
        virtual config_method* make_config_method();

    protected:
        /// @copydoc eap::method::make_config_method()
        virtual method* make_method(_In_ config_method_tls_tunnel &cfg, _In_ credentials_tls_tunnel &cred);
    };

    /// @}
}
