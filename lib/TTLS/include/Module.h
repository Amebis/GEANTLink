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
    class peer_ttls;
}

#pragma once

#include "Config.h"
#include "Credentials.h"
#include "Method.h"
#include "TTLS.h"


namespace eap
{
    /// \addtogroup EAPBaseModule
    /// @{

    ///
    /// EAP-TTLS peer
    ///
    class peer_ttls : public peer
    {
        WINSTD_NONCOPYABLE(peer_ttls)

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

        ///
        /// Spawns a new certificate revocation check thread
        ///
        /// \param[inout] cert  Certificate context to check for revocation. `hCertStore` member should contain all certificates in chain up to and including root CA to test them for revocation too.
        ///
        void spawn_crl_check(_Inout_ winstd::cert_context &&cert);

    protected:
        ///
        /// Checks all configured providers and tries to combine credentials.
        ///
        _Success_(return != 0) const config_method_ttls* combine_credentials(
            _In_                             DWORD                   dwFlags,
            _In_                       const config_connection       &cfg,
            _In_count_(dwUserDataSize) const BYTE                    *pUserData,
            _In_                             DWORD                   dwUserDataSize,
            _Inout_                          credentials_connection& cred_out,
            _In_                             HANDLE                  hTokenImpersonateUser);

    protected:
        ///
        /// EAP-TTLS session
        ///
        class session {
        public:
            ///
            /// Constructs a EAP-TTLS session
            ///
            session(_In_ module &mod);

            ///
            /// Destructs EAP-TTLS session
            ///
            virtual ~session();

        public:
            module &m_module;                   ///< Module
            config_connection m_cfg;            ///< Connection configuration
            credentials_connection m_cred;      ///< Connection credentials
            std::unique_ptr<method> m_method;   ///< EAP-TTLS method

            // The following members are required to avoid memory leakage in get_result() and get_ui_context().
            BYTE *m_blob_cfg;                   ///< Configuration BLOB
#if EAP_USE_NATIVE_CREDENTIAL_CACHE
            BYTE *m_blob_cred;                  ///< Credentials BLOB
#endif
            BYTE *m_blob_ui_ctx;                ///< User Interface context data
        };

        ///
        ///< Post-festum server certificate revocation verify thread
        ///
        class crl_checker {
        public:
            ///
            /// Constructs a thread
            ///
            /// \param[in   ] mod   EAP module to use for global services
            /// \param[inout] cert  Certificate context to check for revocation. `hCertStore` member should contain all certificates in chain up to and including root CA to test them for revocation too.
            ///
            crl_checker(_In_ module &mod, _Inout_ winstd::cert_context &&cert);

            ///
            /// Moves a thread
            ///
            /// \param[in] other  Thread to move from
            ///
            crl_checker(_Inout_ crl_checker &&other) noexcept;

            ///
            /// Moves a thread
            ///
            /// \param[in] other  Thread to move from
            ///
            /// \returns Reference to this object
            ///
            crl_checker& operator=(_Inout_ crl_checker &&other) noexcept;

            ///
            /// Verifies server's certificate if it has been revoked
            ///
            /// \param[in] obj  Pointer to the instance of this object
            ///
            /// \returns Thread exit code
            ///
            static DWORD WINAPI verify(_In_ crl_checker *obj);

        public:
            module &m_module;                  ///< Module
            winstd::win_handle<NULL> m_thread; ///< Thread
            winstd::win_handle<NULL> m_abort;  ///< Thread abort event
            winstd::cert_context m_cert;       ///< Server certificate
        };

        std::list<crl_checker> m_crl_checkers;  ///< List of certificate revocation check threads
    };

    /// @}
}
