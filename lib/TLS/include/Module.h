/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2021 Amebis
    Copyright © 2016 GÉANT
*/

namespace eap
{
    class peer_tls_base;
}

#pragma once

#include "Config.h"
#include "Credentials.h"
#include "Method.h"

#include "../../EAPBase/include/Module.h"


namespace eap
{
    /// \addtogroup EAPBaseModule
    /// @{

    ///
    /// TLS tunnel peer
    ///
    class peer_tls_base : public peer
    {
    public:
        ///
        /// Constructs a TLS tunnel peer module
        ///
        /// \param[in] eap_method  EAP method type ID
        ///
        peer_tls_base(_In_ winstd::eap_type_t eap_method = winstd::eap_type_t::tls);

        virtual void shutdown();

        virtual void get_method_properties(
            _In_                                   DWORD                     dwVersion,
            _In_                                   DWORD                     dwFlags,
            _In_                                   HANDLE                    hUserImpersonationToken,
            _In_count_(dwConnectionDataSize) const BYTE                      *pConnectionData,
            _In_                                   DWORD                     dwConnectionDataSize,
            _In_count_(dwUserDataSize)       const BYTE                      *pUserData,
            _In_                                   DWORD                     dwUserDataSize,
            _Out_                                  EAP_METHOD_PROPERTY_ARRAY *pMethodPropertyArray);

        ///
        /// Spawns a new certificate revocation check thread
        ///
        /// \param[inout] cert  Certificate context to check for revocation. `hCertStore` member should contain all certificates in chain up to and including root CA to test them for revocation too.
        ///
        void spawn_crl_check(_Inout_ winstd::cert_context &&cert);

    protected:
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
