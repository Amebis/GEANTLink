/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2021 Amebis
    Copyright © 2016 GÉANT
*/

#include <WinStd/Common.h>

#include <Windows.h>
#include <WinCrypt.h> // Must include after <Windows.h>

#include <sal.h>

#define EAP_TLS_OWN             0   ///< We do the TLS ourself
#define EAP_TLS_SCHANNEL        1   ///< TLS is done by Schannel, but server certificate check is done ourself
#define EAP_TLS_SCHANNEL_FULL   2   ///< TLS is fully done by Schannel

namespace eap
{
    class config_method_tls;

    /// \addtogroup EAPBaseMethod
    /// @{

    ///
    /// Helper function to compile human-readable certificate name for UI display
    ///
    winstd::tstring get_cert_title(PCCERT_CONTEXT cert);

    /// @}
}

#pragma once

#include "Credentials.h"

#include "../../EAPBase/include/Config.h"

#include <WinStd/Crypt.h>

#include <Windows.h>

#include <list>
#include <string>


namespace eap
{
    /// \addtogroup EAPBaseMethod
    /// @{

    ///
    /// TLS configuration
    ///
    class config_method_tls : public config_method_with_cred
    {
    public:
        ///
        /// Constructs configuration
        ///
        /// \param[in] mod    EAP module to use for global services
        /// \param[in] level  Config level (0=outer, 1=inner, 2=inner-inner...)
        ///
        config_method_tls(_In_ module &mod, _In_ unsigned int level);

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        config_method_tls(_In_ const config_method_tls &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        config_method_tls(_Inout_ config_method_tls &&other) noexcept;

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        /// \returns Reference to this object
        ///
        config_method_tls& operator=(_In_ const config_method_tls &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        /// \returns Reference to this object
        ///
        config_method_tls& operator=(_Inout_ config_method_tls &&other) noexcept;

        /// \name XML management
        /// @{
        virtual void save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot) const;
        virtual void load(_In_ IXMLDOMNode *pConfigRoot);
        /// @}

        /// \name BLOB management
        /// @{
        virtual void operator<<(_Inout_ cursor_out &cursor) const;
        virtual size_t get_pk_size() const;
        virtual void operator>>(_Inout_ cursor_in &cursor);
        /// @}

        ///
        /// @copydoc eap::config_method::make_credentials()
        /// \returns This implementation always returns `eap::credentials_tls` type of credentials
        ///
        virtual credentials* make_credentials() const;

        ///
        /// Adds CA to the list of trusted root CA's
        ///
        /// \note If the CA is already on the list, function fails returning \c false.
        ///
        /// \param[in] dwCertEncodingType  Any bitwise OR combination of \c X509_ASN_ENCODING and \c PKCS_7_ASN_ENCODING flags
        /// \param[in] pbCertEncoded       Certificate data
        /// \param[in] cbCertEncoded       Size of \p pbCertEncoded in bytes
        ///
        /// \returns
        /// - \c true when adding succeeds;
        /// - \c false otherwise.
        ///
        bool add_trusted_ca(_In_ DWORD dwCertEncodingType, _In_ LPCBYTE pbCertEncoded, _In_ DWORD cbCertEncoded);

    public:
        std::list<winstd::cert_context> m_trusted_root_ca;  ///< Trusted root CAs
        std::list<std::wstring> m_server_names;             ///< Acceptable authenticating server names
    };

    /// @}
}
