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

#include <sal.h>

#include <WinStd/Common.h>

#include <Windows.h>
#include <WinCrypt.h> // Must include after <Windows.h>

namespace eap
{
    ///
    /// TLS configuration
    ///
    class config_method_tls;

    ///
    /// Helper function to compile human-readable certificate name for UI display
    ///
    winstd::tstring get_cert_title(PCCERT_CONTEXT cert);
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
    class config_method_tls : public config_method_with_cred<credentials_tls>
    {
    public:
        ///
        /// Constructs configuration
        ///
        /// \param[in] mod  Reference of the EAP module to use for global services
        ///
        config_method_tls(_In_ module &mod);

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
        config_method_tls(_Inout_ config_method_tls &&other);

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
        config_method_tls& operator=(_Inout_ config_method_tls &&other);

        ///
        /// Clones configuration
        ///
        /// \returns Pointer to cloned configuration
        ///
        virtual config* clone() const;

        /// \name XML configuration management
        /// @{

        ///
        /// Save configuration to XML document
        ///
        /// \param[in]  pDoc         XML document
        /// \param[in]  pConfigRoot  Suggested root element for saving configuration
        /// \param[out] ppEapError   Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError) const;

        ///
        /// Load configuration from XML document
        ///
        /// \param[in]  pConfigRoot  Root element for loading configuration
        /// \param[out] ppEapError   Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool load(_In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError);

        /// @}

        /// \name BLOB management
        /// @{

        ///
        /// Packs a configuration
        ///
        /// \param[inout] cursor  Memory cursor
        ///
        virtual void operator<<(_Inout_ cursor_out &cursor) const;

        ///
        /// Returns packed size of a configuration
        ///
        /// \returns Size of data when packed (in bytes)
        ///
        virtual size_t get_pk_size() const;

        ///
        /// Unpacks a configuration
        ///
        /// \param[inout] cursor  Memory cursor
        ///
        virtual void operator>>(_Inout_ cursor_in &cursor);

        /// @}

        ///
        /// Returns EAP method type of this configuration
        ///
        /// \returns `eap::type_tls`
        ///
        virtual eap::type_t get_method_id() const;

        ///
        /// Adds CA to the list of trusted root CA's
        ///
        /// \sa [CertCreateCertificateContext function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa376033.aspx)
        ///
        bool add_trusted_ca(_In_ DWORD dwCertEncodingType, _In_ const BYTE *pbCertEncoded, _In_ DWORD cbCertEncoded);

    public:
        std::list<winstd::cert_context> m_trusted_root_ca;  ///< Trusted root CAs
        std::list<std::string> m_server_names;              ///< Acceptable authenticating server names
    };
}
