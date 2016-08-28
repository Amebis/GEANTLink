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
    /// TTLS credentials
    ///
    class credentials_ttls;
}

#pragma once

#include "../../TLS/include/Credentials.h"

#include <memory>


namespace eap
{
    class credentials_ttls : public credentials_tls
    {
    public:
        ///
        /// Constructs credentials
        ///
        /// \param[in] mod  EAP module to use for global services
        ///
        credentials_ttls(_In_ module &mod);

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        credentials_ttls(_In_ const credentials_ttls &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Credentials to move from
        ///
        credentials_ttls(_Inout_ credentials_ttls &&other);

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        /// \returns Reference to this object
        ///
        credentials_ttls& operator=(_In_ const credentials_ttls &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Credentials to move from
        ///
        /// \returns Reference to this object
        ///
        credentials_ttls& operator=(_Inout_ credentials_ttls &&other);

        ///
        /// Clones credentials
        ///
        /// \returns Pointer to cloned credentials
        ///
        virtual config* clone() const;

        ///
        /// Resets credentials
        ///
        virtual void clear();

        ///
        /// Test credentials if blank
        ///
        /// \returns
        /// - \c true if blank
        /// - \c false otherwise
        ///
        virtual bool empty() const;

        /// \name XML credentials management
        /// @{

        ///
        /// Save to XML document
        ///
        /// \param[in]  pDoc         XML document
        /// \param[in]  pConfigRoot  Suggested root element for saving
        ///
        virtual void save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot) const;

        ///
        /// Load from XML document
        ///
        /// \param[in]  pConfigRoot  Root element for loading
        ///
        virtual void load(_In_ IXMLDOMNode *pConfigRoot);

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

        /// \name Storage
        /// @{

        ///
        /// Save credentials to Windows Credential Manager
        ///
        /// \param[in]  pszTargetName  The name in Windows Credential Manager to store credentials as
        ///
        virtual void store(_In_z_ LPCTSTR pszTargetName) const;

        ///
        /// Retrieve credentials from Windows Credential Manager
        ///
        /// \param[in]  pszTargetName  The name in Windows Credential Manager to retrieve credentials from
        ///
        virtual void retrieve(_In_z_ LPCTSTR pszTargetName);

        ///
        /// Returns credential identity.
        ///
        virtual std::wstring get_identity() const;

        /// @}

        ///
        /// Combine credentials in the following order:
        ///
        /// 1. Cached credentials
        /// 2. Pre-configured credentials
        /// 3. Stored credentials
        ///
        /// \param[in] cred_cached    Cached credentials (optional, can be \c NULL, must be credentials_ttls* type)
        /// \param[in] cfg            Method configuration (must be config_method_ttls type)
        /// \param[in] pszTargetName  The name in Windows Credential Manager to retrieve credentials from (optional, can be \c NULL)
        ///
        /// \returns
        /// - \c source_cache      Credentials were obtained from EapHost cache
        /// - \c source_preshared  Credentials were set by method configuration
        /// - \c source_storage    Credentials were loaded from Windows Credential Manager
        ///
        virtual source_t combine(
            _In_       const credentials             *cred_cached,
            _In_       const config_method_with_cred &cfg,
            _In_opt_z_       LPCTSTR                 pszTargetName);

    public:
        std::unique_ptr<credentials> m_inner;   ///< Inner credentials
    };
}
