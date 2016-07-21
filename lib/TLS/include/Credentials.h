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

namespace eap
{
    ///
    /// TLS credentials
    ///
    class credentials_tls;
}

#pragma once

#include "../../EAPBase/include/Credentials.h"

#include <WinStd/Crypt.h>

#include <Windows.h>
#include <vector>


namespace eap
{
    class credentials_tls : public credentials
    {
    public:
        ///
        /// Constructs credentials
        ///
        /// \param[in] mod  Reference of the EAP module to use for global services
        ///
        credentials_tls(_In_ module &mod);

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        credentials_tls(_In_ const credentials_tls &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Credentials to move from
        ///
        credentials_tls(_Inout_ credentials_tls &&other);

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        /// \returns Reference to this object
        ///
        credentials_tls& operator=(_In_ const credentials_tls &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Credentials to move from
        ///
        /// \returns Reference to this object
        ///
        credentials_tls& operator=(_Inout_ credentials_tls &&other);

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
        virtual bool empty() const;

        /// \name XML credentials management
        /// @{

        ///
        /// Save credentials to XML document
        ///
        /// \param[in]  pDoc         XML document
        /// \param[in]  pConfigRoot  Suggested root element for saving credentials
        /// \param[out] ppEapError   Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError) const;

        ///
        /// Load credentials from XML document
        ///
        /// \param[in]  pConfigRoot  Root element for loading credentials
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

        /// \name Storage
        /// @{

        ///
        /// Save credentials to Windows Credential Manager
        ///
        /// \param[in]  pszTargetName  The name in Windows Credential Manager to store credentials as
        /// \param[out] ppEapError     Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool store(_In_ LPCTSTR pszTargetName, _Out_ EAP_ERROR **ppEapError) const;

        ///
        /// Retrieve credentials from Windows Credential Manager
        ///
        /// \param[in]  pszTargetName  The name in Windows Credential Manager to retrieve credentials from
        /// \param[out] ppEapError     Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool retrieve(_In_ LPCTSTR pszTargetName, _Out_ EAP_ERROR **ppEapError);

        ///
        /// Return target suffix for Windows Credential Manager credential name
        ///
        virtual LPCTSTR target_suffix() const;

        /// @}

        ///
        /// Returns credential identity.
        ///
        virtual std::wstring get_identity() const;

        ///
        /// Returns credential name (for GUI display).
        ///
        virtual winstd::tstring get_name() const;

        /// @}

    public:
        winstd::cert_context m_cert;    ///< Client certificate

    private:
        /// \cond internal
        static const unsigned char s_entropy[1024];
        /// \endcond
    };
}
