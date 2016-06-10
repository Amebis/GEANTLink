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

namespace eapserial
{
    ///
    /// Packs a TLS method credentials
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     Credentials to pack
    ///
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::credentials_tls &val);

    ///
    /// Returns packed size of a TLS method credentials
    ///
    /// \param[in] val  Credentials to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    inline size_t get_pk_size(const eap::credentials_tls &val);

    ///
    /// Unpacks a TLS method credentials
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     Credentials to unpack to
    ///
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::credentials_tls &val);
}

#pragma once

#include "../../EAPBase/include/Credentials.h"

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
        virtual config* clone() const { return new credentials_tls(*this); }

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
        /// Load credentials from XML document
        ///
        /// \param[in]  pConfigRoot  Root element for loading credentials
        /// \param[out] ppEapError   Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c ERROR_SUCCESS if succeeded
        /// - error code otherwise
        ///
        virtual DWORD load(_In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError);

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
        /// - \c ERROR_SUCCESS if succeeded
        /// - error code otherwise
        ///
        virtual DWORD store(_In_ LPCTSTR pszTargetName, _Out_ EAP_ERROR **ppEapError) const;

        ///
        /// Retrieve credentials from Windows Credential Manager
        ///
        /// \param[in]  pszTargetName  The name in Windows Credential Manager to retrieve credentials from
        /// \param[out] ppEapError     Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c ERROR_SUCCESS if succeeded
        /// - error code otherwise
        ///
        virtual DWORD retrieve(_In_ LPCTSTR pszTargetName, _Out_ EAP_ERROR **ppEapError);

        ///
        /// Return target suffix for Windows Credential Manager credential name
        ///
        virtual LPCTSTR target_suffix() const { return _T("TLS"); }

        /// @}

    public:
        std::vector<unsigned char> m_cert_hash;     ///< Client certificate hash (certificates are kept in Personal Certificate Storage)
    };
}


namespace eapserial
{
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::credentials_tls &val)
    {
        pack(cursor, (const eap::credentials&)val);
        pack(cursor, val.m_cert_hash             );
    }


    inline size_t get_pk_size(const eap::credentials_tls &val)
    {
        return
            get_pk_size((const eap::credentials&)val) +
            get_pk_size(val.m_cert_hash             );
    }


    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::credentials_tls &val)
    {
        unpack(cursor, (eap::credentials&)val);
        unpack(cursor, val.m_cert_hash       );
    }
}
