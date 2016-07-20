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

namespace eapserial
{
    ///
    /// Packs a TTLS based method credentials
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     Configuration to pack
    ///
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::credentials_ttls &val);

    ///
    /// Returns packed size of a TTLS based method credentials
    ///
    /// \param[in] val  Configuration to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    inline size_t get_pk_size(const eap::credentials_ttls &val);

    ///
    /// Unpacks a TTLS based method credentials
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     Configuration to unpack to
    ///
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::credentials_ttls &val);
}

#pragma once

#include "../../TLS/include/Credentials.h"
#include "../../PAP/include/Credentials.h"

#include <memory>


namespace eap
{
    class credentials_ttls : public credentials_tls
    {
    public:
        ///
        /// Constructs credentials
        ///
        /// \param[in] mod  Reference of the EAP module to use for global services
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

        /// @}

    public:
        std::unique_ptr<credentials> m_inner;   ///< Inner credentials
    };
}


namespace eapserial
{
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::credentials_ttls &val)
    {
        pack(cursor, (const eap::credentials_tls&)val);
        if (val.m_inner) {
            if (dynamic_cast<eap::credentials_pap*>(val.m_inner.get())) {
                pack(cursor, eap::type_pap);
                pack(cursor, (const eap::credentials_pap&)*val.m_inner);
            } else {
                assert(0); // Unsupported inner authentication method type.
                pack(cursor, eap::type_undefined);
            }
        } else
            pack(cursor, eap::type_undefined);
    }


    inline size_t get_pk_size(const eap::credentials_ttls &val)
    {
        size_t size_inner;
        if (val.m_inner) {
            if (dynamic_cast<eap::credentials_pap*>(val.m_inner.get())) {
                size_inner =
                    get_pk_size(eap::type_pap) +
                    get_pk_size((const eap::credentials_pap&)*val.m_inner);
            } else {
                assert(0); // Unsupported inner authentication method type.
                size_inner = get_pk_size(eap::type_undefined);
            }
        } else
            size_inner = get_pk_size(eap::type_undefined);

        return
            get_pk_size((const eap::credentials_tls&)val) +
            size_inner;
    }


    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::credentials_ttls &val)
    {
        unpack(cursor, (eap::credentials_tls&)val);

        eap::type_t eap_type;
        unpack(cursor, eap_type);
        switch (eap_type) {
            case eap::type_pap:
                val.m_inner.reset(new eap::credentials_pap(val.m_module));
                unpack(cursor, (eap::credentials_pap&)*val.m_inner);
                break;
            default:
                assert(0); // Unsupported inner authentication method type.
                val.m_inner.reset(nullptr);
        }
    }
}
