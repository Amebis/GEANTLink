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
    /// TTLS configuration
    ///
    class config_method_ttls;
}

#pragma once

#include "Credentials.h"

#include "../../TLS/include/Config.h"

#include <Windows.h>
#include <assert.h>

#include <memory>


namespace eap {
    class config_method_ttls : public config_method_tls
    {
    public:
        ///
        /// Constructs configuration
        ///
        /// \param[in] mod    EAP module to use for global services
        /// \param[in] level  Config level (0=outer, 1=inner, 2=inner-inner...)
        ///
        config_method_ttls(_In_ module &mod, _In_ unsigned int level);

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        config_method_ttls(const _In_ config_method_ttls &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        config_method_ttls(_Inout_ config_method_ttls &&other);

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        /// \returns Reference to this object
        ///
        config_method_ttls& operator=(const _In_ config_method_ttls &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        /// \returns Reference to this object
        ///
        config_method_ttls& operator=(_Inout_ config_method_ttls &&other);

        ///
        /// Clones configuration
        ///
        /// \returns Pointer to cloned configuration
        ///
        virtual config* clone() const;

        /// \name XML configuration management
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

        ///
        /// Returns EAP method type of this configuration
        ///
        /// \returns `eap::type_ttls`
        ///
        virtual winstd::eap_type_t get_method_id() const;

        ///
        /// Returns a string \c L"EAP-TTLS"
        ///
        virtual const wchar_t* get_method_str() const;

        ///
        /// Creates a blank set of credentials suitable for this method
        ///
        virtual credentials* make_credentials() const;

        ///
        /// Makes a new inner method config
        ///
        /// \param[in] eap_type  EAP type
        ///
        config_method* make_config_method(_In_ winstd::eap_type_t eap_type) const;

        ///
        /// Makes a new inner method config
        ///
        /// \param[in] eap_type  EAP type
        ///
        config_method* make_config_method(_In_ const wchar_t *eap_type) const;

        ///
        /// Generates public identity using current configuration and given credentials
        ///
        std::wstring get_public_identity(const credentials_ttls &cred) const;

    public:
        std::unique_ptr<config_method> m_inner; ///< Inner authentication configuration
        std::wstring m_anonymous_identity;      ///< Anonymous identity
    };
}
