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

#include "EAP.h"

#include <sal.h>

namespace eap
{
    ///
    /// Base class for configuration storage
    ///
    class config;

    ///
    /// Base class for method configuration storage
    ///
    class config_method;

    ///
    /// Base class for method with credentials
    ///
    class config_method_with_cred;

    ///
    /// Provider configuration storage
    ///
    class config_provider;

    ///
    /// Connection configuration storage
    ///
    class config_connection;
}

///
/// Packs a configuration
///
/// \param[inout] cursor  Memory cursor
/// \param[in]    val     Configuration to pack
///
inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const eap::config &val);

///
/// Returns packed size of a configuration
///
/// \param[in] val  Configuration to pack
///
/// \returns Size of data when packed (in bytes)
///
inline size_t pksizeof(const eap::config &val);

///
/// Unpacks a configuration
///
/// \param[inout] cursor  Memory cursor
/// \param[out]   val     Configuration to unpack to
///
inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ eap::config &val);

#pragma once

#include "Module.h"
#include "EAPXML.h"

#include "../../../include/Version.h"

#include <WinStd/COM.h>
#include <WinStd/Common.h>

#include <Windows.h>
#include <eaptypes.h> // Must include after <Windows.h>
#include <tchar.h>

#include <list>
#include <string>
#include <memory>


namespace eap
{
    class config
    {
    public:
        ///
        /// Constructs configuration
        ///
        /// \param[in] mod  EAP module to use for global services
        ///
        config(_In_ module &mod);

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        config(_In_ const config &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        config(_Inout_ config &&other);

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        /// \returns Reference to this object
        ///
        config& operator=(_In_ const config &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        /// \returns Reference to this object
        ///
        config& operator=(_Inout_ config &&other);

        ///
        /// Clones this configuration
        ///
        /// \returns Pointer to cloned configuration
        ///
        virtual config* clone() const = 0;

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

        /// @}

    public:
        module &m_module;   ///< EAP module

    protected:
        static const winstd::bstr namespace_eapmetadata;
    };


    class config_method : public config
    {
    public:
        ///
        /// Authentication attempt status
        ///
        enum status_t {
            status_success = 0,                             ///< Authentication succeeded
            status_auth_failed,                             ///< Authentication failed
            status_cred_invalid,                            ///< Invalid credentials
            status_cred_expired,                            ///< Credentials expired
            status_cred_changing,                           ///< Credentials are being changed
            status_account_disabled,                        ///< Account is disabled
            status_account_logon_hours,                     ///< Restricted account logon hours
            status_account_denied,                          ///< Account access is denied
            status_server_compromised,                      ///< Authentication server might have been compromised (CRL)

            // Meta statuses
            status_cred_begin = status_cred_invalid,        ///< First credential related problem
            status_cred_end   = status_cred_changing + 1,   ///< First problem, that is not credential related any more
        };

    public:
        ///
        /// Constructs configuration
        ///
        /// \param[in] mod    EAP module to use for global services
        /// \param[in] level  Config level (0=outer, 1=inner, 2=inner-inner...)
        ///
        config_method(_In_ module &mod, _In_ unsigned int level);

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        config_method(_In_ const config_method &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        config_method(_Inout_ config_method &&other);

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        /// \returns Reference to this object
        ///
        config_method& operator=(_In_ const config_method &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        /// \returns Reference to this object
        ///
        config_method& operator=(_Inout_ config_method &&other);

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

        /// @}

        ///
        /// Returns EAP method type of this configuration
        ///
        /// \returns One of `winstd::eap_type_t` constants.
        ///
        virtual winstd::eap_type_t get_method_id() const = 0;

        ///
        /// Returns a string identifier of the EAP method type of this configuration
        ///
        virtual const wchar_t* get_method_str() const = 0;

    public:
        const unsigned int m_level; ///< Config level (0=outer, 1=inner, 2=inner-inner...)
        bool m_allow_save;          ///< Are credentials allowed to be saved to Windows Credential Manager?
        status_t m_last_status;     ///< Status of authentication the last time
        std::wstring m_last_msg;    ///< Server message at the last authentication
    };


    class credentials;


    class config_method_with_cred : public config_method
    {
    public:
        ///
        /// Constructs configuration
        ///
        /// \param[in] mod    EAP module to use for global services
        /// \param[in] level  Config level (0=outer, 1=inner, 2=inner-inner...)
        ///
        config_method_with_cred(_In_ module &mod, _In_ unsigned int level);

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        config_method_with_cred(_In_ const config_method_with_cred &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        config_method_with_cred(_Inout_ config_method_with_cred &&other);

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        /// \returns Reference to this object
        ///
        config_method_with_cred& operator=(_In_ const config_method_with_cred &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        /// \returns Reference to this object
        ///
        config_method_with_cred& operator=(_Inout_ config_method_with_cred &&other);

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

        /// @}

        ///
        /// Creates a blank set of credentials suitable for this method
        ///
        virtual credentials* make_credentials() const = 0;

    public:
        bool m_use_cred;                        ///< Use configured credentials
        std::unique_ptr<credentials> m_cred;    ///< Configured credentials
    };


    class config_provider : public config
    {
    public:
        ///
        /// Constructs configuration
        ///
        /// \param[in] mod  EAP module to use for global services
        ///
        config_provider(_In_ module &mod);

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        config_provider(_In_ const config_provider &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        config_provider(_Inout_ config_provider &&other);

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        /// \returns Reference to this object
        ///
        config_provider& operator=(_In_ const config_provider &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        /// \returns Reference to this object
        ///
        config_provider& operator=(_Inout_ config_provider &&other);

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

        /// @}

        ///
        /// Returns provider namespace and ID concatenated
        ///
        inline std::wstring get_id() const
        {
            if (m_namespace.empty())
                return m_id;
            else {
                std::wstring id(m_namespace);
                id += L':';
                id += m_id;
                return id;
            }
        }

    public:
        std::wstring m_namespace;                               ///< Provider namespace URI
        std::wstring m_id;                                      ///< Provider ID
        bool m_read_only;                                       ///< Is profile read-only
        winstd::tstring m_name;                                 ///< Provider name
        winstd::tstring m_help_email;                           ///< Helpdesk e-mail
        winstd::tstring m_help_web;                             ///< Helpdesk website URL
        winstd::tstring m_help_phone;                           ///< Helpdesk phone
        winstd::tstring m_lbl_alt_credential;                   ///< Alternative label for credential prompt
        winstd::tstring m_lbl_alt_identity;                     ///< Alternative label for identity prompt
        winstd::tstring m_lbl_alt_password;                     ///< Alternative label for password prompt
        std::vector<std::unique_ptr<config_method> > m_methods; ///< Array of method configurations
    };


    class config_connection : public config
    {
    public:
        typedef std::list<eap::config_provider> provider_list;

    public:
        ///
        /// Constructs configuration
        ///
        /// \param[in] mod  EAP module to use for global services
        ///
        config_connection(_In_ module &mod);

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        config_connection(_In_ const config_connection &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        config_connection(_Inout_ config_connection &&other);

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        /// \returns Reference to this object
        ///
        config_connection& operator=(_In_ const config_connection &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        /// \returns Reference to this object
        ///
        config_connection& operator=(_Inout_ config_connection &&other);

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

        /// @}

    public:
        std::list<eap::config_provider> m_providers;    ///< Provider configurations
    };
}


inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const eap::config &val)
{
    val.operator<<(cursor);
}


inline size_t pksizeof(const eap::config &val)
{
    return val.get_pk_size();
}


inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ eap::config &val)
{
    val.operator>>(cursor);
}


inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const eap::config_method::status_t &val)
{
    cursor << (unsigned char)val;
}


inline size_t pksizeof(_In_ const eap::config_method::status_t &val)
{
    return pksizeof((unsigned char)val);
}


inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ eap::config_method::status_t &val)
{
    cursor >> (unsigned char&)val;
}
