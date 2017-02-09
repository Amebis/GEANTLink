﻿/*
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
    class config;
    class config_method;
    class config_method_with_cred;
    class config_provider;
    class config_connection;
}

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
    ///
    /// \defgroup EAPBaseConfig  Configuration
    /// Configuration management
    ///
    /// @{

    ///
    /// Base class for packable and XML-exportable storage
    ///
    class config : public packable
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
        /// Clones this object
        ///
        /// \returns Pointer to cloned object with identical data
        ///
        virtual config* clone() const = 0;

        /// \name XML management
        /// @{

        ///
        /// Save data to XML document
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

    public:
        module &m_module;                                   ///< EAP module

    protected:
        static const winstd::bstr namespace_eapmetadata;    ///< Reusable BSTR containing "urn:ietf:params:xml:ns:yang:ietf-eap-metadata"
    };


    class credentials;


    ///
    /// Base class for method configuration storage
    ///
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
        /// Returns EAP method type of this configuration
        ///
        /// \returns One of `winstd::eap_type_t` constants.
        ///
        virtual winstd::eap_type_t get_method_id() const = 0;

        ///
        /// Returns a string identifier of the EAP method type of this configuration
        ///
        virtual const wchar_t* get_method_str() const = 0;

        ///
        /// Creates a blank set of credentials suitable for this method
        ///
        virtual credentials* make_credentials() const = 0;

    public:
        const unsigned int m_level; ///< Config level (0=outer, 1=inner, 2=inner-inner...)
        bool m_allow_save;          ///< Are credentials allowed to be saved to Windows Credential Manager?
        status_t m_last_status;     ///< Status of authentication the last time
        std::wstring m_last_msg;    ///< Server message at the last authentication
    };


    ///
    /// Base class for method with credentials
    ///
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

    public:
        bool m_use_cred;                        ///< Use configured credentials
        std::unique_ptr<credentials> m_cred;    ///< Configured credentials
    };


    ///
    /// Provider configuration storage
    ///
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

        virtual config* clone() const;

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


    ///
    /// Connection configuration storage
    ///
    class config_connection : public config
    {
    public:
        ///
        /// List of configuration providers
        ///
        typedef std::list<config_provider> provider_list;

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

        virtual config* clone() const;

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

    public:
        std::list<config_provider> m_providers;    ///< Provider configurations
    };

    /// @}
}


/// \addtogroup EAPBaseStream
/// @{

///
/// Packs a method status
///
/// \param[inout] cursor  Memory cursor
/// \param[in]    val     Method status to pack
///
inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const eap::config_method::status_t &val)
{
    cursor << (unsigned char)val;
}


///
/// Returns packed size of a method status
///
/// \param[in] val  Method status to pack
///
/// \returns Size of data when packed (in bytes)
///
inline size_t pksizeof(_In_ const eap::config_method::status_t &val)
{
    return pksizeof((unsigned char)val);
}


///
/// Unpacks a method status
///
/// \param[inout] cursor  Memory cursor
/// \param[out]   val     Method status to unpack to
///
inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ eap::config_method::status_t &val)
{
    val = (eap::config_method::status_t)0; // Reset higher bytes to zero before reading to lower byte.
    cursor >> (unsigned char&)val;
}

/// @}
