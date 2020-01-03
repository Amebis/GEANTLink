/*
    Copyright 2015-2020 Amebis
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
    class credentials;
    class credentials_pass;
    class credentials_connection;
}

#pragma once

#include "Config.h"
#include "Module.h"

#include "../../../include/Version.h"

#include <WinStd/Common.h>

#include <Windows.h>
#include <eaptypes.h> // Must include after <Windows.h>
#include <tchar.h>
#include <wincred.h>

#include <memory>
#include <string>


namespace eap
{
    /// \addtogroup EAPBaseCred
    /// @{

    ///
    /// Base class for method credential storage
    ///
    class credentials : public config
    {
    public:
        ///
        /// Credential source when combined
        ///
        enum source_t {
            source_unknown = -1, ///< Unknown source
            source_cache = 0,    ///< Credentials were obtained from EapHost cache
            source_config,       ///< Credentials were set by method configuration
            source_storage,      ///< Credentials were loaded from Windows Credential Manager
            source_lower,        ///< Credentials were set by lower EAP method
        };


    public:
        ///
        /// Constructs credentials
        ///
        /// \param[in] mod  EAP module to use for global services
        ///
        credentials(_In_ module &mod);

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        credentials(_In_ const credentials &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Credentials to move from
        ///
        credentials(_Inout_ credentials &&other) noexcept;

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        /// \returns Reference to this object
        ///
        credentials& operator=(_In_ const credentials &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Configuration to move from
        ///
        /// \returns Reference to this object
        ///
        credentials& operator=(_Inout_ credentials &&other) noexcept;

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

        /// \name Storage
        /// @{

        ///
        /// Save credentials to Windows Credential Manager
        ///
        /// \param[in]  pszTargetName  The name in Windows Credential Manager to store credentials as
        /// \param[in]  level          Credential level (0=outer, 1=inner, 2=inner-inner...)
        ///
        virtual void store(_In_z_ LPCTSTR pszTargetName, _In_ unsigned int level) const = 0;

        ///
        /// Retrieve credentials from Windows Credential Manager
        ///
        /// \param[in]  pszTargetName  The name in Windows Credential Manager to retrieve credentials from
        /// \param[in]  level          Credential level (0=outer, 1=inner, 2=inner-inner...)
        ///
        virtual void retrieve(_In_z_ LPCTSTR pszTargetName, _In_ unsigned int level) = 0;

        ///
        /// Returns target name for Windows Credential Manager credential name
        ///
        /// \param[in]  pszTargetName  The name in Windows Credential Manager to retrieve credentials from
        /// \param[in]  level          Credential level (0=outer, 1=inner, 2=inner-inner...)
        ///
        /// \returns Final target name to store/retrieve credentials in Windows Credential Manager
        ///
        inline winstd::tstring target_name(_In_z_ LPCTSTR pszTargetName, _In_ unsigned int level) const
        {
            // Start with product name and given target name (identity provider usually).
            winstd::tstring target_name(_T(PRODUCT_NAME_STR) _T("/"));
            target_name += pszTargetName;
            target_name += _T('/');

            // Append level of credentials.
            TCHAR buf[20];
            _ultot_s(level, buf, _countof(buf), 10);
            target_name += buf;
            target_name += _T('/');

            // Append credential type.
            target_name += target_suffix();
            assert(target_name.length() < CRED_MAX_GENERIC_TARGET_NAME_LENGTH);
            return target_name;
        }

        ///
        /// Return target suffix for Windows Credential Manager credential name
        ///
        virtual LPCTSTR target_suffix() const = 0;

        /// @}

        ///
        /// Returns credential identity.
        ///
        virtual std::wstring get_identity() const;

        ///
        /// Returns credential name (for GUI display).
        ///
        virtual winstd::tstring get_name() const;

        ///
        /// Combine credentials in the following order:
        ///
        /// 1. Cached credentials
        /// 2. Configured credentials (if \p cfg is derived from `config_method_with_cred`)
        /// 3. Stored credentials
        ///
        /// \param[in] dwFlags                A combination of [EAP flags](https://msdn.microsoft.com/en-us/library/windows/desktop/bb891975.aspx) that describe the EAP authentication session behavior
        /// \param[in] hTokenImpersonateUser  Impersonation token for a logged-on user to collect user-related information
        /// \param[in] cred_cached            Cached credentials (optional, can be \c NULL, must be the same type of credentials as `this`)
        /// \param[in] cfg                    Method configuration (must be the same type of configuration as `this` credentials belong to)
        /// \param[in] pszTargetName          The name in Windows Credential Manager to retrieve credentials from (optional, can be \c NULL)
        ///
        /// \returns
        /// - \c source_cache   Credentials were obtained from EapHost cache
        /// - \c source_config  Credentials were set by method configuration
        /// - \c source_storage Credentials were loaded from Windows Credential Manager
        ///
        virtual source_t combine(
            _In_             DWORD         dwFlags,
            _In_opt_         HANDLE        hTokenImpersonateUser,
            _In_opt_   const credentials   *cred_cached,
            _In_       const config_method &cfg,
            _In_opt_z_       LPCTSTR       pszTargetName) = 0;

    public:
        std::wstring m_identity;    ///< Identity (username\@domain, certificate name etc.)
    };


    ///
    /// Identity-only based method credentials
    ///
    class credentials_identity : public credentials
    {
    public:
        ///
        /// Constructs credentials
        ///
        /// \param[in] mod  EAP module to use for global services
        ///
        credentials_identity(_In_ module &mod);

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        credentials_identity(_In_ const credentials_identity &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Credentials to move from
        ///
        credentials_identity(_Inout_ credentials_identity &&other) noexcept;

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        /// \returns Reference to this object
        ///
        credentials_identity& operator=(_In_ const credentials_identity &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Credentials to move from
        ///
        /// \returns Reference to this object
        ///
        credentials_identity& operator=(_Inout_ credentials_identity &&other) noexcept;

        virtual config* clone() const;

        /// \name XML management
        /// @{
        virtual void save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot) const;
        virtual void load(_In_ IXMLDOMNode *pConfigRoot);
        /// @}

        /// \name Storage
        /// @{
        virtual void store(_In_z_ LPCTSTR pszTargetName, _In_ unsigned int level) const;
        virtual void retrieve(_In_z_ LPCTSTR pszTargetName, _In_ unsigned int level);

        ///
        /// @copydoc eap::credentials::target_suffix()
        /// \returns This implementation always returns `_T("pass")`
        ///
        virtual LPCTSTR target_suffix() const;
        /// @}

        ///
        /// Combine credentials in the following order:
        ///
        /// 1. Cached credentials
        /// 2. Configured credentials (if \p cfg is derived from `config_method_with_cred`)
        /// 3. Stored credentials
        ///
        /// \param[in] dwFlags                A combination of [EAP flags](https://msdn.microsoft.com/en-us/library/windows/desktop/bb891975.aspx) that describe the EAP authentication session behavior
        /// \param[in] hTokenImpersonateUser  Impersonation token for a logged-on user to collect user-related information
        /// \param[in] cred_cached            Cached credentials (optional, can be \c NULL)
        /// \param[in] cfg                    Method configuration (when derived from `config_method_with_cred`, metod attempt to load credentials from \p cfg)
        /// \param[in] pszTargetName          The name in Windows Credential Manager to retrieve credentials from (optional, can be \c NULL)
        ///
        /// \returns
        /// - \c source_cache   Credentials were obtained from EapHost cache
        /// - \c source_config  Credentials were set by method configuration
        /// - \c source_storage Credentials were loaded from Windows Credential Manager
        ///
        virtual source_t combine(
            _In_             DWORD         dwFlags,
            _In_opt_         HANDLE        hTokenImpersonateUser,
            _In_opt_   const credentials   *cred_cached,
            _In_       const config_method &cfg,
            _In_opt_z_       LPCTSTR       pszTargetName);
    };


    ///
    /// Password based method credentials
    ///
    class credentials_pass : public credentials
    {
    public:
        ///
        /// Password encryption method when loaded/saved to profile configuration XML
        ///
        enum enc_alg_t {
            enc_alg_unknown = -1,   ///< Unknown encryption
            enc_alg_none = 0,       ///< Unencrypted
            enc_alg_geantlink,      ///< GÉANTLink module encryption
            enc_alg_kph,            ///< KPH encryption
        };

    public:
        ///
        /// Constructs credentials
        ///
        /// \param[in] mod  EAP module to use for global services
        ///
        credentials_pass(_In_ module &mod);

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        credentials_pass(_In_ const credentials_pass &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Credentials to move from
        ///
        credentials_pass(_Inout_ credentials_pass &&other) noexcept;

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        /// \returns Reference to this object
        ///
        credentials_pass& operator=(_In_ const credentials_pass &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Credentials to move from
        ///
        /// \returns Reference to this object
        ///
        credentials_pass& operator=(_Inout_ credentials_pass &&other) noexcept;

        virtual config* clone() const;
        virtual void clear();
        virtual bool empty() const;

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

        /// \name Storage
        /// @{
        virtual void store(_In_z_ LPCTSTR pszTargetName, _In_ unsigned int level) const;
        virtual void retrieve(_In_z_ LPCTSTR pszTargetName, _In_ unsigned int level);

        ///
        /// @copydoc eap::credentials::target_suffix()
        /// \returns This implementation always returns `_T("pass")`
        ///
        virtual LPCTSTR target_suffix() const;
        /// @}

        ///
        /// Combine credentials in the following order:
        ///
        /// 1. Cached credentials
        /// 2. Configured credentials (if \p cfg is derived from `config_method_with_cred`)
        /// 3. Stored credentials
        ///
        /// \param[in] dwFlags                A combination of [EAP flags](https://msdn.microsoft.com/en-us/library/windows/desktop/bb891975.aspx) that describe the EAP authentication session behavior
        /// \param[in] hTokenImpersonateUser  Impersonation token for a logged-on user to collect user-related information
        /// \param[in] cred_cached            Cached credentials (optional, can be \c NULL)
        /// \param[in] cfg                    Method configuration (when derived from `config_method_with_cred`, metod attempt to load credentials from \p cfg)
        /// \param[in] pszTargetName          The name in Windows Credential Manager to retrieve credentials from (optional, can be \c NULL)
        ///
        /// \returns
        /// - \c source_cache   Credentials were obtained from EapHost cache
        /// - \c source_config  Credentials were set by method configuration
        /// - \c source_storage Credentials were loaded from Windows Credential Manager
        ///
        virtual source_t combine(
            _In_             DWORD         dwFlags,
            _In_opt_         HANDLE        hTokenImpersonateUser,
            _In_opt_   const credentials   *cred_cached,
            _In_       const config_method &cfg,
            _In_opt_z_       LPCTSTR       pszTargetName);

    public:
        winstd::sanitizing_wstring m_password;      ///< Password
        enc_alg_t m_enc_alg;                        ///< Encryption algorithm used for XML password keeping

    private:
        /// \cond internal
        static const unsigned char s_entropy[1024];
        /// \endcond
    };


    ///
    /// Connection credentials
    ///
    class credentials_connection : public config
    {
    public:
        ///
        /// Constructs credentials
        ///
        /// \param[in] mod  EAP module to use for global services
        /// \param[in] cfg  Connection configuration
        ///
        credentials_connection(_In_ module &mod, _In_ const config_connection &cfg);

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        credentials_connection(_In_ const credentials_connection &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Credentials to move from
        ///
        credentials_connection(_Inout_ credentials_connection &&other) noexcept;

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        /// \returns Reference to this object
        ///
        credentials_connection& operator=(_In_ const credentials_connection &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Credentials to move from
        ///
        /// \returns Reference to this object
        ///
        credentials_connection& operator=(_Inout_ credentials_connection &&other) noexcept;

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

        ///
        /// Checks if credentials match given provider.
        ///
        inline bool match(_In_ const config_provider &cfg_provider) const
        {
            return
                _wcsicmp(m_namespace.c_str(), cfg_provider.m_namespace.c_str()) == 0 &&
                _wcsicmp(m_id       .c_str(), cfg_provider.m_id       .c_str()) == 0;
        }

    public:
        const config_connection& m_cfg;         ///< Connection configuration
        std::wstring m_namespace;               ///< Provider namespace URI
        std::wstring m_id;                      ///< Provider ID
        std::unique_ptr<credentials> m_cred;    ///< Credentials
    };

    /// @}
}

/// \addtogroup EAPBaseStream
/// @{

///
/// Packs a credential encryption algorithm ID
///
/// \param[inout] cursor  Memory cursor
/// \param[in]    val     Credential encryption algorithm ID to pack
///
inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const eap::credentials_pass::enc_alg_t &val)
{
    cursor << (unsigned char)val;
}


///
/// Returns packed size of a credential encryption algorithm ID
///
/// \param[in] val  Credential encryption algorithm ID to pack
///
/// \returns Size of data when packed (in bytes)
///
inline size_t pksizeof(_In_ const eap::credentials_pass::enc_alg_t &val)
{
    return pksizeof((unsigned char)val);
}


///
/// Unpacks a credential encryption algorithm ID
///
/// \param[inout] cursor  Memory cursor
/// \param[out]   val     Credential encryption algorithm ID to unpack to
///
inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ eap::credentials_pass::enc_alg_t &val)
{
    val = (eap::credentials_pass::enc_alg_t)0; // Reset higher bytes to zero before reading to lower byte.
    cursor >> (unsigned char&)val;
}

/// @}
