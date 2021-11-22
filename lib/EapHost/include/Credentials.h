/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2021 Amebis
    Copyright © 2016 GÉANT
*/

#include <sal.h>

namespace eap
{
    class credentials_eaphost;
}

#pragma once

#include "Config.h"

#include "../../EAPBase/include/Credentials.h"

#include <WinStd/Crypt.h>

#include <Windows.h>
#include <vector>


namespace eap
{
    /// \addtogroup EAPBaseCred
    /// @{

    ///
    /// EapHost peer method credentials
    ///
    class credentials_eaphost : public credentials
    {
    public:
        ///
        /// Constructs credentials
        ///
        /// \param[in] mod  EAP module to use for global services
        ///
        credentials_eaphost(_In_ module &mod);

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        credentials_eaphost(_In_ const credentials_eaphost &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Credentials to move from
        ///
        credentials_eaphost(_Inout_ credentials_eaphost &&other) noexcept;

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        /// \returns Reference to this object
        ///
        credentials_eaphost& operator=(_In_ const credentials_eaphost &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Credentials to move from
        ///
        /// \returns Reference to this object
        ///
        credentials_eaphost& operator=(_Inout_ credentials_eaphost &&other) noexcept;

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
        /// \returns This implementation always returns `_T("BLOB")`
        ///
        virtual LPCTSTR target_suffix() const;
        /// @}

        ///
        /// Combine credentials in the following order:
        ///
        /// 1. Cached credentials
        /// 2. Configured credentials (if \p cfg is derived from `config_method_with_cred`)
        /// 3. Stored credentials (must be called in the connecting user context)
        ///
        /// \param[in] dwFlags        A combination of [EAP flags](https://msdn.microsoft.com/en-us/library/windows/desktop/bb891975.aspx) that describe the EAP authentication session behavior
        /// \param[in] cred_cached    Cached credentials (optional, can be \c NULL, must be `credentials_eaphost*` type)
        /// \param[in] cfg            Method configuration (unused, as must be as config_method_eaphost is not derived from `config_method_with_cred`)
        /// \param[in] pszTargetName  The name in Windows Credential Manager to retrieve credentials from (optional, can be \c NULL)
        ///
        /// \returns
        /// - \c source_t::cache   Credentials were obtained from EapHost cache
        /// - \c source_t::config  Credentials were set by method configuration
        /// - \c source_t::storage Credentials were loaded from Windows Credential Manager
        ///
        virtual source_t combine(
            _In_             DWORD         dwFlags,
            _In_opt_   const credentials   *cred_cached,
            _In_       const config_method &cfg,
            _In_opt_z_       LPCTSTR       pszTargetName);

    public:
        sanitizing_blob m_cred_blob;                ///< Credentials BLOB

    private:
        /// \cond internal
        static const unsigned char s_entropy[1024];
        /// \endcond
    };

    /// @}
}
