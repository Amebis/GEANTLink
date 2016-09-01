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
    /// MSCHAPv2 credentials
    ///
    class credentials_mschapv2;
}

#pragma once

#include "Config.h"

#include "../../EAPBase/include/Credentials.h"

#include <Windows.h>
#include <sal.h>
#include <tchar.h>


namespace eap
{
    class credentials_mschapv2 : public credentials_pass
    {
    public:
        ///
        /// Constructs credentials
        ///
        /// \param[in] mod  EAP module to use for global services
        ///
        credentials_mschapv2(_In_ module &mod);

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        credentials_mschapv2(_In_ const credentials_mschapv2 &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Credentials to move from
        ///
        credentials_mschapv2(_Inout_ credentials_mschapv2 &&other);

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        /// \returns Reference to this object
        ///
        credentials_mschapv2& operator=(_In_ const credentials_mschapv2 &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Credentials to move from
        ///
        /// \returns Reference to this object
        ///
        credentials_mschapv2& operator=(_Inout_ credentials_mschapv2 &&other);

        ///
        /// Clones credentials
        ///
        /// \returns Pointer to cloned credentials
        ///
        virtual config* clone() const;

        /// \name Storage
        /// @{

        ///
        /// Return target suffix for Windows Credential Manager credential name
        ///
        virtual LPCTSTR target_suffix() const;

        /// @}

        ///
        /// Combine credentials in the following order:
        ///
        /// 1. Cached credentials
        /// 2. Pre-configured credentials
        /// 3. Stored credentials
        ///
        /// \param[in] cred_cached    Cached credentials (optional, can be \c NULL, must be credentials_mschapv2* type)
        /// \param[in] cfg            Method configuration (must be config_method_mschapv2 type)
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
    };
}
