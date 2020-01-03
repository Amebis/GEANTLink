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

#include <sal.h>

namespace eap
{
    class config_method_pap;
}

#pragma once

#include "../../EAPBase/include/Config.h"

#include <Windows.h>
#include <sal.h>
#include <tchar.h>


namespace eap
{
    /// \addtogroup EAPBaseConfig
    /// @{

    ///
    /// PAP configuration
    ///
    class config_method_pap : public config_method_with_cred
    {
    public:
        ///
        /// Constructs configuration
        ///
        /// \param[in] mod    EAP module to use for global services
        /// \param[in] level  Config level (0=outer, 1=inner, 2=inner-inner...)
        ///
        config_method_pap(_In_ module &mod, _In_ unsigned int level);

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        config_method_pap(_In_ const config_method_pap &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        config_method_pap(_Inout_ config_method_pap &&other) noexcept;

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        /// \returns Reference to this object
        ///
        config_method_pap& operator=(_In_ const config_method_pap &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        /// \returns Reference to this object
        ///
        config_method_pap& operator=(_Inout_ config_method_pap &&other) noexcept;

        virtual config* clone() const;

        ///
        /// @copydoc eap::config_method::get_method_id()
        /// \returns This implementation always returns `winstd::eap_type_legacy_pap`
        ///
        virtual winstd::eap_type_t get_method_id() const;

        ///
        /// @copydoc eap::config_method::get_method_str()
        /// \returns This implementation always returns `L"PAP"`
        ///
        virtual const wchar_t* get_method_str() const;

        ///
        /// @copydoc eap::config_method::make_credentials()
        /// \returns This implementation always returns `eap::credentials_pass` type of credentials
        ///
        virtual credentials* make_credentials() const;
    };

    /// @}
}
