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
    /// PAP configuration
    ///
    class config_pap;
}

namespace eapserial
{
    ///
    /// Packs a PAP based method configuration
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     Configuration to pack
    ///
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::config_pap &val);

    ///
    /// Returns packed size of a PAP based method configuration
    ///
    /// \param[in] val  Configuration to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    inline size_t get_pk_size(const eap::config_pap &val);

    ///
    /// Unpacks a PAP based method configuration
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     Configuration to unpack to
    ///
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::config_pap &val);
}

#pragma once

#include "../../EAPBase/include/Config.h"

#include <Windows.h>
#include <sal.h>
#include <tchar.h>


namespace eap
{
    class config_pap : public config_pass
    {
    public:
        ///
        /// Constructs configuration
        ///
        /// \param[in] mod  Reference of the EAP module to use for global services
        ///
        config_pap(_In_ module &mod);

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        config_pap(_In_ const config_pap &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        config_pap(_Inout_ config_pap &&other);

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        /// \returns Reference to this object
        ///
        config_pap& operator=(_In_ const config_pap &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        /// \returns Reference to this object
        ///
        config_pap& operator=(_Inout_ config_pap &&other);

        ///
        /// Clones configuration
        ///
        /// \returns Pointer to cloned configuration
        ///
        virtual config* clone() const { return new config_pap(*this); }

        ///
        /// Returns EAP method type of this configuration
        ///
        /// \returns `eap::type_pap`
        ///
        virtual eap::type_t get_method_id() { return eap::type_pap; }
    };
}


namespace eapserial
{
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::config_pap &val)
    {
        pack(cursor, (const eap::config_pass&)val);
    }


    inline size_t get_pk_size(const eap::config_pap &val)
    {
        return get_pk_size((const eap::config_pass&)val);
    }


    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::config_pap &val)
    {
        unpack(cursor, (eap::config_pass&)val);
    }
}
