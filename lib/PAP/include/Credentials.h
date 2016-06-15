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

#include "../../EAPBase/include/EAP.h"


namespace eap
{
    ///
    /// PAP credentials
    ///
    class credentials_pap;
}

namespace eapserial
{
    ///
    /// Packs a PAP method credentials
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     Credentials to pack
    ///
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::credentials_pap &val);

    ///
    /// Returns packed size of a PAP method credentials
    ///
    /// \param[in] val  Credentials to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    inline size_t get_pk_size(const eap::credentials_pap &val);

    ///
    /// Unpacks a PAP method credentials
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     Credentials to unpack to
    ///
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::credentials_pap &val);
}

#pragma once

#include "../../EAPBase/include/Credentials.h"

#include <Windows.h>
#include <sal.h>
#include <tchar.h>


namespace eap
{
    class credentials_pap : public credentials_pass
    {
    public:
        ///
        /// Constructs credentials
        ///
        /// \param[in] mod  Reference of the EAP module to use for global services
        ///
        credentials_pap(_In_ module &mod);

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        credentials_pap(_In_ const credentials_pap &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Credentials to move from
        ///
        credentials_pap(_Inout_ credentials_pap &&other);

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        /// \returns Reference to this object
        ///
        credentials_pap& operator=(_In_ const credentials_pap &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Credentials to move from
        ///
        /// \returns Reference to this object
        ///
        credentials_pap& operator=(_Inout_ credentials_pap &&other);

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
    };
}


namespace eapserial
{
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::credentials_pap &val)
    {
        pack(cursor, (const eap::credentials_pass&)val);
    }


    inline size_t get_pk_size(const eap::credentials_pap &val)
    {
        return get_pk_size((const eap::credentials_pass&)val);
    }


    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::credentials_pap &val)
    {
        unpack(cursor, (eap::credentials_pass&)val);
    }
}
