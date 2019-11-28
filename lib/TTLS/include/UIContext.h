/*
    Copyright 2015-2017 Amebis
    Copyright 2016-2017 GÉANT

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
    class ui_context_ttls;
}

#pragma once

#include "TTLS.h"

#include "../../EAPBase/include/UIContext.h"


namespace eap
{
    /// \addtogroup EAPBaseUICtx
    /// @{

    ///
    /// EAP-TTLS UI context
    ///
    class ui_context_ttls : public ui_context
    {
    public:
        ///
        /// Constructs context
        ///
        /// \param[in] cfg   Connection configuration
        /// \param[in] cred  Connection credentials
        ///
        ui_context_ttls(_In_ config_connection &cfg, _In_ credentials_connection &cred);

        ///
        /// Copies context
        ///
        /// \param[in] other  Credentials to copy from
        ///
        ui_context_ttls(_In_ const ui_context_ttls &other);

        ///
        /// Moves context
        ///
        /// \param[in] other  Credentials to move from
        ///
        ui_context_ttls(_Inout_ ui_context_ttls &&other) noexcept;

        ///
        /// Copies context
        ///
        /// \param[in] other  Credentials to copy from
        ///
        /// \returns Reference to this object
        ///
        ui_context_ttls& operator=(_In_ const ui_context_ttls &other);

        ///
        /// Moves context
        ///
        /// \param[in] other  Configuration to move from
        ///
        /// \returns Reference to this object
        ///
        ui_context_ttls& operator=(_Inout_ ui_context_ttls &&other) noexcept;

        /// \name BLOB management
        /// @{
        virtual void operator<<(_Inout_ cursor_out &cursor) const;
        virtual size_t get_pk_size() const;
        virtual void operator>>(_Inout_ cursor_in &cursor);
        /// @}

    public:
        sanitizing_blob m_data;         ///< Context data
    };

    /// @}
}
