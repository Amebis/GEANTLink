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
    /// TTLS session
    ///
    class session_ttls;
}

#pragma once

#include "../../EAPBase/include/Session.h"


namespace eap
{
    class session_ttls : public session<config_ttls, credentials_ttls, int, int>
    {
    public:
        ///
        /// Constructor
        ///
        /// \param[in] mod  Reference of the EAP module to use for global services
        ///
        session_ttls(_In_ module &mod);

        ///
        /// Copies TTLS session
        ///
        /// \param[in] other  Session to copy from
        ///
        session_ttls(_In_ const session_ttls &other);

        ///
        /// Moves TTLS session
        ///
        /// \param[in] other  Session to move from
        ///
        session_ttls(_Inout_ session_ttls &&other);

        ///
        /// Copies TTLS session
        ///
        /// \param[in] other  Session to copy from
        ///
        /// \returns Reference to this object
        ///
        session_ttls& operator=(_In_ const session_ttls &other);

        ///
        /// Moves TTLS session
        ///
        /// \param[in] other  Session to move from
        ///
        /// \returns Reference to this object
        ///
        session_ttls& operator=(_Inout_ session_ttls &&other);
    };
}
