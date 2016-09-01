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
    /// EAP-TTLS packet
    ///
    class packet_ttls;
}

#pragma once

#include "../../TLS/include/TLS.h"


namespace eap
{
    class packet_ttls : public packet_tls
    {
    public:
        ///
        /// EAP-TTLS packet flags
        ///
        /// \sa [Extensible Authentication Protocol Tunneled Transport Layer Security Authenticated Protocol Version 0 (EAP-TTLSv0) (Chapter: 9.1 Packet Format)](https://tools.ietf.org/html/rfc5281#section-9.1)
        ///
        #pragma warning(suppress: 4480)
        enum flags_t : unsigned char {
            flags_length_incl = packet_tls::flags_req_length_incl,  ///< Length included
            flags_more_frag   = packet_tls::flags_req_more_frag,    ///< More fragments
            flags_start       = packet_tls::flags_req_start,        ///< Start
            flags_ver_mask    = 0x07,                               ///< Version mask
        };
    };
}
