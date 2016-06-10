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

#define IDR_EAP_KEY_PUBLIC  1
#define IDR_EAP_KEY_PRIVATE 2

#if !defined(RC_INVOKED) && !defined(MIDL_PASS)

namespace eap
{
    ///
    /// EAP method numbers
    ///
    /// \sa [Extensible Authentication Protocol (EAP) Registry (Chapter: Method Types)](https://www.iana.org/assignments/eap-numbers/eap-numbers.xhtml#eap-numbers-4)
    ///
    enum type_t;
}


#pragma once


namespace eap
{
    enum type_t {
        type_undefined = 0,      ///< Undefined EAP type
        type_tls       = 13,     ///< EAP-TLS
        type_ttls      = 21,     ///< EAP-TTLS
        type_peap      = 25,     ///< EAP-PEAP
        type_mschapv2  = 26,     ///< EAP-MSCHAPv2
        type_pap       = 192,    ///< PAP (Not actually an EAP method; Moved to the Unassigned area)
    };
}

#endif
