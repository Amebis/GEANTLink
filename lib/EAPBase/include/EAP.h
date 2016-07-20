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

#ifndef EAP_ENCRYPT_BLOBS
#define EAP_ENCRYPT_BLOBS 1
#endif

#if !defined(RC_INVOKED) && !defined(MIDL_PASS)

#include <sal.h>

namespace eap
{
    ///
    /// EAP method numbers
    ///
    /// \sa [Extensible Authentication Protocol (EAP) Registry (Chapter: Method Types)](https://www.iana.org/assignments/eap-numbers/eap-numbers.xhtml#eap-numbers-4)
    ///
    enum type_t;
}

namespace eapserial
{
    ///
    /// Packs an EAP method type
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     EAP method type to pack
    ///
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::type_t &val);

    ///
    /// Returns packed size of an EAP method type
    ///
    /// \param[in] val  EAP method type to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    inline size_t get_pk_size(const eap::type_t &val);

    ///
    /// Unpacks an EAP method type
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     EAP method type to unpack to
    ///
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::type_t &val);
}


#pragma once

#include "EAPSerial.h"


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


namespace eapserial
{
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::type_t &val)
    {
        pack(cursor, (unsigned char)val);
    }


    inline size_t get_pk_size(_In_ const eap::type_t &val)
    {
        return get_pk_size((unsigned char)val);
    }


    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::type_t &val)
    {
        unsigned char t;
        unpack(cursor, t);
        val = (eap::type_t)t;
    }
}

#endif
