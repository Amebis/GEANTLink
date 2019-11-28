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

#include "StdAfx.h"

#pragma comment(lib, "Ws2_32.lib")

using namespace std;
using namespace winstd;


//////////////////////////////////////////////////////////////////////
// eap::packable
//////////////////////////////////////////////////////////////////////

eap::packable::packable()
{
}


void eap::packable::operator<<(_Inout_ cursor_out &cursor) const
{
    UNREFERENCED_PARAMETER(cursor);
}


size_t eap::packable::get_pk_size() const
{
    return 0;
}


void eap::packable::operator>>(_Inout_ cursor_in &cursor)
{
    UNREFERENCED_PARAMETER(cursor);
}


//////////////////////////////////////////////////////////////////////
// eap::diameter_avp_append
//////////////////////////////////////////////////////////////////////

void eap::diameter_avp_append(
    _In_                       unsigned int    code,
    _In_                       unsigned char   flags,
    _In_bytecount_(size) const void            *data,
    _In_                       unsigned int    size,
    _Inout_                    sanitizing_blob &packet)
{
    unsigned int
        padding = (unsigned int)((4 - size) % 4),
        size_outer;

    packet.reserve(
        packet.size() + 
        (size_outer = 
        sizeof(diameter_avp_header) + // Diameter header
        size)                       + // Data
        padding);                     // Data padding

    // Diameter AVP header
    diameter_avp_header hdr;
    *reinterpret_cast<unsigned int*>(hdr.code) = htonl(code);
    hdr.flags = flags;
    hton24(size_outer, hdr.length);
    packet.insert(packet.end(), reinterpret_cast<const unsigned char*>(&hdr), reinterpret_cast<const unsigned char*>(&hdr + 1));

    // Data
    packet.insert(packet.end(), reinterpret_cast<const unsigned char*>(data), reinterpret_cast<const unsigned char*>(data) + size);
    packet.insert(packet.end(), padding, 0);
}


//////////////////////////////////////////////////////////////////////
// eap::diameter_avp_append
//////////////////////////////////////////////////////////////////////

void eap::diameter_avp_append(
    _In_                       unsigned int    code,
    _In_                       unsigned int    vendor_id,
    _In_                       unsigned char   flags,
    _In_bytecount_(size) const void            *data,
    _In_                       unsigned int    size,
    _Inout_                    sanitizing_blob &packet)
{
    unsigned int
        padding = (unsigned int)((4 - size) % 4),
        size_outer;

    packet.reserve(
        packet.size() + 
        (size_outer = 
        sizeof(diameter_avp_header_ven) + // Diameter header
        size)                           + // Data
        padding);                         // Data padding

    // Diameter AVP header
    diameter_avp_header_ven hdr;
    *reinterpret_cast<unsigned int*>(hdr.code) = htonl(code);
    hdr.flags = flags | diameter_avp_flag_vendor;
    hton24(size_outer, hdr.length);
    *reinterpret_cast<unsigned int*>(hdr.vendor) = htonl(vendor_id);
    packet.insert(packet.end(), reinterpret_cast<const unsigned char*>(&hdr), reinterpret_cast<const unsigned char*>(&hdr + 1));

    // Data
    packet.insert(packet.end(), reinterpret_cast<const unsigned char*>(data), reinterpret_cast<const unsigned char*>(data) + size);
    packet.insert(packet.end(), padding, 0);
}
