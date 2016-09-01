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

using namespace std;
using namespace winstd;


//////////////////////////////////////////////////////////////////////
// eap::packet
//////////////////////////////////////////////////////////////////////

eap::packet::packet() :
    m_code((EapCode)0),
    m_id(0)
{
}


eap::packet::packet(_In_ const packet &other) :
    m_code(other.m_code),
    m_id  (other.m_id  ),
    m_data(other.m_data)
{
}


eap::packet::packet(_Inout_ packet &&other) :
    m_code(std::move(other.m_code)),
    m_id  (std::move(other.m_id  )),
    m_data(std::move(other.m_data))
{
}


eap::packet& eap::packet::operator=(_In_ const packet &other)
{
    if (this != std::addressof(other)) {
        m_code = other.m_code;
        m_id   = other.m_id  ;
        m_data = other.m_data;
    }

    return *this;
}


eap::packet& eap::packet::operator=(_Inout_ packet &&other)
{
    if (this != std::addressof(other)) {
        m_code = std::move(other.m_code);
        m_id   = std::move(other.m_id  );
        m_data = std::move(other.m_data);
    }

    return *this;
}


void eap::packet::clear()
{
    m_code = (EapCode)0;
    m_id   = 0;
    m_data.clear();
}
