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
// eap::ui_context_ttls
//////////////////////////////////////////////////////////////////////

eap::ui_context_ttls::ui_context_ttls(_In_ config_connection &cfg, _In_ credentials_connection &cred) :
    ui_context(cfg, cred)
{
}


eap::ui_context_ttls::ui_context_ttls(_In_ const ui_context_ttls &other) :
    m_data    (other.m_data),
    ui_context(other       )
{
}


eap::ui_context_ttls::ui_context_ttls(_Inout_ ui_context_ttls &&other) noexcept :
    m_data    (std::move(other.m_data)),
    ui_context(std::move(other       ))
{
}


eap::ui_context_ttls& eap::ui_context_ttls::operator=(_In_ const ui_context_ttls &other)
{
    if (this != &other) {
        (ui_context&)*this = other;
        m_data             = other.m_data;
    }

    return *this;
}


eap::ui_context_ttls& eap::ui_context_ttls::operator=(_Inout_ ui_context_ttls &&other) noexcept
{
    if (this != &other) {
        (ui_context&)*this = std::move(other       );
        m_data             = std::move(other.m_data);
    }

    return *this;
}


void eap::ui_context_ttls::operator<<(_Inout_ cursor_out &cursor) const
{
    ui_context::operator<<(cursor);
    cursor << m_data;
}


size_t eap::ui_context_ttls::get_pk_size() const
{
    return
        ui_context::get_pk_size() +
        pksizeof(m_data);
}


void eap::ui_context_ttls::operator>>(_Inout_ cursor_in &cursor)
{
    ui_context::operator>>(cursor);
    cursor >> m_data;
}
