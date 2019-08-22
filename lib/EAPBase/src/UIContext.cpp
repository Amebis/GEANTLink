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
// eap::ui_context
//////////////////////////////////////////////////////////////////////

eap::ui_context::ui_context(_In_ config_connection &cfg, _In_ credentials_connection &cred) :
    m_cfg(cfg),
    m_cred(cred)
{
}


eap::ui_context::ui_context(_In_ const ui_context &other) :
    m_cfg   (other.m_cfg ),
    m_cred  (other.m_cred),
    packable(other       )
{
}


eap::ui_context::ui_context(_Inout_ ui_context &&other) noexcept :
    m_cfg   (          other.m_cfg  ),
    m_cred  (          other.m_cred ),
    packable(std::move(other       ))
{
}


eap::ui_context& eap::ui_context::operator=(_In_ const ui_context &other)
{
    if (this != &other) {
        assert(std::addressof(m_cfg ) == std::addressof(other.m_cfg )); // Copy context within same configuration only!
        assert(std::addressof(m_cred) == std::addressof(other.m_cred)); // Copy context within same credentials only!
        (packable&)*this = other;
    }

    return *this;
}


eap::ui_context& eap::ui_context::operator=(_Inout_ ui_context &&other) noexcept
{
    if (this != &other) {
        assert(std::addressof(m_cfg ) == std::addressof(other.m_cfg )); // Move context within same configuration only!
        assert(std::addressof(m_cred) == std::addressof(other.m_cred)); // Move context within same credentials only!
        (packable&)*this = std::move(other);
    }

    return *this;
}


void eap::ui_context::operator<<(_Inout_ cursor_out &cursor) const
{
    packable::operator<<(cursor);
    cursor << m_cfg ;
    cursor << m_cred;
}


size_t eap::ui_context::get_pk_size() const
{
    return
        packable::get_pk_size() +
        pksizeof(m_cfg ) +
        pksizeof(m_cred);
}


void eap::ui_context::operator>>(_Inout_ cursor_in &cursor)
{
    packable::operator>>(cursor);
    cursor >> m_cfg ;
    cursor >> m_cred;
}
