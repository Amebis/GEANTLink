/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2022 Amebis
    Copyright © 2016 GÉANT
*/

#include "PCH.h"

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
    m_data  (other.m_data),
    packable(other       )
{
}


eap::ui_context::ui_context(_Inout_ ui_context &&other) noexcept :
    m_cfg   (          other.m_cfg  ),
    m_cred  (          other.m_cred ),
    m_data  (std::move(other.m_data)),
    packable(std::move(other       ))
{
}


eap::ui_context& eap::ui_context::operator=(_In_ const ui_context &other)
{
    if (this != &other) {
        assert(std::addressof(m_cfg ) == std::addressof(other.m_cfg )); // Copy context within same configuration only!
        assert(std::addressof(m_cred) == std::addressof(other.m_cred)); // Copy context within same credentials only!
        (packable&)*this = other;
        m_data           = other.m_data;
    }

    return *this;
}


eap::ui_context& eap::ui_context::operator=(_Inout_ ui_context &&other) noexcept
{
    if (this != &other) {
        assert(std::addressof(m_cfg ) == std::addressof(other.m_cfg )); // Move context within same configuration only!
        assert(std::addressof(m_cred) == std::addressof(other.m_cred)); // Move context within same credentials only!
        (packable&)*this = std::move(other);
        m_data           = std::move(other.m_data);
    }

    return *this;
}


void eap::ui_context::operator<<(_Inout_ cursor_out &cursor) const
{
    packable::operator<<(cursor);
    cursor << m_cfg ;
    cursor << m_cred;
    cursor << m_data;
}


size_t eap::ui_context::get_pk_size() const
{
    return
        packable::get_pk_size() +
        pksizeof(m_cfg ) +
        pksizeof(m_cred) +
        pksizeof(m_data);
}


void eap::ui_context::operator>>(_Inout_ cursor_in &cursor)
{
    packable::operator>>(cursor);
    cursor >> m_cfg ;
    cursor >> m_cred;
    cursor >> m_data;
}
