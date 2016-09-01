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
// eap::credentials_mschapv2
//////////////////////////////////////////////////////////////////////

eap::credentials_mschapv2::credentials_mschapv2(_In_ module &mod) : credentials_pass(mod)
{
}


eap::credentials_mschapv2::credentials_mschapv2(_In_ const credentials_mschapv2 &other) :
    credentials_pass(other)
{
}


eap::credentials_mschapv2::credentials_mschapv2(_Inout_ credentials_mschapv2 &&other) :
    credentials_pass(std::move(other))
{
}


eap::credentials_mschapv2& eap::credentials_mschapv2::operator=(_In_ const credentials_mschapv2 &other)
{
    if (this != &other)
        (credentials_pass&)*this = other;

    return *this;
}


eap::credentials_mschapv2& eap::credentials_mschapv2::operator=(_Inout_ credentials_mschapv2 &&other)
{
    if (this != &other)
        (credentials_pass&&)*this = std::move(other);

    return *this;
}


eap::config* eap::credentials_mschapv2::clone() const
{
    return new credentials_mschapv2(*this);
}


LPCTSTR eap::credentials_mschapv2::target_suffix() const
{
    return _T("MSCHAPv2");
}


eap::credentials::source_t eap::credentials_mschapv2::combine(
    _In_       const credentials             *cred_cached,
    _In_       const config_method_with_cred &cfg,
    _In_opt_z_       LPCTSTR                 pszTargetName)
{
    if (cred_cached) {
        // Using EAP service cached credentials.
        *this = *(credentials_mschapv2*)cred_cached;
        m_module.log_event(&EAPMETHOD_TRACE_EVT_CRED_CACHED1, event_data((unsigned int)eap_type_legacy_mschapv2), event_data(credentials_mschapv2::get_name()), event_data::blank);
        return source_cache;
    }

    if (cfg.m_use_preshared) {
        // Using preshared credentials.
        *this = *(credentials_mschapv2*)cfg.m_preshared.get();
        m_module.log_event(&EAPMETHOD_TRACE_EVT_CRED_PRESHARED1, event_data((unsigned int)eap_type_legacy_mschapv2), event_data(credentials_mschapv2::get_name()), event_data::blank);
        return source_preshared;
    }

    if (pszTargetName) {
        try {
            credentials_mschapv2 cred_loaded(m_module);
            cred_loaded.retrieve(pszTargetName);

            // Using stored credentials.
            *this = std::move(cred_loaded);
            m_module.log_event(&EAPMETHOD_TRACE_EVT_CRED_STORED1, event_data((unsigned int)eap_type_legacy_mschapv2), event_data(credentials_mschapv2::get_name()), event_data::blank);
            return source_storage;
        } catch (...) {
            // Not actually an error.
        }
    }

    return source_unknown;
}
