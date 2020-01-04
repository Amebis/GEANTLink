/*
    Copyright 2015-2020 Amebis
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
// eap::config_method_mschapv2
//////////////////////////////////////////////////////////////////////

eap::config_method_mschapv2::config_method_mschapv2(_In_ module &mod, _In_ unsigned int level) : config_method_with_cred(mod, level)
{
    m_cred.reset(new credentials_pass(mod));
}


eap::config_method_mschapv2::config_method_mschapv2(_In_ const config_method_mschapv2 &other) :
    config_method_with_cred(other)
{
}


eap::config_method_mschapv2::config_method_mschapv2(_Inout_ config_method_mschapv2 &&other) noexcept :
    config_method_with_cred(std::move(other))
{
}


eap::config_method_mschapv2& eap::config_method_mschapv2::operator=(_In_ const config_method_mschapv2 &other)
{
    if (this != &other)
        (config_method_with_cred&)*this = other;

    return *this;
}


eap::config_method_mschapv2& eap::config_method_mschapv2::operator=(_Inout_ config_method_mschapv2 &&other) noexcept
{
    if (this != &other)
        (config_method_with_cred&&)*this = std::move(other);

    return *this;
}


eap::config* eap::config_method_mschapv2::clone() const
{
    return new config_method_mschapv2(*this);
}


eap_type_t eap::config_method_mschapv2::get_method_id() const
{
    return eap_type_t::legacy_mschapv2;
}


const wchar_t* eap::config_method_mschapv2::get_method_str() const
{
    return L"MSCHAPv2";
}


eap::credentials* eap::config_method_mschapv2::make_credentials() const
{
    return new credentials_pass(m_module);
}


//////////////////////////////////////////////////////////////////////
// eap::config_method_eapmschapv2
//////////////////////////////////////////////////////////////////////

eap::config_method_eapmschapv2::config_method_eapmschapv2(_In_ module &mod, _In_ unsigned int level) : config_method_mschapv2(mod, level)
{
}


eap::config_method_eapmschapv2::config_method_eapmschapv2(_In_ const config_method_eapmschapv2 &other) :
    config_method_mschapv2(other)
{
}


eap::config_method_eapmschapv2::config_method_eapmschapv2(_Inout_ config_method_eapmschapv2 &&other) noexcept :
    config_method_mschapv2(std::move(other))
{
}


eap::config_method_eapmschapv2& eap::config_method_eapmschapv2::operator=(_In_ const config_method_eapmschapv2 &other)
{
    if (this != &other)
        (config_method_mschapv2&)*this = other;

    return *this;
}


eap::config_method_eapmschapv2& eap::config_method_eapmschapv2::operator=(_Inout_ config_method_eapmschapv2 &&other) noexcept
{
    if (this != &other)
        (config_method_mschapv2&&)*this = std::move(other);

    return *this;
}


eap::config* eap::config_method_eapmschapv2::clone() const
{
    return new config_method_eapmschapv2(*this);
}


eap_type_t eap::config_method_eapmschapv2::get_method_id() const
{
    return eap_type_t::mschapv2;
}


const wchar_t* eap::config_method_eapmschapv2::get_method_str() const
{
    return L"EAP-MSCHAPv2";
}
