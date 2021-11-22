/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2020 Amebis
    Copyright © 2016 GÉANT
*/

#include "PCH.h"

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
