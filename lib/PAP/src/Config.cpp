/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2020 Amebis
    Copyright © 2016 GÉANT
*/

#include "PCH.h"

using namespace std;
using namespace winstd;


//////////////////////////////////////////////////////////////////////
// eap::config_method_pap
//////////////////////////////////////////////////////////////////////

eap::config_method_pap::config_method_pap(_In_ module &mod, _In_ unsigned int level) : config_method_with_cred(mod, level)
{
    m_cred.reset(new credentials_pass(mod));
}


eap::config_method_pap::config_method_pap(_In_ const config_method_pap &other) :
    config_method_with_cred(other)
{
}


eap::config_method_pap::config_method_pap(_Inout_ config_method_pap &&other) noexcept :
    config_method_with_cred(std::move(other))
{
}


eap::config_method_pap& eap::config_method_pap::operator=(_In_ const config_method_pap &other)
{
    if (this != &other)
        (config_method_with_cred&)*this = other;

    return *this;
}


eap::config_method_pap& eap::config_method_pap::operator=(_Inout_ config_method_pap &&other) noexcept
{
    if (this != &other)
        (config_method_with_cred&&)*this = std::move(other);

    return *this;
}


eap::config* eap::config_method_pap::clone() const
{
    return new config_method_pap(*this);
}


eap_type_t eap::config_method_pap::get_method_id() const
{
    return eap_type_t::legacy_pap;
}


const wchar_t* eap::config_method_pap::get_method_str() const
{
    return L"PAP";
}


eap::credentials* eap::config_method_pap::make_credentials() const
{
    return new credentials_pass(m_module);
}
