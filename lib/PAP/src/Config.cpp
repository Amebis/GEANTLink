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


eap::config_method_pap::config_method_pap(_Inout_ config_method_pap &&other) :
    config_method_with_cred(std::move(other))
{
}


eap::config_method_pap& eap::config_method_pap::operator=(_In_ const config_method_pap &other)
{
    if (this != &other)
        (config_method_with_cred&)*this = other;

    return *this;
}


eap::config_method_pap& eap::config_method_pap::operator=(_Inout_ config_method_pap &&other)
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
    return eap_type_legacy_pap;
}


const wchar_t* eap::config_method_pap::get_method_str() const
{
    return L"PAP";
}


eap::credentials* eap::config_method_pap::make_credentials() const
{
    return new credentials_pass(m_module);
}
