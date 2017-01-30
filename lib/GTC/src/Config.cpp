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
// eap::config_method_eapgtc
//////////////////////////////////////////////////////////////////////

eap::config_method_eapgtc::config_method_eapgtc(_In_ module &mod, _In_ unsigned int level) : config_method(mod, level)
{
}


eap::config_method_eapgtc::config_method_eapgtc(_In_ const config_method_eapgtc &other) :
    config_method(other)
{
}


eap::config_method_eapgtc::config_method_eapgtc(_Inout_ config_method_eapgtc &&other) :
    config_method(std::move(other))
{
}


eap::config_method_eapgtc& eap::config_method_eapgtc::operator=(_In_ const config_method_eapgtc &other)
{
    if (this != &other)
        (config_method&)*this = other;

    return *this;
}


eap::config_method_eapgtc& eap::config_method_eapgtc::operator=(_Inout_ config_method_eapgtc &&other)
{
    if (this != &other)
        (config_method&&)*this = std::move(other);

    return *this;
}


eap::config* eap::config_method_eapgtc::clone() const
{
    return new config_method_eapgtc(*this);
}


eap_type_t eap::config_method_eapgtc::get_method_id() const
{
    return eap_type_gtc;
}


const wchar_t* eap::config_method_eapgtc::get_method_str() const
{
    return L"EAP-GTC";
}


eap::credentials* eap::config_method_eapgtc::make_credentials() const
{
    return NULL;
}
