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


//////////////////////////////////////////////////////////////////////
// eap::config_pap
//////////////////////////////////////////////////////////////////////

eap::config_pap::config_pap(_In_ module &mod) : config_pass(mod)
{
}


eap::config_pap::config_pap(_In_ const config_pap &other) :
    config_pass(other)
{
}


eap::config_pap::config_pap(_Inout_ config_pap &&other) :
    config_pass(std::move(other))
{
}


eap::config_pap& eap::config_pap::operator=(_In_ const config_pap &other)
{
    if (this != &other)
        (config_pass&)*this = other;

    return *this;
}


eap::config_pap& eap::config_pap::operator=(_Inout_ config_pap &&other)
{
    if (this != &other)
        (config_pass&&)*this = std::move(other);

    return *this;
}


eap::config* eap::config_pap::clone() const
{
    return new config_pap(*this);
}


eap::type_t eap::config_pap::get_method_id() const
{
    return eap::type_pap;
}
