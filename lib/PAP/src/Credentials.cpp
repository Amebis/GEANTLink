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
// eap::credentials_pap
//////////////////////////////////////////////////////////////////////

eap::credentials_pap::credentials_pap(_In_ module *mod) : credentials_pass(mod)
{
}


eap::credentials_pap::credentials_pap(_In_ const credentials_pap &other) :
    credentials_pass(other)
{
}


eap::credentials_pap::credentials_pap(_Inout_ credentials_pap &&other) :
    credentials_pass(std::move(other))
{
}


eap::credentials_pap& eap::credentials_pap::operator=(_In_ const credentials_pap &other)
{
    if (this != &other)
        (credentials_pass&)*this = other;

    return *this;
}


eap::credentials_pap& eap::credentials_pap::operator=(_Inout_ credentials_pap &&other)
{
    if (this != &other)
        (credentials_pass&&)*this = std::move(other);

    return *this;
}


eap::config* eap::credentials_pap::clone() const
{
    return new credentials_pap(*this);
}


LPCTSTR eap::credentials_pap::target_suffix() const
{
    return _T("PAP");
}
