/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2021 Amebis
    Copyright © 2016 GÉANT
*/

#include "PCH.h"


//////////////////////////////////////////////////////////////////////
// eap::credentials_eaphost
//////////////////////////////////////////////////////////////////////

eap::credentials_eaphost::credentials_eaphost(_In_ module &mod) : credentials_pass(mod)
{
}


eap::credentials_eaphost::credentials_eaphost(_In_ const credentials_eaphost &other) :
    credentials_pass(other)
{
}


eap::credentials_eaphost::credentials_eaphost(_Inout_ credentials_eaphost &&other) :
    credentials_pass(std::move(other))
{
}


eap::credentials_eaphost& eap::credentials_eaphost::operator=(_In_ const credentials_eaphost &other)
{
    if (this != &other)
        (credentials_pass&)*this = other;

    return *this;
}


eap::credentials_eaphost& eap::credentials_eaphost::operator=(_Inout_ credentials_eaphost &&other)
{
    if (this != &other)
        (credentials_pass&&)*this = std::move(other);

    return *this;
}
