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
// eap::method
//////////////////////////////////////////////////////////////////////

eap::method::method(_In_ module &module, _In_ config_method &cfg, _In_ credentials &cred) :
    m_module(module),
    m_cfg(cfg),
    m_cred(cred)
{
}


eap::method::method(_In_ const method &other) :
    m_module(other.m_module),
    m_cfg(other.m_cfg),
    m_cred(other.m_cred)
{
}


eap::method::method(_Inout_ method &&other) :
    m_module(other.m_module),
    m_cfg(other.m_cfg),
    m_cred(other.m_cred)
{
}


eap::method& eap::method::operator=(_In_ const method &other)
{
    if (this != std::addressof(other)) {
        assert(std::addressof(m_module) == std::addressof(other.m_module)); // Copy method within same module only!
        assert(std::addressof(m_cfg   ) == std::addressof(other.m_cfg   )); // Copy method with same configuration only!
        assert(std::addressof(m_cred  ) == std::addressof(other.m_cred  )); // Copy method with same credentials only!
    }

    return *this;
}


eap::method& eap::method::operator=(_Inout_ method &&other)
{
    if (this != std::addressof(other)) {
        assert(std::addressof(m_module) == std::addressof(other.m_module)); // Copy method within same module only!
        assert(std::addressof(m_cfg   ) == std::addressof(other.m_cfg   )); // Copy method with same configuration only!
        assert(std::addressof(m_cred  ) == std::addressof(other.m_cred  )); // Copy method with same credentials only!
    }

    return *this;
}


void eap::method::begin_session(
    _In_        DWORD         dwFlags,
    _In_  const EapAttributes *pAttributeArray,
    _In_        HANDLE        hTokenImpersonateUser,
    _In_        DWORD         dwMaxSendPacketSize)
{
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(pAttributeArray);
    UNREFERENCED_PARAMETER(hTokenImpersonateUser);
    UNREFERENCED_PARAMETER(dwMaxSendPacketSize);
}


void eap::method::end_session()
{
}
