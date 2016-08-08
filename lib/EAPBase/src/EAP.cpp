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
// eap::win_runtime_error
//////////////////////////////////////////////////////////////////////

eap::win_runtime_error::win_runtime_error(_In_ DWORD error, _In_ const tstring& msg) :
    m_error(error),
    m_msg(msg),
    runtime_error("")
{
}


eap::win_runtime_error::win_runtime_error(_In_ DWORD error, _In_z_ const TCHAR *msg) :
    m_error(error),
    m_msg(msg),
    runtime_error("")
{
}


eap::win_runtime_error::win_runtime_error(_In_ const tstring& msg) :
    m_error(GetLastError()),
    m_msg(msg),
    runtime_error("")
{
}


eap::win_runtime_error::win_runtime_error(_In_z_ const TCHAR *msg) :
    m_error(GetLastError()),
    m_msg(msg),
    runtime_error("")
{
}


eap::win_runtime_error::win_runtime_error(const win_runtime_error &other) :
    m_error(other.m_error),
    m_msg(other.m_msg),
    runtime_error(other.what())
{
}


eap::win_runtime_error& eap::win_runtime_error::operator=(const win_runtime_error &other)
{
    if (this != addressof(other)) {
        *(runtime_error*)this = other;
        m_error               = other.m_error;
        m_msg                 = other.m_msg;
    }

    return *this;
}
