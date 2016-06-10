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
// eap::credentials_ttls
//////////////////////////////////////////////////////////////////////

eap::credentials_ttls::credentials_ttls(_In_ module &mod) : credentials_tls(mod)
{
}


eap::credentials_ttls::credentials_ttls(_In_ const credentials_ttls &other) :
    m_inner(other.m_inner ? (credentials*)other.m_inner->clone() : NULL),
    credentials_tls(other)
{
}


eap::credentials_ttls::credentials_ttls(_Inout_ credentials_ttls &&other) :
    m_inner(other.m_inner),
    credentials_tls(std::move(other))
{
    other.m_inner = NULL;
}


eap::credentials_ttls& eap::credentials_ttls::operator=(_In_ const credentials_ttls &other)
{
    if (this != &other) {
        (credentials_tls&)*this = other;

        if (m_inner) delete m_inner;
        m_inner = other.m_inner ? (credentials*)other.m_inner->clone() : NULL;
    }

    return *this;
}


eap::credentials_ttls& eap::credentials_ttls::operator=(_Inout_ credentials_ttls &&other)
{
    if (this != &other) {
        (credentials_tls&)*this = std::move(other);

        if (m_inner) delete m_inner;
        m_inner = other.m_inner;
        other.m_inner = NULL;
    }

    return *this;
}



void eap::credentials_ttls::clear()
{
    credentials_tls::clear();
    if (m_inner)
        m_inner->clear();
}


bool eap::credentials_ttls::empty() const
{
    return credentials_tls::empty() && (!m_inner || m_inner->empty());
}



DWORD eap::credentials_ttls::load(_In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError)
{
    assert(pConfigRoot);
    DWORD dwResult;

    if ((dwResult = credentials_tls::load(pConfigRoot, ppEapError)) != ERROR_SUCCESS)
        return dwResult;

    if (m_inner) {
        com_obj<IXMLDOMNode> pXmlElInnerAuthenticationMethod;
        if ((dwResult = eapxml::select_node(pConfigRoot, bstr(L"eap-metadata:InnerAuthenticationMethod"), &pXmlElInnerAuthenticationMethod)) != ERROR_SUCCESS) {
            *ppEapError = m_module.make_error(dwResult = ERROR_NOT_FOUND, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error selecting <InnerAuthenticationMethod> element."), NULL);
            return dwResult;
        }

        if ((dwResult = m_inner->load(pXmlElInnerAuthenticationMethod, ppEapError)) != ERROR_SUCCESS)
            return dwResult;
    }

    return ERROR_SUCCESS;
}


DWORD eap::credentials_ttls::store(_In_ LPCTSTR pszTargetName, _Out_ EAP_ERROR **ppEapError) const
{
    DWORD dwResult;

    if ((dwResult = credentials_tls::store(pszTargetName, ppEapError)) != ERROR_SUCCESS)
        return dwResult;

    if (m_inner) {
        if ((dwResult = m_inner->store(pszTargetName, ppEapError)) != ERROR_SUCCESS)
            return dwResult;
    }

    return ERROR_SUCCESS;
}


DWORD eap::credentials_ttls::retrieve(_In_ LPCTSTR pszTargetName, _Out_ EAP_ERROR **ppEapError)
{
    DWORD dwResult;

    if ((dwResult = credentials_tls::retrieve(pszTargetName, ppEapError)) != ERROR_SUCCESS)
        return dwResult;

    if (m_inner) {
        if ((dwResult = m_inner->retrieve(pszTargetName, ppEapError)) != ERROR_SUCCESS)
            return dwResult;
    }

    return ERROR_SUCCESS;
}
