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


eap::config* eap::credentials_ttls::clone() const
{
    return new credentials_ttls(*this);
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


bool eap::credentials_ttls::save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError) const
{
    const bstr bstrNamespace(L"urn:ietf:params:xml:ns:yang:ietf-eap-metadata");
    DWORD dwResult;
    HRESULT hr;

    if (!credentials_tls::save(pDoc, pConfigRoot, ppEapError))
        return false;

    if (m_inner) {
        // <InnerAuthenticationMethod>
        winstd::com_obj<IXMLDOMElement> pXmlElInnerAuthenticationMethod;
        if ((dwResult = eapxml::create_element(pDoc, winstd::bstr(L"InnerAuthenticationMethod"), bstrNamespace, &pXmlElInnerAuthenticationMethod))) {
            *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <InnerAuthenticationMethod> element."));
            return false;
        }

        if (!m_inner->save(pDoc, pXmlElInnerAuthenticationMethod, ppEapError))
            return false;

        if (FAILED(hr = pConfigRoot->appendChild(pXmlElInnerAuthenticationMethod, NULL))) {
            *ppEapError = m_module.make_error(HRESULT_CODE(hr), _T(__FUNCTION__) _T(" Error appending <InnerAuthenticationMethod> element."));
            return false;
        }
    }

    return true;
}


bool eap::credentials_ttls::load(_In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError)
{
    assert(pConfigRoot);
    DWORD dwResult;

    if (!credentials_tls::load(pConfigRoot, ppEapError))
        return false;

    if (m_inner) {
        com_obj<IXMLDOMNode> pXmlElInnerAuthenticationMethod;
        if ((dwResult = eapxml::select_node(pConfigRoot, bstr(L"eap-metadata:InnerAuthenticationMethod"), &pXmlElInnerAuthenticationMethod)) != ERROR_SUCCESS) {
            *ppEapError = m_module.make_error(ERROR_NOT_FOUND, _T(__FUNCTION__) _T(" Error selecting <InnerAuthenticationMethod> element."), _T("Please make sure profile XML is a valid ") _T(PRODUCT_NAME_STR) _T(" profile XML document."));
            return false;
        }

        if (!m_inner->load(pXmlElInnerAuthenticationMethod, ppEapError))
            return false;
    }

    return true;
}


bool eap::credentials_ttls::store(_In_ LPCTSTR pszTargetName, _Out_ EAP_ERROR **ppEapError) const
{
    if (!credentials_tls::store(pszTargetName, ppEapError))
        return false;

    if (m_inner) {
        if (!m_inner->store(pszTargetName, ppEapError))
            return false;
    }

    return true;
}


bool eap::credentials_ttls::retrieve(_In_ LPCTSTR pszTargetName, _Out_ EAP_ERROR **ppEapError)
{
    if (!credentials_tls::retrieve(pszTargetName, ppEapError))
        return false;

    if (m_inner) {
        if (!m_inner->retrieve(pszTargetName, ppEapError))
            return false;
    }

    return true;
}
