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
// eap::config_ttls
//////////////////////////////////////////////////////////////////////

eap::config_ttls::config_ttls(_In_ module &mod) :
    m_inner(NULL),
    config_tls(mod)
{
}


eap::config_ttls::config_ttls(const _In_ config_ttls &other) :
    m_inner(other.m_inner ? (config_method*)other.m_inner->clone() : NULL),
    config_tls(other)
{
}


eap::config_ttls::config_ttls(_Inout_ config_ttls &&other) :
    m_inner(other.m_inner),
    config_tls(std::move(other))
{
    other.m_inner = NULL;
}


eap::config_ttls::~config_ttls()
{
    if (m_inner)
        delete m_inner;
}


eap::config_ttls& eap::config_ttls::operator=(const _In_ config_ttls &other)
{
    if (this != &other) {
        (config_tls&)*this = other;
        if (m_inner) delete m_inner;
        m_inner = other.m_inner ? (config_method*)other.m_inner->clone() : NULL;
    }

    return *this;
}


eap::config_ttls& eap::config_ttls::operator=(_Inout_ config_ttls &&other)
{
    if (this != &other) {
        (config_tls&&)*this = std::move(other);
        if (m_inner) delete m_inner;
        m_inner = other.m_inner;
        other.m_inner = NULL;
    }

    return *this;
}


eap::config* eap::config_ttls::clone() const
{
    return new config_ttls(*this);
}


bool eap::config_ttls::save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError) const
{
    assert(pDoc);
    assert(pConfigRoot);
    assert(ppEapError);

    if (!config_tls::save(pDoc, pConfigRoot, ppEapError))
        return false;

    const bstr bstrNamespace(L"urn:ietf:params:xml:ns:yang:ietf-eap-metadata");
    DWORD dwResult;

    // <InnerAuthenticationMethod>
    com_obj<IXMLDOMElement> pXmlElInnerAuthenticationMethod;
    if ((dwResult = eapxml::create_element(pDoc, pConfigRoot, bstr(L"eap-metadata:InnerAuthenticationMethod"), bstr(L"InnerAuthenticationMethod"), bstrNamespace, &pXmlElInnerAuthenticationMethod)) != ERROR_SUCCESS) {
        *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <InnerAuthenticationMethod> element."));
        return false;
    }

    if (dynamic_cast<const config_pap*>(m_inner)) {
        // <InnerAuthenticationMethod>/<NonEAPAuthMethod>
        if ((dwResult = eapxml::put_element_value(pDoc, pXmlElInnerAuthenticationMethod, bstr(L"NonEAPAuthMethod"), bstrNamespace, bstr(L"PAP"))) != ERROR_SUCCESS) {
            *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <NonEAPAuthMethod> element."));
            return false;
        }

        // <InnerAuthenticationMethod>/...
        if (!m_inner->save(pDoc, pXmlElInnerAuthenticationMethod, ppEapError))
            return false;
    } else {
        *ppEapError = m_module.make_error(ERROR_NOT_SUPPORTED, _T(__FUNCTION__) _T(" Unsupported inner authentication method."));
        return false;
    }

    return true;
}


bool eap::config_ttls::load(_In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError)
{
    assert(pConfigRoot);
    assert(ppEapError);
    DWORD dwResult;

    if (!config_tls::load(pConfigRoot, ppEapError))
        return false;

    std::wstring xpath(eapxml::get_xpath(pConfigRoot));

    // Load inner authentication configuration (<InnerAuthenticationMethod>).
    com_obj<IXMLDOMElement> pXmlElInnerAuthenticationMethod;
    if ((dwResult = eapxml::select_element(pConfigRoot, bstr(L"eap-metadata:InnerAuthenticationMethod"), &pXmlElInnerAuthenticationMethod)) != ERROR_SUCCESS) {
        *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error selecting <InnerAuthenticationMethod> element."), _T("Please make sure profile XML is a valid ") _T(PRODUCT_NAME_STR) _T(" profile XML document."));
        return false;
    }

    // Determine inner authentication type (<EAPMethod> and <NonEAPAuthMethod>).
    //DWORD dwMethodID;
    bstr bstrMethod;
    /*if (eapxml::get_element_value(pXmlElInnerAuthenticationMethod, bstr(L"eap-metadata:EAPMethod"), &dwMethodID) == ERROR_SUCCESS &&
        dwMethodID == EAP_TYPE_MSCHAPV2)
    {
        // MSCHAPv2
        // TODO: Add MSCHAPv2 support.
        return ERROR_NOT_SUPPORTED;
    } else*/ if (eapxml::get_element_value(pXmlElInnerAuthenticationMethod, bstr(L"eap-metadata:NonEAPAuthMethod"), &bstrMethod) == ERROR_SUCCESS &&
        CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstrMethod, bstrMethod.length(), L"PAP", -1, NULL, NULL, 0) == CSTR_EQUAL)
    {
        // PAP
        m_module.log_config((xpath + L"/NonEAPAuthMethod").c_str(), L"PAP");
        assert(!m_inner);
        m_inner = new eap::config_pap(m_module);
        if (!m_inner->load(pXmlElInnerAuthenticationMethod, ppEapError))
            return false;
    } else {
        *ppEapError = m_module.make_error(ERROR_NOT_SUPPORTED, _T(__FUNCTION__) _T(" Unsupported inner authentication method."));
        return false;
    }

    return true;
}


eap::type_t eap::config_ttls::get_method_id() const
{
    return eap::type_ttls;
}
