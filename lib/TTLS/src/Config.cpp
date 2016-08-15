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
// eap::config_method_ttls
//////////////////////////////////////////////////////////////////////

eap::config_method_ttls::config_method_ttls(_In_ module &mod) :
    config_method_tls(mod)
{
}


eap::config_method_ttls::config_method_ttls(const _In_ config_method_ttls &other) :
    m_inner(other.m_inner ? (config_method_with_cred*)other.m_inner->clone() : nullptr),
    m_anonymous_identity(other.m_anonymous_identity),
    config_method_tls(other)
{
}


eap::config_method_ttls::config_method_ttls(_Inout_ config_method_ttls &&other) :
    m_inner(std::move(other.m_inner)),
    m_anonymous_identity(std::move(other.m_anonymous_identity)),
    config_method_tls(std::move(other))
{
}


eap::config_method_ttls& eap::config_method_ttls::operator=(const _In_ config_method_ttls &other)
{
    if (this != &other) {
        (config_method_tls&)*this = other;
        m_inner.reset(other.m_inner ? (config_method_with_cred*)other.m_inner->clone() : nullptr);
        m_anonymous_identity  = other.m_anonymous_identity;
    }

    return *this;
}


eap::config_method_ttls& eap::config_method_ttls::operator=(_Inout_ config_method_ttls &&other)
{
    if (this != &other) {
        (config_method_tls&&)*this = std::move(other);
        m_inner                    = std::move(other.m_inner);
        m_anonymous_identity       = std::move(other.m_anonymous_identity);
    }

    return *this;
}


eap::config* eap::config_method_ttls::clone() const
{
    return new config_method_ttls(*this);
}


void eap::config_method_ttls::save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot) const
{
    assert(pDoc);
    assert(pConfigRoot);

    config_method_tls::save(pDoc, pConfigRoot);

    const bstr bstrNamespace(L"urn:ietf:params:xml:ns:yang:ietf-eap-metadata");
    HRESULT hr;

    // <ClientSideCredential>
    com_obj<IXMLDOMElement> pXmlElClientSideCredential;
    if (FAILED(hr = eapxml::create_element(pDoc, pConfigRoot, bstr(L"eap-metadata:ClientSideCredential"), bstr(L"ClientSideCredential"), bstrNamespace, &pXmlElClientSideCredential)))
        throw com_runtime_error(hr, __FUNCTION__ " Error creating <ClientSideCredential> element.");

    // <ClientSideCredential>/<AnonymousIdentity>
    if (!m_anonymous_identity.empty())
        if (FAILED(hr = eapxml::put_element_value(pDoc, pXmlElClientSideCredential, bstr(L"AnonymousIdentity"), bstrNamespace, bstr(m_anonymous_identity))))
            throw com_runtime_error(hr, __FUNCTION__ " Error creating <AnonymousIdentity> element.");

    // <InnerAuthenticationMethod>
    com_obj<IXMLDOMElement> pXmlElInnerAuthenticationMethod;
    if (FAILED(hr = eapxml::create_element(pDoc, pConfigRoot, bstr(L"eap-metadata:InnerAuthenticationMethod"), bstr(L"InnerAuthenticationMethod"), bstrNamespace, &pXmlElInnerAuthenticationMethod)))
        throw com_runtime_error(hr, __FUNCTION__ " Error creating <InnerAuthenticationMethod> element.");

    if (dynamic_cast<const config_method_pap*>(m_inner.get())) {
        // <InnerAuthenticationMethod>/<NonEAPAuthMethod>
        if (FAILED(hr = eapxml::put_element_value(pDoc, pXmlElInnerAuthenticationMethod, bstr(L"NonEAPAuthMethod"), bstrNamespace, bstr(L"PAP"))))
            throw com_runtime_error(hr, __FUNCTION__ " Error creating <NonEAPAuthMethod> element.");

        // <InnerAuthenticationMethod>/...
        m_inner->save(pDoc, pXmlElInnerAuthenticationMethod);
    } else
        throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Unsupported inner authentication method.");
}


void eap::config_method_ttls::load(_In_ IXMLDOMNode *pConfigRoot)
{
    assert(pConfigRoot);
    HRESULT hr;

    config_method_tls::load(pConfigRoot);

    std::wstring xpath(eapxml::get_xpath(pConfigRoot));

    m_anonymous_identity.clear();

    // <ClientSideCredential>
    com_obj<IXMLDOMElement> pXmlElClientSideCredential;
    if (SUCCEEDED(eapxml::select_element(pConfigRoot, bstr(L"eap-metadata:ClientSideCredential"), &pXmlElClientSideCredential))) {
        wstring xpathClientSideCredential(xpath + L"/ClientSideCredential");

        // <AnonymousIdentity>
        eapxml::get_element_value(pXmlElClientSideCredential, bstr(L"eap-metadata:AnonymousIdentity"), m_anonymous_identity);
        m_module.log_config((xpathClientSideCredential + L"/AnonymousIdentity").c_str(), m_anonymous_identity.c_str());
    }

    // <InnerAuthenticationMethod>
    com_obj<IXMLDOMElement> pXmlElInnerAuthenticationMethod;
    if (FAILED(hr = eapxml::select_element(pConfigRoot, bstr(L"eap-metadata:InnerAuthenticationMethod"), &pXmlElInnerAuthenticationMethod)))
        throw com_runtime_error(hr, __FUNCTION__ " Error selecting <InnerAuthenticationMethod> element.");

    // Determine inner authentication type (<EAPMethod> and <NonEAPAuthMethod>).
    //DWORD dwMethodID;
    bstr bstrMethod;
    /*if (SUCCEEDED(eapxml::get_element_value(pXmlElInnerAuthenticationMethod, bstr(L"eap-metadata:EAPMethod"), &dwMethodID)) &&
        dwMethodID == EAP_TYPE_MSCHAPV2)
    {
        // MSCHAPv2
        // TODO: Add MSCHAPv2 support.
        throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " MSCHAPv2 not supported yet.");
    } else*/ if (SUCCEEDED(eapxml::get_element_value(pXmlElInnerAuthenticationMethod, bstr(L"eap-metadata:NonEAPAuthMethod"), &bstrMethod)) &&
        CompareStringEx(LOCALE_NAME_INVARIANT, NORM_IGNORECASE, bstrMethod, bstrMethod.length(), L"PAP", -1, NULL, NULL, 0) == CSTR_EQUAL)
    {
        // PAP
        m_module.log_config((xpath + L"/NonEAPAuthMethod").c_str(), L"PAP");
        m_inner.reset(new config_method_pap(m_module));
        m_inner->load(pXmlElInnerAuthenticationMethod);
    } else
        throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Unsupported inner authentication method.");
}


void eap::config_method_ttls::operator<<(_Inout_ cursor_out &cursor) const
{
    config_method_tls::operator<<(cursor);

    if (m_inner) {
        if (dynamic_cast<config_method_pap*>(m_inner.get())) {
            cursor << eap_type_pap;
            cursor << *m_inner;
        } else {
            assert(0); // Unsupported inner authentication method type.
            cursor << eap_type_undefined;
        }
    } else
        cursor << eap_type_undefined;

    cursor << m_anonymous_identity;
}


size_t eap::config_method_ttls::get_pk_size() const
{
    size_t size_inner;
    if (m_inner) {
        if (dynamic_cast<config_method_pap*>(m_inner.get())) {
            size_inner =
                pksizeof(eap_type_pap) +
                pksizeof(*m_inner);
        } else {
            assert(0); // Unsupported inner authentication method type.
            size_inner = pksizeof(eap_type_undefined);
        }
    } else
        size_inner = pksizeof(eap_type_undefined);

    return
        config_method_tls::get_pk_size() +
        size_inner +
        pksizeof(m_anonymous_identity);
}


void eap::config_method_ttls::operator>>(_Inout_ cursor_in &cursor)
{
    config_method_tls::operator>>(cursor);

    eap_type_t eap_type;
    cursor >> eap_type;
    switch (eap_type) {
        case eap_type_pap:
            m_inner.reset(new config_method_pap(m_module));
            cursor >> *m_inner;
            break;
        default:
            assert(0); // Unsupported inner authentication method type.
            m_inner.reset(nullptr);
    }

    cursor >> m_anonymous_identity;
}


eap_type_t eap::config_method_ttls::get_method_id() const
{
    return eap_type_ttls;
}


wstring eap::config_method_ttls::get_public_identity(const credentials_ttls &cred) const
{
    if (m_anonymous_identity.empty()) {
        // Use the true identity.
        return cred.get_identity();
    } else if (m_anonymous_identity.compare(L"@") == 0) {
        // Strip username part from identity (RFC 4822).
        wstring identity(std::move(cred.get_identity()));
        wstring::size_type offset = identity.find(L'@');
        if (offset != wstring::npos) identity.erase(0, offset);
        return identity;
    } else {
        // Use configured identity.
        return m_anonymous_identity;
    }
}
