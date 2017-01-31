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

eap::config_method_ttls::config_method_ttls(_In_ module &mod, _In_ unsigned int level) :
    m_inner(new config_method_pap(mod, level + 1)),
    config_method_tls(mod, level)
{
    // TTLS is using blank configured credentials per default.
    m_use_cred = true;
}


eap::config_method_ttls::config_method_ttls(const _In_ config_method_ttls &other) :
    m_inner(other.m_inner ? dynamic_cast<config_method_with_cred*>(other.m_inner->clone()) : nullptr),
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
        m_inner.reset(other.m_inner ? dynamic_cast<config_method_with_cred*>(other.m_inner->clone()) : nullptr);
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

    HRESULT hr;

    // <ClientSideCredential>
    com_obj<IXMLDOMElement> pXmlElClientSideCredential;
    if (FAILED(hr = eapxml::create_element(pDoc, pConfigRoot, bstr(L"eap-metadata:ClientSideCredential"), bstr(L"ClientSideCredential"), namespace_eapmetadata, pXmlElClientSideCredential)))
        throw com_runtime_error(hr, __FUNCTION__ " Error creating <ClientSideCredential> element.");

    // <ClientSideCredential>/<AnonymousIdentity>
    if (!m_anonymous_identity.empty())
        if (FAILED(hr = eapxml::put_element_value(pDoc, pXmlElClientSideCredential, bstr(L"AnonymousIdentity"), namespace_eapmetadata, bstr(m_anonymous_identity))))
            throw com_runtime_error(hr, __FUNCTION__ " Error creating <AnonymousIdentity> element.");

    // <InnerAuthenticationMethod>
    com_obj<IXMLDOMElement> pXmlElInnerAuthenticationMethod;
    if (FAILED(hr = eapxml::create_element(pDoc, pConfigRoot, bstr(L"eap-metadata:InnerAuthenticationMethod"), bstr(L"InnerAuthenticationMethod"), namespace_eapmetadata, pXmlElInnerAuthenticationMethod)))
        throw com_runtime_error(hr, __FUNCTION__ " Error creating <InnerAuthenticationMethod> element.");

    eap_type_t eap_type = m_inner->get_method_id();
    if (eap_type_noneap_start <= eap_type && eap_type < eap_type_noneap_end) {
        // <InnerAuthenticationMethod>/<NonEAPAuthMethod>
        if (FAILED(hr = eapxml::put_element_value(pDoc, pXmlElInnerAuthenticationMethod, bstr(L"NonEAPAuthMethod"), namespace_eapmetadata, bstr(m_inner->get_method_str()))))
            throw com_runtime_error(hr, __FUNCTION__ " Error creating <NonEAPAuthMethod> element.");
    } else {
        // <InnerAuthenticationMethod>/<EAPMethod>
        if (FAILED(hr = eapxml::put_element_value(pDoc, pXmlElInnerAuthenticationMethod, bstr(L"EAPMethod"), namespace_eapmetadata, (DWORD)eap_type)))
            throw com_runtime_error(hr, __FUNCTION__ " Error creating <EAPMethod> element.");
    }

    // <InnerAuthenticationMethod>/...
    m_inner->save(pDoc, pXmlElInnerAuthenticationMethod);

    {
        com_obj<IXMLDOMNode> pXmlElClientSideCredential;
        if (SUCCEEDED(hr = eapxml::select_node(pConfigRoot, bstr(L"eap-metadata:ClientSideCredential"), pXmlElClientSideCredential))) {
            // Fix 1: Configured outer credentials in draft-winter-opsawg-eap-metadata has some bizarre presence/absence/blank logic for EAP-TTLS methods only.
            // To keep our code clean, we do some post-processing, to make draft compliant XML on output, while keeping things simple on the inside.
            if (m_use_cred && m_cred->empty()) {
                // For empty configured client certificate <ClientCertificate/> must not be present.
                com_obj<IXMLDOMNode> pXmlElClientCertificate;
                if (SUCCEEDED(hr = eapxml::select_node(pXmlElClientSideCredential, bstr(L"eap-metadata:ClientCertificate"), pXmlElClientCertificate))) {
                    com_obj<IXMLDOMNode> pXmlElClientCertificateOld;
                    hr = pXmlElClientSideCredential->removeChild(pXmlElClientCertificate, &pXmlElClientCertificateOld);
                }
            } else if (!m_use_cred) {
                // When not using configured client certificate (user must supply one), add empty <ClientCertificate/>.
                com_obj<IXMLDOMElement> pXmlElClientCertificate;
                hr = eapxml::create_element(pDoc, pXmlElClientSideCredential, bstr(L"eap-metadata:ClientCertificate"), bstr(L"ClientCertificate"), namespace_eapmetadata, pXmlElClientCertificate);
            }
        }
    }
}


void eap::config_method_ttls::load(_In_ IXMLDOMNode *pConfigRoot)
{
    assert(pConfigRoot);
    HRESULT hr;

    {
        com_obj<IXMLDOMNode> pXmlElClientSideCredential;
        if (SUCCEEDED(hr = eapxml::select_node(pConfigRoot, bstr(L"eap-metadata:ClientSideCredential"), pXmlElClientSideCredential))) {
            com_obj<IXMLDOMDocument> pDoc;
            if (SUCCEEDED(hr = pXmlElClientSideCredential->get_ownerDocument(&pDoc))) {
                // Fix 1: Configured outer credentials in draft-winter-opsawg-eap-metadata has some bizarre presence/absence/blank logic for EAP-TTLS methods only.
                // To keep our code clean, we do some pre-processing, to accept draft compliant XML on input, while keeping things simple on the inside.
                com_obj<IXMLDOMNode> pXmlElClientCertificate;
                if (SUCCEEDED(hr = eapxml::select_node(pXmlElClientSideCredential, bstr(L"eap-metadata:ClientCertificate"), pXmlElClientCertificate))) {
                    VARIANT_BOOL has_children;
                    if (SUCCEEDED(hr = pXmlElClientCertificate->hasChildNodes(&has_children)) && !has_children) {
                        // Empty <ClientCertificate/> means: do not use configured credentials.
                        com_obj<IXMLDOMNode> pXmlElClientCertificateOld;
                        hr = pXmlElClientSideCredential->removeChild(pXmlElClientCertificate, &pXmlElClientCertificateOld);
                    }
                } else {
                    // Nonexisting <ClientSideCredential> means: use blank configured credentials.
                    com_obj<IXMLDOMElement> pXmlElClientCertificate;
                    hr = eapxml::create_element(pDoc, pXmlElClientSideCredential, bstr(L"eap-metadata:ClientCertificate"), bstr(L"ClientCertificate"), namespace_eapmetadata, pXmlElClientCertificate);
                }
            }
        }
    }

    config_method_tls::load(pConfigRoot);

    std::wstring xpath(eapxml::get_xpath(pConfigRoot));

    m_anonymous_identity.clear();

    // <ClientSideCredential>
    com_obj<IXMLDOMElement> pXmlElClientSideCredential;
    if (SUCCEEDED(eapxml::select_element(pConfigRoot, bstr(L"eap-metadata:ClientSideCredential"), pXmlElClientSideCredential))) {
        wstring xpathClientSideCredential(xpath + L"/ClientSideCredential");

        // <AnonymousIdentity>
        eapxml::get_element_value(pXmlElClientSideCredential, bstr(L"eap-metadata:AnonymousIdentity"), m_anonymous_identity);
        m_module.log_config((xpathClientSideCredential + L"/AnonymousIdentity").c_str(), m_anonymous_identity.c_str());
    }

    // <InnerAuthenticationMethod>
    com_obj<IXMLDOMElement> pXmlElInnerAuthenticationMethod;
    if (FAILED(hr = eapxml::select_element(pConfigRoot, bstr(L"eap-metadata:InnerAuthenticationMethod"), pXmlElInnerAuthenticationMethod)))
        throw com_runtime_error(hr, __FUNCTION__ " Error selecting <InnerAuthenticationMethod> element.");

    // Determine inner authentication type (<EAPMethod> and <NonEAPAuthMethod>).
    DWORD dwMethod;
    bstr bstrMethod;
    if (SUCCEEDED(eapxml::get_element_value(pXmlElInnerAuthenticationMethod, bstr(L"eap-metadata:EAPMethod"), dwMethod)) &&
        eap_type_start <= dwMethod && dwMethod < eap_type_end)
    {
        m_inner.reset(make_config_method((eap_type_t)dwMethod));
        m_module.log_config((xpath + L"/EAPMethod").c_str(), m_inner->get_method_str());
    } else if (SUCCEEDED(eapxml::get_element_value(pXmlElInnerAuthenticationMethod, bstr(L"eap-metadata:NonEAPAuthMethod"), bstrMethod))) {
        m_inner.reset(make_config_method(bstrMethod));
        m_module.log_config((xpath + L"/NonEAPAuthMethod").c_str(), m_inner->get_method_str());
    } else
        throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Unsupported inner authentication method.");

    m_inner->load(pXmlElInnerAuthenticationMethod);
}


void eap::config_method_ttls::operator<<(_Inout_ cursor_out &cursor) const
{
    config_method_tls::operator<<(cursor);
    cursor << m_inner->get_method_id();
    cursor << *m_inner;
    cursor << m_anonymous_identity;
}


size_t eap::config_method_ttls::get_pk_size() const
{
    return
        config_method_tls::get_pk_size() +
        pksizeof(m_inner->get_method_id()) +
        pksizeof(*m_inner) +
        pksizeof(m_anonymous_identity);
}


void eap::config_method_ttls::operator>>(_Inout_ cursor_in &cursor)
{
    config_method_tls::operator>>(cursor);

    eap_type_t eap_type;
    cursor >> eap_type;
    m_inner.reset(make_config_method(eap_type));
    cursor >> *m_inner;
    cursor >> m_anonymous_identity;
}


eap_type_t eap::config_method_ttls::get_method_id() const
{
    return eap_type_ttls;
}


const wchar_t* eap::config_method_ttls::get_method_str() const
{
    return L"EAP-TTLS";
}


eap::credentials* eap::config_method_ttls::make_credentials() const
{
    credentials_ttls *cred = new credentials_ttls(m_module);
    cred->m_inner.reset(m_inner->make_credentials());
    return cred;
}


eap::config_method_with_cred* eap::config_method_ttls::make_config_method(_In_ winstd::eap_type_t eap_type) const
{
    switch (eap_type) {
    case eap_type_tls            : return new config_method_tls     (m_module, m_level + 1);
    case eap_type_ttls           : return new config_method_ttls    (m_module, m_level + 1);
    case eap_type_legacy_pap     : return new config_method_pap     (m_module, m_level + 1);
    case eap_type_legacy_mschapv2: return new config_method_mschapv2(m_module, m_level + 1);
    default                      : throw invalid_argument(string_printf(__FUNCTION__ " Unsupported inner authentication method (%d).", eap_type));
    }
}


eap::config_method_with_cred* eap::config_method_ttls::make_config_method(_In_ const wchar_t *eap_type) const
{
         if (_wcsicmp(eap_type, L"EAP-TLS" ) == 0) return new config_method_tls     (m_module, m_level + 1);
    else if (_wcsicmp(eap_type, L"EAP-TTLS") == 0) return new config_method_ttls    (m_module, m_level + 1);
    else if (_wcsicmp(eap_type, L"PAP"     ) == 0) return new config_method_pap     (m_module, m_level + 1);
    else if (_wcsicmp(eap_type, L"MSCHAPv2") == 0) return new config_method_mschapv2(m_module, m_level + 1);
    else                                           throw invalid_argument(string_printf(__FUNCTION__ " Unsupported inner authentication method (%ls).", eap_type));
}


wstring eap::config_method_ttls::get_public_identity(const credentials_ttls &cred) const
{
    if (m_anonymous_identity.empty()) {
        // Use the true identity.
        return cred.get_identity();
    } else if (m_anonymous_identity.compare(L"@") == 0) {
        // Strip username part from identity.
        wstring identity(std::move(cred.get_identity()));
        auto offset = identity.find(L'@');
        if (offset != wstring::npos) identity.erase(0, offset);
        return identity;
    } else {
        // Use configured identity.
        return m_anonymous_identity;
    }
}
