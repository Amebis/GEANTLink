/*
    Copyright 2015-2020 Amebis
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

#include "PCH.h"

using namespace std;
using namespace winstd;


//////////////////////////////////////////////////////////////////////
// eap::config_method_tls_tunnel
//////////////////////////////////////////////////////////////////////

eap::config_method_tls_tunnel::config_method_tls_tunnel(_In_ module &mod, _In_ unsigned int level) :
    config_method_tls(mod, level)
{
    // TLS tunnel is using blank configured credentials per default.
    m_use_cred = true;
}


eap::config_method_tls_tunnel::config_method_tls_tunnel(const _In_ config_method_tls_tunnel &other) :
    m_inner(other.m_inner ? dynamic_cast<config_method*>(other.m_inner->clone()) : nullptr),
    config_method_tls(other)
{
}


eap::config_method_tls_tunnel::config_method_tls_tunnel(_Inout_ config_method_tls_tunnel &&other) noexcept :
    m_inner(std::move(other.m_inner)),
    config_method_tls(std::move(other))
{
}


eap::config_method_tls_tunnel& eap::config_method_tls_tunnel::operator=(const _In_ config_method_tls_tunnel &other)
{
    if (this != &other) {
        (config_method_tls&)*this = other;
        m_inner.reset(other.m_inner ? dynamic_cast<config_method*>(other.m_inner->clone()) : nullptr);
    }

    return *this;
}


eap::config_method_tls_tunnel& eap::config_method_tls_tunnel::operator=(_Inout_ config_method_tls_tunnel &&other) noexcept
{
    if (this != &other) {
        (config_method_tls&&)*this = std::move(other);
        m_inner                    = std::move(other.m_inner);
    }

    return *this;
}


void eap::config_method_tls_tunnel::operator<<(_Inout_ cursor_out &cursor) const
{
    config_method_tls::operator<<(cursor);
    cursor << m_inner->get_method_id();
    cursor << *m_inner;
}


size_t eap::config_method_tls_tunnel::get_pk_size() const
{
    return
        config_method_tls::get_pk_size() +
        pksizeof(m_inner->get_method_id()) +
        pksizeof(*m_inner);
}


void eap::config_method_tls_tunnel::operator>>(_Inout_ cursor_in &cursor)
{
    config_method_tls::operator>>(cursor);

    eap_type_t eap_type;
    cursor >> eap_type;
    m_inner.reset(make_inner_config(eap_type));
    cursor >> *m_inner;
}


eap::credentials* eap::config_method_tls_tunnel::make_credentials() const
{
    credentials_tls_tunnel *cred = new credentials_tls_tunnel(m_module);
    cred->m_inner.reset(m_inner->make_credentials());
    return cred;
}


//////////////////////////////////////////////////////////////////////
// eap::config_method_ttls
//////////////////////////////////////////////////////////////////////

eap::config_method_ttls::config_method_ttls(_In_ module &mod, _In_ unsigned int level) :
    config_method_tls_tunnel(mod, level)
{
    m_inner.reset(new config_method_pap(mod, level + 1));
}


eap::config_method_ttls::config_method_ttls(const _In_ config_method_ttls &other) :
    config_method_tls_tunnel(other)
{
}


eap::config_method_ttls::config_method_ttls(_Inout_ config_method_ttls &&other) noexcept :
    config_method_tls_tunnel(std::move(other))
{
}


eap::config_method_ttls& eap::config_method_ttls::operator=(const _In_ config_method_ttls &other)
{
    if (this != &other)
        (config_method_tls_tunnel&)*this = other;

    return *this;
}


eap::config_method_ttls& eap::config_method_ttls::operator=(_Inout_ config_method_ttls &&other) noexcept
{
    if (this != &other)
        (config_method_tls_tunnel&&)*this = std::move(other);

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

    config_method_tls_tunnel::save(pDoc, pConfigRoot);

    HRESULT hr;

    // <InnerAuthenticationMethod>
    com_obj<IXMLDOMElement> pXmlElInnerAuthenticationMethod;
    if (FAILED(hr = eapxml::create_element(pDoc, pConfigRoot, bstr(L"eap-metadata:InnerAuthenticationMethod"), bstr(L"InnerAuthenticationMethod"), namespace_eapmetadata, pXmlElInnerAuthenticationMethod)))
        throw com_runtime_error(hr, __FUNCTION__ " Error creating <InnerAuthenticationMethod> element.");

    eap_type_t eap_type = m_inner->get_method_id();
    if (eap_type_t::noneap_start <= eap_type && eap_type < eap_type_t::noneap_end) {
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
                    com_obj<IXMLDOMElement> pXmlElClientCertificate_blank;
                    hr = eapxml::create_element(pDoc, pXmlElClientSideCredential, bstr(L"eap-metadata:ClientCertificate"), bstr(L"ClientCertificate"), namespace_eapmetadata, pXmlElClientCertificate_blank);
                }
            }
        }
    }

    config_method_tls_tunnel::load(pConfigRoot);

    std::wstring xpath(eapxml::get_xpath(pConfigRoot));

    // <InnerAuthenticationMethod>
    com_obj<IXMLDOMElement> pXmlElInnerAuthenticationMethod;
    if (FAILED(hr = eapxml::select_element(pConfigRoot, bstr(L"eap-metadata:InnerAuthenticationMethod"), pXmlElInnerAuthenticationMethod)))
        throw com_runtime_error(hr, __FUNCTION__ " Error selecting <InnerAuthenticationMethod> element.");

    // Determine inner authentication type (<EAPMethod> and <NonEAPAuthMethod>).
    DWORD dwMethod;
    bstr bstrMethod;
    if (SUCCEEDED(eapxml::get_element_value(pXmlElInnerAuthenticationMethod, bstr(L"eap-metadata:EAPMethod"), dwMethod)) &&
        (eap_type_t::start <= (eap_type_t)dwMethod && (eap_type_t)dwMethod < eap_type_t::end
#if EAP_INNER_EAPHOST
        || (eap_type_t)dwMethod == eap_type_t::undefined
#endif
        ))
    {
        m_inner.reset(make_inner_config((eap_type_t)dwMethod));
        m_module.log_config((xpath + L"/EAPMethod").c_str(), m_inner->get_method_str());
    } else if (SUCCEEDED(eapxml::get_element_value(pXmlElInnerAuthenticationMethod, bstr(L"eap-metadata:NonEAPAuthMethod"), bstrMethod))) {
        m_inner.reset(make_inner_config(bstrMethod));
        m_module.log_config((xpath + L"/NonEAPAuthMethod").c_str(), m_inner->get_method_str());
    } else
        throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Unsupported inner authentication method.");

    m_inner->load(pXmlElInnerAuthenticationMethod);
}


eap_type_t eap::config_method_ttls::get_method_id() const
{
    return eap_type_t::ttls;
}


const wchar_t* eap::config_method_ttls::get_method_str() const
{
    return L"EAP-TTLS";
}


eap::config_method* eap::config_method_ttls::make_inner_config(_In_ winstd::eap_type_t eap_type) const
{
    switch (eap_type) {
    case eap_type_t::legacy_pap     : return new config_method_pap        (m_module, m_level + 1);
    case eap_type_t::legacy_mschapv2: return new config_method_mschapv2   (m_module, m_level + 1);
    case eap_type_t::mschapv2       : return new config_method_eapmschapv2(m_module, m_level + 1);
    case eap_type_t::gtc            : return new config_method_eapgtc     (m_module, m_level + 1);
#if EAP_INNER_EAPHOST
    case eap_type_t::undefined      : return new config_method_eaphost    (m_module, m_level + 1);
#endif
    default                         : throw invalid_argument(string_printf(__FUNCTION__ " Unsupported inner authentication method (%d).", eap_type));
    }
}


eap::config_method* eap::config_method_ttls::make_inner_config(_In_ const wchar_t *eap_type) const
{
         if (_wcsicmp(eap_type, L"PAP"         ) == 0) return new config_method_pap        (m_module, m_level + 1);
    else if (_wcsicmp(eap_type, L"MSCHAPv2"    ) == 0) return new config_method_mschapv2   (m_module, m_level + 1);
    else if (_wcsicmp(eap_type, L"EAP-MSCHAPv2") == 0) return new config_method_eapmschapv2(m_module, m_level + 1);
    else if (_wcsicmp(eap_type, L"EAP-GTC"     ) == 0) return new config_method_eapgtc     (m_module, m_level + 1);
#if EAP_INNER_EAPHOST
    else if (_wcsicmp(eap_type, L"EapHost"     ) == 0) return new config_method_eaphost    (m_module, m_level + 1);
#endif
    else                                               throw invalid_argument(string_printf(__FUNCTION__ " Unsupported inner authentication method (%ls).", eap_type));
}
