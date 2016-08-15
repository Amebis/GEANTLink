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

eap::credentials_ttls::credentials_ttls(_In_ module &mod) :
    credentials_tls(mod)
{
}


eap::credentials_ttls::credentials_ttls(_In_ const credentials_ttls &other) :
    m_inner(other.m_inner ? (credentials*)other.m_inner->clone() : nullptr),
    credentials_tls(other)
{
}


eap::credentials_ttls::credentials_ttls(_Inout_ credentials_ttls &&other) :
    m_inner(std::move(other.m_inner)),
    credentials_tls(std::move(other))
{
}


eap::credentials_ttls& eap::credentials_ttls::operator=(_In_ const credentials_ttls &other)
{
    if (this != &other) {
        (credentials_tls&)*this = other;
        m_inner.reset(other.m_inner ? (credentials*)other.m_inner->clone() : nullptr);
    }

    return *this;
}


eap::credentials_ttls& eap::credentials_ttls::operator=(_Inout_ credentials_ttls &&other)
{
    if (this != &other) {
        (credentials_tls&)*this = std::move(other);
        m_inner                 = std::move(other.m_inner);
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


void eap::credentials_ttls::save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot) const
{
    assert(pDoc);
    assert(pConfigRoot);

    credentials_tls::save(pDoc, pConfigRoot);

    const bstr bstrNamespace(L"urn:ietf:params:xml:ns:yang:ietf-eap-metadata");
    HRESULT hr;

    if (m_inner) {
        // <InnerAuthenticationMethod>
        winstd::com_obj<IXMLDOMElement> pXmlElInnerAuthenticationMethod;
        if (FAILED(hr = eapxml::create_element(pDoc, winstd::bstr(L"InnerAuthenticationMethod"), bstrNamespace, &pXmlElInnerAuthenticationMethod)))
            throw com_runtime_error(hr, __FUNCTION__ " Error creating <InnerAuthenticationMethod> element.");

        m_inner->save(pDoc, pXmlElInnerAuthenticationMethod);

        if (FAILED(hr = pConfigRoot->appendChild(pXmlElInnerAuthenticationMethod, NULL)))
            throw com_runtime_error(hr, __FUNCTION__ " Error appending <InnerAuthenticationMethod> element.");
    }
}


void eap::credentials_ttls::load(_In_ IXMLDOMNode *pConfigRoot)
{
    assert(pConfigRoot);
    HRESULT hr;

    credentials_tls::load(pConfigRoot);

    // TODO: For the time being, there is no detection what type is inner method. Introduce one!
    if (m_inner) {
        com_obj<IXMLDOMNode> pXmlElInnerAuthenticationMethod;
        if (FAILED(hr = eapxml::select_node(pConfigRoot, bstr(L"eap-metadata:InnerAuthenticationMethod"), &pXmlElInnerAuthenticationMethod)))
            throw com_runtime_error(hr, __FUNCTION__ " Error selecting <InnerAuthenticationMethod> element.");

        m_inner->load(pXmlElInnerAuthenticationMethod);
    }
}


void eap::credentials_ttls::operator<<(_Inout_ cursor_out &cursor) const
{
    credentials_tls::operator<<(cursor);
    if (m_inner) {
        if (dynamic_cast<credentials_pap*>(m_inner.get())) {
            cursor << eap_type_pap;
            cursor << *m_inner;
        } else {
            assert(0); // Unsupported inner authentication method type.
            cursor << eap_type_undefined;
        }
    } else
        cursor << eap_type_undefined;
}


size_t eap::credentials_ttls::get_pk_size() const
{
    size_t size_inner;
    if (m_inner) {
        if (dynamic_cast<credentials_pap*>(m_inner.get())) {
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
        credentials_tls::get_pk_size() +
        size_inner;
}


void eap::credentials_ttls::operator>>(_Inout_ cursor_in &cursor)
{
    credentials_tls::operator>>(cursor);

    eap_type_t eap_type;
    cursor >> eap_type;
    switch (eap_type) {
        case eap_type_pap:
            m_inner.reset(new credentials_pap(m_module));
            cursor >> *m_inner;
            break;
        default:
            assert(0); // Unsupported inner authentication method type.
            m_inner.reset(nullptr);
    }
}


void eap::credentials_ttls::store(_In_z_ LPCTSTR pszTargetName) const
{
    credentials_tls::store(pszTargetName);

    if (m_inner)
        m_inner->store(pszTargetName);
}


void eap::credentials_ttls::retrieve(_In_z_ LPCTSTR pszTargetName)
{
    credentials_tls::retrieve(pszTargetName);

    if (m_inner)
        m_inner->retrieve(pszTargetName);
}


LPCTSTR eap::credentials_ttls::target_suffix() const
{
    assert(0); // Not that we would ever store inner&outer credentials to Windows Credential Manager joined, but for completness sake... Here we go:
    return _T("TTLS");
}


std::wstring eap::credentials_ttls::get_identity() const
{
    // Outer identity has the right-of-way.
    if (!credentials_tls::empty())
        return credentials_tls::get_identity();

    // Inner identity.
    if (m_inner)
        return m_inner->get_identity();

    return L"";
}


bool eap::credentials_ttls::combine(
    _In_       const credentials_ttls   *cred_cached,
    _In_       const config_method_ttls &cfg,
    _In_opt_z_       LPCTSTR            pszTargetName)
{
    bool
        is_outer_set = credentials_tls::combine(cred_cached, cfg, pszTargetName),
        is_inner_set =
            dynamic_cast<const credentials_pap*>(m_inner.get()) ? ((credentials_pap*)m_inner.get())->combine(cred_cached ? (credentials_pap*)cred_cached->m_inner.get() : NULL, (const config_method_pap&)*cfg.m_inner, pszTargetName) : false;

    return is_outer_set && is_inner_set;
}
