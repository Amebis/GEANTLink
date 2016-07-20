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
// eap::config
//////////////////////////////////////////////////////////////////////

eap::config::config(_In_ module &mod) :
    m_module(mod)
{
}


eap::config::config(_In_ const config &other) :
    m_module(other.m_module)
{
}


eap::config::config(_Inout_ config &&other) :
    m_module(other.m_module)
{
}


eap::config& eap::config::operator=(_In_ const config &other)
{
    UNREFERENCED_PARAMETER(other);
    assert(&m_module == &other.m_module); // Copy configuration within same module only!
    return *this;
}


eap::config& eap::config::operator=(_Inout_ config &&other)
{
    UNREFERENCED_PARAMETER(other);
    assert(&m_module == &other.m_module); // Move configuration within same module only!
    return *this;
}


bool eap::config::save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError) const
{
    UNREFERENCED_PARAMETER(pDoc);
    UNREFERENCED_PARAMETER(pConfigRoot);
    UNREFERENCED_PARAMETER(ppEapError);

    return true;
}


bool eap::config::load(_In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError)
{
    UNREFERENCED_PARAMETER(pConfigRoot);
    UNREFERENCED_PARAMETER(ppEapError);

    return true;
}


void eap::config::pack(_Inout_ unsigned char *&cursor) const
{
    UNREFERENCED_PARAMETER(cursor);
}


size_t eap::config::get_pk_size() const
{
    return 0;
}


void eap::config::unpack(_Inout_ const unsigned char *&cursor)
{
    UNREFERENCED_PARAMETER(cursor);
}


//////////////////////////////////////////////////////////////////////
// eap::config_method
//////////////////////////////////////////////////////////////////////

eap::config_method::config_method(_In_ module &mod) :
    m_allow_save(true),
    config(mod)
{
}


eap::config_method::config_method(_In_ const config_method &other) :
    m_allow_save(other.m_allow_save),
    m_anonymous_identity(other.m_anonymous_identity),
    m_preshared(other.m_preshared ? (credentials*)other.m_preshared->clone() : nullptr),
    config(other)
{
}


eap::config_method::config_method(_Inout_ config_method &&other) :
    m_allow_save(std::move(other.m_allow_save)),
    m_anonymous_identity(std::move(other.m_anonymous_identity)),
    m_preshared(std::move(other.m_preshared)),
    config(std::move(other))
{
}


eap::config_method& eap::config_method::operator=(_In_ const config_method &other)
{
    if (this != &other) {
        (config&)*this       = other;
        m_allow_save         = other.m_allow_save;
        m_anonymous_identity = other.m_anonymous_identity;
        m_preshared.reset(other.m_preshared ? (credentials*)other.m_preshared->clone() : nullptr);
    }

    return *this;
}


eap::config_method& eap::config_method::operator=(_Inout_ config_method &&other)
{
    if (this != &other) {
        (config&&)*this      = std::move(other);
        m_allow_save         = std::move(other.m_allow_save);
        m_anonymous_identity = std::move(other.m_anonymous_identity);
        m_preshared          = std::move(other.m_preshared);
    }

    return *this;
}


bool eap::config_method::save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError) const
{
    assert(pDoc);
    assert(pConfigRoot);
    assert(ppEapError);

    if (!config::save(pDoc, pConfigRoot, ppEapError))
        return false;

    const winstd::bstr bstrNamespace(L"urn:ietf:params:xml:ns:yang:ietf-eap-metadata");
    DWORD dwResult;

    // <ClientSideCredential>
    winstd::com_obj<IXMLDOMElement> pXmlElClientSideCredential;
    if ((dwResult = eapxml::create_element(pDoc, pConfigRoot, winstd::bstr(L"eap-metadata:ClientSideCredential"), winstd::bstr(L"ClientSideCredential"), bstrNamespace, &pXmlElClientSideCredential)) != ERROR_SUCCESS) {
        *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <ClientSideCredential> element."));
        return false;
    }

    // <ClientSideCredential>/<allow-save>
    if ((dwResult = eapxml::put_element_value(pDoc, pXmlElClientSideCredential, winstd::bstr(L"allow-save"), bstrNamespace, m_allow_save)) != ERROR_SUCCESS) {
        *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <allow-save> element."));
        return false;
    }

    // <ClientSideCredential>/<AnonymousIdentity>
    if (!m_anonymous_identity.empty())
        if ((dwResult = eapxml::put_element_value(pDoc, pXmlElClientSideCredential, winstd::bstr(L"AnonymousIdentity"), bstrNamespace, winstd::bstr(m_anonymous_identity))) != ERROR_SUCCESS) {
            *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <AnonymousIdentity> element."));
            return false;
        }

    if (m_preshared)
        if (!m_preshared->save(pDoc, pXmlElClientSideCredential, ppEapError))
            return false;

    return true;
}


bool eap::config_method::load(_In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError)
{
    assert(pConfigRoot);
    assert(ppEapError);

    if (!config::load(pConfigRoot, ppEapError))
        return false;

    m_allow_save = true;
    m_preshared.reset(nullptr);
    m_anonymous_identity.clear();

    // <ClientSideCredential>
    winstd::com_obj<IXMLDOMElement> pXmlElClientSideCredential;
    if (eapxml::select_element(pConfigRoot, winstd::bstr(L"eap-metadata:ClientSideCredential"), &pXmlElClientSideCredential) == ERROR_SUCCESS) {
        std::wstring xpath(eapxml::get_xpath(pXmlElClientSideCredential));

        // <allow-save>
        eapxml::get_element_value(pXmlElClientSideCredential, winstd::bstr(L"eap-metadata:allow-save"), &m_allow_save);
        m_module.log_config((xpath + L"/allow-save").c_str(), m_allow_save);

        // <AnonymousIdentity>
        eapxml::get_element_value(pXmlElClientSideCredential, winstd::bstr(L"eap-metadata:AnonymousIdentity"), m_anonymous_identity);
        m_module.log_config((xpath + L"/AnonymousIdentity").c_str(), m_anonymous_identity.c_str());

        std::unique_ptr<credentials> preshared(make_credentials());
        assert(preshared);
        if (preshared->load(pXmlElClientSideCredential, ppEapError)) {
            m_preshared = std::move(preshared);
        } else {
            // This is not really an error - merely an indication pre-shared credentials are unavailable.
            if (*ppEapError) {
                m_module.free_error_memory(*ppEapError);
                *ppEapError = NULL;
            }
        }
    }

    return true;
}


void eap::config_method::pack(_Inout_ unsigned char *&cursor) const
{
    eap::config::pack(cursor);
    eapserial::pack(cursor, m_allow_save        );
    eapserial::pack(cursor, m_anonymous_identity);
    if (m_preshared) {
        eapserial::pack(cursor, true);
        m_preshared->pack(cursor);
    } else
        eapserial::pack(cursor, false);
}


size_t eap::config_method::get_pk_size() const
{
    return
        eap::config::get_pk_size()        +
        eapserial::get_pk_size(m_allow_save        ) +
        eapserial::get_pk_size(m_anonymous_identity) +
        (m_preshared ? 
            eapserial::get_pk_size(true) +
            m_preshared->get_pk_size() :
            eapserial::get_pk_size(false));
}


void eap::config_method::unpack(_Inout_ const unsigned char *&cursor)
{
    eap::config::unpack(cursor);
    eapserial::unpack(cursor, m_allow_save        );
    eapserial::unpack(cursor, m_anonymous_identity);

    bool use_preshared;
    eapserial::unpack(cursor, use_preshared);
    if (use_preshared) {
        m_preshared.reset(make_credentials());
        assert(m_preshared);
        m_preshared->unpack(cursor);
    } else
        m_preshared.reset(nullptr);
}
