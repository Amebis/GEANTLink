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


eap::config::~config()
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
    assert(&m_module == &other.m_module); // Copy configuration within same module only!
    return *this;
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
    config(other)
{
}


eap::config_method::config_method(_Inout_ config_method &&other) :
    m_allow_save(std::move(other.m_allow_save)),
    m_anonymous_identity(std::move(other.m_anonymous_identity)),
    config(std::move(other))
{
}


eap::config_method& eap::config_method::operator=(_In_ const config_method &other)
{
    if (this != &other) {
        (config&)*this       = other;
        m_allow_save         = other.m_allow_save;
        m_anonymous_identity = other.m_anonymous_identity;
    }

    return *this;
}


eap::config_method& eap::config_method::operator=(_Inout_ config_method &&other)
{
    if (this != &other) {
        (config&&)*this      = std::move(other);
        m_allow_save         = std::move(other.m_allow_save);
        m_anonymous_identity = std::move(other.m_anonymous_identity);
    }

    return *this;
}


DWORD eap::config_method::save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError) const
{
    const bstr bstrNamespace(L"urn:ietf:params:xml:ns:yang:ietf-eap-metadata");
    DWORD dwResult;

    // <ClientSideCredential>
    com_obj<IXMLDOMElement> pXmlElClientSideCredential;
    if ((dwResult = eapxml::create_element(pDoc, pConfigRoot, bstr(L"eap-metadata:ClientSideCredential"), bstr(L"ClientSideCredential"), bstrNamespace, &pXmlElClientSideCredential)) != ERROR_SUCCESS) {
        *ppEapError = m_module.make_error(dwResult, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error creating <ClientSideCredential> element."), NULL);
        return dwResult;
    }

    // <ClientSideCredential>/<allow-save>
    if ((dwResult = eapxml::put_element_value(pDoc, pXmlElClientSideCredential, bstr(L"allow-save"), bstrNamespace, m_allow_save)) != ERROR_SUCCESS) {
        *ppEapError = m_module.make_error(dwResult, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error creating <allow-save> element."), NULL);
        return dwResult;
    }

    // <ClientSideCredential>/<AnonymousIdentity>
    if (!m_anonymous_identity.empty())
        if ((dwResult = eapxml::put_element_value(pDoc, pXmlElClientSideCredential, bstr(L"AnonymousIdentity"), bstrNamespace, bstr(m_anonymous_identity))) != ERROR_SUCCESS) {
            *ppEapError = m_module.make_error(dwResult, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error creating <AnonymousIdentity> element."), NULL);
            return dwResult;
        }

    return ERROR_SUCCESS;
}


DWORD eap::config_method::load(_In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError)
{
    UNREFERENCED_PARAMETER(ppEapError);

    m_allow_save = true;
    m_anonymous_identity.clear();

    // <ClientSideCredential>
    com_obj<IXMLDOMElement> pXmlElClientSideCredential;
    if (eapxml::select_element(pConfigRoot, bstr(L"eap-metadata:ClientSideCredential"), &pXmlElClientSideCredential) == ERROR_SUCCESS) {
        // <allow-save>
        eapxml::get_element_value(pXmlElClientSideCredential, bstr(L"eap-metadata:allow-save"), &m_allow_save);

        // <AnonymousIdentity>
        eapxml::get_element_value(pXmlElClientSideCredential, bstr(L"eap-metadata:AnonymousIdentity"), m_anonymous_identity);
    }

    return ERROR_SUCCESS;
}
