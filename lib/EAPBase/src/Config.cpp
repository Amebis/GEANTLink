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
    m_allow_save(move(other.m_allow_save)),
    m_anonymous_identity(move(other.m_anonymous_identity)),
    m_preshared(move(other.m_preshared)),
    config(move(other))
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
        (config&&)*this      = move(other);
        m_allow_save         = move(other.m_allow_save);
        m_anonymous_identity = move(other.m_anonymous_identity);
        m_preshared          = move(other.m_preshared);
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

    const bstr bstrNamespace(L"urn:ietf:params:xml:ns:yang:ietf-eap-metadata");
    DWORD dwResult;

    // <ClientSideCredential>
    com_obj<IXMLDOMElement> pXmlElClientSideCredential;
    if ((dwResult = eapxml::create_element(pDoc, pConfigRoot, bstr(L"eap-metadata:ClientSideCredential"), bstr(L"ClientSideCredential"), bstrNamespace, &pXmlElClientSideCredential)) != ERROR_SUCCESS) {
        *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <ClientSideCredential> element."));
        return false;
    }

    // <ClientSideCredential>/<allow-save>
    if ((dwResult = eapxml::put_element_value(pDoc, pXmlElClientSideCredential, bstr(L"allow-save"), bstrNamespace, m_allow_save)) != ERROR_SUCCESS) {
        *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <allow-save> element."));
        return false;
    }

    // <ClientSideCredential>/<AnonymousIdentity>
    if (!m_anonymous_identity.empty())
        if ((dwResult = eapxml::put_element_value(pDoc, pXmlElClientSideCredential, bstr(L"AnonymousIdentity"), bstrNamespace, bstr(m_anonymous_identity))) != ERROR_SUCCESS) {
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
    com_obj<IXMLDOMElement> pXmlElClientSideCredential;
    if (eapxml::select_element(pConfigRoot, bstr(L"eap-metadata:ClientSideCredential"), &pXmlElClientSideCredential) == ERROR_SUCCESS) {
        wstring xpath(eapxml::get_xpath(pXmlElClientSideCredential));

        // <allow-save>
        eapxml::get_element_value(pXmlElClientSideCredential, bstr(L"eap-metadata:allow-save"), &m_allow_save);
        m_module.log_config((xpath + L"/allow-save").c_str(), m_allow_save);

        // <AnonymousIdentity>
        eapxml::get_element_value(pXmlElClientSideCredential, bstr(L"eap-metadata:AnonymousIdentity"), m_anonymous_identity);
        m_module.log_config((xpath + L"/AnonymousIdentity").c_str(), m_anonymous_identity.c_str());

        unique_ptr<credentials> preshared(make_credentials());
        assert(preshared);
        if (preshared->load(pXmlElClientSideCredential, ppEapError)) {
            m_preshared = move(preshared);
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
    config::pack(cursor);
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
        config::get_pk_size()        +
        eapserial::get_pk_size(m_allow_save        ) +
        eapserial::get_pk_size(m_anonymous_identity) +
        (m_preshared ? 
            eapserial::get_pk_size(true) +
            m_preshared->get_pk_size() :
            eapserial::get_pk_size(false));
}


void eap::config_method::unpack(_Inout_ const unsigned char *&cursor)
{
    config::unpack(cursor);
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


//////////////////////////////////////////////////////////////////////
// eap::config_provider
//////////////////////////////////////////////////////////////////////

eap::config_provider::config_provider(_In_ module &mod) :
    m_read_only(false),
    config(mod)
{
}


eap::config_provider::config_provider(_In_ const config_provider &other) :
    m_read_only(other.m_read_only),
    m_id(other.m_id),
    m_name(other.m_name),
    m_help_email(other.m_help_email),
    m_help_web(other.m_help_web),
    m_help_phone(other.m_help_phone),
    m_lbl_alt_credential(other.m_lbl_alt_credential),
    m_lbl_alt_identity(other.m_lbl_alt_identity),
    m_lbl_alt_password(other.m_lbl_alt_password),
    config(other)
{
    for (list<unique_ptr<config_method> >::const_iterator method = other.m_methods.cbegin(), method_end = other.m_methods.cend(); method != method_end; ++method)
        m_methods.push_back(move(unique_ptr<config_method>(*method ? (config_method*)method->get()->clone() : nullptr)));
}


eap::config_provider::config_provider(_Inout_ config_provider &&other) :
    m_read_only(move(other.m_read_only)),
    m_id(move(other.m_id)),
    m_name(move(other.m_name)),
    m_help_email(move(other.m_help_email)),
    m_help_web(move(other.m_help_web)),
    m_help_phone(move(other.m_help_phone)),
    m_lbl_alt_credential(move(other.m_lbl_alt_credential)),
    m_lbl_alt_identity(move(other.m_lbl_alt_identity)),
    m_lbl_alt_password(move(other.m_lbl_alt_password)),
    m_methods(move(other.m_methods)),
    config(move(other))
{
}


eap::config_provider& eap::config_provider::operator=(_In_ const config_provider &other)
{
    if (this != &other) {
        (config&)*this       = other;
        m_read_only          = other.m_read_only;
        m_id                 = other.m_id;
        m_name               = other.m_name;
        m_help_email         = other.m_help_email;
        m_help_web           = other.m_help_web;
        m_help_phone         = other.m_help_phone;
        m_lbl_alt_credential = other.m_lbl_alt_credential;
        m_lbl_alt_identity   = other.m_lbl_alt_identity;
        m_lbl_alt_password   = other.m_lbl_alt_password;

        m_methods.clear();
        for (list<unique_ptr<config_method> >::const_iterator method = other.m_methods.cbegin(), method_end = other.m_methods.cend(); method != method_end; ++method)
            m_methods.push_back(move(unique_ptr<config_method>(*method ? (config_method*)method->get()->clone() : nullptr)));
    }

    return *this;
}


eap::config_provider& eap::config_provider::operator=(_Inout_ config_provider &&other)
{
    if (this != &other) {
        (config&&)*this      = move(other);
        m_read_only          = move(m_read_only);
        m_id                 = move(other.m_id);
        m_name               = move(other.m_name);
        m_help_email         = move(other.m_help_email);
        m_help_web           = move(other.m_help_web);
        m_help_phone         = move(other.m_help_phone);
        m_lbl_alt_credential = move(other.m_lbl_alt_credential);
        m_lbl_alt_identity   = move(other.m_lbl_alt_identity);
        m_lbl_alt_password   = move(other.m_lbl_alt_password);
        m_methods            = move(other.m_methods);
    }

    return *this;
}


eap::config* eap::config_provider::clone() const
{
    return new config_provider(*this);
}


bool eap::config_provider::save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError) const
{
    if (!config::save(pDoc, pConfigRoot, ppEapError))
        return false;

    const bstr bstrNamespace(L"urn:ietf:params:xml:ns:yang:ietf-eap-metadata");
    DWORD dwResult;
    HRESULT hr;

    // <read-only>
    if ((dwResult = eapxml::put_element_value(pDoc, pConfigRoot, bstr(L"read-only"), bstrNamespace, m_read_only)) != ERROR_SUCCESS) {
        *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <read-only> element."));
        return false;
    }

    // <ID>
    if (!m_id.empty())
        if ((dwResult = eapxml::put_element_value(pDoc, pConfigRoot, bstr(L"ID"), bstrNamespace, bstr(m_id))) != ERROR_SUCCESS) {
            *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <ID> element."));
            return false;
        }

    // <ProviderInfo>
    com_obj<IXMLDOMElement> pXmlElProviderInfo;
    if ((dwResult = eapxml::create_element(pDoc, pConfigRoot, bstr(L"eap-metadata:ProviderInfo"), bstr(L"ProviderInfo"), bstrNamespace, &pXmlElProviderInfo)) != ERROR_SUCCESS) {
        *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <ProviderInfo> element."));
        return false;
    }

    // <ProviderInfo>/<DisplayName>
    if (!m_name.empty())
        if ((dwResult = eapxml::put_element_value(pDoc, pXmlElProviderInfo, bstr(L"DisplayName"), bstrNamespace, bstr(m_name))) != ERROR_SUCCESS) {
            *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <DisplayName> element."));
            return false;
        }

    // <ProviderInfo>/<Helpdesk>
    com_obj<IXMLDOMElement> pXmlElHelpdesk;
    if ((dwResult = eapxml::create_element(pDoc, pXmlElProviderInfo, bstr(L"eap-metadata:Helpdesk"), bstr(L"Helpdesk"), bstrNamespace, &pXmlElHelpdesk)) != ERROR_SUCCESS) {
        *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <Helpdesk> element."));
        return false;
    }

    // <ProviderInfo>/<Helpdesk>/<EmailAddress>
    if (!m_help_email.empty())
        if ((dwResult = eapxml::put_element_value(pDoc, pXmlElHelpdesk, bstr(L"EmailAddress"), bstrNamespace, bstr(m_help_email))) != ERROR_SUCCESS) {
            *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <EmailAddress> element."));
            return false;
        }

    // <ProviderInfo>/<Helpdesk>/<WebAddress>
    if (!m_help_web.empty())
        if ((dwResult = eapxml::put_element_value(pDoc, pXmlElHelpdesk, bstr(L"WebAddress"), bstrNamespace, bstr(m_help_web))) != ERROR_SUCCESS) {
            *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <WebAddress> element."));
            return false;
        }

    // <ProviderInfo>/<Helpdesk>/<Phone>
    if (!m_help_phone.empty())
        if ((dwResult = eapxml::put_element_value(pDoc, pXmlElHelpdesk, bstr(L"Phone"), bstrNamespace, bstr(m_help_phone))) != ERROR_SUCCESS) {
            *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <Phone> element."));
            return false;
        }

    // <ProviderInfo>/<CredentialPrompt>
    if (!m_lbl_alt_credential.empty())
        if ((dwResult = eapxml::put_element_value(pDoc, pXmlElProviderInfo, bstr(L"CredentialPrompt"), bstrNamespace, bstr(m_lbl_alt_credential))) != ERROR_SUCCESS) {
            *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <CredentialPrompt> element."));
            return false;
        }

    // <ProviderInfo>/<UserNameLabel>
    if (!m_lbl_alt_identity.empty())
        if ((dwResult = eapxml::put_element_value(pDoc, pXmlElProviderInfo, bstr(L"UserNameLabel"), bstrNamespace, bstr(m_lbl_alt_identity))) != ERROR_SUCCESS) {
            *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <UserNameLabel> element."));
            return false;
        }

    // <ProviderInfo>/<PasswordLabel>
    if (!m_lbl_alt_password.empty())
        if ((dwResult = eapxml::put_element_value(pDoc, pXmlElProviderInfo, bstr(L"PasswordLabel"), bstrNamespace, bstr(m_lbl_alt_password))) != ERROR_SUCCESS) {
            *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <PasswordLabel> element."));
            return false;
        }

    // <AuthenticationMethods>
    com_obj<IXMLDOMElement> pXmlElAuthenticationMethods;
    if ((dwResult = eapxml::create_element(pDoc, pConfigRoot, bstr(L"eap-metadata:AuthenticationMethods"), bstr(L"AuthenticationMethods"), bstrNamespace, &pXmlElAuthenticationMethods)) != ERROR_SUCCESS) {
        *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <AuthenticationMethods> element."));
        return false;
    }

    for (list<unique_ptr<config_method> >::const_iterator method = m_methods.cbegin(), method_end = m_methods.cend(); method != method_end; ++method) {
        // <AuthenticationMethod>
        com_obj<IXMLDOMElement> pXmlElAuthenticationMethod;
        if ((dwResult = eapxml::create_element(pDoc, bstr(L"AuthenticationMethod"), bstrNamespace, &pXmlElAuthenticationMethod))) {
            *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <AuthenticationMethod> element."));
            return false;
        }

        // <AuthenticationMethod>/...
        if (!method->get()->save(pDoc, pXmlElAuthenticationMethod, ppEapError))
            return false;

        if (FAILED(hr = pXmlElAuthenticationMethods->appendChild(pXmlElAuthenticationMethod, NULL))) {
            *ppEapError = m_module.make_error(HRESULT_CODE(hr), _T(__FUNCTION__) _T(" Error appending <AuthenticationMethod> element."));
            return false;
        }
    }

    return true;
}


bool eap::config_provider::load(_In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError)
{
    assert(pConfigRoot);
    assert(ppEapError);
    DWORD dwResult;
    wstring xpath(eapxml::get_xpath(pConfigRoot));

    if (!config::load(pConfigRoot, ppEapError))
        return false;

    // <read-only>
    if ((dwResult = eapxml::get_element_value(pConfigRoot, bstr(L"eap-metadata:read-only"), &m_read_only)) != ERROR_SUCCESS)
        m_read_only = true;
    m_module.log_config((xpath + L"/read-only").c_str(), m_read_only);

    // <ID>
    m_id.clear();
    eapxml::get_element_value(pConfigRoot, bstr(L"eap-metadata:ID"), m_id);
    m_module.log_config((xpath + L"/ID").c_str(), m_id.c_str());

    // <ProviderInfo>
    m_name.clear();
    m_help_email.clear();
    m_help_web.clear();
    m_help_phone.clear();
    m_lbl_alt_credential.clear();
    m_lbl_alt_identity.clear();
    m_lbl_alt_password.clear();
    com_obj<IXMLDOMElement> pXmlElProviderInfo;
    if (eapxml::select_element(pConfigRoot, bstr(L"eap-metadata:ProviderInfo"), &pXmlElProviderInfo) == ERROR_SUCCESS) {
        wstring lang;
        LoadString(m_module.m_instance, 2, lang);
        wstring xpathProviderInfo(xpath + L"/ProviderInfo");

        // <DisplayName>
        eapxml::get_element_localized(pXmlElProviderInfo, bstr(L"eap-metadata:DisplayName"), lang.c_str(), m_name);
        m_module.log_config((xpathProviderInfo + L"/DisplayName").c_str(), m_name.c_str());

        com_obj<IXMLDOMElement> pXmlElHelpdesk;
        if (eapxml::select_element(pXmlElProviderInfo, bstr(L"eap-metadata:Helpdesk"), &pXmlElHelpdesk) == ERROR_SUCCESS) {
            wstring xpathHelpdesk(xpathProviderInfo + L"/Helpdesk");

            // <Helpdesk>/<EmailAddress>
            eapxml::get_element_localized(pXmlElHelpdesk, bstr(L"eap-metadata:EmailAddress"), lang.c_str(), m_help_email);
            m_module.log_config((xpathHelpdesk + L"/EmailAddress").c_str(), m_help_email.c_str());

            // <Helpdesk>/<WebAddress>
            eapxml::get_element_localized(pXmlElHelpdesk, bstr(L"eap-metadata:WebAddress"), lang.c_str(), m_help_web);
            m_module.log_config((xpathHelpdesk + L"/WebAddress").c_str(), m_help_web.c_str());

            // <Helpdesk>/<Phone>
            eapxml::get_element_localized(pXmlElHelpdesk, bstr(L"eap-metadata:Phone"), lang.c_str(), m_help_phone);
            m_module.log_config((xpathHelpdesk + L"/Phone").c_str(), m_help_phone.c_str());
        }

        // <CredentialPrompt>
        eapxml::get_element_localized(pXmlElProviderInfo, bstr(L"eap-metadata:CredentialPrompt"), lang.c_str(), m_lbl_alt_credential);
        m_module.log_config((xpathProviderInfo + L"/CredentialPrompt").c_str(), m_lbl_alt_credential.c_str());

        // <UserNameLabel>
        eapxml::get_element_localized(pXmlElProviderInfo, bstr(L"eap-metadata:UserNameLabel"), lang.c_str(), m_lbl_alt_identity);
        m_module.log_config((xpathProviderInfo + L"/UserNameLabel").c_str(), m_lbl_alt_identity.c_str());

        // <PasswordLabel>
        eapxml::get_element_localized(pXmlElProviderInfo, bstr(L"eap-metadata:PasswordLabel"), lang.c_str(), m_lbl_alt_password);
        m_module.log_config((xpathProviderInfo + L"/PasswordLabel").c_str(), m_lbl_alt_password.c_str());
    }

    // Iterate authentication methods (<AuthenticationMethods>).
    m_methods.clear();
    com_obj<IXMLDOMNodeList> pXmlListMethods;
    if ((dwResult = eapxml::select_nodes(pConfigRoot, bstr(L"eap-metadata:AuthenticationMethods/eap-metadata:AuthenticationMethod"), &pXmlListMethods)) != ERROR_SUCCESS) {
        *ppEapError = m_module.make_error(ERROR_NOT_FOUND, _T(__FUNCTION__) _T(" Error selecting <AuthenticationMethods>/<AuthenticationMethod> elements."), _T("Please make sure profile XML is a valid ") _T(PRODUCT_NAME_STR) _T(" profile XML document."));
        return false;
    }
    long lCount = 0;
    pXmlListMethods->get_length(&lCount);
    for (long i = 0; i < lCount; i++) {
        com_obj<IXMLDOMNode> pXmlElMethod;
        pXmlListMethods->get_item(i, &pXmlElMethod);

        unique_ptr<config_method> cfg(m_module.make_config_method());

        // Check EAP method type (<EAPMethod>).
        DWORD dwMethodID;
        if (eapxml::get_element_value(pXmlElMethod, bstr(L"eap-metadata:EAPMethod"), &dwMethodID) == ERROR_SUCCESS) {
            if ((type_t)dwMethodID != cfg->get_method_id()) {
                // Wrong type.
                continue;
            }
        }

        // Load configuration.
        if (!cfg->load(pXmlElMethod, ppEapError))
            return false;

        // Add configuration to the list.
        m_methods.push_back(move(cfg));
    }

    return true;
}


void eap::config_provider::pack(_Inout_ unsigned char *&cursor) const
{
    config::pack(cursor);
    eapserial::pack(cursor, m_read_only         );
    eapserial::pack(cursor, m_id                );
    eapserial::pack(cursor, m_name              );
    eapserial::pack(cursor, m_help_email        );
    eapserial::pack(cursor, m_help_web          );
    eapserial::pack(cursor, m_help_phone        );
    eapserial::pack(cursor, m_lbl_alt_credential);
    eapserial::pack(cursor, m_lbl_alt_identity  );
    eapserial::pack(cursor, m_lbl_alt_password  );
    eapserial::pack(cursor, m_methods           );
}


size_t eap::config_provider::get_pk_size() const
{
    return
        config::get_pk_size()                   +
        eapserial::get_pk_size(m_read_only         ) +
        eapserial::get_pk_size(m_id                ) +
        eapserial::get_pk_size(m_name              ) +
        eapserial::get_pk_size(m_help_email        ) +
        eapserial::get_pk_size(m_help_web          ) +
        eapserial::get_pk_size(m_help_phone        ) +
        eapserial::get_pk_size(m_lbl_alt_credential) +
        eapserial::get_pk_size(m_lbl_alt_identity  ) +
        eapserial::get_pk_size(m_lbl_alt_password  ) +
        eapserial::get_pk_size(m_methods           );
}


void eap::config_provider::unpack(_Inout_ const unsigned char *&cursor)
{
    config::unpack(cursor);
    eapserial::unpack(cursor, m_read_only         );
    eapserial::unpack(cursor, m_id                );
    eapserial::unpack(cursor, m_name              );
    eapserial::unpack(cursor, m_help_email        );
    eapserial::unpack(cursor, m_help_web          );
    eapserial::unpack(cursor, m_help_phone        );
    eapserial::unpack(cursor, m_lbl_alt_credential);
    eapserial::unpack(cursor, m_lbl_alt_identity  );
    eapserial::unpack(cursor, m_lbl_alt_password  );

    list<config_method>::size_type count;
    bool is_nonnull;
    eapserial::unpack(cursor, count);
    m_methods.clear();
    for (list<config_method>::size_type i = 0; i < count; i++) {
        eapserial::unpack(cursor, is_nonnull);
        if (is_nonnull) {
            unique_ptr<config_method> el(m_module.make_config_method());
            el->unpack(cursor);
            m_methods.push_back(move(el));
        } else
            m_methods.push_back(nullptr);
    }
}


//////////////////////////////////////////////////////////////////////
// eap::config_providers
//////////////////////////////////////////////////////////////////////

eap::config_providers::config_providers(_In_ module &mod) : config(mod)
{
}


eap::config_providers::config_providers(_In_ const config_providers &other) :
    m_providers(other.m_providers),
    config(other)
{
}


eap::config_providers::config_providers(_Inout_ config_providers &&other) :
    m_providers(move(other.m_providers)),
    config(move(other))
{
}


eap::config_providers& eap::config_providers::operator=(_In_ const config_providers &other)
{
    if (this != &other) {
        (config&)*this = other;
        m_providers = other.m_providers;
    }

    return *this;
}


eap::config_providers& eap::config_providers::operator=(_Inout_ config_providers &&other)
{
    if (this != &other) {
        (config&&)*this = move(other);
        m_providers     = move(other.m_providers);
    }

    return *this;
}


eap::config* eap::config_providers::clone() const
{
    return new config_providers(*this);
}


bool eap::config_providers::save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError) const
{
    if (!config::save(pDoc, pConfigRoot, ppEapError))
        return false;

    const bstr bstrNamespace(L"urn:ietf:params:xml:ns:yang:ietf-eap-metadata");
    DWORD dwResult;
    HRESULT hr;

    // Select <EAPIdentityProviderList> node.
    com_obj<IXMLDOMNode> pXmlElIdentityProviderList;
    if ((dwResult = eapxml::select_node(pConfigRoot, bstr(L"eap-metadata:EAPIdentityProviderList"), &pXmlElIdentityProviderList)) != ERROR_SUCCESS) {
        *ppEapError = m_module.make_error(ERROR_NOT_FOUND, _T(__FUNCTION__) _T(" Error selecting <EAPIdentityProviderList> element."), _T("Please make sure profile XML is a valid ") _T(PRODUCT_NAME_STR) _T(" profile XML document."));
        return false;
    }

    for (list<config_provider>::const_iterator provider = m_providers.cbegin(), provider_end = m_providers.cend(); provider != provider_end; ++provider) {
        // <EAPIdentityProvider>
        com_obj<IXMLDOMElement> pXmlElIdentityProvider;
        if ((dwResult = eapxml::create_element(pDoc, bstr(L"EAPIdentityProvider"), bstrNamespace, &pXmlElIdentityProvider))) {
            *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <EAPIdentityProvider> element."));
            return false;
        }

        // <EAPIdentityProvider>/...
        if (!provider->save(pDoc, pXmlElIdentityProvider, ppEapError))
            return false;

        if (FAILED(hr = pXmlElIdentityProviderList->appendChild(pXmlElIdentityProvider, NULL))) {
            *ppEapError = m_module.make_error(HRESULT_CODE(hr), _T(__FUNCTION__) _T(" Error appending <EAPIdentityProvider> element."));
            return false;
        }
    }

    return true;
}


bool eap::config_providers::load(_In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError)
{
    assert(pConfigRoot);
    assert(ppEapError);
    DWORD dwResult;

    if (!config::load(pConfigRoot, ppEapError))
        return false;

    // Iterate authentication providers (<EAPIdentityProvider>).
    com_obj<IXMLDOMNodeList> pXmlListProviders;
    if ((dwResult = eapxml::select_nodes(pConfigRoot, bstr(L"eap-metadata:EAPIdentityProviderList/eap-metadata:EAPIdentityProvider"), &pXmlListProviders)) != ERROR_SUCCESS) {
        *ppEapError = m_module.make_error(ERROR_NOT_FOUND, _T(__FUNCTION__) _T(" Error selecting <EAPIdentityProviderList><EAPIdentityProvider> elements."), _T("Please make sure profile XML is a valid ") _T(PRODUCT_NAME_STR) _T(" profile XML document."));
        return false;
    }
    long lCount = 0;
    pXmlListProviders->get_length(&lCount);
    for (long i = 0; i < lCount; i++) {
        com_obj<IXMLDOMNode> pXmlElProvider;
        pXmlListProviders->get_item(i, &pXmlElProvider);

        config_provider prov(m_module);

        // Load provider.
        if (!prov.load(pXmlElProvider, ppEapError))
            return false;

        // Add provider to the list.
        m_providers.push_back(move(prov));
    }

    return true;
}


void eap::config_providers::pack(_Inout_ unsigned char *&cursor) const
{
    config::pack(cursor);
    eapserial::pack(cursor, m_providers);
}


size_t eap::config_providers::get_pk_size() const
{
    return
        config::get_pk_size() +
        eapserial::get_pk_size(m_providers);
}


void eap::config_providers::unpack(_Inout_ const unsigned char *&cursor)
{
    config::unpack(cursor);

    list<config_provider>::size_type count;
    eapserial::unpack(cursor, count);
    m_providers.clear();
    for (list<config_provider>::size_type i = 0; i < count; i++) {
        config_provider el(m_module);
        el.unpack(cursor);
        m_providers.push_back(move(el));
    }
}
