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
    if (this != &other)
        assert(&m_module == &other.m_module);

    return *this;
}


eap::config& eap::config::operator=(_Inout_ config &&other)
{
    if (this != &other)
        assert(&m_module == &other.m_module);

    return *this;
}


void eap::config::save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot) const
{
    UNREFERENCED_PARAMETER(pDoc);
    UNREFERENCED_PARAMETER(pConfigRoot);
}


void eap::config::load(_In_ IXMLDOMNode *pConfigRoot)
{
    UNREFERENCED_PARAMETER(pConfigRoot);
}


void eap::config::operator<<(_Inout_ cursor_out &cursor) const
{
    UNREFERENCED_PARAMETER(cursor);
}


size_t eap::config::get_pk_size() const
{
    return 0;
}


void eap::config::operator>>(_Inout_ cursor_in &cursor)
{
    UNREFERENCED_PARAMETER(cursor);
}


//////////////////////////////////////////////////////////////////////
// eap::config_method
//////////////////////////////////////////////////////////////////////

eap::config_method::config_method(_In_ module &mod) : config(mod)
{
}


eap::config_method::config_method(_In_ const config_method &other) : config(other)
{
}


eap::config_method::config_method(_Inout_ config_method &&other) : config(std::move(other))
{
}


eap::config_method& eap::config_method::operator=(_In_ const config_method &other)
{
    if (this != &other)
        (config&)*this = other;

    return *this;
}


eap::config_method& eap::config_method::operator=(_Inout_ config_method &&other)
{
    if (this != &other)
        (config&&)*this = std::move(other);

    return *this;
}


//////////////////////////////////////////////////////////////////////
// eap::config_method_with_cred
//////////////////////////////////////////////////////////////////////

eap::config_method_with_cred::config_method_with_cred(_In_ module &mod) :
    m_allow_save(true),
    m_use_preshared(false),
    config_method(mod)
{
}


eap::config_method_with_cred::config_method_with_cred(_In_ const config_method_with_cred &other) :
    m_allow_save(other.m_allow_save),
    m_use_preshared(other.m_use_preshared),
    m_preshared(other.m_preshared ? (credentials*)other.m_preshared->clone() : nullptr),
    config_method(other)
{
}


eap::config_method_with_cred::config_method_with_cred(_Inout_ config_method_with_cred &&other) :
    m_allow_save(std::move(other.m_allow_save)),
    m_use_preshared(std::move(other.m_use_preshared)),
    m_preshared(std::move(other.m_preshared)),
    config_method(std::move(other))
{
}


eap::config_method_with_cred& eap::config_method_with_cred::operator=(_In_ const config_method_with_cred &other)
{
    if (this != &other) {
        (config_method&)*this = other;
        m_allow_save          = other.m_allow_save;
        m_use_preshared       = other.m_use_preshared;
        m_preshared.reset(other.m_preshared ? (credentials*)other.m_preshared->clone() : nullptr);
    }

    return *this;
}


eap::config_method_with_cred& eap::config_method_with_cred::operator=(_Inout_ config_method_with_cred &&other)
{
    if (this != &other) {
        (config_method&)*this = std::move(other                );
        m_allow_save          = std::move(other.m_allow_save   );
        m_use_preshared       = std::move(other.m_use_preshared);
        m_preshared           = std::move(other.m_preshared    );
    }

    return *this;
}


void eap::config_method_with_cred::save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot) const
{
    assert(pDoc);
    assert(pConfigRoot);

    const winstd::bstr bstrNamespace(L"urn:ietf:params:xml:ns:yang:ietf-eap-metadata");
    DWORD dwResult;

    // <ClientSideCredential>
    winstd::com_obj<IXMLDOMElement> pXmlElClientSideCredential;
    if ((dwResult = eapxml::create_element(pDoc, pConfigRoot, winstd::bstr(L"eap-metadata:ClientSideCredential"), winstd::bstr(L"ClientSideCredential"), bstrNamespace, &pXmlElClientSideCredential)) != ERROR_SUCCESS)
        throw win_runtime_error(dwResult, _T(__FUNCTION__) _T(" Error creating <ClientSideCredential> element."));

    // <ClientSideCredential>/<allow-save>
    if ((dwResult = eapxml::put_element_value(pDoc, pXmlElClientSideCredential, winstd::bstr(L"allow-save"), bstrNamespace, m_allow_save)) != ERROR_SUCCESS)
        throw win_runtime_error(dwResult, _T(__FUNCTION__) _T(" Error creating <allow-save> element."));

    if (m_use_preshared)
        m_preshared->save(pDoc, pXmlElClientSideCredential);
}


void eap::config_method_with_cred::load(_In_ IXMLDOMNode *pConfigRoot)
{
    assert(pConfigRoot);

    m_allow_save    = true;
    m_use_preshared = false;
    m_preshared->clear();

    // <ClientSideCredential>
    winstd::com_obj<IXMLDOMElement> pXmlElClientSideCredential;
    if (eapxml::select_element(pConfigRoot, winstd::bstr(L"eap-metadata:ClientSideCredential"), &pXmlElClientSideCredential) == ERROR_SUCCESS) {
        std::wstring xpath(eapxml::get_xpath(pXmlElClientSideCredential));

        // <allow-save>
        eapxml::get_element_value(pXmlElClientSideCredential, winstd::bstr(L"eap-metadata:allow-save"), &m_allow_save);
        m_module.log_config((xpath + L"/allow-save").c_str(), m_allow_save);

        try {
            m_preshared->load(pXmlElClientSideCredential);
            m_use_preshared = true;
        } catch (...) {
            // This is not really an error - merely an indication pre-shared credentials are unavailable.
        }
    }
}


void eap::config_method_with_cred::operator<<(_Inout_ cursor_out &cursor) const
{
    config_method::operator<<(cursor);
    cursor << m_allow_save;
    cursor << m_use_preshared;
    cursor << *m_preshared;
}


size_t eap::config_method_with_cred::get_pk_size() const
{
    return
        config_method::get_pk_size() +
        pksizeof(m_allow_save   ) +
        pksizeof(m_use_preshared) +
        pksizeof(*m_preshared   );
}


void eap::config_method_with_cred::operator>>(_Inout_ cursor_in &cursor)
{
    config_method::operator>>(cursor);
    cursor >> m_allow_save;
    cursor >> m_use_preshared;
    cursor >> *m_preshared;
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
        m_methods.push_back(std::move(unique_ptr<config_method>(*method ? (config_method*)method->get()->clone() : nullptr)));
}


eap::config_provider::config_provider(_Inout_ config_provider &&other) :
    m_read_only(std::move(other.m_read_only)),
    m_id(std::move(other.m_id)),
    m_name(std::move(other.m_name)),
    m_help_email(std::move(other.m_help_email)),
    m_help_web(std::move(other.m_help_web)),
    m_help_phone(std::move(other.m_help_phone)),
    m_lbl_alt_credential(std::move(other.m_lbl_alt_credential)),
    m_lbl_alt_identity(std::move(other.m_lbl_alt_identity)),
    m_lbl_alt_password(std::move(other.m_lbl_alt_password)),
    m_methods(std::move(other.m_methods)),
    config(std::move(other))
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
            m_methods.push_back(std::move(unique_ptr<config_method>(*method ? (config_method*)method->get()->clone() : nullptr)));
    }

    return *this;
}


eap::config_provider& eap::config_provider::operator=(_Inout_ config_provider &&other)
{
    if (this != &other) {
        (config&&)*this      = std::move(other);
        m_read_only          = std::move(m_read_only);
        m_id                 = std::move(other.m_id);
        m_name               = std::move(other.m_name);
        m_help_email         = std::move(other.m_help_email);
        m_help_web           = std::move(other.m_help_web);
        m_help_phone         = std::move(other.m_help_phone);
        m_lbl_alt_credential = std::move(other.m_lbl_alt_credential);
        m_lbl_alt_identity   = std::move(other.m_lbl_alt_identity);
        m_lbl_alt_password   = std::move(other.m_lbl_alt_password);
        m_methods            = std::move(other.m_methods);
    }

    return *this;
}


eap::config* eap::config_provider::clone() const
{
    return new config_provider(*this);
}


void eap::config_provider::save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot) const
{
    config::save(pDoc, pConfigRoot);

    const bstr bstrNamespace(L"urn:ietf:params:xml:ns:yang:ietf-eap-metadata");
    DWORD dwResult;
    HRESULT hr;

    // <read-only>
    if ((dwResult = eapxml::put_element_value(pDoc, pConfigRoot, bstr(L"read-only"), bstrNamespace, m_read_only)) != ERROR_SUCCESS)
        throw win_runtime_error(dwResult, _T(__FUNCTION__) _T(" Error creating <read-only> element."));

    // <ID>
    if (!m_id.empty())
        if ((dwResult = eapxml::put_element_value(pDoc, pConfigRoot, bstr(L"ID"), bstrNamespace, bstr(m_id))) != ERROR_SUCCESS)
            throw win_runtime_error(dwResult, _T(__FUNCTION__) _T(" Error creating <ID> element."));

    // <ProviderInfo>
    com_obj<IXMLDOMElement> pXmlElProviderInfo;
    if ((dwResult = eapxml::create_element(pDoc, pConfigRoot, bstr(L"eap-metadata:ProviderInfo"), bstr(L"ProviderInfo"), bstrNamespace, &pXmlElProviderInfo)) != ERROR_SUCCESS)
        throw win_runtime_error(dwResult, _T(__FUNCTION__) _T(" Error creating <ProviderInfo> element."));

    // <ProviderInfo>/<DisplayName>
    if (!m_name.empty())
        if ((dwResult = eapxml::put_element_value(pDoc, pXmlElProviderInfo, bstr(L"DisplayName"), bstrNamespace, bstr(m_name))) != ERROR_SUCCESS)
            throw win_runtime_error(dwResult, _T(__FUNCTION__) _T(" Error creating <DisplayName> element."));

    // <ProviderInfo>/<Helpdesk>
    com_obj<IXMLDOMElement> pXmlElHelpdesk;
    if ((dwResult = eapxml::create_element(pDoc, pXmlElProviderInfo, bstr(L"eap-metadata:Helpdesk"), bstr(L"Helpdesk"), bstrNamespace, &pXmlElHelpdesk)) != ERROR_SUCCESS)
        throw win_runtime_error(dwResult, _T(__FUNCTION__) _T(" Error creating <Helpdesk> element."));

    // <ProviderInfo>/<Helpdesk>/<EmailAddress>
    if (!m_help_email.empty())
        if ((dwResult = eapxml::put_element_value(pDoc, pXmlElHelpdesk, bstr(L"EmailAddress"), bstrNamespace, bstr(m_help_email))) != ERROR_SUCCESS)
            throw win_runtime_error(dwResult, _T(__FUNCTION__) _T(" Error creating <EmailAddress> element."));

    // <ProviderInfo>/<Helpdesk>/<WebAddress>
    if (!m_help_web.empty())
        if ((dwResult = eapxml::put_element_value(pDoc, pXmlElHelpdesk, bstr(L"WebAddress"), bstrNamespace, bstr(m_help_web))) != ERROR_SUCCESS)
            throw win_runtime_error(dwResult, _T(__FUNCTION__) _T(" Error creating <WebAddress> element."));

    // <ProviderInfo>/<Helpdesk>/<Phone>
    if (!m_help_phone.empty())
        if ((dwResult = eapxml::put_element_value(pDoc, pXmlElHelpdesk, bstr(L"Phone"), bstrNamespace, bstr(m_help_phone))) != ERROR_SUCCESS)
            throw win_runtime_error(dwResult, _T(__FUNCTION__) _T(" Error creating <Phone> element."));

    // <ProviderInfo>/<CredentialPrompt>
    if (!m_lbl_alt_credential.empty())
        if ((dwResult = eapxml::put_element_value(pDoc, pXmlElProviderInfo, bstr(L"CredentialPrompt"), bstrNamespace, bstr(m_lbl_alt_credential))) != ERROR_SUCCESS)
            throw win_runtime_error(dwResult, _T(__FUNCTION__) _T(" Error creating <CredentialPrompt> element."));

    // <ProviderInfo>/<UserNameLabel>
    if (!m_lbl_alt_identity.empty())
        if ((dwResult = eapxml::put_element_value(pDoc, pXmlElProviderInfo, bstr(L"UserNameLabel"), bstrNamespace, bstr(m_lbl_alt_identity))) != ERROR_SUCCESS)
            throw win_runtime_error(dwResult, _T(__FUNCTION__) _T(" Error creating <UserNameLabel> element."));

    // <ProviderInfo>/<PasswordLabel>
    if (!m_lbl_alt_password.empty())
        if ((dwResult = eapxml::put_element_value(pDoc, pXmlElProviderInfo, bstr(L"PasswordLabel"), bstrNamespace, bstr(m_lbl_alt_password))) != ERROR_SUCCESS)
            throw win_runtime_error(dwResult, _T(__FUNCTION__) _T(" Error creating <PasswordLabel> element."));

    // <AuthenticationMethods>
    com_obj<IXMLDOMElement> pXmlElAuthenticationMethods;
    if ((dwResult = eapxml::create_element(pDoc, pConfigRoot, bstr(L"eap-metadata:AuthenticationMethods"), bstr(L"AuthenticationMethods"), bstrNamespace, &pXmlElAuthenticationMethods)) != ERROR_SUCCESS)
        throw win_runtime_error(dwResult, _T(__FUNCTION__) _T(" Error creating <AuthenticationMethods> element."));

    for (list<unique_ptr<config_method> >::const_iterator method = m_methods.cbegin(), method_end = m_methods.cend(); method != method_end; ++method) {
        // <AuthenticationMethod>
        com_obj<IXMLDOMElement> pXmlElAuthenticationMethod;
        if ((dwResult = eapxml::create_element(pDoc, bstr(L"AuthenticationMethod"), bstrNamespace, &pXmlElAuthenticationMethod)))
            throw win_runtime_error(dwResult, _T(__FUNCTION__) _T(" Error creating <AuthenticationMethod> element."));

        // <AuthenticationMethod>/...
        method->get()->save(pDoc, pXmlElAuthenticationMethod);

        if (FAILED(hr = pXmlElAuthenticationMethods->appendChild(pXmlElAuthenticationMethod, NULL)))
            throw win_runtime_error(HRESULT_CODE(hr), _T(__FUNCTION__) _T(" Error appending <AuthenticationMethod> element."));
    }
}


void eap::config_provider::load(_In_ IXMLDOMNode *pConfigRoot)
{
    assert(pConfigRoot);
    DWORD dwResult;
    wstring xpath(eapxml::get_xpath(pConfigRoot));

    config::load(pConfigRoot);

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
    if ((dwResult = eapxml::select_nodes(pConfigRoot, bstr(L"eap-metadata:AuthenticationMethods/eap-metadata:AuthenticationMethod"), &pXmlListMethods)) != ERROR_SUCCESS)
        throw invalid_argument(__FUNCTION__ " Error selecting <AuthenticationMethods>/<AuthenticationMethod> elements.");
    long lCount = 0;
    pXmlListMethods->get_length(&lCount);
    for (long i = 0; i < lCount; i++) {
        com_obj<IXMLDOMNode> pXmlElMethod;
        pXmlListMethods->get_item(i, &pXmlElMethod);

        unique_ptr<config_method> cfg(m_module.make_config_method());

        // Check EAP method type (<EAPMethod>).
        DWORD dwMethodID;
        if (eapxml::get_element_value(pXmlElMethod, bstr(L"eap-metadata:EAPMethod"), &dwMethodID) == ERROR_SUCCESS) {
            if ((eap_type_t)dwMethodID != cfg->get_method_id()) {
                // Wrong type.
                continue;
            }
        }

        // Load configuration.
        cfg->load(pXmlElMethod);

        // Add configuration to the list.
        m_methods.push_back(std::move(cfg));
    }
}


void eap::config_provider::operator<<(_Inout_ cursor_out &cursor) const
{
    config::operator<<(cursor);
    cursor << m_read_only         ;
    cursor << m_id                ;
    cursor << m_name              ;
    cursor << m_help_email        ;
    cursor << m_help_web          ;
    cursor << m_help_phone        ;
    cursor << m_lbl_alt_credential;
    cursor << m_lbl_alt_identity  ;
    cursor << m_lbl_alt_password  ;
    cursor << m_methods           ;
}


size_t eap::config_provider::get_pk_size() const
{
    return
        config::get_pk_size()          +
        pksizeof(m_read_only         ) +
        pksizeof(m_id                ) +
        pksizeof(m_name              ) +
        pksizeof(m_help_email        ) +
        pksizeof(m_help_web          ) +
        pksizeof(m_help_phone        ) +
        pksizeof(m_lbl_alt_credential) +
        pksizeof(m_lbl_alt_identity  ) +
        pksizeof(m_lbl_alt_password  ) +
        pksizeof(m_methods           );
}


void eap::config_provider::operator>>(_Inout_ cursor_in &cursor)
{
    config::operator>>(cursor);
    cursor >> m_read_only         ;
    cursor >> m_id                ;
    cursor >> m_name              ;
    cursor >> m_help_email        ;
    cursor >> m_help_web          ;
    cursor >> m_help_phone        ;
    cursor >> m_lbl_alt_credential;
    cursor >> m_lbl_alt_identity  ;
    cursor >> m_lbl_alt_password  ;

    list<config_method>::size_type count;
    bool is_nonnull;
    cursor >> count;
    m_methods.clear();
    for (list<config_method>::size_type i = 0; i < count; i++) {
        cursor >> is_nonnull;
        if (is_nonnull) {
            unique_ptr<config_method> el(m_module.make_config_method());
            cursor >> *el;
            m_methods.push_back(std::move(el));
        } else
            m_methods.push_back(nullptr);
    }
}


//////////////////////////////////////////////////////////////////////
// eap::config_provider_list
//////////////////////////////////////////////////////////////////////

eap::config_provider_list::config_provider_list(_In_ module &mod) : config(mod)
{
}


eap::config_provider_list::config_provider_list(_In_ const config_provider_list &other) :
    m_providers(other.m_providers),
    config(other)
{
}


eap::config_provider_list::config_provider_list(_Inout_ config_provider_list &&other) :
    m_providers(std::move(other.m_providers)),
    config(std::move(other))
{
}


eap::config_provider_list& eap::config_provider_list::operator=(_In_ const config_provider_list &other)
{
    if (this != &other) {
        (config&)*this = other;
        m_providers = other.m_providers;
    }

    return *this;
}


eap::config_provider_list& eap::config_provider_list::operator=(_Inout_ config_provider_list &&other)
{
    if (this != &other) {
        (config&&)*this = std::move(other);
        m_providers     = std::move(other.m_providers);
    }

    return *this;
}


eap::config* eap::config_provider_list::clone() const
{
    return new config_provider_list(*this);
}


void eap::config_provider_list::save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot) const
{
    config::save(pDoc, pConfigRoot);

    const bstr bstrNamespace(L"urn:ietf:params:xml:ns:yang:ietf-eap-metadata");
    DWORD dwResult;
    HRESULT hr;

    // Select <EAPIdentityProviderList> node.
    com_obj<IXMLDOMNode> pXmlElIdentityProviderList;
    if ((dwResult = eapxml::select_node(pConfigRoot, bstr(L"eap-metadata:EAPIdentityProviderList"), &pXmlElIdentityProviderList)) != ERROR_SUCCESS)
        throw invalid_argument(__FUNCTION__ " Error selecting <EAPIdentityProviderList> element.");

    for (list<config_provider>::const_iterator provider = m_providers.cbegin(), provider_end = m_providers.cend(); provider != provider_end; ++provider) {
        // <EAPIdentityProvider>
        com_obj<IXMLDOMElement> pXmlElIdentityProvider;
        if ((dwResult = eapxml::create_element(pDoc, bstr(L"EAPIdentityProvider"), bstrNamespace, &pXmlElIdentityProvider)))
            throw win_runtime_error(dwResult, _T(__FUNCTION__) _T(" Error creating <EAPIdentityProvider> element."));

        // <EAPIdentityProvider>/...
        provider->save(pDoc, pXmlElIdentityProvider);

        if (FAILED(hr = pXmlElIdentityProviderList->appendChild(pXmlElIdentityProvider, NULL)))
            throw win_runtime_error(HRESULT_CODE(hr), _T(__FUNCTION__) _T(" Error appending <EAPIdentityProvider> element."));
    }
}


void eap::config_provider_list::load(_In_ IXMLDOMNode *pConfigRoot)
{
    assert(pConfigRoot);
    DWORD dwResult;

    config::load(pConfigRoot);

    // Iterate authentication providers (<EAPIdentityProvider>).
    com_obj<IXMLDOMNodeList> pXmlListProviders;
    if ((dwResult = eapxml::select_nodes(pConfigRoot, bstr(L"eap-metadata:EAPIdentityProviderList/eap-metadata:EAPIdentityProvider"), &pXmlListProviders)) != ERROR_SUCCESS)
        throw invalid_argument(__FUNCTION__ " Error selecting <EAPIdentityProviderList><EAPIdentityProvider> elements.");
    long lCount = 0;
    pXmlListProviders->get_length(&lCount);
    for (long i = 0; i < lCount; i++) {
        com_obj<IXMLDOMNode> pXmlElProvider;
        pXmlListProviders->get_item(i, &pXmlElProvider);

        config_provider prov(m_module);

        // Load provider.
        prov.load(pXmlElProvider);

        // Add provider to the list.
        m_providers.push_back(std::move(prov));
    }
}


void eap::config_provider_list::operator<<(_Inout_ cursor_out &cursor) const
{
    config::operator<<(cursor);
    cursor << m_providers;
}


size_t eap::config_provider_list::get_pk_size() const
{
    return
        config::get_pk_size() +
        pksizeof(m_providers);
}


void eap::config_provider_list::operator>>(_Inout_ cursor_in &cursor)
{
    config::operator>>(cursor);

    list<config_provider>::size_type count;
    cursor >> count;
    m_providers.clear();
    for (list<config_provider>::size_type i = 0; i < count; i++) {
        config_provider el(m_module);
        cursor >> el;
        m_providers.push_back(std::move(el));
    }
}
