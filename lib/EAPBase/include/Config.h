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

#include <sal.h>

namespace eap
{
    ///
    /// Base class for configuration storage
    ///
    class config;

    ///
    /// Base class for method configuration storage
    ///
    class config_method;

    ///
    /// Single provider configuration
    ///
    template <class _Tmeth> class config_provider;

    ///
    /// List of providers configuration
    ///
    template <class _Tprov> class config_providers;
}

namespace eapserial
{
    ///
    /// Packs a configuration
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     Configuration to pack
    ///
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::config &val);

    ///
    /// Returns packed size of a configuration
    ///
    /// \param[in] val  Configuration to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    inline size_t get_pk_size(const eap::config &val);

    ///
    /// Unpacks a configuration
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     Configuration to unpack to
    ///
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::config &val);
}

#pragma once

#include "Module.h"
#include "EAPSerial.h"
#include "EAPXML.h"

#include "../../../include/Version.h"

#include <WinStd/COM.h>
#include <WinStd/Common.h>

#include <Windows.h>
#include <eaptypes.h> // Must include after <Windows.h>
#include <tchar.h>

#include <list>
#include <string>
#include <memory>


namespace eap
{
    class config
    {
    public:
        ///
        /// Constructs configuration
        ///
        /// \param[in] mod  Reference of the EAP module to use for global services
        ///
        config(_In_ module &mod);

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        config(_In_ const config &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        config(_Inout_ config &&other);

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        /// \returns Reference to this object
        ///
        config& operator=(_In_ const config &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        /// \returns Reference to this object
        ///
        config& operator=(_Inout_ config &&other);

        ///
        /// Clones this configuration
        ///
        /// \returns Pointer to cloned configuration
        ///
        virtual config* clone() const = 0;

        /// \name XML configuration management
        /// @{

        ///
        /// Save configuration to XML document
        ///
        /// \param[in]  pDoc         XML document
        /// \param[in]  pConfigRoot  Suggested root element for saving configuration
        /// \param[out] ppEapError   Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError) const;

        ///
        /// Load configuration from XML document
        ///
        /// \param[in]  pConfigRoot  Root element for loading configuration
        /// \param[out] ppEapError   Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool load(_In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError);

        /// @}

        /// \name BLOB management
        /// @{

        ///
        /// Packs a configuration
        ///
        /// \param[inout] cursor  Memory cursor
        ///
        virtual void pack(_Inout_ unsigned char *&cursor) const;

        ///
        /// Returns packed size of a configuration
        ///
        /// \returns Size of data when packed (in bytes)
        ///
        virtual size_t get_pk_size() const;

        ///
        /// Unpacks a configuration
        ///
        /// \param[inout] cursor  Memory cursor
        ///
        virtual void unpack(_Inout_ const unsigned char *&cursor);

        /// @}

    public:
        module &m_module;   ///< Reference of the EAP module
    };


    // Forward declaration, otherwise we would have to merge Credentials.h here.
    class credentials;


    class config_method : public config
    {
    public:
        ///
        /// Constructs configuration
        ///
        /// \param[in] mod  Reference of the EAP module to use for global services
        ///
        config_method(_In_ module &mod);

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        config_method(_In_ const config_method &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        config_method(_Inout_ config_method &&other);

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        /// \returns Reference to this object
        ///
        config_method& operator=(_In_ const config_method &other);

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        /// \returns Reference to this object
        ///
        config_method& operator=(_Inout_ config_method &&other);

        /// \name XML configuration management
        /// @{

        ///
        /// Save configuration to XML document
        ///
        /// \param[in]  pDoc         XML document
        /// \param[in]  pConfigRoot  Suggested root element for saving configuration
        /// \param[out] ppEapError   Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError) const;

        ///
        /// Load configuration from XML document
        ///
        /// \param[in]  pConfigRoot  Root element for loading configuration
        /// \param[out] ppEapError   Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool load(_In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError);

        /// @}

        /// \name BLOB management
        /// @{

        ///
        /// Packs a configuration
        ///
        /// \param[inout] cursor  Memory cursor
        ///
        virtual void pack(_Inout_ unsigned char *&cursor) const;

        ///
        /// Returns packed size of a configuration
        ///
        /// \returns Size of data when packed (in bytes)
        ///
        virtual size_t get_pk_size() const;

        ///
        /// Unpacks a configuration
        ///
        /// \param[inout] cursor  Memory cursor
        ///
        virtual void unpack(_Inout_ const unsigned char *&cursor);

        /// @}

        ///
        /// Makes a new set of credentials for the given method type
        ///
        virtual credentials* make_credentials() const = 0;

        ///
        /// Returns EAP method type of this configuration
        ///
        /// \returns One of `eap::type_t` constants.
        ///
        virtual type_t get_method_id() const = 0;

    public:
        bool m_allow_save;                          ///< Are credentials allowed to be saved to Windows Credential Manager?
        std::wstring m_anonymous_identity;          ///< Anonymous identity
        std::unique_ptr<credentials> m_preshared;   ///< Pre-shared credentials
    };


    template <class _Tmeth>
    class config_provider : public config
    {
    public:
        ///
        /// Constructs configuration
        ///
        /// \param[in] mod  Reference of the EAP module to use for global services
        ///
        config_provider(_In_ module &mod) :
            m_read_only(false),
            config(mod)
        {
        }

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        config_provider(_In_ const config_provider &other) :
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
            for (std::list<std::unique_ptr<config_method> >::const_iterator method = other.m_methods.cbegin(), method_end = other.m_methods.cend(); method != method_end; ++method)
                m_methods.push_back(std::move(std::unique_ptr<config_method>(*method ? (config_method*)method->get()->clone() : nullptr)));
        }

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        config_provider(_Inout_ config_provider &&other) :
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

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        /// \returns Reference to this object
        ///
        config_provider& operator=(_In_ const config_provider &other)
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
                for (std::list<std::unique_ptr<config_method> >::const_iterator method = other.m_methods.cbegin(), method_end = other.m_methods.cend(); method != method_end; ++method)
                    m_methods.push_back(std::move(std::unique_ptr<config_method>(*method ? (config_method*)method->get()->clone() : nullptr)));
            }

            return *this;
        }

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        /// \returns Reference to this object
        ///
        config_provider& operator=(_Inout_ config_provider &&other)
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

        ///
        /// Clones configuration
        ///
        /// \returns Pointer to cloned configuration
        ///
        virtual config* clone() const { return new config_provider<_Tmeth>(*this); }

        /// \name XML configuration management
        /// @{

        ///
        /// Save configuration to XML document
        ///
        /// \param[in]  pDoc         XML document
        /// \param[in]  pConfigRoot  Suggested root element for saving configuration
        /// \param[out] ppEapError   Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError) const
        {
            if (!config::save(pDoc, pConfigRoot, ppEapError))
                return false;

            const winstd::bstr bstrNamespace(L"urn:ietf:params:xml:ns:yang:ietf-eap-metadata");
            DWORD dwResult;
            HRESULT hr;

            // <read-only>
            if ((dwResult = eapxml::put_element_value(pDoc, pConfigRoot, winstd::bstr(L"read-only"), bstrNamespace, m_read_only)) != ERROR_SUCCESS) {
                *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <read-only> element."));
                return false;
            }

            // <ID>
            if (!m_id.empty())
                if ((dwResult = eapxml::put_element_value(pDoc, pConfigRoot, winstd::bstr(L"ID"), bstrNamespace, winstd::bstr(m_id))) != ERROR_SUCCESS) {
                    *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <ID> element."));
                    return false;
                }

            // <ProviderInfo>
            winstd::com_obj<IXMLDOMElement> pXmlElProviderInfo;
            if ((dwResult = eapxml::create_element(pDoc, pConfigRoot, winstd::bstr(L"eap-metadata:ProviderInfo"), winstd::bstr(L"ProviderInfo"), bstrNamespace, &pXmlElProviderInfo)) != ERROR_SUCCESS) {
                *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <ProviderInfo> element."));
                return false;
            }

            // <ProviderInfo>/<DisplayName>
            if (!m_name.empty())
                if ((dwResult = eapxml::put_element_value(pDoc, pXmlElProviderInfo, winstd::bstr(L"DisplayName"), bstrNamespace, winstd::bstr(m_name))) != ERROR_SUCCESS) {
                    *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <DisplayName> element."));
                    return false;
                }

            // <ProviderInfo>/<Helpdesk>
            winstd::com_obj<IXMLDOMElement> pXmlElHelpdesk;
            if ((dwResult = eapxml::create_element(pDoc, pXmlElProviderInfo, winstd::bstr(L"eap-metadata:Helpdesk"), winstd::bstr(L"Helpdesk"), bstrNamespace, &pXmlElHelpdesk)) != ERROR_SUCCESS) {
                *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <Helpdesk> element."));
                return false;
            }

            // <ProviderInfo>/<Helpdesk>/<EmailAddress>
            if (!m_help_email.empty())
                if ((dwResult = eapxml::put_element_value(pDoc, pXmlElHelpdesk, winstd::bstr(L"EmailAddress"), bstrNamespace, winstd::bstr(m_help_email))) != ERROR_SUCCESS) {
                    *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <EmailAddress> element."));
                    return false;
                }

            // <ProviderInfo>/<Helpdesk>/<WebAddress>
            if (!m_help_web.empty())
                if ((dwResult = eapxml::put_element_value(pDoc, pXmlElHelpdesk, winstd::bstr(L"WebAddress"), bstrNamespace, winstd::bstr(m_help_web))) != ERROR_SUCCESS) {
                    *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <WebAddress> element."));
                    return false;
                }

            // <ProviderInfo>/<Helpdesk>/<Phone>
            if (!m_help_phone.empty())
                if ((dwResult = eapxml::put_element_value(pDoc, pXmlElHelpdesk, winstd::bstr(L"Phone"), bstrNamespace, winstd::bstr(m_help_phone))) != ERROR_SUCCESS) {
                    *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <Phone> element."));
                    return false;
                }

            // <ProviderInfo>/<CredentialPrompt>
            if (!m_lbl_alt_credential.empty())
                if ((dwResult = eapxml::put_element_value(pDoc, pXmlElProviderInfo, winstd::bstr(L"CredentialPrompt"), bstrNamespace, winstd::bstr(m_lbl_alt_credential))) != ERROR_SUCCESS) {
                    *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <CredentialPrompt> element."));
                    return false;
                }

            // <ProviderInfo>/<UserNameLabel>
            if (!m_lbl_alt_identity.empty())
                if ((dwResult = eapxml::put_element_value(pDoc, pXmlElProviderInfo, winstd::bstr(L"UserNameLabel"), bstrNamespace, winstd::bstr(m_lbl_alt_identity))) != ERROR_SUCCESS) {
                    *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <UserNameLabel> element."));
                    return false;
                }

            // <ProviderInfo>/<PasswordLabel>
            if (!m_lbl_alt_password.empty())
                if ((dwResult = eapxml::put_element_value(pDoc, pXmlElProviderInfo, winstd::bstr(L"PasswordLabel"), bstrNamespace, winstd::bstr(m_lbl_alt_password))) != ERROR_SUCCESS) {
                    *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <PasswordLabel> element."));
                    return false;
                }

            // <AuthenticationMethods>
            winstd::com_obj<IXMLDOMElement> pXmlElAuthenticationMethods;
            if ((dwResult = eapxml::create_element(pDoc, pConfigRoot, winstd::bstr(L"eap-metadata:AuthenticationMethods"), winstd::bstr(L"AuthenticationMethods"), bstrNamespace, &pXmlElAuthenticationMethods)) != ERROR_SUCCESS) {
                *ppEapError = m_module.make_error(dwResult, _T(__FUNCTION__) _T(" Error creating <AuthenticationMethods> element."));
                return false;
            }

            for (std::list<std::unique_ptr<config_method> >::const_iterator method = m_methods.cbegin(), method_end = m_methods.cend(); method != method_end; ++method) {
                // <AuthenticationMethod>
                winstd::com_obj<IXMLDOMElement> pXmlElAuthenticationMethod;
                if ((dwResult = eapxml::create_element(pDoc, winstd::bstr(L"AuthenticationMethod"), bstrNamespace, &pXmlElAuthenticationMethod))) {
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


        ///
        /// Load configuration from XML document
        ///
        /// \param[in]  pConfigRoot  Root element for loading configuration
        /// \param[out] ppEapError   Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool load(_In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError)
        {
            assert(pConfigRoot);
            assert(ppEapError);
            DWORD dwResult;
            std::wstring xpath(eapxml::get_xpath(pConfigRoot));

            if (!config::load(pConfigRoot, ppEapError))
                return false;

            // <read-only>
            if ((dwResult = eapxml::get_element_value(pConfigRoot, winstd::bstr(L"eap-metadata:read-only"), &m_read_only)) != ERROR_SUCCESS)
                m_read_only = true;
            m_module.log_config((xpath + L"/read-only").c_str(), m_read_only);

            // <ID>
            m_id.clear();
            eapxml::get_element_value(pConfigRoot, winstd::bstr(L"eap-metadata:ID"), m_id);
            m_module.log_config((xpath + L"/ID").c_str(), m_id.c_str());

            // <ProviderInfo>
            m_name.clear();
            m_help_email.clear();
            m_help_web.clear();
            m_help_phone.clear();
            m_lbl_alt_credential.clear();
            m_lbl_alt_identity.clear();
            m_lbl_alt_password.clear();
            winstd::com_obj<IXMLDOMElement> pXmlElProviderInfo;
            if (eapxml::select_element(pConfigRoot, winstd::bstr(L"eap-metadata:ProviderInfo"), &pXmlElProviderInfo) == ERROR_SUCCESS) {
                std::wstring lang;
                LoadString(m_module.m_instance, 2, lang);
                std::wstring xpathProviderInfo(xpath + L"/ProviderInfo");

                // <DisplayName>
                eapxml::get_element_localized(pXmlElProviderInfo, winstd::bstr(L"eap-metadata:DisplayName"), lang.c_str(), m_name);
                m_module.log_config((xpathProviderInfo + L"/DisplayName").c_str(), m_name.c_str());

                winstd::com_obj<IXMLDOMElement> pXmlElHelpdesk;
                if (eapxml::select_element(pXmlElProviderInfo, winstd::bstr(L"eap-metadata:Helpdesk"), &pXmlElHelpdesk) == ERROR_SUCCESS) {
                    std::wstring xpathHelpdesk(xpathProviderInfo + L"/Helpdesk");

                    // <Helpdesk>/<EmailAddress>
                    eapxml::get_element_localized(pXmlElHelpdesk, winstd::bstr(L"eap-metadata:EmailAddress"), lang.c_str(), m_help_email);
                    m_module.log_config((xpathHelpdesk + L"/EmailAddress").c_str(), m_help_email.c_str());

                    // <Helpdesk>/<WebAddress>
                    eapxml::get_element_localized(pXmlElHelpdesk, winstd::bstr(L"eap-metadata:WebAddress"), lang.c_str(), m_help_web);
                    m_module.log_config((xpathHelpdesk + L"/WebAddress").c_str(), m_help_web.c_str());

                    // <Helpdesk>/<Phone>
                    eapxml::get_element_localized(pXmlElHelpdesk, winstd::bstr(L"eap-metadata:Phone"), lang.c_str(), m_help_phone);
                    m_module.log_config((xpathHelpdesk + L"/Phone").c_str(), m_help_phone.c_str());
                }

                // <CredentialPrompt>
                eapxml::get_element_localized(pXmlElProviderInfo, winstd::bstr(L"eap-metadata:CredentialPrompt"), lang.c_str(), m_lbl_alt_credential);
                m_module.log_config((xpathProviderInfo + L"/CredentialPrompt").c_str(), m_lbl_alt_credential.c_str());

                // <UserNameLabel>
                eapxml::get_element_localized(pXmlElProviderInfo, winstd::bstr(L"eap-metadata:UserNameLabel"), lang.c_str(), m_lbl_alt_identity);
                m_module.log_config((xpathProviderInfo + L"/UserNameLabel").c_str(), m_lbl_alt_identity.c_str());

                // <PasswordLabel>
                eapxml::get_element_localized(pXmlElProviderInfo, winstd::bstr(L"eap-metadata:PasswordLabel"), lang.c_str(), m_lbl_alt_password);
                m_module.log_config((xpathProviderInfo + L"/PasswordLabel").c_str(), m_lbl_alt_password.c_str());
            }

            // Iterate authentication methods (<AuthenticationMethods>).
            m_methods.clear();
            winstd::com_obj<IXMLDOMNodeList> pXmlListMethods;
            if ((dwResult = eapxml::select_nodes(pConfigRoot, winstd::bstr(L"eap-metadata:AuthenticationMethods/eap-metadata:AuthenticationMethod"), &pXmlListMethods)) != ERROR_SUCCESS) {
                *ppEapError = m_module.make_error(ERROR_NOT_FOUND, _T(__FUNCTION__) _T(" Error selecting <AuthenticationMethods>/<AuthenticationMethod> elements."), _T("Please make sure profile XML is a valid ") _T(PRODUCT_NAME_STR) _T(" profile XML document."));
                return false;
            }
            long lCount = 0;
            pXmlListMethods->get_length(&lCount);
            for (long i = 0; i < lCount; i++) {
                winstd::com_obj<IXMLDOMNode> pXmlElMethod;
                pXmlListMethods->get_item(i, &pXmlElMethod);

                std::unique_ptr<config_method> cfg(m_module.make_config_method());

                // Check EAP method type (<EAPMethod>).
                DWORD dwMethodID;
                if (eapxml::get_element_value(pXmlElMethod, winstd::bstr(L"eap-metadata:EAPMethod"), &dwMethodID) == ERROR_SUCCESS) {
                    if ((type_t)dwMethodID != cfg->get_method_id()) {
                        // Wrong type.
                        continue;
                    }
                }

                // Load configuration.
                if (!cfg->load(pXmlElMethod, ppEapError))
                    return false;

                // Add configuration to the list.
                m_methods.push_back(std::move(cfg));
            }

            return true;
        }

        /// @}

        /// \name BLOB management
        /// @{

        ///
        /// Packs a configuration
        ///
        /// \param[inout] cursor  Memory cursor
        ///
        virtual void pack(_Inout_ unsigned char *&cursor) const
        {
            eap::config::pack(cursor);
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


        ///
        /// Returns packed size of a configuration
        ///
        /// \returns Size of data when packed (in bytes)
        ///
        virtual size_t get_pk_size() const
        {
            return
                eap::config::get_pk_size()                   +
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


        ///
        /// Unpacks a configuration
        ///
        /// \param[inout] cursor  Memory cursor
        ///
        virtual void unpack(_Inout_ const unsigned char *&cursor)
        {
            eap::config::unpack(cursor);
            eapserial::unpack(cursor, m_read_only         );
            eapserial::unpack(cursor, m_id                );
            eapserial::unpack(cursor, m_name              );
            eapserial::unpack(cursor, m_help_email        );
            eapserial::unpack(cursor, m_help_web          );
            eapserial::unpack(cursor, m_help_phone        );
            eapserial::unpack(cursor, m_lbl_alt_credential);
            eapserial::unpack(cursor, m_lbl_alt_identity  );
            eapserial::unpack(cursor, m_lbl_alt_password  );

            std::list<config_method>::size_type count;
            bool is_nonnull;
            eapserial::unpack(cursor, count);
            m_methods.clear();
            for (std::list<config_method>::size_type i = 0; i < count; i++) {
                eapserial::unpack(cursor, is_nonnull);
                if (is_nonnull) {
                    std::unique_ptr<config_method> el(m_module.make_config_method());
                    el->unpack(cursor);
                    m_methods.push_back(std::move(el));
                } else
                    m_methods.push_back(nullptr);
            }
        }

        /// @}

    public:
        bool m_read_only;                                       ///< Is profile read-only
        std::wstring m_id;                                      ///< Profile ID
        winstd::tstring m_name;                                 ///< Provider name
        winstd::tstring m_help_email;                           ///< Helpdesk e-mail
        winstd::tstring m_help_web;                             ///< Helpdesk website URL
        winstd::tstring m_help_phone;                           ///< Helpdesk phone
        winstd::tstring m_lbl_alt_credential;                   ///< Alternative label for credential prompt
        winstd::tstring m_lbl_alt_identity;                     ///< Alternative label for identity prompt
        winstd::tstring m_lbl_alt_password;                     ///< Alternative label for password prompt
        std::list<std::unique_ptr<config_method> > m_methods;   ///< List of method configurations
    };


    template <class _Tprov>
    class config_providers : public config
    {
    public:
        ///
        /// Constructs configuration
        ///
        /// \param[in] mod  Reference of the EAP module to use for global services
        ///
        config_providers(_In_ module &mod) : config(mod)
        {
        }

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        config_providers(_In_ const config_providers &other) :
            m_providers(other.m_providers),
            config(other)
        {
        }

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        config_providers(_Inout_ config_providers &&other) :
            m_providers(std::move(other.m_providers)),
            config(std::move(other))
        {
        }

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        /// \returns Reference to this object
        ///
        config_providers& operator=(_In_ const config_providers &other)
        {
            if (this != &other) {
                (config&)*this = other;
                m_providers = other.m_providers;
            }

            return *this;
        }

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        /// \returns Reference to this object
        ///
        config_providers& operator=(_Inout_ config_providers &&other)
        {
            if (this != &other) {
                (config&&)*this = std::move(other);
                m_providers     = std::move(other.m_providers);
            }

            return *this;
        }

        ///
        /// Clones configuration
        ///
        /// \returns Pointer to cloned configuration
        ///
        virtual config* clone() const { return new config_providers<_Tprov>(*this); }

        /// \name XML configuration management
        /// @{

        ///
        /// Save configuration to XML document
        ///
        /// \param[in]  pDoc         XML document
        /// \param[in]  pConfigRoot  Suggested root element for saving configuration
        /// \param[out] ppEapError   Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError) const
        {
            if (!config::save(pDoc, pConfigRoot, ppEapError))
                return false;

            const winstd::bstr bstrNamespace(L"urn:ietf:params:xml:ns:yang:ietf-eap-metadata");
            DWORD dwResult;
            HRESULT hr;

            // Select <EAPIdentityProviderList> node.
            winstd::com_obj<IXMLDOMNode> pXmlElIdentityProviderList;
            if ((dwResult = eapxml::select_node(pConfigRoot, winstd::bstr(L"eap-metadata:EAPIdentityProviderList"), &pXmlElIdentityProviderList)) != ERROR_SUCCESS) {
                *ppEapError = m_module.make_error(ERROR_NOT_FOUND, _T(__FUNCTION__) _T(" Error selecting <EAPIdentityProviderList> element."), _T("Please make sure profile XML is a valid ") _T(PRODUCT_NAME_STR) _T(" profile XML document."));
                return false;
            }

            for (std::list<_Tprov>::const_iterator provider = m_providers.cbegin(), provider_end = m_providers.cend(); provider != provider_end; ++provider) {
                // <EAPIdentityProvider>
                winstd::com_obj<IXMLDOMElement> pXmlElIdentityProvider;
                if ((dwResult = eapxml::create_element(pDoc, winstd::bstr(L"EAPIdentityProvider"), bstrNamespace, &pXmlElIdentityProvider))) {
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


        ///
        /// Load configuration from XML document
        ///
        /// \param[in]  pConfigRoot  Root element for loading configuration
        /// \param[out] ppEapError   Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        virtual bool load(_In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError)
        {
            assert(pConfigRoot);
            assert(ppEapError);
            DWORD dwResult;

            if (!config::load(pConfigRoot, ppEapError))
                return false;

            // Iterate authentication providers (<EAPIdentityProvider>).
            winstd::com_obj<IXMLDOMNodeList> pXmlListProviders;
            if ((dwResult = eapxml::select_nodes(pConfigRoot, winstd::bstr(L"eap-metadata:EAPIdentityProviderList/eap-metadata:EAPIdentityProvider"), &pXmlListProviders)) != ERROR_SUCCESS) {
                *ppEapError = m_module.make_error(ERROR_NOT_FOUND, _T(__FUNCTION__) _T(" Error selecting <EAPIdentityProviderList><EAPIdentityProvider> elements."), _T("Please make sure profile XML is a valid ") _T(PRODUCT_NAME_STR) _T(" profile XML document."));
                return false;
            }
            long lCount = 0;
            pXmlListProviders->get_length(&lCount);
            for (long i = 0; i < lCount; i++) {
                winstd::com_obj<IXMLDOMNode> pXmlElProvider;
                pXmlListProviders->get_item(i, &pXmlElProvider);

                _Tprov prov(m_module);

                // Load provider.
                if (!prov.load(pXmlElProvider, ppEapError))
                    return false;

                // Add provider to the list.
                m_providers.push_back(std::move(prov));
            }

            return true;
        }

        /// @}

        /// \name BLOB management
        /// @{

        ///
        /// Packs a configuration
        ///
        /// \param[inout] cursor  Memory cursor
        ///
        virtual void pack(_Inout_ unsigned char *&cursor) const
        {
            eap::config::pack(cursor);
            eapserial::pack(cursor, m_providers);
        }


        ///
        /// Returns packed size of a configuration
        ///
        /// \returns Size of data when packed (in bytes)
        ///
        virtual size_t get_pk_size() const
        {
            return
                eap::config::get_pk_size() +
                eapserial::get_pk_size(m_providers);
        }


        ///
        /// Unpacks a configuration
        ///
        /// \param[inout] cursor  Memory cursor
        ///
        virtual void unpack(_Inout_ const unsigned char *&cursor)
        {
            eap::config::unpack(cursor);

            std::list<_Tprov>::size_type count = *(const std::list<_Tprov>::size_type*&)cursor;
            eapserial::unpack(cursor, count);
            m_providers.clear();
            for (std::list<_Tprov>::size_type i = 0; i < count; i++) {
                _Tprov el(m_module);
                el.unpack(cursor);
                m_providers.push_back(std::move(el));
            }
        }

        /// @}

    public:
        std::list<_Tprov> m_providers;  ///< List of provider configurations
    };
}


namespace eapserial
{
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::config &val)
    {
        val.pack(cursor);
    }


    inline size_t get_pk_size(const eap::config &val)
    {
        return val.get_pk_size();
    }


    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::config &val)
    {
        val.unpack(cursor);
    }
}
