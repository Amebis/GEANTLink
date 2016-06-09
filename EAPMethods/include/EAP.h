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

#define IDR_EAP_KEY_PUBLIC  1
#define IDR_EAP_KEY_PRIVATE 2

#if !defined(RC_INVOKED) && !defined(MIDL_PASS)

#include <WinStd/COM.h>
#include <WinStd/Crypt.h>
#include <WinStd/ETW.h>
#include <WinStd/Win.h>

#include <eaptypes.h>
extern "C" {
#include <eapmethodpeerapis.h>
}

#include <tchar.h>
#include <wincred.h>
#include <list>
#include <utility>

#include <EAPMethodETW.h>
#include "EAPSerial.h"
#include "EAPXML.h"


namespace eap
{
    enum type_t;

    class session;

    class config;
    class config_method;
    template <class _Tmeth> class config_provider;
    template <class _Tprov> class config_providers;
    typedef config_method config_pass;

    class credentials;
    class credentials_pass;

    class module;
    template <class _Tcfg, class _Tid, class _Tint, class _Tintres> class peer_base;
    template <class _Tcfg, class _Tid, class _Tint, class _Tintres> class peer;
}

namespace eapserial
{
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::config_method &val);
    inline size_t get_pk_size(const eap::config_method &val);
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::config_method &val);

    template <class _Tmeth> inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::config_provider<_Tmeth> &val);
    template <class _Tmeth> inline size_t get_pk_size(const eap::config_provider<_Tmeth> &val);
    template <class _Tmeth> inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::config_provider<_Tmeth> &val);

    template <class _Tprov> inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::config_providers<_Tprov> &val);
    template <class _Tprov> inline size_t get_pk_size(const eap::config_providers<_Tprov> &val);
    template <class _Tprov> inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::config_providers<_Tprov> &val);

    inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::credentials &val);
    inline size_t get_pk_size(const eap::credentials &val);
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::credentials &val);

    inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::credentials_pass &val);
    inline size_t get_pk_size(const eap::credentials_pass &val);
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::credentials_pass &val);
}

#pragma once


#define ETW_ERROR(kw, f, ...)   m_ep.write(TRACE_LEVEL_ERROR      , kw, _T(__FUNCTION__) _T(" ") f, ##__VA_ARGS__)
#define ETW_WARNING(kw, f, ...) m_ep.write(TRACE_LEVEL_WARNING    , kw, _T(__FUNCTION__) _T(" ") f, ##__VA_ARGS__)
#define ETW_INFO(kw, f, ...)    m_ep.write(TRACE_LEVEL_INFORMATION, kw, _T(__FUNCTION__) _T(" ") f, ##__VA_ARGS__)
#define ETW_VERBOSE(kw, f, ...) m_ep.write(TRACE_LEVEL_VERBOSE    , kw, _T(__FUNCTION__) _T(" ") f, ##__VA_ARGS__)
#define ETW_FN_VOID             winstd::event_fn_auto    <         &EAPMETHOD_TRACE_EVT_FN_CALL, &EAPMETHOD_TRACE_EVT_FN_RETURN        > _event_auto(m_ep, __FUNCTION__)
#define ETW_FN_DWORD(res)       winstd::event_fn_auto_ret<DWORD  , &EAPMETHOD_TRACE_EVT_FN_CALL, &EAPMETHOD_TRACE_EVT_FN_RETURN_DWORD  > _event_auto(m_ep, __FUNCTION__, res)
#define ETW_FN_HRESULT(res)     winstd::event_fn_auto_ret<HRESULT, &EAPMETHOD_TRACE_EVT_FN_CALL, &EAPMETHOD_TRACE_EVT_FN_RETURN_HRESULT> _event_auto(m_ep, __FUNCTION__, res)


namespace eap
{
    ///
    /// EAP method numbers
    ///
    /// \sa [Extensible Authentication Protocol (EAP) Registry (Chapter: Method Types)](https://www.iana.org/assignments/eap-numbers/eap-numbers.xhtml#eap-numbers-4)
    ///
    enum type_t {
        type_tls      = 13,
        type_ttls     = 21,
        type_peap     = 25,
        type_mschapv2 = 26,
        type_pap      = 192, // Not actually an EAP method (moved to the Unassigned area)
    };


    ///
    /// EAP session
    ///
    class session
    {
    public:
        ///
        /// Constructs a session
        ///
        session();

        ///
        /// Destructs the session
        ///
        virtual ~session();

        /// \name Session start/end
        /// @{

        ///
        /// Starts an EAP authentication session on the peer EAPHost using the EAP method.
        ///
        /// \sa [EapPeerBeginSession function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363600.aspx)
        ///
        virtual DWORD begin(
            _In_                                   DWORD         dwFlags,
            _In_                             const EapAttributes *pAttributeArray,
            _In_                                   HANDLE        hTokenImpersonateUser,
            _In_                                   DWORD         dwConnectionDataSize,
            _In_count_(dwConnectionDataSize) const BYTE          *pConnectionData,
            _In_                                   DWORD         dwUserDataSize,
            _In_count_(dwUserDataSize)       const BYTE          *pUserData,
            _In_                                   DWORD         dwMaxSendPacketSize,
            _Out_                                  EAP_ERROR     **ppEapError);

        ///
        /// Ends an EAP authentication session for the EAP method.
        ///
        /// \sa [EapPeerEndSession function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363604.aspx)
        ///
        virtual DWORD end(_Out_ EAP_ERROR **ppEapError);

        /// @}

        /// \name Packet processing
        /// @{

        ///
        /// Processes a packet received by EAPHost from a supplicant.
        ///
        /// \sa [EapPeerProcessRequestPacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363621.aspx)
        ///
        virtual DWORD process_request_packet(
            _In_                                       DWORD               dwReceivedPacketSize,
            _In_bytecount_(dwReceivedPacketSize) const EapPacket           *pReceivedPacket,
            _Out_                                      EapPeerMethodOutput *pEapOutput,
            _Out_                                      EAP_ERROR           **ppEapError);

        ///
        /// Obtains a response packet from the EAP method.
        ///
        /// \sa [EapPeerGetResponsePacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363610.aspx)
        ///
        virtual DWORD get_response_packet(
            _Inout_                            DWORD              *pdwSendPacketSize,
            _Inout_bytecap_(*dwSendPacketSize) EapPacket          *pSendPacket,
            _Out_                              EAP_ERROR          **ppEapError);

        ///
        /// Obtains the result of an authentication session from the EAP method.
        ///
        /// \sa [EapPeerGetResult function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363611.aspx)
        ///
        virtual DWORD get_result(_In_ EapPeerMethodResultReason reason, _Out_ EapPeerMethodResult *ppResult, _Out_ EAP_ERROR **ppEapError);

        /// @}

        /// \name UI interaction
        /// @{

        ///
        /// Obtains the user interface context from the EAP method.
        ///
        /// \note This function is always followed by the `EapPeerInvokeInteractiveUI()` function, which is followed by the `EapPeerSetUIContext()` function.
        ///
        /// \sa [EapPeerGetUIContext function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363612.aspx)
        ///
        virtual DWORD get_ui_context(
            _Out_ DWORD     *pdwUIContextDataSize,
            _Out_ BYTE      **ppUIContextData,
            _Out_ EAP_ERROR **ppEapError);

        ///
        /// Provides a user interface context to the EAP method.
        ///
        /// \note This function is called after the UI has been raised through the `EapPeerGetUIContext()` function.
        ///
        /// \sa [EapPeerSetUIContext function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363626.aspx)
        ///
        virtual DWORD set_ui_context(
            _In_                                  DWORD               dwUIContextDataSize,
            _In_count_(dwUIContextDataSize) const BYTE                *pUIContextData,
            _In_                            const EapPeerMethodOutput *pEapOutput,
            _Out_                                 EAP_ERROR           **ppEapError);

        /// @}

        /// \name Response attributes
        /// @{

        ///
        /// Obtains an array of EAP response attributes from the EAP method.
        ///
        /// \sa [EapPeerGetResponseAttributes function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363609.aspx)
        ///
        virtual DWORD get_response_attributes(_Out_ EapAttributes *pAttribs, _Out_ EAP_ERROR **ppEapError);

        ///
        /// Provides an updated array of EAP response attributes to the EAP method.
        ///
        /// \sa [EapPeerSetResponseAttributes function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363625.aspx)
        ///
        virtual DWORD set_response_attributes(const _In_ EapAttributes *pAttribs, _Out_ EapPeerMethodOutput *pEapOutput, _Out_ EAP_ERROR **ppEapError);

        /// @}
    };


    ///
    /// Base class for configuration storage
    ///
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
        /// Destructs configuration
        ///
        virtual ~config();

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
        /// - \c ERROR_SUCCESS if succeeded
        /// - error code otherwise
        ///
        virtual DWORD save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError) const = 0;

        ///
        /// Load configuration from XML document
        ///
        /// \param[in]  pConfigRoot  Root element for loading configuration
        /// \param[out] ppEapError   Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c ERROR_SUCCESS if succeeded
        /// - error code otherwise
        ///
        virtual DWORD load(_In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError) = 0;

        /// @}

    public:
        module &m_module;   ///< Reference of the EAP module
    };


    ///
    /// Base class for method configuration storage
    ///
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
        /// - \c ERROR_SUCCESS if succeeded
        /// - error code otherwise
        ///
        virtual DWORD save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError) const;

        ///
        /// Load configuration from XML document
        ///
        /// \param[in]  pConfigRoot  Root element for loading configuration
        /// \param[out] ppEapError   Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c ERROR_SUCCESS if succeeded
        /// - error code otherwise
        ///
        virtual DWORD load(_In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError);

        /// @}

        ///
        /// Returns EAP method type of this configuration
        ///
        /// \returns One of `eap::type_t` constants.
        ///
        virtual type_t get_method_id() = 0;

    public:
        bool m_allow_save;                      ///< Are credentials allowed to be saved to Windows Credential Manager?
        std::wstring m_anonymous_identity;      ///< Anonymous identity
    };


    ///
    /// Provider configuration
    ///
    template <class _Tmeth>
    class config_provider : public config
    {
    public:
        ///
        /// Constructs configuration
        ///
        /// \param[in] mod  Reference of the EAP module to use for global services
        ///
        config_provider(_In_ module &mod) : config(mod)
        {
        }

        ///
        /// Copies configuration
        ///
        /// \param[in] other  Configuration to copy from
        ///
        config_provider(_In_ const config_provider &other) :
            m_id(other.m_id),
            m_lbl_alt_credential(other.m_lbl_alt_credential),
            m_lbl_alt_identity(other.m_lbl_alt_identity),
            m_lbl_alt_password(other.m_lbl_alt_password),
            m_methods(other.m_methods),
            config(other)
        {
        }

        ///
        /// Moves configuration
        ///
        /// \param[in] other  Configuration to move from
        ///
        config_provider(_Inout_ config_provider &&other) :
            m_id(std::move(other.m_id)),
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
                m_id                 = other.m_id;
                m_lbl_alt_credential = other.m_lbl_alt_credential;
                m_lbl_alt_identity   = other.m_lbl_alt_identity;
                m_lbl_alt_password   = other.m_lbl_alt_password;
                m_methods            = other.m_methods;
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
                m_id                 = std::move(other.m_id);
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
        /// - \c ERROR_SUCCESS if succeeded
        /// - error code otherwise
        ///
        virtual DWORD save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError) const
        {
            const winstd::bstr bstrNamespace(L"urn:ietf:params:xml:ns:yang:ietf-eap-metadata");
            DWORD dwResult;
            HRESULT hr;

            // <ID>
            if (!m_id.empty())
                if ((dwResult = eapxml::put_element_value(pDoc, pConfigRoot, winstd::bstr(L"ID"), bstrNamespace, winstd::bstr(m_id))) != ERROR_SUCCESS) {
                    *ppEapError = m_module.make_error(dwResult, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error creating <ID> element."), NULL);
                    return dwResult;
                }

            // <ProviderInfo>
            winstd::com_obj<IXMLDOMElement> pXmlElProviderInfo;
            if ((dwResult = eapxml::create_element(pDoc, pConfigRoot, winstd::bstr(L"eap-metadata:ProviderInfo"), winstd::bstr(L"ProviderInfo"), bstrNamespace, &pXmlElProviderInfo)) != ERROR_SUCCESS) {
                *ppEapError = m_module.make_error(dwResult, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error creating <ProviderInfo> element."), NULL);
                return dwResult;
            }

            // <ProviderInfo>/<CredentialPrompt>
            if (!m_lbl_alt_credential.empty())
                if ((dwResult = eapxml::put_element_value(pDoc, pXmlElProviderInfo, winstd::bstr(L"CredentialPrompt"), bstrNamespace, winstd::bstr(m_lbl_alt_credential))) != ERROR_SUCCESS) {
                    *ppEapError = m_module.make_error(dwResult, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error creating <CredentialPrompt> element."), NULL);
                    return dwResult;
                }

            // <ProviderInfo>/<UserNameLabel>
            if (!m_lbl_alt_identity.empty())
                if ((dwResult = eapxml::put_element_value(pDoc, pXmlElProviderInfo, winstd::bstr(L"UserNameLabel"), bstrNamespace, winstd::bstr(m_lbl_alt_identity))) != ERROR_SUCCESS) {
                    *ppEapError = m_module.make_error(dwResult, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error creating <UserNameLabel> element."), NULL);
                    return dwResult;
                }

            // <ProviderInfo>/<PasswordLabel>
            if (!m_lbl_alt_password.empty())
                if ((dwResult = eapxml::put_element_value(pDoc, pXmlElProviderInfo, winstd::bstr(L"PasswordLabel"), bstrNamespace, winstd::bstr(m_lbl_alt_password))) != ERROR_SUCCESS) {
                    *ppEapError = m_module.make_error(dwResult, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error creating <PasswordLabel> element."), NULL);
                    return dwResult;
                }

            // <AuthenticationMethods>
            winstd::com_obj<IXMLDOMElement> pXmlElAuthenticationMethods;
            if ((dwResult = eapxml::create_element(pDoc, pConfigRoot, winstd::bstr(L"eap-metadata:AuthenticationMethods"), winstd::bstr(L"AuthenticationMethods"), bstrNamespace, &pXmlElAuthenticationMethods)) != ERROR_SUCCESS) {
                *ppEapError = m_module.make_error(dwResult, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error creating <AuthenticationMethods> element."), NULL);
                return dwResult;
            }

            for (std::list<_Tmeth>::const_iterator method = m_methods.cbegin(), method_end = m_methods.cend(); method != method_end; ++method) {
                // <AuthenticationMethod>
                winstd::com_obj<IXMLDOMElement> pXmlElAuthenticationMethod;
                if ((dwResult = eapxml::create_element(pDoc, winstd::bstr(L"AuthenticationMethod"), bstrNamespace, &pXmlElAuthenticationMethod))) {
                    *ppEapError = m_module.make_error(dwResult, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error creating <AuthenticationMethod> element."), NULL);
                    return dwResult;
                }

                // <AuthenticationMethod>/...
                if ((dwResult = method->save(pDoc, pXmlElAuthenticationMethod, ppEapError)) != ERROR_SUCCESS)
                    return dwResult;

                if (FAILED(hr = pXmlElAuthenticationMethods->appendChild(pXmlElAuthenticationMethod, NULL))) {
                    *ppEapError = m_module.make_error(dwResult = HRESULT_CODE(hr), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error appending <AuthenticationMethod> element."), NULL);
                    return dwResult;
                }
            }

            return dwResult;
        }


        ///
        /// Load configuration from XML document
        ///
        /// \param[in]  pConfigRoot  Root element for loading configuration
        /// \param[out] ppEapError   Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c ERROR_SUCCESS if succeeded
        /// - error code otherwise
        ///
        virtual DWORD load(_In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError)
        {
            assert(pConfigRoot);
            assert(ppEapError);
            DWORD dwResult;
            std::wstring lang;
            LoadString(m_module.m_instance, 2, lang);

            // <ID>
            m_id.clear();
            eapxml::get_element_value(pConfigRoot, winstd::bstr(L"eap-metadata:ID"), m_id);

            // <ProviderInfo>
            m_lbl_alt_credential.clear();
            m_lbl_alt_identity.clear();
            m_lbl_alt_password.clear();
            winstd::com_obj<IXMLDOMElement> pXmlElProviderInfo;
            if (eapxml::select_element(pConfigRoot, winstd::bstr(L"eap-metadata:ProviderInfo"), &pXmlElProviderInfo) == ERROR_SUCCESS) {
                // <CredentialPrompt>
                eapxml::get_element_localized(pXmlElProviderInfo, winstd::bstr(L"eap-metadata:CredentialPrompt"), lang.c_str(), m_lbl_alt_credential);

                // <UserNameLabel>
                eapxml::get_element_localized(pXmlElProviderInfo, winstd::bstr(L"eap-metadata:UserNameLabel"), lang.c_str(), m_lbl_alt_identity);

                // <PasswordLabel>
                eapxml::get_element_localized(pXmlElProviderInfo, winstd::bstr(L"eap-metadata:PasswordLabel"), lang.c_str(), m_lbl_alt_password);
            }

            // Iterate authentication methods (<AuthenticationMethods>).
            m_methods.clear();
            winstd::com_obj<IXMLDOMNodeList> pXmlListMethods;
            if ((dwResult = eapxml::select_nodes(pConfigRoot, winstd::bstr(L"eap-metadata:AuthenticationMethods/eap-metadata:AuthenticationMethod"), &pXmlListMethods)) != ERROR_SUCCESS) {
                *ppEapError = m_module.make_error(dwResult = ERROR_NOT_FOUND, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error selecting <AuthenticationMethods>/<AuthenticationMethod> elements."), NULL);
                return dwResult;
            }
            long lCount = 0;
            pXmlListMethods->get_length(&lCount);
            for (long i = 0; i < lCount; i++) {
                winstd::com_obj<IXMLDOMNode> pXmlElMethod;
                pXmlListMethods->get_item(i, &pXmlElMethod);

                _Tmeth cfg(m_module);

                // Check EAP method type (<EAPMethod>).
                DWORD dwMethodID;
                if (eapxml::get_element_value(pXmlElMethod, winstd::bstr(L"eap-metadata:EAPMethod"), &dwMethodID) == ERROR_SUCCESS) {
                    if ((type_t)dwMethodID != cfg.get_method_id()) {
                        // Wrong type.
                        continue;
                    }
                }

                // Load configuration.
                dwResult = cfg.load(pXmlElMethod, ppEapError);
                if (dwResult != ERROR_SUCCESS)
                    return dwResult;

                // Add configuration to the list.
                m_methods.push_back(std::move(cfg));
            }

            return ERROR_SUCCESS;
        }

        /// @}

    public:
        std::wstring m_id;                      ///< Profile ID
        winstd::tstring m_lbl_alt_credential;   ///< Alternative label for credential prompt
        winstd::tstring m_lbl_alt_identity;     ///< Alternative label for identity prompt
        winstd::tstring m_lbl_alt_password;     ///< Alternative label for password prompt
        std::list<_Tmeth> m_methods;            ///< List of method configurations
    };


    ///
    /// Providers configuration
    ///
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
        /// - \c ERROR_SUCCESS if succeeded
        /// - error code otherwise
        ///
        virtual DWORD save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError) const
        {
            const winstd::bstr bstrNamespace(L"urn:ietf:params:xml:ns:yang:ietf-eap-metadata");
            DWORD dwResult;
            HRESULT hr;

            // Select <EAPIdentityProviderList> node.
            winstd::com_obj<IXMLDOMNode> pXmlElIdentityProviderList;
            if ((dwResult = eapxml::select_node(pConfigRoot, winstd::bstr(L"eap-metadata:EAPIdentityProviderList"), &pXmlElIdentityProviderList)) != ERROR_SUCCESS) {
                *ppEapError = m_module.make_error(dwResult = ERROR_NOT_FOUND, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error selecting <EAPIdentityProviderList> element."), NULL);
                return dwResult;
            }

            for (std::list<_Tprov>::const_iterator provider = m_providers.cbegin(), provider_end = m_providers.cend(); provider != provider_end; ++provider) {
                // <EAPIdentityProvider>
                winstd::com_obj<IXMLDOMElement> pXmlElIdentityProvider;
                if ((dwResult = eapxml::create_element(pDoc, winstd::bstr(L"EAPIdentityProvider"), bstrNamespace, &pXmlElIdentityProvider))) {
                    *ppEapError = m_module.make_error(dwResult, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error creating <EAPIdentityProvider> element."), NULL);
                    return dwResult;
                }

                // <EAPIdentityProvider>/...
                if ((dwResult = provider->save(pDoc, pXmlElIdentityProvider, ppEapError)) != ERROR_SUCCESS)
                    return dwResult;

                if (FAILED(hr = pXmlElIdentityProviderList->appendChild(pXmlElIdentityProvider, NULL))) {
                    *ppEapError = m_module.make_error(dwResult = HRESULT_CODE(hr), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error appending <EAPIdentityProvider> element."), NULL);
                    return dwResult;
                }
            }

            return dwResult;
        }


        ///
        /// Load configuration from XML document
        ///
        /// \param[in]  pConfigRoot  Root element for loading configuration
        /// \param[out] ppEapError   Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c ERROR_SUCCESS if succeeded
        /// - error code otherwise
        ///
        virtual DWORD load(_In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError)
        {
            assert(pConfigRoot);
            assert(ppEapError);
            DWORD dwResult;

            // Iterate authentication providers (<EAPIdentityProvider>).
            winstd::com_obj<IXMLDOMNodeList> pXmlListProviders;
            if ((dwResult = eapxml::select_nodes(pConfigRoot, winstd::bstr(L"eap-metadata:EAPIdentityProviderList/eap-metadata:EAPIdentityProvider"), &pXmlListProviders)) != ERROR_SUCCESS) {
                *ppEapError = m_module.make_error(dwResult = ERROR_NOT_FOUND, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error selecting <EAPIdentityProviderList><EAPIdentityProvider> elements."), NULL);
                return dwResult;
            }
            long lCount = 0;
            pXmlListProviders->get_length(&lCount);
            for (long i = 0; i < lCount; i++) {
                winstd::com_obj<IXMLDOMNode> pXmlElProvider;
                pXmlListProviders->get_item(i, &pXmlElProvider);

                _Tprov prov(m_module);

                // Load provider.
                dwResult = prov.load(pXmlElProvider, ppEapError);
                if (dwResult != ERROR_SUCCESS)
                    return dwResult;

                // Add provider to the list.
                m_providers.push_back(std::move(prov));
            }

            return dwResult;
        }

        /// @}

    public:
        std::list<_Tprov> m_providers;  ///< List of provider configurations
    };


    ///
    /// Base class for method credential storage
    ///
    class credentials : public config
    {
    public:
        ///
        /// Constructs credentials
        ///
        /// \param[in] mod  Reference of the EAP module to use for global services
        ///
        credentials(_In_ module &mod);

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        credentials(_In_ const credentials &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Credentials to move from
        ///
        credentials(_Inout_ credentials &&other);

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        /// \returns Reference to this object
        ///
        credentials& operator=(_In_ const credentials &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Configuration to move from
        ///
        /// \returns Reference to this object
        ///
        credentials& operator=(_Inout_ credentials &&other);

        ///
        /// Resets credentials
        ///
        virtual void clear();

        ///
        /// Test credentials if blank
        ///
        virtual bool empty() const;

        /// \name XML credentials management
        /// @{

        ///
        /// Save credentials to XML document
        ///
        /// \param[in]  pDoc         XML document
        /// \param[in]  pConfigRoot  Suggested root element for saving credentials
        /// \param[out] ppEapError   Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns Always returns \c ERROR_NOT_SUPPORTED, as credentials are non-exportable.
        ///
        virtual DWORD save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError) const;

        /// @}

        /// \name Storage
        /// @{

        ///
        /// Save credentials to Windows Credential Manager
        ///
        /// \param[in]  pszTargetName  The name in Windows Credential Manager to store credentials as
        /// \param[out] ppEapError     Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c ERROR_SUCCESS if succeeded
        /// - error code otherwise
        ///
        virtual DWORD store(_In_ LPCTSTR pszTargetName, _Out_ EAP_ERROR **ppEapError) const = 0;

        ///
        /// Retrieve credentials from Windows Credential Manager
        ///
        /// \param[in]  pszTargetName  The name in Windows Credential Manager to retrieve credentials from
        /// \param[out] ppEapError     Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c ERROR_SUCCESS if succeeded
        /// - error code otherwise
        ///
        virtual DWORD retrieve(_In_ LPCTSTR pszTargetName, _Out_ EAP_ERROR **ppEapError) = 0;

        ///
        /// Return target suffix for Windows Credential Manager credential name
        ///
        virtual LPCTSTR target_suffix() const = 0;

        ///
        /// Returns target name for Windows Credential Manager credential name
        ///
        /// \param[in]  pszTargetName  The name in Windows Credential Manager to retrieve credentials from
        ///
        /// \returns Final target name to store/retrieve credentials in Windows Credential Manager
        ///
        inline winstd::tstring target_name(_In_ LPCTSTR pszTargetName) const
        {
            winstd::tstring target_name(_T(PRODUCT_NAME_STR) _T("/"));
            target_name += pszTargetName;
            target_name += _T('/');
            target_name += target_suffix();
            assert(target_name.length() < CRED_MAX_GENERIC_TARGET_NAME_LENGTH);
            return target_name;
        }

        /// @}

    public:
        std::wstring m_identity;    ///< Identity (username\@domain, certificate name etc.)
    };


    ///
    /// Password based method credentials
    ///
    class credentials_pass : public credentials
    {
    public:
        ///
        /// Constructs credentials
        ///
        /// \param[in] mod  Reference of the EAP module to use for global services
        ///
        credentials_pass(_In_ module &mod);

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        credentials_pass(_In_ const credentials_pass &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Credentials to move from
        ///
        credentials_pass(_Inout_ credentials_pass &&other);

        ///
        /// Copies credentials
        ///
        /// \param[in] other  Credentials to copy from
        ///
        /// \returns Reference to this object
        ///
        credentials_pass& operator=(_In_ const credentials_pass &other);

        ///
        /// Moves credentials
        ///
        /// \param[in] other  Credentials to move from
        ///
        /// \returns Reference to this object
        ///
        credentials_pass& operator=(_Inout_ credentials_pass &&other);

        ///
        /// Resets credentials
        ///
        virtual void clear();

        ///
        /// Test credentials if blank
        ///
        virtual bool empty() const;

        /// \name XML configuration management
        /// @{

        ///
        /// Load credentials from XML document
        ///
        /// \param[in]  pConfigRoot  Root element for loading credentials
        /// \param[out] ppEapError   Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c ERROR_SUCCESS if succeeded
        /// - error code otherwise
        ///
        virtual DWORD load(_In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError);

        /// @}

        /// \name Storage
        /// @{

        ///
        /// Save credentials to Windows Credential Manager
        ///
        /// \param[in]  pszTargetName  The name in Windows Credential Manager to store credentials as
        /// \param[out] ppEapError     Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c ERROR_SUCCESS if succeeded
        /// - error code otherwise
        ///
        virtual DWORD store(_In_ LPCTSTR pszTargetName, _Out_ EAP_ERROR **ppEapError) const;

        ///
        /// Retrieve credentials from Windows Credential Manager
        ///
        /// \param[in]  pszTargetName  The name in Windows Credential Manager to retrieve credentials from
        /// \param[out] ppEapError     Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c ERROR_SUCCESS if succeeded
        /// - error code otherwise
        ///
        virtual DWORD retrieve(_In_ LPCTSTR pszTargetName, _Out_ EAP_ERROR **ppEapError);

        /// @}

    public:
        winstd::sanitizing_wstring m_password;  ///< Password
    };


    ///
    /// EAP module base class
    ///
    /// Provides basic services to EAP methods.
    ///
    class module
    {
    public:
        module();
        virtual ~module();

        ///
        /// Allocate a EAP_ERROR and fill it according to dwErrorCode
        ///
        EAP_ERROR* make_error(_In_ DWORD dwErrorCode, _In_ DWORD dwReasonCode, _In_ LPCGUID pRootCauseGuid, _In_ LPCGUID pRepairGuid, _In_ LPCGUID pHelpLinkGuid, _In_z_ LPCWSTR pszRootCauseString, _In_z_ LPCWSTR pszRepairString) const;

        ///
        /// Allocate BLOB
        ///
        BYTE* alloc_memory(_In_ size_t size);

        ///
        /// Free BLOB allocated with this peer
        ///
        void free_memory(_In_ BYTE *ptr);

        ///
        /// Free EAP_ERROR allocated with `make_error()` method
        ///
        void free_error_memory(_In_ EAP_ERROR *err);

    public:
        HINSTANCE m_instance;                   ///< Windows module instance

    protected:
        winstd::heap m_heap;                    ///< Heap
        mutable winstd::event_provider m_ep;    ///< Event Provider
    };


    ///
    /// EAP peer base class
    ///
    /// A group of methods all EAP peers must or should implement.
    ///
    template <class _Tcfg, class _Tid, class _Tint, class _Tintres>
    class peer_base : public module
    {
    public:
        ///
        /// Configuration data type
        ///
        typedef config_providers<config_provider<_Tcfg> > config_type;

        ///
        /// Identity data type
        ///
        typedef _Tid identity_type;

        ///
        /// Interactive request data type
        ///
        typedef _Tint interactive_request_type;

        ///
        /// Interactive response data type
        ///
        typedef _Tintres interactive_response_type;

    public:
        ///
        /// Constructor
        ///
        peer_base() : module() {}
    };


    ///
    /// EAP peer base class
    ///
    /// A group of methods all EAP peers must or should implement.
    ///
    template <class _Tcfg, class _Tid, class _Tint, class _Tintres>
    class peer : public peer_base<_Tcfg, _Tid, _Tint, _Tintres>
    {
    public:
        peer() : peer_base<_Tcfg, _Tid, _Tint, _Tintres>() {}

        ///
        /// Initializes an EAP peer method for EAPHost.
        ///
        /// \sa [EapPeerGetInfo function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363613.aspx)
        ///
        virtual DWORD initialize(_Out_ EAP_ERROR **ppEapError) = 0;

        ///
        /// Shuts down the EAP method and prepares to unload its corresponding DLL.
        ///
        /// \sa [EapPeerShutdown function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363627.aspx)
        ///
        virtual DWORD shutdown(_Out_ EAP_ERROR **ppEapError) = 0;

        ///
        /// Returns the user data and user identity after being called by EAPHost.
        ///
        /// \sa [EapPeerGetIdentity function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363607.aspx)
        ///
        virtual DWORD get_identity(
            _In_                                   DWORD     dwFlags,
            _In_                                   DWORD     dwConnectionDataSize,
            _In_count_(dwConnectionDataSize) const BYTE      *pConnectionData,
            _In_                                   DWORD     dwUserDataSize,
            _In_count_(dwUserDataSize)       const BYTE      *pUserData,
            _In_                                   HANDLE    hTokenImpersonateUser,
            _Out_                                  BOOL      *pfInvokeUI,
            _Out_                                  DWORD     *pdwUserDataOutSize,
            _Out_                                  BYTE      **ppUserDataOut,
            _Out_                                  WCHAR     **ppwszIdentity,
            _Out_                                  EAP_ERROR **ppEapError) = 0;

        ///
        /// Defines the implementation of an EAP method-specific function that retrieves the properties of an EAP method given the connection and user data.
        ///
        /// \sa [EapPeerGetMethodProperties function](https://msdn.microsoft.com/en-us/library/windows/desktop/hh706636.aspx)
        ///
        virtual DWORD get_method_properties(
            _In_                                DWORD                     dwVersion,
            _In_                                DWORD                     dwFlags,
            _In_                                HANDLE                    hUserImpersonationToken,
            _In_                                DWORD                     dwEapConnDataSize,
            _In_count_(dwEapConnDataSize) const BYTE                      *pEapConnData,
            _In_                                DWORD                     dwUserDataSize,
            _In_count_(dwUserDataSize)    const BYTE                      *pUserData,
            _Out_                               EAP_METHOD_PROPERTY_ARRAY *pMethodPropertyArray,
            _Out_                               EAP_ERROR                 **ppEapError) const = 0;

        ///
        /// Defines the implementation of an EAP method-specific function that obtains the EAP Single-Sign-On (SSO) credential input fields for an EAP method.
        ///
        /// \sa [EapPeerQueryCredentialInputFields function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363622.aspx)
        ///
        virtual DWORD query_credential_input_fields(
            _In_                                HANDLE                       hUserImpersonationToken,
            _In_                                DWORD                        dwFlags,
            _In_                                DWORD                        dwEapConnDataSize,
            _In_count_(dwEapConnDataSize) const BYTE                         *pEapConnData,
            _Out_                               EAP_CONFIG_INPUT_FIELD_ARRAY *pEapConfigInputFieldsArray,
            _Out_                               EAP_ERROR                    **ppEapError) const
        {
            UNREFERENCED_PARAMETER(hUserImpersonationToken);
            UNREFERENCED_PARAMETER(dwFlags);
            UNREFERENCED_PARAMETER(dwEapConnDataSize);
            UNREFERENCED_PARAMETER(pEapConnData);
            UNREFERENCED_PARAMETER(pEapConfigInputFieldsArray);
            UNREFERENCED_PARAMETER(ppEapError);

            DWORD dwResult = ERROR_NOT_SUPPORTED;
            ETW_FN_DWORD(dwResult);
            return dwResult;
        }

        ///
        /// Defines the implementation of an EAP method function that obtains the user BLOB data provided in an interactive Single-Sign-On (SSO) UI raised on the supplicant.
        ///
        /// \sa [EapPeerQueryUserBlobFromCredentialInputFields function](https://msdn.microsoft.com/en-us/library/windows/desktop/bb204697.aspx)
        ///
        virtual DWORD query_user_blob_from_credential_input_fields(
            _In_                                HANDLE                       hUserImpersonationToken,
            _In_                                DWORD                        dwFlags,
            _In_                                DWORD                        dwEapConnDataSize,
            _In_count_(dwEapConnDataSize) const BYTE                         *pEapConnData,
            _In_                          const EAP_CONFIG_INPUT_FIELD_ARRAY *pEapConfigInputFieldArray,
            _Inout_                             DWORD                        *pdwUsersBlobSize,
            _Inout_                             BYTE                         **ppUserBlob,
            _Out_                               EAP_ERROR                    **ppEapError) const
        {
            UNREFERENCED_PARAMETER(hUserImpersonationToken);
            UNREFERENCED_PARAMETER(dwFlags);
            UNREFERENCED_PARAMETER(dwEapConnDataSize);
            UNREFERENCED_PARAMETER(pEapConnData);
            UNREFERENCED_PARAMETER(pEapConfigInputFieldArray);
            UNREFERENCED_PARAMETER(pdwUsersBlobSize);
            UNREFERENCED_PARAMETER(ppUserBlob);
            UNREFERENCED_PARAMETER(ppEapError);

            DWORD dwResult = ERROR_NOT_SUPPORTED;
            ETW_FN_DWORD(dwResult);
            return dwResult;
        }

        ///
        /// Defines the implementation of an EAP method API that provides the input fields for interactive UI components to be raised on the supplicant.
        ///
        /// \sa [EapPeerQueryInteractiveUIInputFields function](https://msdn.microsoft.com/en-us/library/windows/desktop/bb204695.aspx)
        ///
        virtual DWORD query_interactive_ui_input_fields(
            _In_                                  DWORD                   dwVersion,
            _In_                                  DWORD                   dwFlags,
            _In_                                  DWORD                   dwUIContextDataSize,
            _In_count_(dwUIContextDataSize) const BYTE                    *pUIContextData,
            _Out_                                 EAP_INTERACTIVE_UI_DATA *pEapInteractiveUIData,
            _Out_                                 EAP_ERROR               **ppEapError,
            _Inout_                               LPVOID                  *pvReserved) const
        {
            UNREFERENCED_PARAMETER(dwVersion);
            UNREFERENCED_PARAMETER(dwFlags);
            UNREFERENCED_PARAMETER(dwUIContextDataSize);
            UNREFERENCED_PARAMETER(pUIContextData);
            UNREFERENCED_PARAMETER(pEapInteractiveUIData);
            UNREFERENCED_PARAMETER(ppEapError);
            UNREFERENCED_PARAMETER(pvReserved);

            DWORD dwResult = ERROR_NOT_SUPPORTED;
            ETW_FN_DWORD(dwResult);
            return dwResult;
        }

        ///
        /// Converts user information into a user BLOB that can be consumed by EAPHost run-time functions.
        ///
        /// \sa [EapPeerQueryUIBlobFromInteractiveUIInputFields function](https://msdn.microsoft.com/en-us/library/windows/desktop/bb204696.aspx)
        ///
        virtual DWORD query_ui_blob_from_interactive_ui_input_fields(
            _In_                                  DWORD                   dwVersion,
            _In_                                  DWORD                   dwFlags,
            _In_                                  DWORD                   dwUIContextDataSize,
            _In_count_(dwUIContextDataSize) const BYTE                    *pUIContextData,
            _In_                            const EAP_INTERACTIVE_UI_DATA *pEapInteractiveUIData,
            _Out_                                 DWORD                   *pdwDataFromInteractiveUISize,
            _Out_                                 BYTE                    **ppDataFromInteractiveUI,
            _Out_                                 EAP_ERROR               **ppEapError,
            _Inout_                               LPVOID                  *ppvReserved) const
        {
            UNREFERENCED_PARAMETER(dwVersion);
            UNREFERENCED_PARAMETER(dwFlags);
            UNREFERENCED_PARAMETER(dwUIContextDataSize);
            UNREFERENCED_PARAMETER(pUIContextData);
            UNREFERENCED_PARAMETER(pEapInteractiveUIData);
            UNREFERENCED_PARAMETER(pdwDataFromInteractiveUISize);
            UNREFERENCED_PARAMETER(ppDataFromInteractiveUI);
            UNREFERENCED_PARAMETER(ppEapError);
            UNREFERENCED_PARAMETER(ppvReserved);

            DWORD dwResult = ERROR_NOT_SUPPORTED;
            ETW_FN_DWORD(dwResult);
            return dwResult;
        }
    };
}


namespace eapserial
{
    ///
    /// Packs a method configuration
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     Configuration to pack
    ///
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::config_method &val)
    {
        pack(cursor, val.m_allow_save        );
        pack(cursor, val.m_anonymous_identity);
    }


    ///
    /// Returns packed size of a method configuration
    ///
    /// \param[in] val  Configuration to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    inline size_t get_pk_size(const eap::config_method &val)
    {
        return
            get_pk_size(val.m_allow_save        ) +
            get_pk_size(val.m_anonymous_identity);
    }


    ///
    /// Unpacks a method configuration
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     Configuration to unpack to
    ///
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::config_method &val)
    {
        unpack(cursor, val.m_allow_save        );
        unpack(cursor, val.m_anonymous_identity);
    }


    ///
    /// Packs a provider configuration
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     Configuration to pack
    ///
    template <class _Tmeth>
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::config_provider<_Tmeth> &val)
    {
        pack(cursor, val.m_id                );
        pack(cursor, val.m_lbl_alt_credential);
        pack(cursor, val.m_lbl_alt_identity  );
        pack(cursor, val.m_lbl_alt_password  );
        pack(cursor, val.m_methods           );
    }


    ///
    /// Returns packed size of a provider configuration
    ///
    /// \param[in] val  Configuration to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    template <class _Tmeth>
    inline size_t get_pk_size(const eap::config_provider<_Tmeth> &val)
    {
        return
            get_pk_size(val.m_id                ) +
            get_pk_size(val.m_lbl_alt_credential) +
            get_pk_size(val.m_lbl_alt_identity  ) +
            get_pk_size(val.m_lbl_alt_password  ) +
            get_pk_size(val.m_methods           );
    }


    ///
    /// Unpacks a provider configuration
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     Configuration to unpack to
    ///
    template <class _Tmeth>
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::config_provider<_Tmeth> &val)
    {
        unpack(cursor, val.m_id                );
        unpack(cursor, val.m_lbl_alt_credential);
        unpack(cursor, val.m_lbl_alt_identity  );
        unpack(cursor, val.m_lbl_alt_password  );

        std::list<_Tmeth>::size_type count = *(const std::list<_Tmeth>::size_type*&)cursor;
        cursor += sizeof(std::list<_Tmeth>::size_type);
        val.m_methods.clear();
        for (std::list<_Tmeth>::size_type i = 0; i < count; i++) {
            _Tmeth el(val.m_module);
            unpack(cursor, el);
            val.m_methods.push_back(std::move(el));
        }
    }


    ///
    /// Packs a providers configuration
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     Configuration to pack
    ///
    template <class _Tprov>
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::config_providers<_Tprov> &val)
    {
        pack(cursor, val.m_providers);
    }


    ///
    /// Returns packed size of a providers configuration
    ///
    /// \param[in] val  Configuration to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    template <class _Tprov>
    inline size_t get_pk_size(const eap::config_providers<_Tprov> &val)
    {
        return get_pk_size(val.m_providers);
    }


    ///
    /// Unpacks a providers configuration
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     Configuration to unpack to
    ///
    template <class _Tprov>
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::config_providers<_Tprov> &val)
    {
        std::list<_Tprov>::size_type count = *(const std::list<_Tprov>::size_type*&)cursor;
        cursor += sizeof(std::list<_Tprov>::size_type);
        val.m_providers.clear();
        for (std::list<_Tprov>::size_type i = 0; i < count; i++) {
            _Tprov el(val.m_module);
            unpack(cursor, el);
            val.m_providers.push_back(std::move(el));
        }
    }


    ///
    /// Packs a method credentials
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     Credentials to pack
    ///
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::credentials &val)
    {
        pack(cursor, (const eap::config&)val);
        pack(cursor, val.m_identity         );
    }


    ///
    /// Returns packed size of a method credentials
    ///
    /// \param[in] val  Credentials to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    inline size_t get_pk_size(const eap::credentials &val)
    {
        return
            get_pk_size((const eap::config&)val) +
            get_pk_size(val.m_identity         );
    }


    ///
    /// Unpacks a method credentials
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     Credentials to unpack to
    ///
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::credentials &val)
    {
        unpack(cursor, (eap::config&)val);
        unpack(cursor, val.m_identity   );
    }


    ///
    /// Packs a password based method credentials
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     Credentials to pack
    ///
    inline void pack(_Inout_ unsigned char *&cursor, _In_ const eap::credentials_pass &val)
    {
        pack(cursor, (const eap::credentials&)val);
        pack(cursor, val.m_password              );
    }


    ///
    /// Returns packed size of a password based method credentials
    ///
    /// \param[in] val  Credentials to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    inline size_t get_pk_size(const eap::credentials_pass &val)
    {
        return
            get_pk_size((const eap::credentials&)val) +
            get_pk_size(val.m_password              );
    }


    ///
    /// Unpacks a password based method credentials
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     Credentials to unpack to
    ///
    inline void unpack(_Inout_ const unsigned char *&cursor, _Out_ eap::credentials_pass &val)
    {
        unpack(cursor, (eap::credentials&)val);
        unpack(cursor, val.m_password        );
    }
}

#endif
