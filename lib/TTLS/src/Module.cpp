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

#pragma comment(lib, "Eappprxy.lib")

using namespace std;
using namespace winstd;


//////////////////////////////////////////////////////////////////////
// eap::peer_ttls
//////////////////////////////////////////////////////////////////////

eap::peer_ttls::peer_ttls() : peer(eap_type_ttls)
{
}


eap::config_method* eap::peer_ttls::make_config_method()
{
    return new config_method_ttls(*this, 0);
}


void eap::peer_ttls::initialize()
{
    // MSI's feature completeness check removed: It might invoke UI (prompt user for missing MSI),
    // which would be disasterous in EapHost system service.
#if 0
    // Perform the Microsoft Installer's feature completeness check manually.
    // If execution got this far in the first place (dependent DLLs are present and loadable).
    // Furthermore, this increments program usage counter.
    if (MsiQueryFeatureState(_T(PRODUCT_VERSION_GUID), _T("featEAPTTLS")) != INSTALLSTATE_UNKNOWN)
        MsiUseFeature(_T(PRODUCT_VERSION_GUID), _T("featEAPTTLS"));
#endif

    // Initialize EapHost based inner authentication methods.
    DWORD dwResult = EapHostPeerInitialize();
    if (dwResult != ERROR_SUCCESS)
        throw win_runtime_error(dwResult, __FUNCTION__ " EapHostPeerConfigBlob2Xml failed.");
}


void eap::peer_ttls::shutdown()
{
    // Uninitialize EapHost. It was initialized for EapHost based inner authentication methods.
    EapHostPeerUninitialize();
}


void eap::peer_ttls::get_identity(
    _In_                                   DWORD  dwFlags,
    _In_count_(dwConnectionDataSize) const BYTE   *pConnectionData,
    _In_                                   DWORD  dwConnectionDataSize,
    _In_count_(dwUserDataSize)       const BYTE   *pUserData,
    _In_                                   DWORD  dwUserDataSize,
    _Out_                                  BYTE   **ppUserDataOut,
    _Out_                                  DWORD  *pdwUserDataOutSize,
    _In_                                   HANDLE hTokenImpersonateUser,
    _Out_                                  BOOL   *pfInvokeUI,
    _Out_                                  WCHAR  **ppwszIdentity)
{
    assert(pfInvokeUI);
    assert(ppwszIdentity);

    // Unpack configuration.
    config_connection cfg(*this);
    unpack(cfg, pConnectionData, dwConnectionDataSize);

    // Combine credentials.
    credentials_connection cred_out(*this, cfg);
    const config_method_ttls *cfg_method = combine_credentials(dwFlags, cfg, pUserData, dwUserDataSize, cred_out, hTokenImpersonateUser);

    if (cfg_method) {
        // No UI will be necessary.
        *pfInvokeUI = FALSE;
    } else {
        // Credentials missing or incomplete.
        if ((dwFlags & EAP_FLAG_MACHINE_AUTH) == 0) {
            // Per-user authentication, request UI.
            log_event(&EAPMETHOD_TRACE_EVT_CRED_INVOKE_UI2, event_data::blank);
            *pfInvokeUI = TRUE;
            return;
        } else {
            // Per-machine authentication, cannot use UI.
            throw win_runtime_error(ERROR_NO_SUCH_USER, __FUNCTION__ " Credentials for per-machine authentication not available.");
        }
    }

    // Build our identity. ;)
    wstring identity(std::move(cfg_method->get_public_identity(*dynamic_cast<const credentials_ttls*>(cred_out.m_cred.get()))));
    log_event(&EAPMETHOD_TRACE_EVT_CRED_OUTER_ID1, event_data((unsigned int)eap_type_ttls), event_data(identity), event_data::blank);
    size_t size = sizeof(WCHAR)*(identity.length() + 1);
    *ppwszIdentity = (WCHAR*)alloc_memory(size);
    memcpy(*ppwszIdentity, identity.c_str(), size);

    // Pack credentials.
    pack(cred_out, ppUserDataOut, pdwUserDataOutSize);
}


void eap::peer_ttls::get_method_properties(
    _In_                                   DWORD                     dwVersion,
    _In_                                   DWORD                     dwFlags,
    _In_                                   HANDLE                    hUserImpersonationToken,
    _In_count_(dwConnectionDataSize) const BYTE                      *pConnectionData,
    _In_                                   DWORD                     dwConnectionDataSize,
    _In_count_(dwUserDataSize)       const BYTE                      *pUserData,
    _In_                                   DWORD                     dwUserDataSize,
    _Out_                                  EAP_METHOD_PROPERTY_ARRAY *pMethodPropertyArray)
{
    UNREFERENCED_PARAMETER(dwVersion);
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(hUserImpersonationToken);
    UNREFERENCED_PARAMETER(pConnectionData);
    UNREFERENCED_PARAMETER(dwConnectionDataSize);
    UNREFERENCED_PARAMETER(pUserData);
    UNREFERENCED_PARAMETER(dwUserDataSize);
    assert(pMethodPropertyArray);

    vector<EAP_METHOD_PROPERTY> properties;
    properties.reserve(20);

    properties.push_back(eap_method_prop(emptPropCipherSuiteNegotiation,     TRUE));
    properties.push_back(eap_method_prop(emptPropMutualAuth,                 TRUE));
    properties.push_back(eap_method_prop(emptPropIntegrity,                  TRUE));
    properties.push_back(eap_method_prop(emptPropReplayProtection,           TRUE));
    properties.push_back(eap_method_prop(emptPropConfidentiality,            TRUE));
    properties.push_back(eap_method_prop(emptPropKeyDerivation,              TRUE));
    properties.push_back(eap_method_prop(emptPropKeyStrength128,             TRUE));
    properties.push_back(eap_method_prop(emptPropDictionaryAttackResistance, TRUE));
    properties.push_back(eap_method_prop(emptPropFastReconnect,              TRUE));
    properties.push_back(eap_method_prop(emptPropCryptoBinding,              TRUE));
    properties.push_back(eap_method_prop(emptPropSessionIndependence,        TRUE));
    properties.push_back(eap_method_prop(emptPropFragmentation,              TRUE));
    properties.push_back(eap_method_prop(emptPropStandalone,                 TRUE));
    properties.push_back(eap_method_prop(emptPropMppeEncryption,             TRUE));
    properties.push_back(eap_method_prop(emptPropTunnelMethod,               TRUE));
    properties.push_back(eap_method_prop(emptPropSupportsConfig,             TRUE));
    properties.push_back(eap_method_prop(emptPropMachineAuth,                TRUE));
    properties.push_back(eap_method_prop(emptPropUserAuth,                   TRUE));
    properties.push_back(eap_method_prop(emptPropIdentityPrivacy,            TRUE));
    properties.push_back(eap_method_prop(emptPropSharedStateEquivalence,     TRUE));

    // Allocate property array.
    DWORD dwCount = (DWORD)properties.size();
    pMethodPropertyArray->pMethodProperty = (EAP_METHOD_PROPERTY*)alloc_memory(sizeof(EAP_METHOD_PROPERTY) * dwCount);

    // Copy properties.
    memcpy(pMethodPropertyArray->pMethodProperty, properties.data(), sizeof(EAP_METHOD_PROPERTY) * dwCount);
    pMethodPropertyArray->dwNumberOfProperties = dwCount;
}


void eap::peer_ttls::credentials_xml2blob(
    _In_                                   DWORD       dwFlags,
    _In_                                   IXMLDOMNode *pConfigRoot,
    _In_count_(dwConnectionDataSize) const BYTE        *pConnectionData,
    _In_                                   DWORD       dwConnectionDataSize,
    _Out_                                  BYTE        **ppCredentialsOut,
    _Out_                                  DWORD       *pdwCredentialsOutSize)
{
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(pConnectionData);
    UNREFERENCED_PARAMETER(dwConnectionDataSize);

    // Load credentials from XML.
    credentials_ttls cred(*this);
    cred.load(pConfigRoot);

    // Pack credentials.
    pack(cred, ppCredentialsOut, pdwCredentialsOutSize);
}


EAP_SESSION_HANDLE eap::peer_ttls::begin_session(
    _In_                                   DWORD              dwFlags,
    _In_                           const   EapAttributes      *pAttributeArray,
    _In_                                   HANDLE             hTokenImpersonateUser,
    _In_count_(dwConnectionDataSize) const BYTE               *pConnectionData,
    _In_                                   DWORD              dwConnectionDataSize,
    _In_count_(dwUserDataSize)       const BYTE               *pUserData,
    _In_                                   DWORD              dwUserDataSize,
    _In_                                   DWORD              dwMaxSendPacketSize)
{
    // Create new session.
    unique_ptr<session> s(new session(*this));

    // Unpack configuration.
    unpack(s->m_cfg, pConnectionData, dwConnectionDataSize);

    // Unpack credentials.
    unpack(s->m_cred, pUserData, dwUserDataSize);

    config_method_ttls *cfg_method;

    for (auto cfg_prov = s->m_cfg.m_providers.begin(), cfg_prov_end = s->m_cfg.m_providers.end();; ++cfg_prov) {
        if (cfg_prov != cfg_prov_end) {
            if (s->m_cred.match(*cfg_prov)) {
                // Matching provider found.
                if (cfg_prov->m_methods.empty())
                    throw invalid_argument(string_printf(__FUNCTION__ " %ls provider has no methods.", cfg_prov->get_id().c_str()).c_str());
                cfg_method = dynamic_cast<config_method_ttls*>(cfg_prov->m_methods.front().get());
                break;
            }
        } else
            throw invalid_argument(string_printf(__FUNCTION__ " Credentials do not match to any provider within this connection configuration (provider: %ls).", s->m_cred.get_id().c_str()).c_str());
    }

    // We have configuration, we have credentials, create method.
    unique_ptr<method> meth_inner;
    auto  cfg_inner        = cfg_method->m_inner.get();
    auto cred_inner        = dynamic_cast<credentials_ttls*>(s->m_cred.m_cred.get())->m_inner.get();
#ifdef EAP_INNER_EAPHOST
    auto cfg_inner_eaphost = dynamic_cast<config_method_eaphost*>(cfg_inner);
    if (!cfg_inner_eaphost)
#endif
    {
        // Native inner methods
        switch (cfg_inner->get_method_id()) {
        case eap_type_legacy_pap     : meth_inner.reset(new method_pap              (*this, dynamic_cast<config_method_pap     &>(*cfg_inner), dynamic_cast<credentials_pass&>(*cred_inner))); break;
        case eap_type_legacy_mschapv2: meth_inner.reset(new method_mschapv2_diameter(*this, dynamic_cast<config_method_mschapv2&>(*cfg_inner), dynamic_cast<credentials_pass&>(*cred_inner))); break;
        case eap_type_mschapv2       : meth_inner.reset(
                                           new method_eapmsg  (*this, cred_inner->get_identity().c_str(),
                                           new method_eap     (*this, eap_type_mschapv2,
                                           new method_mschapv2(*this, dynamic_cast<config_method_mschapv2&>(*cfg_inner), dynamic_cast<credentials_pass&>(*cred_inner))))); break;
        default: throw invalid_argument(__FUNCTION__ " Unsupported inner authentication method.");
        }
    }
#ifdef EAP_INNER_EAPHOST
    else {
        // EapHost inner method
        meth_inner.reset(
            new method_eapmsg (*this, cred_inner->get_identity().c_str(),
            new method_eaphost(*this, *cfg_inner_eaphost, dynamic_cast<credentials_eaphost&>(*cred_inner))));
    }
#endif
    s->m_method.reset(
        new method_eap   (*this, eap_type_ttls,
        new method_defrag(*this,
        new method_ttls  (*this, *cfg_method, *dynamic_cast<credentials_ttls*>(s->m_cred.m_cred.get()), meth_inner.release()))));

    // Initialize method.
    s->m_method->begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, dwMaxSendPacketSize);

    return s.release();
}


void eap::peer_ttls::end_session(_In_ EAP_SESSION_HANDLE hSession)
{
    assert(hSession);

    // End the session.
    auto s = static_cast<session*>(hSession);
    //s->end(ppEapError);
    delete s;
}


void eap::peer_ttls::process_request_packet(
    _In_                                       EAP_SESSION_HANDLE  hSession,
    _In_bytecount_(dwReceivedPacketSize) const EapPacket           *pReceivedPacket,
    _In_                                       DWORD               dwReceivedPacketSize,
    _Out_                                      EapPeerMethodOutput *pEapOutput)
{
    assert(dwReceivedPacketSize == ntohs(*(WORD*)pReceivedPacket->Length));
    assert(pEapOutput);
    pEapOutput->action              = static_cast<session*>(hSession)->m_method->process_request_packet(pReceivedPacket, dwReceivedPacketSize);
    pEapOutput->fAllowNotifications = TRUE;
}


void eap::peer_ttls::get_response_packet(
    _In_                               EAP_SESSION_HANDLE hSession,
    _Inout_bytecap_(*dwSendPacketSize) EapPacket          *pSendPacket,
    _Inout_                            DWORD              *pdwSendPacketSize)
{
    assert(pdwSendPacketSize);
    assert(pSendPacket || !*pdwSendPacketSize);

    sanitizing_blob packet;
    static_cast<session*>(hSession)->m_method->get_response_packet(packet, *pdwSendPacketSize);
    assert(packet.size() <= *pdwSendPacketSize);

    memcpy(pSendPacket, packet.data(), *pdwSendPacketSize = (DWORD)packet.size());
}


void eap::peer_ttls::get_result(
    _In_    EAP_SESSION_HANDLE        hSession,
    _In_    EapPeerMethodResultReason reason,
    _Inout_ EapPeerMethodResult       *pResult)
{
    auto s = static_cast<session*>(hSession);

    s->m_method->get_result(reason, pResult);

    // Do not report failure to EapHost, as it will not save updated configuration then. But we need it to save it, to alert user on next connection attempt.
    // EapHost is well aware of the failed condition.
    //pResult->fIsSuccess          = FALSE;
    //pResult->dwFailureReasonCode = EAP_E_AUTHENTICATION_FAILED;
    pResult->fIsSuccess          = TRUE;
    pResult->dwFailureReasonCode = ERROR_SUCCESS;

    if (pResult->fSaveConnectionData) {
        pack(s->m_cfg, &pResult->pConnectionData, &pResult->dwSizeofConnectionData);
        if (s->m_blob_cfg)
            free_memory(s->m_blob_cfg);
        s->m_blob_cfg = pResult->pConnectionData;
    }

#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
    pResult->fSaveUserData = TRUE;
    pack(s->m_cred, &pResult->pUserData, &pResult->dwSizeofUserData);
    if (s->m_blob_cred)
        free_memory(s->m_blob_cred);
    s->m_blob_cred = pResult->pUserData;
#endif
}


void eap::peer_ttls::get_ui_context(
    _In_  EAP_SESSION_HANDLE hSession,
    _Out_ BYTE               **ppUIContextData,
    _Out_ DWORD              *pdwUIContextDataSize)
{
    static_cast<session*>(hSession)->m_method->get_ui_context(ppUIContextData, pdwUIContextDataSize);
}


void eap::peer_ttls::set_ui_context(
    _In_                                  EAP_SESSION_HANDLE  hSession,
    _In_count_(dwUIContextDataSize) const BYTE                *pUIContextData,
    _In_                                  DWORD               dwUIContextDataSize,
    _Out_                                 EapPeerMethodOutput *pEapOutput)
{
    assert(pEapOutput);
    pEapOutput->action              = static_cast<session*>(hSession)->m_method->set_ui_context(pUIContextData, dwUIContextDataSize);
    pEapOutput->fAllowNotifications = TRUE;
}


void eap::peer_ttls::get_response_attributes(
    _In_    EAP_SESSION_HANDLE hSession,
    _Inout_ EapAttributes      *pAttribs)
{
    static_cast<session*>(hSession)->m_method->get_response_attributes(pAttribs);
}


void eap::peer_ttls::set_response_attributes(
    _In_       EAP_SESSION_HANDLE  hSession,
    _In_ const EapAttributes       *pAttribs,
    _Out_      EapPeerMethodOutput *pEapOutput)
{
    assert(pEapOutput);
    pEapOutput->action              = static_cast<session*>(hSession)->m_method->set_response_attributes(pAttribs);
    pEapOutput->fAllowNotifications = TRUE;
}


const eap::config_method_ttls* eap::peer_ttls::combine_credentials(
    _In_                             DWORD                   dwFlags,
    _In_                       const config_connection       &cfg,
    _In_count_(dwUserDataSize) const BYTE                    *pUserData,
    _In_                             DWORD                   dwUserDataSize,
    _Out_                            credentials_connection& cred_out,
    _In_                             HANDLE                  hTokenImpersonateUser)
{
#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
    // Unpack cached credentials.
    credentials_connection cred_in(*this, cfg);
    if (dwUserDataSize)
        unpack(cred_in, pUserData, dwUserDataSize);
#else
    UNREFERENCED_PARAMETER(pUserData);
    UNREFERENCED_PARAMETER(dwUserDataSize);
#endif

    for (auto cfg_prov = cfg.m_providers.cbegin(), cfg_prov_end = cfg.m_providers.cend(); cfg_prov != cfg_prov_end; ++cfg_prov) {
        wstring target_name(std::move(cfg_prov->get_id()));

        // Get method configuration.
        if (cfg_prov->m_methods.empty()) {
            log_event(&EAPMETHOD_TRACE_EVT_CRED_NO_METHOD, event_data(target_name), event_data::blank);
            continue;
        }
        const config_method_ttls *cfg_method = dynamic_cast<const config_method_ttls*>(cfg_prov->m_methods.front().get());
        assert(cfg_method);

        // Combine credentials. We could use eap::credentials_ttls() to do all the work, but we would not know which credentials is missing then.
        credentials_ttls *cred = dynamic_cast<credentials_ttls*>(cfg_method->make_credentials());
        cred_out.m_cred.reset(cred);
#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
        bool has_cached = cred_in.m_cred && cred_in.match(*cfg_prov);
#endif

        // Combine outer credentials.
        LPCTSTR _target_name = (dwFlags & EAP_FLAG_GUEST_ACCESS) == 0 ? target_name.c_str() : NULL;
        eap::credentials::source_t src_outer = cred->credentials_tls::combine(
            dwFlags,
            hTokenImpersonateUser,
#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
            has_cached ? cred_in.m_cred.get() : NULL,
#else
            NULL,
#endif
            *cfg_method,
            cfg_method->m_allow_save ? _target_name : NULL);
        if (src_outer == eap::credentials::source_unknown) {
            log_event(&EAPMETHOD_TRACE_EVT_CRED_UNKNOWN3, event_data(target_name), event_data((unsigned int)eap_type_tls), event_data::blank);
            continue;
        }

        // Combine inner credentials.
        eap::credentials::source_t src_inner = cred->m_inner->combine(
            dwFlags,
            hTokenImpersonateUser,
#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
            has_cached ? dynamic_cast<credentials_ttls*>(cred_in.m_cred.get())->m_inner.get() : NULL,
#else
            NULL,
#endif
            *cfg_method->m_inner,
            cfg_method->m_inner->m_allow_save ? _target_name : NULL);
        if (src_inner == eap::credentials::source_unknown) {
            log_event(&EAPMETHOD_TRACE_EVT_CRED_UNKNOWN3, event_data(target_name), event_data((unsigned int)cfg_method->m_inner->get_method_id()), event_data::blank);
            continue;
        }

        // If we got here, we have all credentials we need. But, wait!

        if ((dwFlags & EAP_FLAG_MACHINE_AUTH) == 0) {
            if (config_method::status_cred_begin <= cfg_method->m_last_status && cfg_method->m_last_status < config_method::status_cred_end) {
                // Outer: Credentials failed on last connection attempt.
                log_event(&EAPMETHOD_TRACE_EVT_CRED_PROBLEM1, event_data(target_name), event_data((unsigned int)eap_type_tls), event_data::blank);
                continue;
            }

            if (config_method::status_cred_begin <= cfg_method->m_inner->m_last_status && cfg_method->m_inner->m_last_status < config_method::status_cred_end) {
                // Inner: Credentials failed on last connection attempt.
                log_event(&EAPMETHOD_TRACE_EVT_CRED_PROBLEM1, event_data(target_name), event_data((unsigned int)cfg_method->m_inner->get_method_id()), event_data::blank);
                continue;
            }
        }

        cred_out.m_namespace = cfg_prov->m_namespace;
        cred_out.m_id        = cfg_prov->m_id;
        return cfg_method;
    }

    return NULL;
}


//////////////////////////////////////////////////////////////////////
// eap::peer_ttls::session
//////////////////////////////////////////////////////////////////////

eap::peer_ttls::session::session(_In_ module &mod) :
    m_module(mod),
    m_cfg(mod),
    m_cred(mod, m_cfg),
    m_blob_cfg(NULL)
#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
    , m_blob_cred(NULL)
#endif
{}


eap::peer_ttls::session::~session()
{
    if (m_blob_cfg)
        m_module.free_memory(m_blob_cfg);

#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
    if (m_blob_cred)
        m_module.free_memory(m_blob_cred);
#endif
}
