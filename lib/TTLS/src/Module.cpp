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
// eap::peer_ttls
//////////////////////////////////////////////////////////////////////

eap::peer_ttls::peer_ttls() : peer(eap_type_ttls)
{
}


eap::config_method* eap::peer_ttls::make_config_method()
{
    return new config_method_ttls(*this);
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
}


void eap::peer_ttls::shutdown()
{
}


void eap::peer_ttls::get_identity(
    _In_                                   DWORD  dwFlags,
    _In_count_(dwConnectionDataSize) const BYTE   *pConnectionData,
    _In_                                   DWORD  dwConnectionDataSize,
    _In_count_(dwUserDataSize)       const BYTE   *pUserData,
    _In_                                   DWORD  dwUserDataSize,
    _Inout_                                BYTE   **ppUserDataOut,
    _Inout_                                DWORD  *pdwUserDataOutSize,
    _In_                                   HANDLE hTokenImpersonateUser,
    _Inout_                                BOOL   *pfInvokeUI,
    _Inout_                                WCHAR  **ppwszIdentity)
{
    assert(pfInvokeUI);
    assert(ppwszIdentity);

    // Unpack configuration.
    config_connection cfg(*this);
    unpack(cfg, pConnectionData, dwConnectionDataSize);
    if (cfg.m_providers.empty() || cfg.m_providers.front().m_methods.empty())
        throw invalid_argument(__FUNCTION__ " Configuration has no providers and/or methods.");

    // Get method configuration.
    const config_provider &cfg_prov(cfg.m_providers.front());
    const config_method_ttls *cfg_method = dynamic_cast<const config_method_ttls*>(cfg_prov.m_methods.front().get());
    assert(cfg_method);

#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
    // Unpack cached credentials.
    credentials_ttls cred_in(*this);
    if (dwUserDataSize)
        unpack(cred_in, pUserData, dwUserDataSize);
#else
    UNREFERENCED_PARAMETER(pUserData);
    UNREFERENCED_PARAMETER(dwUserDataSize);
#endif

    credentials_ttls cred_out(*this);

    // Determine inner credential type.
    eap_type_t type_inner;
    if (dynamic_cast<const config_method_pap*>(cfg_method->m_inner.get())) {
        cred_out.m_inner.reset(new credentials_pap(*this));
        type_inner = eap_type_pap;
    } else {
        assert(0); // Unsupported inner authentication method type.
        type_inner = eap_type_undefined;
    }

    {
        // Combine credentials.
        user_impersonator impersonating(hTokenImpersonateUser);
        pair<eap::credentials::source_t, eap::credentials::source_t> cred_source(cred_out.combine(
#ifdef EAP_USE_NATIVE_CREDENTIAL_CACHE
            &cred_in,
#else
            NULL,
#endif
            *cfg_method,
            (dwFlags & EAP_FLAG_GUEST_ACCESS) == 0 ? cfg_prov.m_id.c_str() : NULL));

        // If either of credentials is unknown, request UI.
        *pfInvokeUI = cred_source.first == eap::credentials::source_unknown || cred_source.second == eap::credentials::source_unknown ? TRUE : FALSE;
    }

    if (*pfInvokeUI) {
        if ((dwFlags & EAP_FLAG_MACHINE_AUTH) == 0) {
            // Per-user authentication
            log_event(&EAPMETHOD_TRACE_EVT_CRED_INVOKE_UI2, event_data::blank);
            return;
        } else {
            // Per-machine authentication
            throw win_runtime_error(ERROR_NO_SUCH_USER, __FUNCTION__ " Credentials for per-machine authentication not available.");
        }
    }

    // If we got here, we have all credentials we need. But, wait!

    if (cfg_method->m_auth_failed) {
        // Outer TLS: Credentials failed on last connection attempt.
        log_event(&EAPMETHOD_TRACE_EVT_CRED_PROBLEM, event_data((unsigned int)eap_type_tls), event_data::blank);
        *pfInvokeUI = TRUE;
        return;
    }

    if (cfg_method->m_inner->m_auth_failed) {
        // Inner: Credentials failed on last connection attempt.
        log_event(&EAPMETHOD_TRACE_EVT_CRED_PROBLEM, event_data((unsigned int)type_inner), event_data::blank);
        *pfInvokeUI = TRUE;
        return;
    }

    // Build our identity. ;)
    wstring identity(std::move(cfg_method->get_public_identity(cred_out)));
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
    _Inout_                                EAP_METHOD_PROPERTY_ARRAY *pMethodPropertyArray)
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
    _Inout_                                BYTE        **ppCredentialsOut,
    _Inout_                                DWORD       *pdwCredentialsOutSize)
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

    // Initialize method.
    s->m_method.begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, dwMaxSendPacketSize);

    return s.release();
}


void eap::peer_ttls::end_session(_In_ EAP_SESSION_HANDLE hSession)
{
    assert(hSession);

    // End the session.
    session *s = static_cast<session*>(hSession);
    //s->end(ppEapError);
    delete s;
}


void eap::peer_ttls::process_request_packet(
    _In_                                       EAP_SESSION_HANDLE  hSession,
    _In_bytecount_(dwReceivedPacketSize) const EapPacket           *pReceivedPacket,
    _In_                                       DWORD               dwReceivedPacketSize,
    _Inout_                                    EapPeerMethodOutput *pEapOutput)
{
    assert(dwReceivedPacketSize == ntohs(*(WORD*)pReceivedPacket->Length));
    static_cast<session*>(hSession)->m_method.process_request_packet(pReceivedPacket, dwReceivedPacketSize, pEapOutput);
}


void eap::peer_ttls::get_response_packet(
    _In_                               EAP_SESSION_HANDLE hSession,
    _Inout_bytecap_(*dwSendPacketSize) EapPacket          *pSendPacket,
    _Inout_                            DWORD              *pdwSendPacketSize)
{
    static_cast<session*>(hSession)->m_method.get_response_packet(pSendPacket, pdwSendPacketSize);
}


void eap::peer_ttls::get_result(
    _In_    EAP_SESSION_HANDLE        hSession,
    _In_    EapPeerMethodResultReason reason,
    _Inout_ EapPeerMethodResult       *ppResult)
{
    static_cast<session*>(hSession)->m_method.get_result(reason, ppResult);
}


void eap::peer_ttls::get_ui_context(
    _In_    EAP_SESSION_HANDLE hSession,
    _Inout_ BYTE               **ppUIContextData,
    _Inout_ DWORD              *pdwUIContextDataSize)
{
    UNREFERENCED_PARAMETER(hSession);
    UNREFERENCED_PARAMETER(ppUIContextData);
    UNREFERENCED_PARAMETER(pdwUIContextDataSize);

    throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Not supported.");
}


void eap::peer_ttls::set_ui_context(
    _In_                                  EAP_SESSION_HANDLE  hSession,
    _In_count_(dwUIContextDataSize) const BYTE                *pUIContextData,
    _In_                                  DWORD               dwUIContextDataSize,
    _In_                            const EapPeerMethodOutput *pEapOutput)
{
    UNREFERENCED_PARAMETER(hSession);
    UNREFERENCED_PARAMETER(pUIContextData);
    UNREFERENCED_PARAMETER(dwUIContextDataSize);
    UNREFERENCED_PARAMETER(pEapOutput);

    throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Not supported.");
}


void eap::peer_ttls::get_response_attributes(
    _In_    EAP_SESSION_HANDLE hSession,
    _Inout_ EapAttributes      *pAttribs)
{
    UNREFERENCED_PARAMETER(hSession);
    UNREFERENCED_PARAMETER(pAttribs);

    throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Not supported.");
}


void eap::peer_ttls::set_response_attributes(
            _In_       EAP_SESSION_HANDLE  hSession,
            _In_ const EapAttributes       *pAttribs,
            _Inout_    EapPeerMethodOutput *pEapOutput)
{
    UNREFERENCED_PARAMETER(hSession);
    UNREFERENCED_PARAMETER(pAttribs);
    UNREFERENCED_PARAMETER(pEapOutput);

    throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Not supported.");
}
