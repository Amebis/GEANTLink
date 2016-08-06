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


bool eap::peer_ttls::initialize(_Out_ EAP_ERROR **ppEapError)
{
    UNREFERENCED_PARAMETER(ppEapError);

    // MSI's feature completeness check removed: It might invoke UI (prompt user for missing MSI),
    // which would be disasterous in EapHost system service.
#if 0
    // Perform the Microsoft Installer's feature completeness check manually.
    // If execution got this far in the first place (dependent DLLs are present and loadable).
    // Furthermore, this increments program usage counter.
    if (MsiQueryFeatureState(_T(PRODUCT_VERSION_GUID), _T("featEAPTTLS")) != INSTALLSTATE_UNKNOWN)
        MsiUseFeature(_T(PRODUCT_VERSION_GUID), _T("featEAPTTLS"));
#endif

    return true;
}


bool eap::peer_ttls::shutdown(_Out_ EAP_ERROR **ppEapError)
{
    UNREFERENCED_PARAMETER(ppEapError);
    return true;
}


bool eap::peer_ttls::get_identity(
    _In_                                   DWORD     dwFlags,
    _In_count_(dwConnectionDataSize) const BYTE      *pConnectionData,
    _In_                                   DWORD     dwConnectionDataSize,
    _In_count_(dwUserDataSize)       const BYTE      *pUserData,
    _In_                                   DWORD     dwUserDataSize,
    _Out_                                  BYTE      **ppUserDataOut,
    _Out_                                  DWORD     *pdwUserDataOutSize,
    _In_                                   HANDLE    hTokenImpersonateUser,
    _Out_                                  BOOL      *pfInvokeUI,
    _Out_                                  WCHAR     **ppwszIdentity,
    _Out_                                  EAP_ERROR **ppEapError)
{
    assert(pfInvokeUI);
    assert(ppwszIdentity);
    assert(ppEapError);

    // Unpack configuration.
    config_provider_list cfg(*this);
    if (!unpack(cfg, pConnectionData, dwConnectionDataSize, ppEapError))
        return false;
    else if (cfg.m_providers.empty() || cfg.m_providers.front().m_methods.empty()) {
        *ppEapError = make_error(ERROR_INVALID_PARAMETER, _T(__FUNCTION__) _T(" Configuration has no providers and/or methods."));
        return false;
    }

    // Get method configuration.
    const config_provider &cfg_prov(cfg.m_providers.front());
    const config_method_ttls *cfg_method = dynamic_cast<const config_method_ttls*>(cfg_prov.m_methods.front().get());
    assert(cfg_method);
    const config_method_pap *cfg_inner_pap = dynamic_cast<const config_method_pap*>(cfg_method->m_inner.get());

    // Unpack cached credentials.
    credentials_ttls cred_in(*this);
    if (dwUserDataSize && !unpack(cred_in, pUserData, dwUserDataSize, ppEapError))
        return false;

    credentials_ttls cred_out(*this);

    // Determine credential storage target(s). Also used as user-friendly method name for logging.
    eap_type_t type_inner;
    if (cfg_inner_pap) {
        type_inner = eap_type_pap;
    } else {
        assert(0); // Unsupported inner authentication method type.
        type_inner = eap_type_undefined;
    }

    bool
        is_outer_set = false,
        is_inner_set = false;

    if (dwUserDataSize) {
        // Try cached credentials.

        if (!is_outer_set) {
            // Outer TLS: Using EAP service cached credentials.
            cred_out.m_outer = cred_in.m_outer;
            log_event(&EAPMETHOD_TRACE_EVT_CRED_CACHED1, event_data((DWORD)eap_type_tls), event_data(cred_out.m_outer.get_name()), event_data::blank);
            is_outer_set = true;
        }

        if (!is_inner_set && cred_in.m_inner) {
            // Inner PAP: Using EAP service cached credentials.
            cred_out.m_inner.reset((credentials*)cred_in.m_inner->clone());
            log_event(&EAPMETHOD_TRACE_EVT_CRED_CACHED1, event_data((DWORD)type_inner), event_data(cred_out.m_inner->get_name()), event_data::blank);
            is_inner_set = true;
        }
    }

    if (!is_outer_set && cfg_method->m_outer.m_use_preshared) {
        // Outer TLS: Using preshared credentials.
        cred_out.m_outer = *(credentials_tls*)cfg_method->m_outer.m_preshared.get();
        log_event(&EAPMETHOD_TRACE_EVT_CRED_PRESHARED1, event_data((DWORD)eap_type_tls), event_data(cred_out.m_outer.get_name()), event_data::blank);
        is_outer_set = true;
    }

    if (!is_inner_set) {
        if (cfg_inner_pap) {
            if (cfg_inner_pap->m_use_preshared) {
                // Inner PAP: Using preshared credentials.
                cred_out.m_inner.reset((credentials*)cfg_inner_pap->m_preshared->clone());
                log_event(&EAPMETHOD_TRACE_EVT_CRED_PRESHARED1, event_data((DWORD)type_inner), event_data(cred_out.m_inner->get_name()), event_data::blank);
                is_inner_set = true;
            }
        } else
            assert(0); // Unsupported inner authentication method type.
    }

    if ((dwFlags & EAP_FLAG_GUEST_ACCESS) == 0 && (!is_outer_set || !is_inner_set)) {
        // Not a guest & some credentials may be missing: Try to load credentials from Windows Credential Manager.

        // Change user context. When applicable.
        bool user_ctx_changed = hTokenImpersonateUser && ImpersonateLoggedOnUser(hTokenImpersonateUser);

        if (!is_outer_set) {
            credentials_tls cred_loaded(*this);
            if (cred_loaded.retrieve(cfg_prov.m_id.c_str(), ppEapError)) {
                // Outer TLS: Using stored credentials.
                cred_out.m_outer = std::move(cred_loaded);
                log_event(&EAPMETHOD_TRACE_EVT_CRED_STORED1, event_data((DWORD)eap_type_tls), event_data(cred_out.m_outer.get_name()), event_data::blank);
                is_outer_set = true;
            } else {
                // Not actually an error.
                free_error_memory(*ppEapError);
            }
        }

        if (!is_inner_set) {
            unique_ptr<credentials> cred_loaded;
            if (cfg_inner_pap) cred_loaded.reset(new credentials_pap(*this));
            else               assert(0); // Unsupported inner authentication method type.
            if (cred_loaded->retrieve(cfg_prov.m_id.c_str(), ppEapError)) {
                // Inner PAP: Using stored credentials.
                cred_out.m_inner = std::move(cred_loaded);
                log_event(&EAPMETHOD_TRACE_EVT_CRED_STORED1, event_data((DWORD)type_inner), event_data(cred_out.m_inner->get_name()), event_data::blank);
                is_inner_set = true;
            } else {
                // Not actually an error.
                free_error_memory(*ppEapError);
            }
        }

        // Restore user context.
        if (user_ctx_changed) RevertToSelf();
    }

    *pfInvokeUI = FALSE;
    if ((dwFlags & EAP_FLAG_MACHINE_AUTH) == 0) {
        // Per-user authentication
        if (!is_outer_set) {
            log_event(&EAPMETHOD_TRACE_EVT_CRED_INVOKE_UI1, event_data((DWORD)eap_type_tls), event_data::blank);
            *pfInvokeUI = TRUE;
            return true;
        }

        if (!is_inner_set) {
            log_event(&EAPMETHOD_TRACE_EVT_CRED_INVOKE_UI1, event_data((DWORD)type_inner), event_data::blank);
            *pfInvokeUI = TRUE;
            return true;
        }
    } else {
        // Per-machine authentication
        if (!is_outer_set || !is_inner_set) {
            *ppEapError = make_error(ERROR_NO_SUCH_USER, _T(__FUNCTION__) _T(" Credentials for per-machine authentication not available."));
            return false;
        }
    }

    // If we got here, we have all credentials we need.

    // Build our identity. ;)
    wstring identity(std::move(cfg_method->get_public_identity(cred_out)));
    log_event(&EAPMETHOD_TRACE_EVT_CRED_OUTER_ID1, event_data((DWORD)eap_type_ttls), event_data(identity), event_data::blank);
    size_t size = sizeof(WCHAR)*(identity.length() + 1);
    *ppwszIdentity = (WCHAR*)alloc_memory(size);
    memcpy(*ppwszIdentity, identity.c_str(), size);

    // Pack credentials.
    return pack(cred_out, ppUserDataOut, pdwUserDataOutSize, ppEapError);
}


bool eap::peer_ttls::get_method_properties(
    _In_                                   DWORD                     dwVersion,
    _In_                                   DWORD                     dwFlags,
    _In_                                   HANDLE                    hUserImpersonationToken,
    _In_count_(dwConnectionDataSize) const BYTE                      *pConnectionData,
    _In_                                   DWORD                     dwConnectionDataSize,
    _In_count_(dwUserDataSize)       const BYTE                      *pUserData,
    _In_                                   DWORD                     dwUserDataSize,
    _Out_                                  EAP_METHOD_PROPERTY_ARRAY *pMethodPropertyArray,
    _Out_                                  EAP_ERROR                 **ppEapError)
{
    UNREFERENCED_PARAMETER(dwVersion);
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(hUserImpersonationToken);
    UNREFERENCED_PARAMETER(pConnectionData);
    UNREFERENCED_PARAMETER(dwConnectionDataSize);
    UNREFERENCED_PARAMETER(pUserData);
    UNREFERENCED_PARAMETER(dwUserDataSize);
    assert(pMethodPropertyArray);
    assert(ppEapError);

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
    if (!pMethodPropertyArray->pMethodProperty) {
        *ppEapError = make_error(ERROR_OUTOFMEMORY, _T(__FUNCTION__) _T(" Error allocating memory for propery array."));
        return false;
    }

    // Copy properties.
    memcpy(pMethodPropertyArray->pMethodProperty, properties.data(), sizeof(EAP_METHOD_PROPERTY) * dwCount);
    pMethodPropertyArray->dwNumberOfProperties = dwCount;

    return true;
}


bool eap::peer_ttls::credentials_xml2blob(
    _In_                                   DWORD       dwFlags,
    _In_                                   IXMLDOMNode *pConfigRoot,
    _In_count_(dwConnectionDataSize) const BYTE        *pConnectionData,
    _In_                                   DWORD       dwConnectionDataSize,
    _Out_                                  BYTE        **ppCredentialsOut,
    _Out_                                  DWORD       *pdwCredentialsOutSize,
    _Out_                                  EAP_ERROR   **ppEapError)
{
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(pConnectionData);
    UNREFERENCED_PARAMETER(dwConnectionDataSize);

    // Load credentials from XML.
    credentials_ttls cred(*this);
    if (!cred.load(pConfigRoot, ppEapError))
        return false;

    // Pack credentials.
    return pack(cred, ppCredentialsOut, pdwCredentialsOutSize, ppEapError);
}


bool eap::peer_ttls::begin_session(
    _In_                                   DWORD              dwFlags,
    _In_                           const   EapAttributes      *pAttributeArray,
    _In_                                   HANDLE             hTokenImpersonateUser,
    _In_count_(dwConnectionDataSize) const BYTE               *pConnectionData,
    _In_                                   DWORD              dwConnectionDataSize,
    _In_count_(dwUserDataSize)       const BYTE               *pUserData,
    _In_                                   DWORD              dwUserDataSize,
    _In_                                   DWORD              dwMaxSendPacketSize,
    _Out_                                  EAP_SESSION_HANDLE *phSession,
    _Out_                                  EAP_ERROR          **ppEapError)
{
    *phSession = NULL;

    // Allocate new session.
    unique_ptr<session> s(new session(*this));
    if (!s) {
        *ppEapError = make_error(ERROR_OUTOFMEMORY, _T(__FUNCTION__) _T(" Error allocating memory for EAP-TTLS session."));
        return false;
    }

    // Unpack configuration.
    config_provider_list cfg(*this);
    if (!unpack(cfg, pConnectionData, dwConnectionDataSize, ppEapError))
        return false;
    else if (cfg.m_providers.empty() || cfg.m_providers.front().m_methods.empty()) {
        *ppEapError = make_error(ERROR_INVALID_PARAMETER, _T(__FUNCTION__) _T(" Configuration has no providers and/or methods."));
        return false;
    }

    // Copy method configuration.
    const config_provider &cfg_prov(cfg.m_providers.front());
    s->m_cfg = *dynamic_cast<const config_method_ttls*>(cfg_prov.m_methods.front().get());

    // Unpack credentials.
    if (!unpack(s->m_cred, pUserData, dwUserDataSize, ppEapError))
        return false;

    // Initialize method.
    if (!s->m_method.begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, dwMaxSendPacketSize, ppEapError))
        return false;

    *phSession = s.release();
    return true;
}


bool eap::peer_ttls::end_session(_In_ EAP_SESSION_HANDLE hSession, _Out_ EAP_ERROR **ppEapError)
{
    assert(hSession);
    UNREFERENCED_PARAMETER(ppEapError); // What could possibly go wrong when destroying!? ;)

    // End the session.
    session *s = static_cast<session*>(hSession);
    //s->end(ppEapError);
    delete s;

    return true;
}


bool eap::peer_ttls::process_request_packet(
    _In_                                       EAP_SESSION_HANDLE  hSession,
    _In_bytecount_(dwReceivedPacketSize) const EapPacket           *pReceivedPacket,
    _In_                                       DWORD               dwReceivedPacketSize,
    _Out_                                      EapPeerMethodOutput *pEapOutput,
    _Out_                                      EAP_ERROR           **ppEapError)
{
    assert(dwReceivedPacketSize == ntohs(*(WORD*)pReceivedPacket->Length));
    return static_cast<session*>(hSession)->m_method.process_request_packet(pReceivedPacket, dwReceivedPacketSize, pEapOutput, ppEapError);
}


bool eap::peer_ttls::get_response_packet(
    _In_                               EAP_SESSION_HANDLE hSession,
    _Inout_bytecap_(*dwSendPacketSize) EapPacket          *pSendPacket,
    _Inout_                            DWORD              *pdwSendPacketSize,
    _Out_                              EAP_ERROR          **ppEapError)
{
    return static_cast<session*>(hSession)->m_method.get_response_packet(pSendPacket, pdwSendPacketSize, ppEapError);
}


bool eap::peer_ttls::get_result(
    _In_  EAP_SESSION_HANDLE        hSession,
    _In_  EapPeerMethodResultReason reason,
    _Out_ EapPeerMethodResult       *ppResult,
    _Out_ EAP_ERROR                 **ppEapError)
{
    UNREFERENCED_PARAMETER(hSession);
    UNREFERENCED_PARAMETER(reason);
    UNREFERENCED_PARAMETER(ppResult);
    assert(ppEapError);

    *ppEapError = make_error(ERROR_NOT_SUPPORTED, _T(__FUNCTION__) _T(" Not supported."));
    return false;
}


bool eap::peer_ttls::get_ui_context(
    _In_  EAP_SESSION_HANDLE hSession,
    _Out_ BYTE               **ppUIContextData,
    _Out_ DWORD              *pdwUIContextDataSize,
    _Out_ EAP_ERROR          **ppEapError)
{
    UNREFERENCED_PARAMETER(hSession);
    UNREFERENCED_PARAMETER(ppUIContextData);
    UNREFERENCED_PARAMETER(pdwUIContextDataSize);
    assert(ppEapError);

    *ppEapError = make_error(ERROR_NOT_SUPPORTED, _T(__FUNCTION__) _T(" Not supported."));
    return false;
}


bool eap::peer_ttls::set_ui_context(
    _In_                                  EAP_SESSION_HANDLE  hSession,
    _In_count_(dwUIContextDataSize) const BYTE                *pUIContextData,
    _In_                                  DWORD               dwUIContextDataSize,
    _In_                            const EapPeerMethodOutput *pEapOutput,
    _Out_                                 EAP_ERROR           **ppEapError)
{
    UNREFERENCED_PARAMETER(hSession);
    UNREFERENCED_PARAMETER(pUIContextData);
    UNREFERENCED_PARAMETER(dwUIContextDataSize);
    UNREFERENCED_PARAMETER(pEapOutput);
    assert(ppEapError);

    *ppEapError = make_error(ERROR_NOT_SUPPORTED, _T(__FUNCTION__) _T(" Not supported."));
    return false;
}


bool eap::peer_ttls::get_response_attributes(
    _In_  EAP_SESSION_HANDLE hSession,
    _Out_ EapAttributes      *pAttribs,
    _Out_ EAP_ERROR          **ppEapError)
{
    UNREFERENCED_PARAMETER(hSession);
    UNREFERENCED_PARAMETER(pAttribs);
    UNREFERENCED_PARAMETER(ppEapError);
    assert(ppEapError);

    *ppEapError = make_error(ERROR_NOT_SUPPORTED, _T(__FUNCTION__) _T(" Not supported."));
    return false;
}


bool eap::peer_ttls::set_response_attributes(
    _In_       EAP_SESSION_HANDLE  hSession,
    _In_ const EapAttributes       *pAttribs,
    _Out_      EapPeerMethodOutput *pEapOutput,
    _Out_      EAP_ERROR           **ppEapError)
{
    UNREFERENCED_PARAMETER(hSession);
    UNREFERENCED_PARAMETER(pAttribs);
    UNREFERENCED_PARAMETER(pEapOutput);
    UNREFERENCED_PARAMETER(ppEapError);
    assert(ppEapError);

    *ppEapError = make_error(ERROR_NOT_SUPPORTED, _T(__FUNCTION__) _T(" Not supported."));
    return false;
}
