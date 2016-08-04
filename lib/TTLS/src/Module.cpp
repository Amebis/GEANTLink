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

eap::peer_ttls::peer_ttls() : peer<config_method_ttls, credentials_ttls, bool, bool>(eap_type_ttls)
{
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
    _In_           DWORD            dwFlags,
    _In_     const config_providers &cfg,
    _In_opt_ const credentials_type *cred_in,
    _Inout_        credentials_type &cred_out,
    _In_           HANDLE           hTokenImpersonateUser,
    _Out_          BOOL             *pfInvokeUI,
    _Out_          WCHAR            **ppwszIdentity,
    _Out_          EAP_ERROR        **ppEapError)
{
    assert(pfInvokeUI);
    assert(ppwszIdentity);
    assert(ppEapError);

    if (cfg.m_providers.empty() || cfg.m_providers.front().m_methods.empty()) {
        *ppEapError = make_error(ERROR_INVALID_PARAMETER, _T(__FUNCTION__) _T(" Configuration has no providers and/or methods."));
        return false;
    }

    // Get method configuration.
    const config_provider &cfg_prov(cfg.m_providers.front());
    const config_method_ttls *cfg_method = dynamic_cast<const config_method_ttls*>(cfg_prov.m_methods.front().get());
    assert(cfg_method);
    const config_method_pap *cfg_inner_pap = dynamic_cast<const config_method_pap*>(cfg_method->m_inner.get());

    // Determine credential storage target(s). Also used as user-friendly method name for logging.
    wstring target_outer(std::move(cred_out.m_outer.target_suffix()));
    wstring target_inner;

    bool
        is_outer_set = false,
        is_inner_set = false;

    if (cred_in) {
        // Try cached credentials.

        if (!is_outer_set) {
            // Outer TLS: Using EAP service cached credentials.
            cred_out.m_outer = cred_in->m_outer;
            log_event(&EAPMETHOD_TRACE_EVT_CRED_CACHED, event_data(target_outer), event_data(cred_out.m_outer.get_name()), event_data::blank);
            is_outer_set = true;
        }

        if (!is_inner_set && cred_in->m_inner) {
            // Inner PAP: Using EAP service cached credentials.
            cred_out.m_inner.reset((credentials*)cred_in->m_inner->clone());
            log_event(&EAPMETHOD_TRACE_EVT_CRED_CACHED, event_data(target_inner), event_data(cred_out.m_inner->get_name()), event_data::blank);
            is_inner_set = true;
        }
    }

    if (!is_outer_set && cfg_method->m_outer.m_use_preshared) {
        // Outer TLS: Using preshared credentials.
        cred_out.m_outer = (credentials_tls&)cfg_method->m_outer.m_preshared;
        log_event(&EAPMETHOD_TRACE_EVT_CRED_PRESHARED, event_data(target_outer), event_data(cred_out.m_outer.get_name()), event_data::blank);
        is_outer_set = true;
    }

    if (!is_inner_set) {
        if (cfg_inner_pap) {
            target_inner = L"PAP";
            if (cfg_inner_pap->m_use_preshared) {
                // Inner PAP: Using preshared credentials.
                cred_out.m_inner.reset((credentials*)cfg_inner_pap->m_preshared.clone());
                log_event(&EAPMETHOD_TRACE_EVT_CRED_PRESHARED, event_data(target_inner), event_data(cred_out.m_inner->get_name()), event_data::blank);
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
                log_event(&EAPMETHOD_TRACE_EVT_CRED_STORED, event_data(target_outer), event_data(cred_out.m_outer.get_name()), event_data::blank);
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
                log_event(&EAPMETHOD_TRACE_EVT_CRED_STORED, event_data(target_inner), event_data(cred_out.m_inner->get_name()), event_data::blank);
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
            log_event(&EAPMETHOD_TRACE_EVT_CRED_INVOKE_UI, event_data(target_outer), event_data::blank);
            *pfInvokeUI = TRUE;
            return true;
        }

        if (!is_inner_set) {
            log_event(&EAPMETHOD_TRACE_EVT_CRED_INVOKE_UI, event_data(target_inner), event_data::blank);
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
    log_event(&EAPMETHOD_TRACE_EVT_CRED_OUTER_ID, event_data(L"TTLS"), event_data(identity), event_data::blank);
    size_t size = sizeof(WCHAR)*(identity.length() + 1);
    *ppwszIdentity = (WCHAR*)alloc_memory(size);
    memcpy(*ppwszIdentity, identity.c_str(), size);

    return true;
}


bool eap::peer_ttls::get_method_properties(
    _In_        DWORD                     dwVersion,
    _In_        DWORD                     dwFlags,
    _In_        HANDLE                    hUserImpersonationToken,
    _In_  const config_providers          &cfg,
    _In_  const credentials_type          &cred,
    _Out_       EAP_METHOD_PROPERTY_ARRAY *pMethodPropertyArray,
    _Out_       EAP_ERROR                 **ppEapError)
{
    UNREFERENCED_PARAMETER(dwVersion);
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(hUserImpersonationToken);
    UNREFERENCED_PARAMETER(cfg);
    UNREFERENCED_PARAMETER(cred);
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
