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

eap::peer_ttls::peer_ttls() : peer<config_method_ttls, credentials_ttls, bool, bool>(type_ttls)
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
    _In_          DWORD            dwFlags,
    _In_    const config_providers &cfg,
    _Inout_       credentials_type &cred,
    _In_          HANDLE           hTokenImpersonateUser,
    _Out_         BOOL             *pfInvokeUI,
    _Out_         WCHAR            **ppwszIdentity,
    _Out_         EAP_ERROR        **ppEapError)
{
    assert(pfInvokeUI);
    assert(ppwszIdentity);
    assert(ppEapError);

    if (cfg.m_providers.empty() || cfg.m_providers.front().m_methods.empty()) {
        *ppEapError = make_error(ERROR_INVALID_PARAMETER, _T(__FUNCTION__) _T(" Configuration has no providers and/or methods."));
        return false;
    }

    const config_provider &cfg_prov(cfg.m_providers.front());
    const config_method_ttls *cfg_method = dynamic_cast<const config_method_ttls*>(cfg_prov.m_methods.front().get());

    bool outer_set = false;
    assert(cfg_method);
    if (cfg_method->m_preshared) {
        // Outer TLS identity: Preshared credentials.
        (credentials_tls&)cred = (credentials_tls&)*cfg_method->m_preshared;
        log_event(&EAPMETHOD_TRACE_EVT_CRED_PRESHARED, event_data(cred.credentials_tls::target_suffix()), event_data(cred.credentials_tls::get_name()), event_data::blank);
        outer_set = true;
    }

    bool inner_set = false;
    const config_method_pap *cfg_inner_pap = dynamic_cast<const config_method_pap*>(cfg_method->m_inner.get());
    if (cfg_inner_pap) {
        if (cfg_inner_pap->m_preshared) {
            // Inner PAP identity: Preshared credentials.
            cred.m_inner.reset((credentials*)cfg_inner_pap->m_preshared->clone());
            log_event(&EAPMETHOD_TRACE_EVT_CRED_PRESHARED, event_data(cred.m_inner->target_suffix()), event_data(cred.m_inner->get_name()), event_data::blank);
            inner_set = true;
        }
    } else
        assert(0); // Unsupported inner authentication method type.

    if ((dwFlags & EAP_FLAG_GUEST_ACCESS) == 0 && (!outer_set || !inner_set)) {
        // Not a guest && some credentials may be missing: Try to load credentials from Windows Credential Manager.

        // Change user context. When applicable.
        bool user_ctx_changed = hTokenImpersonateUser && ImpersonateLoggedOnUser(hTokenImpersonateUser);

        if (!outer_set) {
            if (cred.credentials_tls::retrieve(cfg_prov.m_id.c_str(), ppEapError)) {
                // Outer TLS identity: Stored credentials.
                log_event(&EAPMETHOD_TRACE_EVT_CRED_STORED, event_data(cred.credentials_tls::target_suffix()), event_data(cred.credentials_tls::get_name()), event_data::blank);
                outer_set = true;
            } else {
                // Not actually an error.
                free_error_memory(*ppEapError);
            }
        }

        if (!inner_set) {
            unique_ptr<credentials> cred_loaded;
            if (cfg_inner_pap)
                cred_loaded.reset(new credentials_pap(*this));
            else
                assert(0); // Unsupported inner authentication method type.

            if (cred_loaded->retrieve(cfg_prov.m_id.c_str(), ppEapError)) {
                // Inner PAP identity: Stored credentials.
                cred.m_inner = std::move(cred_loaded);
                log_event(&EAPMETHOD_TRACE_EVT_CRED_STORED, event_data(cred.m_inner->target_suffix()), event_data(cred.m_inner->get_name()), event_data::blank);
                inner_set = true;
            } else {
                // Not actually an error.
                free_error_memory(*ppEapError);
            }
        }

        // Restore user context.
        if (user_ctx_changed) RevertToSelf();
    }

    // Test if we have credentials available anyway (from before - EAP can cache them).

    // Note: Outer TLS credentials can be empty!
    //if (!cred.credentials_tls::empty())
    //    outer_set = true;

    if (cred.m_inner && !cred.m_inner->empty())
        inner_set = true;

    *pfInvokeUI = FALSE;
    if ((dwFlags & EAP_FLAG_MACHINE_AUTH) == 0) {
        // Per-user authentication
        if (!outer_set) {
            log_event(&EAPMETHOD_TRACE_EVT_CRED_INVOKE_UI, event_data(cred.credentials_tls::target_suffix()), event_data::blank);
            *pfInvokeUI = TRUE;
            return true;
        }

        if (!inner_set) {
            log_event(&EAPMETHOD_TRACE_EVT_CRED_INVOKE_UI, event_data(cred.m_inner->target_suffix()), event_data::blank);
            *pfInvokeUI = TRUE;
            return true;
        }
    } else {
        // Per-machine authentication
        if (!outer_set || !inner_set) {
            *ppEapError = make_error(ERROR_NO_SUCH_USER, _T(__FUNCTION__) _T(" Credentials for per-machine authentication not available."));
            return false;
        }
    }

    // If we got here, we have all credentials we need.

    // Build our identity. ;)
    wstring identity;
    if (cfg_method->m_anonymous_identity.empty()) {
        // Use the true identity. Outer has the right-of-way.
        identity = std::move(cred.get_identity());
    } else if (cfg_method->m_anonymous_identity.compare(L"@") == 0) {
        // Strip username part from identity (RFC 4822).
        identity = std::move(cred.get_identity());
        wstring::size_type offset = identity.find(L'@');
        if (offset != wstring::npos) identity.erase(0, offset);
    } else {
        // Use configured identity.
        identity = cfg_method->m_anonymous_identity;
    }

    log_event(&EAPMETHOD_TRACE_EVT_CRED_OUTER_ID, event_data(L"TTLS"), event_data(identity), event_data::blank);

    // Save the identity for EAPHost.
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
    _Out_       EAP_ERROR                 **ppEapError) const
{
    UNREFERENCED_PARAMETER(dwVersion);
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(hUserImpersonationToken);
    UNREFERENCED_PARAMETER(cfg);
    UNREFERENCED_PARAMETER(cred);
    UNREFERENCED_PARAMETER(pMethodPropertyArray);
    UNREFERENCED_PARAMETER(ppEapError);

    *ppEapError = make_error(ERROR_NOT_SUPPORTED, _T(__FUNCTION__) _T(" Not supported."));
    return false;
}
