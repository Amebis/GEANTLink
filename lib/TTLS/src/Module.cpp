/*
    Copyright 2015-2020 Amebis
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

#if EAP_INNER_EAPHOST
#pragma comment(lib, "Eappprxy.lib")
#endif

using namespace std;
using namespace winstd;


//////////////////////////////////////////////////////////////////////
// eap::peer_tls_tunnel
//////////////////////////////////////////////////////////////////////

eap::peer_tls_tunnel::peer_tls_tunnel(_In_ eap_type_t eap_method) : peer_tls_base(eap_method)
{
}


void eap::peer_tls_tunnel::initialize()
{
    peer_tls_base::initialize();

#if EAP_INNER_EAPHOST
    // Initialize EapHost based inner authentication methods.
    DWORD dwResult = EapHostPeerInitialize();
    if (dwResult != ERROR_SUCCESS)
        throw win_runtime_error(dwResult, __FUNCTION__ " EapHostPeerConfigBlob2Xml failed.");
#endif
}


void eap::peer_tls_tunnel::shutdown()
{
#if EAP_INNER_EAPHOST
    // Uninitialize EapHost. It was initialized for EapHost based inner authentication methods.
    EapHostPeerUninitialize();
#endif

    peer_tls_base::shutdown();
}


_Success_(return != 0) const eap::config_method_with_cred* eap::peer_tls_tunnel::combine_credentials(
    _In_                             DWORD                   dwFlags,
    _In_                       const config_connection       &cfg,
    _In_count_(dwUserDataSize) const BYTE                    *pUserData,
    _In_                             DWORD                   dwUserDataSize,
    _Inout_                          credentials_connection& cred_out,
    _In_                             HANDLE                  hTokenImpersonateUser)
{
#if EAP_USE_NATIVE_CREDENTIAL_CACHE
    // Unpack cached credentials.
    credentials_connection cred_in(*this, cfg);
    if (dwUserDataSize)
        unpack(cred_in, pUserData, dwUserDataSize);
#else
    UNREFERENCED_PARAMETER(pUserData);
    UNREFERENCED_PARAMETER(dwUserDataSize);
#endif

    // Iterate over providers.
    for (auto cfg_prov = cfg.m_providers.cbegin(), cfg_prov_end = cfg.m_providers.cend(); cfg_prov != cfg_prov_end; ++cfg_prov) {
        wstring target_name(std::move(cfg_prov->get_id()));

        // Get method configuration.
        if (cfg_prov->m_methods.empty()) {
            log_event(&EAPMETHOD_TRACE_EVT_CRED_NO_METHOD, event_data(target_name), event_data::blank);
            continue;
        }
        const config_method_tls_tunnel *cfg_method = dynamic_cast<const config_method_tls_tunnel*>(cfg_prov->m_methods.front().get());
        assert(cfg_method);

        // Combine credentials. We could use eap::credentials_tls_tunnel() to do all the work, but we would not know which credentials is missing then.
        credentials_tls_tunnel *cred = dynamic_cast<credentials_tls_tunnel*>(cfg_method->make_credentials());
        cred_out.m_cred.reset(cred);
#if EAP_USE_NATIVE_CREDENTIAL_CACHE
        bool has_cached = cred_in.m_cred && cred_in.match(*cfg_prov);
#endif

        // Combine outer credentials.
        LPCTSTR _target_name = (dwFlags & EAP_FLAG_GUEST_ACCESS) == 0 ? target_name.c_str() : NULL;
        eap::credentials::source_t src_outer = cred->credentials_tls::combine(
            dwFlags,
            hTokenImpersonateUser,
#if EAP_USE_NATIVE_CREDENTIAL_CACHE
            has_cached ? cred_in.m_cred.get() : NULL,
#else
            NULL,
#endif
            *cfg_method,
            cfg_method->m_allow_save ? _target_name : NULL);
        if (src_outer == eap::credentials::source_t::unknown) {
            log_event(&EAPMETHOD_TRACE_EVT_CRED_UNKNOWN3, event_data(target_name), event_data((unsigned int)eap_type_t::tls), event_data::blank);
            continue;
        }

        // Combine inner credentials.
        eap::credentials::source_t src_inner = cred->m_inner->combine(
            dwFlags,
            hTokenImpersonateUser,
#if EAP_USE_NATIVE_CREDENTIAL_CACHE
            has_cached ? dynamic_cast<credentials_tls_tunnel*>(cred_in.m_cred.get())->m_inner.get() : NULL,
#else
            NULL,
#endif
            *cfg_method->m_inner,
            cfg_method->m_inner->m_allow_save ? _target_name : NULL);
        if (src_inner == eap::credentials::source_t::unknown) {
            log_event(&EAPMETHOD_TRACE_EVT_CRED_UNKNOWN3, event_data(target_name), event_data((unsigned int)cfg_method->m_inner->get_method_id()), event_data::blank);
            continue;
        }

        // If we got here, we have all credentials we need. But, wait!

        if ((dwFlags & EAP_FLAG_MACHINE_AUTH) == 0) {
            if (config_method::status_t::cred_begin <= cfg_method->m_last_status && cfg_method->m_last_status < config_method::status_t::cred_end) {
                // Outer: Credentials failed on last connection attempt.
                log_event(&EAPMETHOD_TRACE_EVT_CRED_PROBLEM2, event_data(target_name), event_data((unsigned int)eap_type_t::tls), event_data((unsigned int)cfg_method->m_last_status), event_data::blank);
                continue;
            }

            if (config_method::status_t::cred_begin <= cfg_method->m_inner->m_last_status && cfg_method->m_inner->m_last_status < config_method::status_t::cred_end) {
                // Inner: Credentials failed on last connection attempt.
                log_event(&EAPMETHOD_TRACE_EVT_CRED_PROBLEM2, event_data(target_name), event_data((unsigned int)cfg_method->m_inner->get_method_id()), event_data((unsigned int)cfg_method->m_inner->m_last_status), event_data::blank);
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
// eap::peer_ttls
//////////////////////////////////////////////////////////////////////

eap::peer_ttls::peer_ttls() : peer_tls_tunnel(eap_type_t::ttls)
{
}


eap::config_method* eap::peer_ttls::make_config()
{
    return new config_method_ttls(*this, 0);
}


eap::method* eap::peer_ttls::make_method(_In_ config_method &cfg, _In_ credentials &cred)
{
    unique_ptr<method> meth_inner;
    auto &cfg_ttls    = dynamic_cast<config_method_ttls&>(cfg);
    auto  cfg_inner   = cfg_ttls.m_inner.get();
    auto &cred_tunnel = dynamic_cast<credentials_tls_tunnel&>(cred);
    auto  cred_inner  = cred_tunnel.m_inner.get();

    assert(cfg_inner);
    switch (cfg_inner->get_method_id()) {
    case eap_type_t::legacy_pap:
        meth_inner.reset(
            new method_pap_diameter(*this, dynamic_cast<config_method_pap&>(*cfg_inner), dynamic_cast<credentials_pass&>(*cred_inner)));
        break;

    case eap_type_t::legacy_mschapv2:
        meth_inner.reset(
            new method_mschapv2_diameter(*this, dynamic_cast<config_method_mschapv2&>(*cfg_inner), dynamic_cast<credentials_pass&>(*cred_inner)));
        break;

    case eap_type_t::mschapv2:
        meth_inner.reset(
            new method_eapmsg  (*this,
            new method_eap     (*this, eap_type_t::mschapv2, *cred_inner,
            new method_mschapv2(*this, dynamic_cast<config_method_mschapv2&>(*cfg_inner), dynamic_cast<credentials_pass&>(*cred_inner)))));
        break;

    case eap_type_t::gtc:
        meth_inner.reset(
            new method_eapmsg(*this,
            new method_eap   (*this, eap_type_t::gtc, *cred_inner,
            new method_gtc   (*this, dynamic_cast<config_method_eapgtc&>(*cfg_inner), *cred_inner))));
        break;

#if EAP_INNER_EAPHOST
    case eap_type_t::undefined:
        meth_inner.reset(
            new method_eapmsg (*this,
            new method_eaphost(*this, dynamic_cast<config_method_eaphost&>(*cfg_inner), dynamic_cast<credentials_eaphost&>(*cred_inner))));
        break;
#endif

    default:
        throw invalid_argument(__FUNCTION__ " Unsupported inner authentication method.");
    }

    return
        new method_eap   (*this, eap_type_t::ttls, cred,
        new method_defrag(*this, 0 /* Schannel supports retrieving keying material for EAP-TTLSv0 only. */,
        new method_ttls  (*this, cfg_ttls, cred_tunnel, meth_inner.release())));
}
