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

using namespace std;
using namespace winstd;


//////////////////////////////////////////////////////////////////////
// eap::peer_tls
//////////////////////////////////////////////////////////////////////

eap::peer_tls::peer_tls(_In_ eap_type_t eap_method) : peer(eap_method)
{
}


void eap::peer_tls::shutdown()
{
    // Signal all certificate revocation verify threads to abort and wait for them (10sec max).
    vector<HANDLE> chks;
    chks.reserve(m_crl_checkers.size());
    for (auto chk = m_crl_checkers.begin(), chk_end = m_crl_checkers.end(); chk != chk_end; ++chk) {
        SetEvent(chk->m_abort);
        chks.push_back(chk->m_thread);
    }
    WaitForMultipleObjects((DWORD)chks.size(), chks.data(), TRUE, 10000);

    peer::shutdown();
}


void eap::peer_tls::get_identity(
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
    assert(ppUserDataOut);
    assert(pdwUserDataOutSize);
    assert(pfInvokeUI);
    assert(ppwszIdentity);

    // Unpack configuration.
    config_connection cfg(*this);
    unpack(cfg, pConnectionData, dwConnectionDataSize);

    // Combine credentials.
    credentials_connection cred_out(*this, cfg);
    const config_method_with_cred *cfg_method = combine_credentials(dwFlags, cfg, pUserData, dwUserDataSize, cred_out, hTokenImpersonateUser);

    if (cfg_method) {
        // No UI will be necessary.
        *pfInvokeUI = FALSE;
    } else {
        // Credentials missing or incomplete.
        if ((dwFlags & EAP_FLAG_MACHINE_AUTH) == 0) {
            // Per-user authentication, request UI.
            log_event(&EAPMETHOD_TRACE_EVT_CRED_INVOKE_UI2, event_data::blank);
            *ppUserDataOut = NULL;
            *pdwUserDataOutSize = 0;
            *pfInvokeUI = TRUE;
            *ppwszIdentity = NULL;
            return;
        } else {
            // Per-machine authentication, cannot use UI.
            throw win_runtime_error(ERROR_NO_SUCH_USER, __FUNCTION__ " Credentials for per-machine authentication not available.");
        }
    }

    // Build our identity. ;)
    wstring identity(std::move(cfg_method->get_public_identity(*cred_out.m_cred.get())));
    log_event(&EAPMETHOD_TRACE_EVT_CRED_OUTER_ID1, event_data((unsigned int)cfg_method->get_method_id()), event_data(identity), event_data::blank);
    size_t size = sizeof(WCHAR)*(identity.length() + 1);
    *ppwszIdentity = (WCHAR*)alloc_memory(size);
    memcpy(*ppwszIdentity, identity.c_str(), size);

    // Pack credentials.
    pack(cred_out, ppUserDataOut, pdwUserDataOutSize);
}


void eap::peer_tls::get_method_properties(
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


void eap::peer_tls::credentials_xml2blob(
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
    unique_ptr<config_method> cfg(make_config_method());
    unique_ptr<credentials> cred(cfg->make_credentials());
    cred->load(pConfigRoot);

    // Pack credentials.
    pack(*cred, ppCredentialsOut, pdwCredentialsOutSize);
}


EAP_SESSION_HANDLE eap::peer_tls::begin_session(
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

    // Look-up the provider.
    config_method_tls *cfg_method;
    for (auto cfg_prov = s->m_cfg.m_providers.begin(), cfg_prov_end = s->m_cfg.m_providers.end();; ++cfg_prov) {
        if (cfg_prov != cfg_prov_end) {
            if (s->m_cred.match(*cfg_prov)) {
                // Matching provider found.
                if (cfg_prov->m_methods.empty())
                    throw invalid_argument(string_printf(__FUNCTION__ " %ls provider has no methods.", cfg_prov->get_id().c_str()));
                cfg_method = dynamic_cast<config_method_tls*>(cfg_prov->m_methods.front().get());
                break;
            }
        } else
            throw invalid_argument(string_printf(__FUNCTION__ " Credentials do not match to any provider within this connection configuration (provider: %ls).", s->m_cred.get_id().c_str()));
    }

    // We have configuration, we have credentials, create method.
    s->m_method.reset(make_method(*cfg_method, *dynamic_cast<credentials_tls*>(s->m_cred.m_cred.get())));

    // Initialize method.
    s->m_method->begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, dwMaxSendPacketSize);

    return s.release();
}


void eap::peer_tls::end_session(_In_ EAP_SESSION_HANDLE hSession)
{
    assert(hSession);

    // End the session.
    auto s = static_cast<session*>(hSession);
    s->m_method->end_session();
    delete s;
}


void eap::peer_tls::process_request_packet(
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


void eap::peer_tls::get_response_packet(
    _In_                                   EAP_SESSION_HANDLE hSession,
    _Out_bytecapcount_(*pdwSendPacketSize) EapPacket          *pSendPacket,
    _Inout_                                DWORD              *pdwSendPacketSize)
{
    assert(pdwSendPacketSize);
    assert(pSendPacket || !*pdwSendPacketSize);

    sanitizing_blob packet;
    static_cast<session*>(hSession)->m_method->get_response_packet(packet, *pdwSendPacketSize);
    assert(packet.size() <= *pdwSendPacketSize);

    memcpy(pSendPacket, packet.data(), *pdwSendPacketSize = (DWORD)packet.size());
}


void eap::peer_tls::get_result(
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

#if EAP_USE_NATIVE_CREDENTIAL_CACHE
    pResult->fSaveUserData = TRUE;
    pack(s->m_cred, &pResult->pUserData, &pResult->dwSizeofUserData);
    if (s->m_blob_cred)
        free_memory(s->m_blob_cred);
    s->m_blob_cred = pResult->pUserData;
#endif
}


void eap::peer_tls::get_ui_context(
    _In_  EAP_SESSION_HANDLE hSession,
    _Out_ BYTE               **ppUIContextData,
    _Out_ DWORD              *pdwUIContextDataSize)
{
    assert(ppUIContextData);
    assert(pdwUIContextDataSize);

    auto s = static_cast<session*>(hSession);

    // Get context data from method.
    ui_context ctx(s->m_cfg, s->m_cred);
    s->m_method->get_ui_context(ctx.m_data);

    // Pack context data.
    pack(ctx, ppUIContextData, pdwUIContextDataSize);
    if (s->m_blob_ui_ctx)
        free_memory(s->m_blob_ui_ctx);
    s->m_blob_ui_ctx = *ppUIContextData;
}


void eap::peer_tls::set_ui_context(
    _In_                                  EAP_SESSION_HANDLE  hSession,
    _In_count_(dwUIContextDataSize) const BYTE                *pUIContextData,
    _In_                                  DWORD               dwUIContextDataSize,
    _Out_                                 EapPeerMethodOutput *pEapOutput)
{
    assert(pEapOutput);

    sanitizing_blob data(std::move(unpack(pUIContextData, dwUIContextDataSize)));
    pEapOutput->action              = static_cast<session*>(hSession)->m_method->set_ui_context(data.data(), (DWORD)data.size());
    pEapOutput->fAllowNotifications = TRUE;
}


void eap::peer_tls::get_response_attributes(
    _In_  EAP_SESSION_HANDLE hSession,
    _Out_ EapAttributes      *pAttribs)
{
    static_cast<session*>(hSession)->m_method->get_response_attributes(pAttribs);
}


void eap::peer_tls::set_response_attributes(
    _In_       EAP_SESSION_HANDLE  hSession,
    _In_ const EapAttributes       *pAttribs,
    _Out_      EapPeerMethodOutput *pEapOutput)
{
    assert(pEapOutput);
    pEapOutput->action              = static_cast<session*>(hSession)->m_method->set_response_attributes(pAttribs);
    pEapOutput->fAllowNotifications = TRUE;
}


void eap::peer_tls::spawn_crl_check(_Inout_ winstd::cert_context &&cert)
{
    // Create the thread and add it to the list.
    m_crl_checkers.push_back(std::move(crl_checker(*this, std::move(cert))));

    // Now the thread is in-place, start it.
    crl_checker &chk = m_crl_checkers.back();
    chk.m_thread = CreateThread(NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(crl_checker::verify), &chk, 0, NULL);
}


//////////////////////////////////////////////////////////////////////
// eap::peer_tls_tunnel::session
//////////////////////////////////////////////////////////////////////

eap::peer_tls::session::session(_In_ module &mod) :
    m_module(mod),
    m_cfg(mod),
    m_cred(mod, m_cfg),
    m_blob_cfg(NULL),
#if EAP_USE_NATIVE_CREDENTIAL_CACHE
    m_blob_cred(NULL),
#endif
    m_blob_ui_ctx(NULL)
{}


eap::peer_tls::session::~session()
{
    if (m_blob_cfg)
        m_module.free_memory(m_blob_cfg);

#if EAP_USE_NATIVE_CREDENTIAL_CACHE
    if (m_blob_cred)
        m_module.free_memory(m_blob_cred);
#endif

    if (m_blob_ui_ctx)
        m_module.free_memory(m_blob_ui_ctx);
}


//////////////////////////////////////////////////////////////////////
// eap::peer_tls::crl_checker
//////////////////////////////////////////////////////////////////////

eap::peer_tls::crl_checker::crl_checker(_In_ module &mod, _Inout_ winstd::cert_context &&cert) :
    m_module(mod),
    m_cert  (std::move(cert)),
    m_abort (CreateEvent(NULL, TRUE, FALSE, NULL))
{
}


eap::peer_tls::crl_checker::crl_checker(_Inout_ crl_checker &&other) noexcept :
    m_module(          other.m_module ),
    m_thread(std::move(other.m_thread)),
    m_abort (std::move(other.m_abort )),
    m_cert  (std::move(other.m_cert  ))
{
}


eap::peer_tls::crl_checker& eap::peer_tls::crl_checker::operator=(_Inout_ crl_checker &&other) noexcept
{
    if (this != std::addressof(other)) {
        assert(std::addressof(m_module) == std::addressof(other.m_module)); // Move threads within same module only!
        m_thread = std::move(other.m_thread);
        m_abort  = std::move(other.m_abort );
        m_cert   = std::move(other.m_cert  );
    }

    return *this;
}


DWORD WINAPI eap::peer_tls::crl_checker::verify(_In_ crl_checker *obj)
{
    // Initialize COM.
    com_initializer com_init(NULL);

    // Wait for 5sec for the link to become online. (Hopefuly!)
    if (WaitForSingleObject(obj->m_abort, 5000) == WAIT_OBJECT_0) {
        // Aborted.
        return 1;
    }

    // Prepare a list of certificates forming certificate chain.
    list<cert_context> context_data;
    for (cert_context c(obj->m_cert); c;) {
        context_data.push_back(std::move(c));
        DWORD flags = 0;
        c = CertGetIssuerCertificateFromStore(obj->m_cert->hCertStore, context_data.back(), NULL, &flags);
        if (!c) break;
    }

    // Create an array of pointers to CERT_CONTEXT required by CertVerifyRevocation().
    vector<PCERT_CONTEXT> context;
    context.reserve(context_data.size());
    for (auto c = context_data.cbegin(), c_end = context_data.cend(); c != c_end; ++c)
        context.push_back(const_cast<PCERT_CONTEXT>(c->operator PCCERT_CONTEXT()));

    CERT_REVOCATION_STATUS status_rev = { sizeof(CERT_REVOCATION_STATUS) };
    for (auto c = context.begin(), c_end = context.end(); c != c_end;) {
        // Check for thread abort signal.
        if (WaitForSingleObject(obj->m_abort, 0) == WAIT_OBJECT_0)
            return 1;

        // Perform revocation check.
        if (!CertVerifyRevocation(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, CERT_CONTEXT_REVOCATION_TYPE,
            (DWORD)(c_end - c), reinterpret_cast<PVOID*>(&*c),
            CERT_VERIFY_REV_CHAIN_FLAG, NULL, &status_rev))
        {
            PCCERT_CONTEXT cert = *(c + status_rev.dwIndex);
            wstring subj;
            if (!CertGetNameStringW(cert, CERT_NAME_DNS_TYPE, CERT_NAME_STR_ENABLE_PUNYCODE_FLAG, NULL, subj))
                sprintf(subj, L"(error %u)", GetLastError());

            switch (status_rev.dwError) {
            case CRYPT_E_NO_REVOCATION_CHECK:
                // Revocation check could not be performed.
                c += (size_t)status_rev.dwIndex + 1;
                if (c == c_end) {
                    // This "error" is expected for the root CA certificate.
                } else {
                    // This really was an error, as it appeared before the root CA cerficate in the chain.
                    obj->m_module.log_event(&EAPMETHOD_TLS_SERVER_CERT_REVOKE_SKIPPED, event_data((unsigned int)obj->m_module.m_eap_method), event_data(subj), event_data::blank);
                }
                break;

            case CRYPT_E_REVOKED:
                // One of the certificates in the chain was revoked.
                switch (status_rev.dwReason) {
                case CRL_REASON_AFFILIATION_CHANGED:
                case CRL_REASON_SUPERSEDED:
                case CRL_REASON_CESSATION_OF_OPERATION:
                case CRL_REASON_CERTIFICATE_HOLD:
                    // The revocation was of administrative nature. No need to black-list.
                    obj->m_module.log_event(&EAPMETHOD_TLS_SERVER_CERT_REVOKED1, event_data((unsigned int)obj->m_module.m_eap_method), event_data(subj), event_data(status_rev.dwReason), event_data::blank);
                    break;

                default: {
                    // One of the certificates in the chain was revoked as compromised. Black-list it.
                    obj->m_module.log_event(&EAPMETHOD_TLS_SERVER_CERT_REVOKED, event_data((unsigned int)obj->m_module.m_eap_method), event_data(subj), event_data(status_rev.dwReason), event_data::blank);
                    reg_key key;
                    if (key.create(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\") _T(VENDOR_NAME_STR) _T("\\") _T(PRODUCT_NAME_STR) _T("\\TLSCRL"), NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE)) {
                        vector<unsigned char> hash;
                        if (CertGetCertificateContextProperty(cert, CERT_HASH_PROP_ID, hash)) {
                            wstring hash_unicode;
                            hex_enc enc;
                            enc.encode(hash_unicode, hash.data(), hash.size());
                            RegSetValueExW(key, hash_unicode.c_str(), NULL, REG_SZ, reinterpret_cast<LPCBYTE>(subj.c_str()), (DWORD)((subj.length() + 1) * sizeof(wstring::value_type)));
                        }
                    }
                }}

                // Resume checking the rest of the chain.
                c += (size_t)status_rev.dwIndex + 1;
                break;

            case ERROR_SUCCESS:
                // Odd. CertVerifyRevocation() should return TRUE then. Nevertheless, we take this as a "yes".
                c = c_end;
                break;

            default:
                // Checking one of the certificates in the chain for revocation failed. Resume checking the rest.
                obj->m_module.log_event(&EAPMETHOD_TLS_SERVER_CERT_REVOKE_FAILED, event_data((unsigned int)obj->m_module.m_eap_method), event_data(subj), event_data(status_rev.dwError), event_data::blank);
                c += (size_t)status_rev.dwIndex + 1;
            }
        } else {
            // Revocation check finished.
            break;
        }
    }

    // Revocation check succeeded.
    obj->m_module.log_event(&EAPMETHOD_TLS_SERVER_CERT_REVOKE_FINISHED, event_data((unsigned int)obj->m_module.m_eap_method), event_data::blank);
    return 0;
}
