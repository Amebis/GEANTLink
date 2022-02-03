/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2022 Amebis
    Copyright © 2016 GÉANT
*/

#include "PCH.h"

using namespace std;
using namespace stdex;
using namespace winstd;


//////////////////////////////////////////////////////////////////////
// eap::peer_tls_base
//////////////////////////////////////////////////////////////////////

eap::peer_tls_base::peer_tls_base(_In_ eap_type_t eap_method) : peer(eap_method)
{
}


void eap::peer_tls_base::shutdown()
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


void eap::peer_tls_base::get_method_properties(
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


void eap::peer_tls_base::spawn_crl_check(_Inout_ winstd::cert_context &&cert)
{
    // Create the thread and add it to the list.
    m_crl_checkers.push_back(std::move(crl_checker(*this, std::move(cert))));

    // Now the thread is in-place, start it.
    crl_checker &chk = m_crl_checkers.back();
    chk.m_thread = CreateThread(NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(crl_checker::verify), &chk, 0, NULL);
}


//////////////////////////////////////////////////////////////////////
// eap::peer_tls_base::crl_checker
//////////////////////////////////////////////////////////////////////

eap::peer_tls_base::crl_checker::crl_checker(_In_ module &mod, _Inout_ winstd::cert_context &&cert) :
    m_module(mod),
    m_cert  (std::move(cert)),
    m_abort (CreateEvent(NULL, TRUE, FALSE, NULL))
{
}


eap::peer_tls_base::crl_checker::crl_checker(_Inout_ crl_checker &&other) noexcept :
    m_module(          other.m_module ),
    m_thread(std::move(other.m_thread)),
    m_abort (std::move(other.m_abort )),
    m_cert  (std::move(other.m_cert  ))
{
}


eap::peer_tls_base::crl_checker& eap::peer_tls_base::crl_checker::operator=(_Inout_ crl_checker &&other) noexcept
{
    if (this != std::addressof(other)) {
        assert(std::addressof(m_module) == std::addressof(other.m_module)); // Move threads within same module only!
        m_thread = std::move(other.m_thread);
        m_abort  = std::move(other.m_abort );
        m_cert   = std::move(other.m_cert  );
    }

    return *this;
}


DWORD WINAPI eap::peer_tls_base::crl_checker::verify(_In_ crl_checker *obj)
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
                    obj->m_module.log_event(&EAPMETHOD_TLS_SERVER_CERT_REVOKE_SKIPPED, event_data((unsigned int)obj->m_module.m_eap_method), event_data(subj), blank_event_data);
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
                    obj->m_module.log_event(&EAPMETHOD_TLS_SERVER_CERT_REVOKED1, event_data((unsigned int)obj->m_module.m_eap_method), event_data(subj), event_data(status_rev.dwReason), blank_event_data);
                    break;

                default: {
                    // One of the certificates in the chain was revoked as compromised. Black-list it.
                    obj->m_module.log_event(&EAPMETHOD_TLS_SERVER_CERT_REVOKED, event_data((unsigned int)obj->m_module.m_eap_method), event_data(subj), event_data(status_rev.dwReason), blank_event_data);
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
                obj->m_module.log_event(&EAPMETHOD_TLS_SERVER_CERT_REVOKE_FAILED, event_data((unsigned int)obj->m_module.m_eap_method), event_data(subj), event_data(status_rev.dwError), blank_event_data);
                c += (size_t)status_rev.dwIndex + 1;
            }
        } else {
            // Revocation check finished.
            break;
        }
    }

    // Revocation check succeeded.
    obj->m_module.log_event(&EAPMETHOD_TLS_SERVER_CERT_REVOKE_FINISHED, event_data((unsigned int)obj->m_module.m_eap_method), blank_event_data);
    return 0;
}
