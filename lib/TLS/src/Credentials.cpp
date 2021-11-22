/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2021 Amebis
    Copyright © 2016 GÉANT
*/

#include "PCH.h"

using namespace std;
using namespace winstd;


//////////////////////////////////////////////////////////////////////
// eap::credentials_tls
//////////////////////////////////////////////////////////////////////

eap::credentials_tls::credentials_tls(_In_ module &mod) : credentials(mod)
{
}


eap::credentials_tls::credentials_tls(_In_ const credentials_tls &other) :
    m_cert_hash(other.m_cert_hash),
    credentials(other)
{
}


eap::credentials_tls::credentials_tls(_Inout_ credentials_tls &&other) noexcept :
    m_cert_hash(std::move(other.m_cert_hash)),
    credentials(std::move(other))
{
}


eap::credentials_tls& eap::credentials_tls::operator=(_In_ const credentials_tls &other)
{
    if (this != &other) {
        (credentials&)*this = other;
        m_cert_hash         = other.m_cert_hash;
    }

    return *this;
}


eap::credentials_tls& eap::credentials_tls::operator=(_Inout_ credentials_tls &&other) noexcept
{
    if (this != &other) {
        (credentials&)*this = std::move(other);
        m_cert_hash         = std::move(other.m_cert_hash);
    }

    return *this;
}


eap::config* eap::credentials_tls::clone() const
{
    return new credentials_tls(*this);
}


void eap::credentials_tls::clear()
{
    credentials::clear();
    m_cert_hash.clear();
}


bool eap::credentials_tls::empty() const
{
    return m_cert_hash.empty();
}


void eap::credentials_tls::save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot) const
{
    assert(pDoc);
    assert(pConfigRoot);

    credentials::save(pDoc, pConfigRoot);

    HRESULT hr;

    // <ClientCertificate>
    com_obj<IXMLDOMElement> pXmlElClientCertificate;
    if (FAILED(hr = eapxml::create_element(pDoc, pConfigRoot, bstr(L"eap-metadata:ClientCertificate"), bstr(L"ClientCertificate"), namespace_eapmetadata, pXmlElClientCertificate)))
        throw com_runtime_error(hr, __FUNCTION__ " Error creating <ClientCertificate> element.");

    if (!m_cert_hash.empty()) {
        // <ClientCertificate>/<hash>
        if (FAILED(hr = eapxml::put_element_hex(pDoc, pXmlElClientCertificate, bstr(L"hash"), namespace_eapmetadata, m_cert_hash.data(), m_cert_hash.size())))
            throw com_runtime_error(hr, __FUNCTION__ " Error creating <hash> element.");
    }
}


void eap::credentials_tls::load(_In_ IXMLDOMNode *pConfigRoot)
{
    assert(pConfigRoot);
    HRESULT hr;

    credentials::load(pConfigRoot);

    std::wstring xpath(eapxml::get_xpath(pConfigRoot));

    m_cert_hash.clear();

    // <ClientCertificate>
    com_obj<IXMLDOMElement> pXmlElClientCertificate;
    if (FAILED(hr = eapxml::select_element(pConfigRoot, bstr(L"eap-metadata:ClientCertificate"), pXmlElClientCertificate)))
        throw com_runtime_error(hr, __FUNCTION__ " Error reading <ClientCertificate> element.");

    // <ClientCertificate>/<hash>
    eapxml::get_element_hex(pXmlElClientCertificate, bstr(L"eap-metadata:hash"), m_cert_hash);

    m_module.log_config((xpath + L"/ClientCertificateHash").c_str(), m_cert_hash.data(), (ULONG)m_cert_hash.size());
}


void eap::credentials_tls::operator<<(_Inout_ cursor_out &cursor) const
{
    credentials::operator<<(cursor);
    cursor << m_cert_hash;
}


size_t eap::credentials_tls::get_pk_size() const
{
    return
        credentials::get_pk_size() +
        pksizeof(m_cert_hash);
}


void eap::credentials_tls::operator>>(_Inout_ cursor_in &cursor)
{
    credentials::operator>>(cursor);
    cursor >> m_cert_hash;
}


void eap::credentials_tls::store(_In_z_ LPCTSTR pszTargetName, _In_ unsigned int level) const
{
    assert(pszTargetName);
    tstring target(target_name(pszTargetName, level));

    // Write credentials.
    assert(m_cert_hash.size()  < CRED_MAX_CREDENTIAL_BLOB_SIZE);
    assert(m_identity.length() < CRED_MAX_USERNAME_LENGTH     );
    CREDENTIAL cred = {
        0,                                     // Flags
        CRED_TYPE_GENERIC,                     // Type
        const_cast<LPTSTR>(target.c_str()),    // TargetName
        _T(""),                                // Comment
        { 0, 0 },                              // LastWritten
        (DWORD)m_cert_hash.size(),             // CredentialBlobSize
        (LPBYTE)m_cert_hash.data(),            // CredentialBlob
        CRED_PERSIST_ENTERPRISE,               // Persist
        0,                                     // AttributeCount
        NULL,                                  // Attributes
        NULL,                                  // TargetAlias
        const_cast<LPTSTR>(m_identity.c_str()) // UserName
    };
    if (!CredWrite(&cred, 0))
        throw win_runtime_error(__FUNCTION__ " CredWrite failed.");
}


void eap::credentials_tls::retrieve(_In_z_ LPCTSTR pszTargetName, _In_ unsigned int level)
{
    assert(pszTargetName);

    // Read credentials.
    unique_ptr<CREDENTIAL, CredFree_delete<CREDENTIAL> > cred;
    if (!CredRead(target_name(pszTargetName, level).c_str(), CRED_TYPE_GENERIC, 0, (PCREDENTIAL*)&cred))
        throw win_runtime_error(__FUNCTION__ " CredRead failed.");

    if (cred->CredentialBlobSize)
        m_cert_hash.assign(cred->CredentialBlob, cred->CredentialBlob + cred->CredentialBlobSize);
    else
        m_cert_hash.clear();

    if (cred->UserName)
        m_identity = cred->UserName;
    else
        m_identity.clear();

    wstring xpath(pszTargetName);
    m_module.log_config((xpath + L"/Identity").c_str(), m_identity.c_str());
    m_module.log_config((xpath + L"/CertificateHash").c_str(), m_cert_hash.data(), (ULONG)m_cert_hash.size());
}


LPCTSTR eap::credentials_tls::target_suffix() const
{
    return _T("cert");
}


std::wstring eap::credentials_tls::get_identity() const
{
    if (!m_identity.empty()) {
        return m_identity;
    } else if (!m_cert_hash.empty()) {
        // Find certificate in the store.
        winstd::cert_store store;
        vector<unsigned char> hash;
        if (store.create(CERT_STORE_PROV_SYSTEM, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, (HCRYPTPROV)NULL, CERT_SYSTEM_STORE_CURRENT_USER, _T("My"))) {
            for (PCCERT_CONTEXT cert = NULL; (cert = CertEnumCertificatesInStore(store, cert)) != NULL;) {
                if (CertGetCertificateContextProperty(cert, CERT_HASH_PROP_ID, hash) &&
                    hash == m_cert_hash)
                {
                    wstring name;
                    CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, name);
                    return name;
                }
            }
        }
    }

    return L"";
}


eap::credentials::source_t eap::credentials_tls::combine(
    _In_             DWORD         dwFlags,
    _In_opt_   const credentials   *cred_cached,
    _In_       const config_method &cfg,
    _In_opt_z_       LPCTSTR       pszTargetName)
{
    UNREFERENCED_PARAMETER(dwFlags);

    if (cred_cached) {
        // Using EAP service cached credentials.
        *this = *dynamic_cast<const credentials_tls*>(cred_cached);
        m_module.log_event(&EAPMETHOD_TRACE_EVT_CRED_CACHED2, event_data((unsigned int)eap_type_t::tls), event_data(credentials_tls::get_name()), event_data(pszTargetName), event_data::blank);
        return source_t::cache;
    }

    auto cfg_with_cred = dynamic_cast<const config_method_with_cred*>(&cfg);
    if (cfg_with_cred && cfg_with_cred->m_use_cred) {
        // Using configured credentials.
        *this = *dynamic_cast<const credentials_tls*>(cfg_with_cred->m_cred.get());
        m_module.log_event(&EAPMETHOD_TRACE_EVT_CRED_CONFIG2, event_data((unsigned int)eap_type_t::tls), event_data(credentials_tls::get_name()), event_data(pszTargetName), event_data::blank);
        return source_t::config;
    }

    if (pszTargetName) {
        try {
            credentials_tls cred_loaded(m_module);
            cred_loaded.retrieve(pszTargetName, cfg.m_level);

            // Using stored credentials.
            *this = std::move(cred_loaded);
            m_module.log_event(&EAPMETHOD_TRACE_EVT_CRED_STORED2, event_data((unsigned int)eap_type_t::tls), event_data(credentials_tls::get_name()), event_data(pszTargetName), event_data::blank);
            return source_t::storage;
        } catch (...) {
            // Not actually an error.
        }
    }

    return source_t::unknown;
}
