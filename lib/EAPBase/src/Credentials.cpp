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

#pragma comment(lib, "Crypt32.lib")

using namespace std;
using namespace winstd;


//////////////////////////////////////////////////////////////////////
// eap::credentials
//////////////////////////////////////////////////////////////////////

eap::credentials::credentials(_In_ module &mod) : config(mod)
{
}


eap::credentials::credentials(_In_ const credentials &other) :
    m_identity(other.m_identity),
    config(other)
{
}


eap::credentials::credentials(_Inout_ credentials &&other) :
    m_identity(std::move(other.m_identity)),
    config(std::move(other))
{
}


eap::credentials& eap::credentials::operator=(_In_ const credentials &other)
{
    if (this != &other) {
        (config&)*this = other;
        m_identity     = other.m_identity;
    }

    return *this;
}


eap::credentials& eap::credentials::operator=(_Inout_ credentials &&other)
{
    if (this != &other) {
        (config&)*this = std::move(other);
        m_identity     = std::move(other.m_identity);
    }

    return *this;
}


void eap::credentials::clear()
{
    m_identity.clear();
}


bool eap::credentials::empty() const
{
    return m_identity.empty();
}


void eap::credentials::save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot) const
{
    assert(pDoc);
    assert(pConfigRoot);

    config::save(pDoc, pConfigRoot);

    HRESULT hr;

    // <UserName>
    if (!m_identity.empty())
        if (FAILED(hr = eapxml::put_element_value(pDoc, pConfigRoot, bstr(L"UserName"), namespace_eapmetadata, bstr(m_identity))))
            throw com_runtime_error(hr, __FUNCTION__ " Error creating <UserName> element.");
}


void eap::credentials::load(_In_ IXMLDOMNode *pConfigRoot)
{
    assert(pConfigRoot);
    HRESULT hr;

    config::load(pConfigRoot);

    std::wstring xpath(eapxml::get_xpath(pConfigRoot));

    if (FAILED(hr = eapxml::get_element_value(pConfigRoot, bstr(L"eap-metadata:UserName"), m_identity)))
        m_identity.clear();

    m_module.log_config((xpath + L"/UserName").c_str(), m_identity.c_str());
}


void eap::credentials::operator<<(_Inout_ cursor_out &cursor) const
{
    config::operator<<(cursor);
    cursor << m_identity;
}


size_t eap::credentials::get_pk_size() const
{
    return
        config::get_pk_size() +
        pksizeof(m_identity);
}


void eap::credentials::operator>>(_Inout_ cursor_in &cursor)
{
    config::operator>>(cursor);
    cursor >> m_identity;
}


wstring eap::credentials::get_identity() const
{
    return m_identity;
}


tstring eap::credentials::get_name() const
{
    tstring identity(std::move(get_identity()));
    return
        !identity.empty() ? identity :
        empty()           ? _T("<empty>") : _T("<blank ID>");
}


//////////////////////////////////////////////////////////////////////
// eap::credentials_pass
//////////////////////////////////////////////////////////////////////

eap::credentials_pass::credentials_pass(_In_ module &mod) : credentials(mod)
{
}


eap::credentials_pass::credentials_pass(_In_ const credentials_pass &other) :
    m_password(other.m_password),
    credentials(other)
{
}


eap::credentials_pass::credentials_pass(_Inout_ credentials_pass &&other) :
    m_password(std::move(other.m_password)),
    credentials(std::move(other))
{
}


eap::credentials_pass& eap::credentials_pass::operator=(_In_ const credentials_pass &other)
{
    if (this != &other) {
        (credentials&)*this = other;
        m_password          = other.m_password;
    }

    return *this;
}


eap::credentials_pass& eap::credentials_pass::operator=(_Inout_ credentials_pass &&other)
{
    if (this != &other) {
        (credentials&)*this = std::move(other);
        m_password          = std::move(other.m_password);
    }

    return *this;
}


eap::config* eap::credentials_pass::clone() const
{
    return new credentials_pass(*this);
}


void eap::credentials_pass::clear()
{
    credentials::clear();
    m_password.clear();
}


bool eap::credentials_pass::empty() const
{
    return credentials::empty() && m_password.empty();
}


void eap::credentials_pass::save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot) const
{
    assert(pDoc);
    assert(pConfigRoot);

    credentials::save(pDoc, pConfigRoot);

    HRESULT hr;

    // <Password>
    bstr pass(m_password);
    hr = eapxml::put_element_value(pDoc, pConfigRoot, bstr(L"Password"), namespace_eapmetadata, pass);
    SecureZeroMemory((BSTR)pass, sizeof(OLECHAR)*pass.length());
    if (FAILED(hr))
        throw com_runtime_error(hr, __FUNCTION__ " Error creating <Password> element.");
}


void eap::credentials_pass::load(_In_ IXMLDOMNode *pConfigRoot)
{
    assert(pConfigRoot);
    HRESULT hr;

    credentials::load(pConfigRoot);

    std::wstring xpath(eapxml::get_xpath(pConfigRoot));

    bstr pass;
    if (FAILED(hr = eapxml::get_element_value(pConfigRoot, bstr(L"eap-metadata:Password"), &pass)))
        throw com_runtime_error(hr, __FUNCTION__ " Error reading <Password> element.");
    m_password = pass;
    SecureZeroMemory((BSTR)pass, sizeof(OLECHAR)*pass.length());

    m_module.log_config((xpath + L"/Password").c_str(),
#ifdef _DEBUG
        m_password.c_str()
#else
        L"********"
#endif
        );
}


void eap::credentials_pass::operator<<(_Inout_ cursor_out &cursor) const
{
    credentials::operator<<(cursor);
    cursor << m_password;
}


size_t eap::credentials_pass::get_pk_size() const
{
    return
        credentials::get_pk_size() +
        pksizeof(m_password);
}


void eap::credentials_pass::operator>>(_Inout_ cursor_in &cursor)
{
    credentials::operator>>(cursor);
    cursor >> m_password;
}


void eap::credentials_pass::store(_In_z_ LPCTSTR pszTargetName, _In_ unsigned int level) const
{
    assert(pszTargetName);

    // Convert password to UTF-8.
    sanitizing_string cred_utf8;
    WideCharToMultiByte(CP_UTF8, 0, m_password.c_str(), (int)m_password.length(), cred_utf8, NULL, NULL);

    // Encrypt the password using user's key.
    DATA_BLOB cred_blob    = { (DWORD)cred_utf8.size() , (LPBYTE)cred_utf8.data() };
    DATA_BLOB entropy_blob = {        sizeof(s_entropy), (LPBYTE)s_entropy        };
    data_blob cred_enc;
    if (!CryptProtectData(&cred_blob, NULL, &entropy_blob, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &cred_enc))
        throw win_runtime_error(__FUNCTION__ " CryptProtectData failed.");

    tstring target(target_name(pszTargetName, level));

    // Write credentials.
    assert(cred_enc.cbData     < CRED_MAX_CREDENTIAL_BLOB_SIZE);
    assert(m_identity.length() < CRED_MAX_USERNAME_LENGTH     );
    CREDENTIAL cred = {
        0,                          // Flags
        CRED_TYPE_GENERIC,          // Type
        (LPTSTR)target.c_str(),     // TargetName
        _T(""),                     // Comment
        { 0, 0 },                   // LastWritten
        cred_enc.cbData,            // CredentialBlobSize
        cred_enc.pbData,            // CredentialBlob
        CRED_PERSIST_ENTERPRISE,    // Persist
        0,                          // AttributeCount
        NULL,                       // Attributes
        NULL,                       // TargetAlias
        (LPTSTR)m_identity.c_str()  // UserName
    };
    if (!CredWrite(&cred, 0))
        throw win_runtime_error(__FUNCTION__ " CredWrite failed.");
}


void eap::credentials_pass::retrieve(_In_z_ LPCTSTR pszTargetName, _In_ unsigned int level)
{
    assert(pszTargetName);

    // Read credentials.
    unique_ptr<CREDENTIAL, CredFree_delete<CREDENTIAL> > cred;
    if (!CredRead(target_name(pszTargetName, level).c_str(), CRED_TYPE_GENERIC, 0, (PCREDENTIAL*)&cred))
        throw win_runtime_error(__FUNCTION__ " CredRead failed.");

    // Decrypt the password using user's key.
    DATA_BLOB cred_enc     = { cred->CredentialBlobSize,         cred->CredentialBlob };
    DATA_BLOB entropy_blob = { sizeof(s_entropy)       , (LPBYTE)s_entropy            };
    data_blob cred_int;
    if (!CryptUnprotectData(&cred_enc, NULL, &entropy_blob, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_VERIFY_PROTECTION, &cred_int))
        throw win_runtime_error(__FUNCTION__ " CryptUnprotectData failed.");

    // Convert password from UTF-8.
    MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)cred_int.pbData, (int)cred_int.cbData, m_password);
    SecureZeroMemory(cred_int.pbData, cred_int.cbData);

    if (cred->UserName)
        m_identity = cred->UserName;
    else
        m_identity.clear();

    wstring xpath(pszTargetName);
    m_module.log_config((xpath + L"/Identity").c_str(), m_identity.c_str());
    m_module.log_config((xpath + L"/Password").c_str(),
#ifdef _DEBUG
        m_password.c_str()
#else
        L"********"
#endif
        );
}


LPCTSTR eap::credentials_pass::target_suffix() const
{
    return _T("pass");
}


eap::credentials::source_t eap::credentials_pass::combine(
    _In_       const credentials             *cred_cached,
    _In_       const config_method_with_cred &cfg,
    _In_opt_z_       LPCTSTR                 pszTargetName)
{
    if (cred_cached) {
        // Using EAP service cached credentials.
        *this = *(credentials_pass*)cred_cached;
        m_module.log_event(&EAPMETHOD_TRACE_EVT_CRED_CACHED1, event_data((unsigned int)cfg.get_method_id()), event_data(credentials_pass::get_name()), event_data::blank);
        return source_cache;
    }

    if (cfg.m_use_preshared) {
        // Using preshared credentials.
        *this = *(credentials_pass*)cfg.m_preshared.get();
        m_module.log_event(&EAPMETHOD_TRACE_EVT_CRED_PRESHARED1, event_data((unsigned int)cfg.get_method_id()), event_data(credentials_pass::get_name()), event_data::blank);
        return source_preshared;
    }

    if (pszTargetName) {
        try {
            credentials_pass cred_loaded(m_module);
            cred_loaded.retrieve(pszTargetName, cfg.m_level);

            // Using stored credentials.
            *this = std::move(cred_loaded);
            m_module.log_event(&EAPMETHOD_TRACE_EVT_CRED_STORED1, event_data((unsigned int)cfg.get_method_id()), event_data(credentials_pass::get_name()), event_data::blank);
            return source_storage;
        } catch (...) {
            // Not actually an error.
        }
    }

    return source_unknown;
}


const unsigned char eap::credentials_pass::s_entropy[1024] = {
    0x40, 0x88, 0xd3, 0x13, 0x81, 0x8a, 0xf6, 0x74, 0x55, 0x8e, 0xcc, 0x73, 0x2c, 0xf8, 0x93, 0x37,
    0x4f, 0xeb, 0x1d, 0x66, 0xb7, 0xfb, 0x47, 0x75, 0xb4, 0xfd, 0x07, 0xbb, 0xf6, 0xb3, 0x05, 0x30,
    0x4a, 0xc0, 0xff, 0x05, 0xbd, 0x1e, 0x2f, 0x55, 0xc8, 0x77, 0x70, 0x47, 0xc9, 0x85, 0x57, 0x22,
    0x8e, 0x54, 0x0b, 0x4d, 0x26, 0x80, 0x11, 0x0c, 0x52, 0x55, 0xc2, 0x3b, 0x9b, 0xd2, 0x19, 0x61,
    0xf1, 0x71, 0xf5, 0x4b, 0x49, 0x73, 0xf9, 0x6d, 0x44, 0xd2, 0x90, 0x92, 0x2d, 0xae, 0xc6, 0xbb,
    0x3d, 0xfe, 0x52, 0x47, 0x82, 0xc1, 0xa9, 0xe1, 0x6a, 0xd1, 0xd2, 0x4e, 0x3d, 0x9b, 0x4e, 0xc0,
    0x40, 0x36, 0x79, 0xd3, 0x88, 0xfc, 0x0b, 0x79, 0x8c, 0xb2, 0x9d, 0x74, 0x13, 0x29, 0x59, 0x0c,
    0xe0, 0x87, 0x34, 0x7d, 0xc1, 0x30, 0xd4, 0xe9, 0x98, 0xd1, 0x3f, 0x82, 0xcb, 0x8b, 0x44, 0x09,
    0x2d, 0xc5, 0x9e, 0x3d, 0x66, 0xe5, 0x1a, 0x9d, 0xa6, 0x87, 0x20, 0x7f, 0x55, 0xd7, 0x89, 0xf2,
    0xbb, 0x5f, 0x00, 0xf9, 0x38, 0xd3, 0x49, 0x10, 0x6f, 0x3a, 0xab, 0x5d, 0x8f, 0x73, 0x8c, 0xbc,
    0x6f, 0xf1, 0xef, 0x83, 0x43, 0xcb, 0xc9, 0xb7, 0x9f, 0x24, 0xe4, 0x91, 0x3a, 0xe6, 0xab, 0x6c,
    0xf2, 0xfd, 0x66, 0xf0, 0xb1, 0x1a, 0xc8, 0xc4, 0x6b, 0x9d, 0xa7, 0x10, 0x7d, 0x30, 0x29, 0x1b,
    0xe5, 0xfe, 0x1c, 0x97, 0x86, 0x1e, 0x80, 0xe5, 0x12, 0x0a, 0x2a, 0x0d, 0xd9, 0x4a, 0x35, 0xe5,
    0xab, 0xdf, 0x61, 0x76, 0x4e, 0x36, 0xff, 0xb1, 0x26, 0x5e, 0x12, 0x7f, 0xdf, 0xd7, 0x98, 0x55,
    0xf9, 0x89, 0x30, 0xcc, 0xe9, 0xf6, 0xd0, 0xc0, 0x69, 0xf4, 0x78, 0x81, 0x10, 0xeb, 0x34, 0xf3,
    0x5a, 0x8a, 0x62, 0xd4, 0x97, 0xe6, 0xb7, 0x98, 0x86, 0x5f, 0xb6, 0xcb, 0x9c, 0xab, 0xd6, 0xe9,
    0xda, 0x2b, 0x41, 0xbb, 0xa3, 0x37, 0x1f, 0x7d, 0x4e, 0x19, 0x13, 0xc3, 0xab, 0x23, 0x4d, 0xa6,
    0x51, 0xa9, 0x07, 0x60, 0xb9, 0x0c, 0x49, 0xce, 0x40, 0x29, 0x15, 0x0d, 0x10, 0xde, 0xc9, 0x0c,
    0x11, 0x91, 0xdc, 0xdf, 0xc8, 0xac, 0x13, 0xe5, 0xe9, 0x11, 0xdc, 0x47, 0xb7, 0xb3, 0xf5, 0xd0,
    0xc4, 0x38, 0x10, 0x17, 0xf7, 0x93, 0x93, 0x6b, 0x56, 0x10, 0xc6, 0xa6, 0x4c, 0xf8, 0x9c, 0x52,
    0xb7, 0xbd, 0x87, 0xe8, 0xff, 0x84, 0x01, 0xbb, 0x40, 0x84, 0x03, 0x19, 0x6f, 0xf7, 0x46, 0x6f,
    0x10, 0xc0, 0x85, 0xdf, 0xfd, 0xad, 0x00, 0xf6, 0xd5, 0x05, 0x22, 0xf4, 0x28, 0x87, 0xf6, 0x0c,
    0xca, 0xda, 0x9a, 0x67, 0x63, 0xa4, 0x2d, 0x4d, 0xa5, 0x06, 0xa1, 0x8b, 0x32, 0x9b, 0xb0, 0xed,
    0x05, 0x8e, 0x36, 0xa4, 0xbe, 0xa0, 0x9c, 0x78, 0xfa, 0x2c, 0x9e, 0x99, 0x02, 0x50, 0x63, 0xd4,
    0xd5, 0x4a, 0x9b, 0xc3, 0x81, 0x95, 0xab, 0x18, 0x47, 0x3d, 0x44, 0x15, 0x33, 0x79, 0xd0, 0x53,
    0x4e, 0xfc, 0x2f, 0x66, 0xc9, 0x7c, 0xb9, 0xda, 0xa2, 0xce, 0xfa, 0x39, 0xea, 0x72, 0x2c, 0xe2,
    0x5c, 0x1f, 0x7e, 0xcd, 0x2a, 0x3e, 0x11, 0x19, 0x06, 0xc7, 0x03, 0x89, 0x4c, 0xd3, 0x73, 0xea,
    0xa5, 0x69, 0x1e, 0x68, 0x04, 0xcd, 0xbb, 0xc4, 0x74, 0x7b, 0x1e, 0x75, 0x6f, 0xf1, 0x89, 0xea,
    0x21, 0xdf, 0x9e, 0x1b, 0x27, 0x4a, 0x20, 0xb4, 0x5b, 0x72, 0x68, 0x8e, 0x47, 0xe2, 0x18, 0x75,
    0x36, 0x82, 0xae, 0xa9, 0xa9, 0x40, 0xe5, 0x19, 0xa7, 0xea, 0x48, 0xad, 0x26, 0x7c, 0x93, 0x3e,
    0xbf, 0x48, 0x6c, 0x3e, 0x66, 0xf7, 0x3c, 0x8f, 0x3c, 0x0e, 0x77, 0xc8, 0xb5, 0x56, 0x3b, 0x3a,
    0x25, 0x13, 0x49, 0xb4, 0xcc, 0xbb, 0x8e, 0x94, 0x73, 0xa4, 0x35, 0x16, 0x95, 0x74, 0xa5, 0x98,
    0xa4, 0x61, 0xa2, 0x36, 0xaf, 0x7f, 0xdf, 0x04, 0xce, 0x34, 0xd3, 0xfc, 0x09, 0x83, 0x43, 0xc1,
    0x7a, 0x22, 0xc7, 0xfa, 0x3d, 0x97, 0xce, 0xc0, 0xcd, 0x15, 0xa4, 0x97, 0xb4, 0xd4, 0x55, 0x51,
    0xf1, 0xef, 0x81, 0x1a, 0xce, 0x1f, 0x5a, 0x2d, 0xba, 0xce, 0xec, 0xbd, 0x85, 0x57, 0x53, 0xc6,
    0x2f, 0x2a, 0x84, 0xab, 0xf3, 0x6e, 0x3b, 0xac, 0xf8, 0x73, 0xf2, 0x20, 0x42, 0x6f, 0xc4, 0xe2,
    0x20, 0xb7, 0xf8, 0x5e, 0xbd, 0xe7, 0xd2, 0x2b, 0xe6, 0x10, 0xc2, 0x66, 0xe7, 0x25, 0xf9, 0xb9,
    0xcb, 0xe4, 0x85, 0xbd, 0xf9, 0x62, 0x10, 0xfd, 0x67, 0x8f, 0x3f, 0x15, 0x4b, 0x10, 0x9e, 0xde,
    0x8a, 0x9c, 0xb5, 0x46, 0xb7, 0x96, 0xa8, 0x9d, 0xe8, 0xf1, 0xde, 0x34, 0xcf, 0x4c, 0xa4, 0xe6,
    0x35, 0x24, 0xcf, 0x47, 0xc5, 0x2d, 0xf2, 0xe3, 0x15, 0xf3, 0x39, 0xb7, 0x45, 0x2c, 0x92, 0x23,
    0x37, 0x28, 0xfa, 0x7b, 0x7b, 0xe9, 0xc3, 0x04, 0x57, 0x0c, 0x30, 0xab, 0x52, 0x3a, 0x1d, 0xf7,
    0x3a, 0x7b, 0xa0, 0xf0, 0x22, 0x14, 0xa8, 0xc7, 0x4e, 0xd5, 0x8b, 0x9a, 0xac, 0x67, 0x33, 0x0a,
    0xa2, 0xa4, 0x76, 0x65, 0x45, 0x48, 0x7d, 0x92, 0xd7, 0xdb, 0xb1, 0x51, 0xae, 0x5f, 0x95, 0x1c,
    0x8c, 0xe0, 0xaa, 0x28, 0x72, 0xbb, 0x2d, 0x97, 0x65, 0xfb, 0x3f, 0x41, 0x06, 0x46, 0xd1, 0x8c,
    0x99, 0x64, 0x0e, 0xc7, 0xf0, 0x82, 0x1f, 0x1e, 0x5e, 0x8a, 0xc8, 0x6e, 0x29, 0xf0, 0xa8, 0x38,
    0xa5, 0x38, 0x12, 0xaa, 0x9d, 0x60, 0x3d, 0x40, 0xfc, 0x29, 0x17, 0xc5, 0xe1, 0x1d, 0xba, 0x14,
    0x45, 0xf0, 0x16, 0x32, 0x8f, 0x37, 0x88, 0xad, 0x7c, 0x77, 0x57, 0x06, 0x89, 0x70, 0x1f, 0x0e,
    0x88, 0x9d, 0x2b, 0x5f, 0x83, 0x69, 0xb0, 0x48, 0x03, 0x86, 0xe4, 0x2e, 0x1c, 0xfb, 0x85, 0xb1,
    0xce, 0x1c, 0x0e, 0xe0, 0xd4, 0x17, 0x0f, 0xb2, 0xf1, 0x79, 0xde, 0x8f, 0xd2, 0x0a, 0xa5, 0x10,
    0xee, 0x9e, 0x05, 0x57, 0x0d, 0x42, 0x21, 0xaa, 0x53, 0xb1, 0x53, 0xd9, 0x59, 0x8b, 0x43, 0x22,
    0x82, 0xbe, 0xa3, 0x2a, 0x79, 0x89, 0x46, 0xc4, 0x18, 0x31, 0x3e, 0xd4, 0x3d, 0x79, 0x9b, 0x06,
    0xde, 0x7e, 0xe5, 0x20, 0xdd, 0xae, 0x34, 0xa8, 0x31, 0xc2, 0xdf, 0x61, 0x6d, 0x1b, 0x47, 0xc4,
    0xae, 0x25, 0x44, 0xa8, 0x79, 0x5c, 0x2b, 0x4a, 0x17, 0x6e, 0x7a, 0xe5, 0xf1, 0x48, 0x3f, 0x82,
    0x24, 0x6a, 0xc5, 0xc1, 0xfc, 0x65, 0x61, 0xca, 0xe4, 0x89, 0x52, 0x14, 0xe4, 0xb3, 0x7a, 0x24,
    0xc2, 0xe5, 0x59, 0x1d, 0x55, 0xa3, 0x95, 0x16, 0xe2, 0xcf, 0x07, 0xd8, 0xad, 0x9c, 0x30, 0xbe,
    0x96, 0xee, 0x80, 0x54, 0x63, 0xe7, 0xd4, 0xa6, 0xac, 0xe8, 0x15, 0xd4, 0xfc, 0x7b, 0xf8, 0xee,
    0x0e, 0x88, 0x51, 0xd9, 0xad, 0x6f, 0x0d, 0xea, 0x19, 0x3a, 0x1a, 0x20, 0xbc, 0x99, 0x59, 0xcc,
    0xba, 0x19, 0xc8, 0x26, 0x79, 0x79, 0xe8, 0xf6, 0x3f, 0xa0, 0xdb, 0xa6, 0x52, 0x4d, 0xc0, 0x98,
    0x22, 0xcf, 0x30, 0xae, 0xdf, 0x22, 0x94, 0x5c, 0x19, 0x01, 0xe3, 0xf0, 0x44, 0x23, 0xe5, 0xeb,
    0x70, 0x1a, 0xd2, 0x7f, 0xe8, 0x91, 0x1b, 0x55, 0xe7, 0xcb, 0x0d, 0xc2, 0x53, 0xa0, 0xe6, 0x7a,
    0x48, 0xab, 0x05, 0xbb, 0x55, 0x28, 0x98, 0x12, 0xe5, 0xd1, 0xd9, 0x44, 0xe9, 0xa8, 0x8d, 0xa4,
    0x68, 0xc8, 0x21, 0xa8, 0xe9, 0x49, 0x46, 0x22, 0xce, 0x81, 0xfe, 0x4a, 0xe3, 0xa0, 0x1c, 0xb0,
    0x30, 0x29, 0x39, 0x9a, 0xd6, 0xab, 0x2e, 0xc6, 0x42, 0x47, 0x5e, 0x54, 0xbb, 0x90, 0xe6, 0x98,
    0xe6, 0x52, 0x58, 0x58, 0x1e, 0xd0, 0x00, 0x9c, 0x8f, 0x4a, 0x17, 0x7e, 0x8a, 0x5a, 0xef, 0x3e,
};


//////////////////////////////////////////////////////////////////////
// eap::credentials_connection
//////////////////////////////////////////////////////////////////////

eap::credentials_connection::credentials_connection(_In_ module &mod, _In_ const config_connection &cfg) :
    m_cfg(cfg),
    config(mod)
{
}


eap::credentials_connection::credentials_connection(_In_ const credentials_connection &other) :
    m_cfg      (other.m_cfg      ),
    m_namespace(other.m_namespace),
    m_id       (other.m_id       ),
    m_cred     (other.m_cred ? (credentials*)other.m_cred->clone() : nullptr),
    config     (other            )
{
}


eap::credentials_connection::credentials_connection(_Inout_ credentials_connection &&other) :
    m_cfg      (          other.m_cfg       ),
    m_namespace(std::move(other.m_namespace)),
    m_id       (std::move(other.m_id       )),
    m_cred     (std::move(other.m_cred     )),
    config     (std::move(other            ))
{
}


eap::credentials_connection& eap::credentials_connection::operator=(_In_ const credentials_connection &other)
{
    if (this != &other) {
        (config&)*this = other;
        m_namespace    = other.m_namespace;
        m_id           = other.m_id;
        m_cred.reset(other.m_cred ? (credentials*)other.m_cred->clone() : nullptr);
    }

    return *this;
}


eap::credentials_connection& eap::credentials_connection::operator=(_Inout_ credentials_connection &&other)
{
    if (this != &other) {
        (config&)*this = std::move(other            );
        m_namespace    = std::move(other.m_namespace);
        m_id           = std::move(other.m_id       );
        m_cred         = std::move(other.m_cred     );
    }

    return *this;
}


eap::config* eap::credentials_connection::clone() const
{
    return new credentials_connection(*this);
}


void eap::credentials_connection::save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot) const
{
    assert(pDoc);
    assert(pConfigRoot);

    config::save(pDoc, pConfigRoot);

    HRESULT hr;

    // Create <EAPIdentityProvider> node.
    com_obj<IXMLDOMElement> pXmlElIdentityProvider;
    if (FAILED(hr = eapxml::create_element(pDoc, pConfigRoot, bstr(L"eap-metadata:EAPIdentityProvider"), bstr(L"EAPIdentityProvider"), namespace_eapmetadata, &pXmlElIdentityProvider)))
        throw com_runtime_error(hr, __FUNCTION__ " Error creating <EAPIdentityProvider> element.");

    // namespace
    if (!m_namespace.empty())
        if (FAILED(hr = eapxml::put_attrib_value(pXmlElIdentityProvider, bstr(L"namespace"), bstr(m_namespace))))
            throw com_runtime_error(hr, __FUNCTION__ " Error creating namespace attribute.");

    // ID
    if (!m_id.empty())
        if (FAILED(hr = eapxml::put_attrib_value(pXmlElIdentityProvider, bstr(L"ID"), bstr(m_id))))
            throw com_runtime_error(hr, __FUNCTION__ " Error creating ID attribute.");

    m_cred->save(pDoc, pXmlElIdentityProvider);
}


void eap::credentials_connection::load(_In_ IXMLDOMNode *pConfigRoot)
{
    assert(pConfigRoot);
    HRESULT hr;

    config::load(pConfigRoot);

    // <EAPIdentityProvider>
    winstd::com_obj<IXMLDOMElement> pXmlElClientSideCredential;
    if (FAILED(hr = eapxml::select_element(pConfigRoot, winstd::bstr(L"eap-metadata:EAPIdentityProvider"), &pXmlElClientSideCredential)))
        throw com_runtime_error(hr, __FUNCTION__ " Error loading <EAPIdentityProvider> element.");

    std::wstring xpath(eapxml::get_xpath(pXmlElClientSideCredential));

    // namespace
    m_namespace.clear();
    eapxml::get_attrib_value(pXmlElClientSideCredential, bstr(L"namespace"), m_namespace);
    m_module.log_config((xpath + L" namespace").c_str(), m_namespace.c_str());

    // ID
    m_id.clear();
    eapxml::get_attrib_value(pXmlElClientSideCredential, bstr(L"ID"), m_id);
    m_module.log_config((xpath + L" ID").c_str(), m_id.c_str());

    // Look-up the provider.
    for (config_connection::provider_list::const_iterator cfg_prov = m_cfg.m_providers.cbegin(), cfg_prov_end = m_cfg.m_providers.cend(); ; ++cfg_prov) {
        if (cfg_prov != cfg_prov_end) {
            if (match(*cfg_prov)) {
                // Matching provider found. Create matching blank credential set, then load.
                if (cfg_prov->m_methods.empty())
                    throw invalid_argument(string_printf(__FUNCTION__ " %ls provider has no methods.", cfg_prov->get_id().c_str()).c_str());
                const config_method_with_cred *cfg_method = dynamic_cast<const config_method_with_cred*>(cfg_prov->m_methods.front().get());
                m_cred.reset(cfg_method->make_credentials());
                m_cred->load(pXmlElClientSideCredential);
                break;
            }
        } else
            throw invalid_argument(string_printf(__FUNCTION__ " Credentials do not match to any provider within this connection configuration (provider: %ls).", get_id().c_str()).c_str());
    }
}


void eap::credentials_connection::operator<<(_Inout_ cursor_out &cursor) const
{
    config::operator<<(cursor);
    cursor <<  m_namespace;
    cursor <<  m_id       ;
    cursor << *m_cred     ;
}


size_t eap::credentials_connection::get_pk_size() const
{
    return
        config::get_pk_size() +
        pksizeof( m_namespace) +
        pksizeof( m_id       ) +
        pksizeof(*m_cred     );
}


void eap::credentials_connection::operator>>(_Inout_ cursor_in &cursor)
{
    config::operator>>(cursor);
    cursor >> m_namespace;
    cursor >> m_id       ;

    // Look-up the provider.
    for (config_connection::provider_list::const_iterator cfg_prov = m_cfg.m_providers.cbegin(), cfg_prov_end = m_cfg.m_providers.cend(); ; ++cfg_prov) {
        if (cfg_prov != cfg_prov_end) {
            if (match(*cfg_prov)) {
                // Matching provider found. Create matching blank credential set, then read.
                if (cfg_prov->m_methods.empty())
                    throw invalid_argument(string_printf(__FUNCTION__ " %ls provider has no methods.", cfg_prov->get_id().c_str()).c_str());
                const config_method_with_cred *cfg_method = dynamic_cast<const config_method_with_cred*>(cfg_prov->m_methods.front().get());
                m_cred.reset(cfg_method->make_credentials());
                cursor >> *m_cred;
                break;
            }
        } else
            throw invalid_argument(string_printf(__FUNCTION__ " Credentials do not match to any provider within this connection configuration (provider: %ls).", get_id().c_str()).c_str());
    }
}
