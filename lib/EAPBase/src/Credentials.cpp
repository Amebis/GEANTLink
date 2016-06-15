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


bool eap::credentials::save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError) const
{
    const bstr bstrNamespace(L"urn:ietf:params:xml:ns:yang:ietf-eap-metadata");
    DWORD dwResult;

    // <UserName>
    if ((dwResult = eapxml::put_element_value(pDoc, pConfigRoot, bstr(L"UserName"), bstrNamespace, bstr(m_identity))) != ERROR_SUCCESS) {
        *ppEapError = m_module.make_error(dwResult, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error creating <UserName> element."), NULL);
        return false;
    }

    return true;
}


bool eap::credentials::load(_In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError)
{
    assert(pConfigRoot);
    DWORD dwResult;

    if ((dwResult = eapxml::get_element_value(pConfigRoot, bstr(L"eap-metadata:UserName"), m_identity)) != ERROR_SUCCESS) {
        *ppEapError = m_module.make_error(dwResult, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error reading <UserName> element."), NULL);
        return false;
    }

    return true;
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


void eap::credentials_pass::clear()
{
    credentials::clear();
    m_password.clear();
}


bool eap::credentials_pass::empty() const
{
    return credentials::empty() && m_password.empty();
}


bool eap::credentials_pass::save(_In_ IXMLDOMDocument *pDoc, _In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError) const
{
    const bstr bstrNamespace(L"urn:ietf:params:xml:ns:yang:ietf-eap-metadata");
    DWORD dwResult;

    if (!credentials::save(pDoc, pConfigRoot, ppEapError))
        return false;

    // <Password>
    bstr pass(m_password);
    dwResult = eapxml::put_element_value(pDoc, pConfigRoot, bstr(L"Password"), bstrNamespace, pass);
    SecureZeroMemory((BSTR)pass, sizeof(OLECHAR)*pass.length());
    if (dwResult != ERROR_SUCCESS) {
        *ppEapError = m_module.make_error(dwResult, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error creating <Password> element."), NULL);
        return false;
    }

    return true;
}


bool eap::credentials_pass::load(_In_ IXMLDOMNode *pConfigRoot, _Out_ EAP_ERROR **ppEapError)
{
    assert(pConfigRoot);
    DWORD dwResult;

    if (!credentials::load(pConfigRoot, ppEapError))
        return false;

    bstr pass;
    if ((dwResult = eapxml::get_element_value(pConfigRoot, bstr(L"eap-metadata:Password"), &pass)) != ERROR_SUCCESS) {
        *ppEapError = m_module.make_error(dwResult, 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Error reading <Password> element."), NULL);
        return false;
    }
    m_password = pass;
    SecureZeroMemory((BSTR)pass, sizeof(OLECHAR)*pass.length());

    return true;
}


bool eap::credentials_pass::store(_In_ LPCTSTR pszTargetName, _Out_ EAP_ERROR **ppEapError) const
{
    assert(pszTargetName);
    assert(ppEapError);
    string password_enc;

    // Prepare cryptographics provider.
    crypt_prov cp;
    if (!cp.create(NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        *ppEapError = m_module.make_error(GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" CryptAcquireContext failed."), NULL);
        return false;
    }

    // Encrypt password.
    vector<unsigned char> password;
    if (!m_module.encrypt_md5(cp, m_password, password, ppEapError))
        return false;

    // Convert encrypted password to Base64, since CredProtectA() fail for binary strings.
    string password_base64;
    base64_enc enc;
    enc.encode(password_base64, password.data(), password.size());

    // Encrypt the password using user's key.
    CRED_PROTECTION_TYPE cpt;
    if (!CredProtectA(TRUE, password_base64.c_str(), (DWORD)password_base64.length(), password_enc, &cpt)) {
        *ppEapError = m_module.make_error(GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" CredProtect failed."), NULL);
        return false;
    }

    tstring target(target_name(pszTargetName));

    // Write credentials.
    assert(password_enc.size() < CRED_MAX_CREDENTIAL_BLOB_SIZE);
    assert(m_identity.length() < CRED_MAX_USERNAME_LENGTH     );
    CREDENTIAL cred = {
        0,                          // Flags
        CRED_TYPE_GENERIC,          // Type
        (LPTSTR)target.c_str(),     // TargetName
        _T(""),                     // Comment
        { 0, 0 },                   // LastWritten
        (DWORD)password_enc.size(), // CredentialBlobSize
        (LPBYTE)password_enc.data(),// CredentialBlob
        CRED_PERSIST_ENTERPRISE,    // Persist
        0,                          // AttributeCount
        NULL,                       // Attributes
        NULL,                       // TargetAlias
        (LPTSTR)m_identity.c_str()  // UserName
    };
    if (!CredWrite(&cred, 0)) {
        *ppEapError = m_module.make_error(GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" CredWrite failed."), NULL);
        return false;
    }

    return true;
}


bool eap::credentials_pass::retrieve(_In_ LPCTSTR pszTargetName, _Out_ EAP_ERROR **ppEapError)
{
    assert(pszTargetName);

    // Read credentials.
    unique_ptr<CREDENTIAL, CredFree_delete<CREDENTIAL> > cred;
    if (!CredRead(target_name(pszTargetName).c_str(), CRED_TYPE_GENERIC, 0, (PCREDENTIAL*)&cred)) {
        *ppEapError = m_module.make_error(GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" CredRead failed."), NULL);
        return false;
    }

    m_identity = cred->UserName;

    // Decrypt the password using user's key.
    string password_base64;
    if (!CredUnprotectA(TRUE, (LPCSTR)(cred->CredentialBlob), cred->CredentialBlobSize, password_base64)) {
        *ppEapError = m_module.make_error(GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" CredUnprotect failed."), NULL);
        return false;
    }

    // Convert Base64 to binary encrypted password, since CredProtectA() fail for binary strings.
    vector<char, sanitizing_allocator<char> > password;
    base64_dec dec;
    bool is_last;
    dec.decode(password, is_last, password_base64.c_str(), password_base64.length());

    // Prepare cryptographics provider.
    crypt_prov cp;
    if (!cp.create(NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        *ppEapError = m_module.make_error(GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" CryptAcquireContext failed."), NULL);
        return false;
    }

    // Decrypt password.
    return m_module.decrypt_md5(cp, password.data(), password.size(), m_password, ppEapError);
}
